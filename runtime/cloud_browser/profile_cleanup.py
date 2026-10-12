"""Exact approved legacy cleanup during exclusive pre-admission startup.

No staged manifest means no I/O. Unknown DELETE outcomes require exact GET
reconciliation; saved accounts, credentials, grants and canonical profiles stay.
"""
from copy import deepcopy
import hashlib
import json
import re
from pathlib import Path


REVIEWED_SCOPE = '373faae5b829abeb36ae710b572159baa52ecfa2380fe98305f38a2e2ea5f2ff'
SHA = re.compile(r'[a-f0-9]{64}\Z')
EVIDENCE_ROOT=Path(__file__).resolve().parents[2]/'.local/clanker-qa'
ID = re.compile(r'[A-Za-z0-9_-]{1,160}\Z')


class Refused(Exception):
    def __init__(self, code='metadata_changed'):
        # Only backend literals become receipts; no provider exception text.
        super().__init__(code)
        self.code = code


def require(condition, code='metadata_changed'):
    if not condition: raise Refused(code)


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def fields(value, keys):
    require(isinstance(value,dict) and set(value)==set(keys.split()))


def identity(value): require(isinstance(value,str) and ID.fullmatch(value))


def credential_reference(value):
    from .kernel_auth_client import _reference
    try:_reference(value,response=True)
    except Exception:raise Refused('credential_unknown') from None


def profile(value):
    fields(value,'id name owner')
    for v in value.values(): identity(v)
    return deepcopy(value)


def connection(value):
    fields(value,'id profile_name generation terminal active_writer credential_ids backing_references')
    identity(value['id']);identity(value['profile_name'])
    require(isinstance(value['generation'],str) and SHA.fullmatch(value['generation']))
    require(value['terminal'] is True and value['active_writer'] is False,'active_auth_writer')
    require(type(value['backing_references']) is int and value['backing_references']==0,'saved_vault_reference')
    require(isinstance(value['credential_ids'],list) and len(value['credential_ids'])==len(set(value['credential_ids'])))
    for v in value['credential_ids']: credential_reference(v)
    return deepcopy(value)


class Executor:
    """Journal deletes in the owning SQLite transaction, then reconcile by GET.

    local.connect() provides a transaction; local.snapshot(db) must read current
    source rows/files without constructors, excluding this executor's journal.
    It supplies exact canonical identity, opaque CAS digest and target blockers.
    The production adapter journals and retires only exact inactive legacy references.
    Provider adapters must return complete lists or raise (never partial lists).
    DELETE methods dispatch once without automatic transport retries.
    maintenance.check() must verify a held gateway process lock and no Vault
    admission; an idle snapshot or caller-provided boolean is not sufficient.
    """
    def __init__(self,local,provider,maintenance):
        self.local,self.provider,self.maintenance=local,provider,maintenance

    def _authority(self):
        try:
            boot=self.maintenance.check();identity(boot);return boot
        except Exception:
            raise Refused('maintenance_unavailable') from None

    def _snapshot(self,db,scope):
        value=self.local.snapshot(db)
        fields(value,'canonical local_digest target_blockers')
        require(isinstance(value['local_digest'],str) and SHA.fullmatch(value['local_digest']))
        require(isinstance(value['canonical'],list) and len(value['canonical'])==4)
        canonical=[profile(p) for p in value['canonical']]
        require(len({p['id'] for p in canonical})==4 and len({p['name'] for p in canonical})==4)
        targets=scope['delete_profiles']
        require(not ({p['id'] for p in canonical}&{t['id'] for t in targets}),'canonical_target')
        require(not ({p['name'] for p in canonical}&{t['name'] for t in targets}),'canonical_target')
        require(isinstance(value['target_blockers'],dict) and set(value['target_blockers'])=={t['id'] for t in targets})
        for blockers in value['target_blockers'].values():
            require(blockers==[],'local_reference_or_work')
        return deepcopy(value)

    def _scope(self,scope):
        require(isinstance(scope,dict) and digest(scope)==REVIEWED_SCOPE,'scope_changed')
        require(len(scope['delete_profiles'])==32 and len({t['id'] for t in scope['delete_profiles']})==32)
        return deepcopy(scope)

    def _credentials(self,ids):
        result=[]
        for identity_ in sorted(ids):
            value=self.provider.credential(identity_)
            fields(value,'id fingerprint')
            require(value['id']==identity_ and isinstance(value['fingerprint'],str) and SHA.fullmatch(value['fingerprint']),'credential_changed')
            result.append(deepcopy(value))
        return result

    def prepare(self,scope,*,acceptance_sha256):
        """Read-only review preparation. Approval is still required for execute."""
        scope=self._scope(scope)
        require(isinstance(acceptance_sha256,str) and SHA.fullmatch(acceptance_sha256),'replacement_unverified')
        with self.local.connect() as db: snapshot=self._snapshot(db,scope)
        require(self.provider.active_browsers()==[],'active_browser')
        targets=[];credentials=set()
        for target in scope['delete_profiles']:
            expected={k:target[k] for k in ('id','name','owner')}
            require(profile(self.provider.profile(target['id']))==expected)
            require(profile(self.provider.profile(target['name']))==expected)
            raw=self.provider.connections(target['name']);require(isinstance(raw,list))
            rows=[connection(r) for r in raw]
            require(len(rows)==len(target['connection_ids']) and {r['id'] for r in rows}==set(target['connection_ids']))
            require(all(r['profile_name']==target['name'] for r in rows))
            credentials.update(c for r in rows for c in r['credential_ids'])
            targets.append(dict(profile=expected,connections=sorted(rows,key=lambda r:r['id'])))
        manifest=dict(version=1,scope=scope,local=snapshot,targets=targets,
                      credentials=self._credentials(credentials),acceptance_sha256=acceptance_sha256,
                      vault_fingerprint=self.provider.verify_vaults())
        # Final read catches a local change while provider metadata was fetched.
        with self.local.connect() as db: require(self._snapshot(db,scope)==snapshot,'local_changed')
        self._inventory(manifest,set())
        return manifest

    @staticmethod
    def _schema(db):
        db.execute('''CREATE TABLE IF NOT EXISTS legacy_profile_cleanup_ops(
          kind TEXT NOT NULL, resource_id TEXT NOT NULL, manifest_sha256 TEXT NOT NULL,
          identity_sha256 TEXT NOT NULL, local_sha256 TEXT NOT NULL, gateway_boot TEXT NOT NULL,
          state TEXT NOT NULL CHECK(state IN ('unknown','absent')),
          PRIMARY KEY(kind,resource_id))''')

    def _ops(self,db,manifest_sha,m):
        rows=[dict(r) for r in db.execute('SELECT * FROM legacy_profile_cleanup_ops')]
        expected={('profile',t['profile']['id']):t['profile'] for t in m['targets']}
        expected.update({('connection',c['id']):c for t in m['targets'] for c in t['connections']})
        result={}
        for row in rows:
            key=(row['kind'],row['resource_id'])
            if key not in expected:
                require(row['manifest_sha256']!=manifest_sha,'reservation_conflict');continue
            require(row['manifest_sha256']==manifest_sha and row['identity_sha256']==digest(expected[key]) and
                    row['local_sha256']==digest(m['local']) and row['state'] in {'unknown','absent'},'reservation_conflict')
            identity(row['gateway_boot']);result[key]=row
        return result

    def _validate(self,m,approved):
        fields(m,'version scope local targets credentials acceptance_sha256 vault_fingerprint')
        require(m['version']==1 and approved==digest(m),'approval_mismatch')
        self._scope(m['scope'])
        require(isinstance(m['acceptance_sha256'],str) and SHA.fullmatch(m['acceptance_sha256']))
        require(isinstance(m['targets'],list) and len(m['targets'])==32)
        for expected,target in zip(m['scope']['delete_profiles'],m['targets']):
            fields(target,'profile connections');profile(target['profile'])
            require(target['profile']=={k:expected[k] for k in ('id','name','owner')})
            require(isinstance(target['connections'],list))
            rows=[connection(r) for r in target['connections']]
            require(len(rows)==len(expected['connection_ids']) and {r['id'] for r in rows}==set(expected['connection_ids']))
            require(all(r['profile_name']==expected['name'] for r in rows))
        require(self._credentials({c['id'] for c in m['credentials']})==m['credentials'],'credential_changed')
        require(isinstance(m['vault_fingerprint'],str) and SHA.fullmatch(m['vault_fingerprint']) and
                self.provider.verify_vaults()==m['vault_fingerprint'],'vault_metadata_changed')
        expected_credentials={cid for t in m['targets'] for c in t['connections'] for cid in c['credential_ids']}
        require({c['id'] for c in m['credentials']}==expected_credentials,'credential_changed')
        self._authority()

    def _inventory(self,m,deleted):
        raw=self.provider.inventory();require(isinstance(raw,list),'incomplete_inventory')
        rows=[profile(p) for p in raw]
        expected=m['local']['canonical']+[t['profile'] for t in m['targets'] if t['profile']['id'] not in deleted]
        require(sorted(rows,key=lambda r:r['id'])==sorted(expected,key=lambda r:r['id']),'inventory_changed')
        return len(rows)

    def _current(self,m,ops,only=None):
        self._authority()
        require(self.provider.active_browsers()==[],'active_browser')
        self._check_credentials(m,only)
        for target in m['targets']:
            if only is not None and target['profile']['name']!=only:continue
            p=target['profile'];key=('profile',p['id']);op=ops.get(key)
            actual=self.provider.profile(p['id']);named=self.provider.profile(p['name'])
            if op and actual is None:
                require(named is None,'profile_replaced')
            else:
                require(actual is not None and profile(actual)==p and profile(named)==p)
                require(not op or op['state']!='absent','resource_reappeared')
            rows=self.provider.connections(p['name']);require(isinstance(rows,list),'incomplete_connections')
            rows=[connection(c) for c in rows]
            expected=[]
            for c in target['connections']:
                operation=ops.get(('connection',c['id']))
                direct=self.provider.connection(c['id'])
                if operation and direct is None: continue
                require(direct is not None and connection(direct)==c,'connection_changed')
                require(not operation or operation['state']!='absent','resource_reappeared')
                expected.append(c)
            require(sorted(rows,key=lambda r:r['id'])==sorted(expected,key=lambda r:r['id']),'connection_set_changed')
        with self.local.connect() as db:
            require(self._snapshot(db,m['scope'])==m['local'],'local_changed')

    def _check_credentials(self,m,only=None):
        ids={cid for t in m['targets'] if only is None or t['profile']['name']==only
             for c in t['connections'] for cid in c['credential_ids']}
        expected=[c for c in m['credentials'] if c['id'] in ids]
        require(self._credentials(ids)==expected,'credential_changed')

    def _step(self,m,sha,kind,expected,ops):
        resource=expected['id'];key=(kind,resource)
        self._current(m,ops,expected.get('profile_name',expected.get('name')))
        boot=self._authority()
        with self.local.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            require(self._snapshot(db,m['scope'])==m['local'],'local_changed')
            self._authority()
            old=db.execute('SELECT * FROM legacy_profile_cleanup_ops WHERE kind=? AND resource_id=?',key).fetchone()
            if old:
                require(old['manifest_sha256']==sha and old['identity_sha256']==digest(expected) and old['local_sha256']==digest(m['local']),'reservation_conflict')
            else:
                db.execute('INSERT INTO legacy_profile_cleanup_ops VALUES (?,?,?,?,?,?,?)',
                    (kind,resource,sha,digest(expected),digest(m['local']),boot,'unknown'))
        # Unknown is committed before dispatch. A crash or timeout never permits
        # another DELETE. Subsequent attempts may only GET this exact resource.
        if old is None:
            self._authority()
            try:
                if kind=='connection': self.provider.delete_connection(resource)
                else: self.provider.delete_profile(resource)
            except Exception:
                pass
        actual=(self.provider.connection(resource) if kind=='connection' else self.provider.profile(resource))
        require(actual is None,'delete_outcome_unknown')
        if kind=='profile': require(self.provider.profile(expected['name']) is None,'profile_replaced')
        with self.local.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            self._authority()
            require(self._snapshot(db,m['scope'])==m['local'],'local_changed')
            row=db.execute('SELECT * FROM legacy_profile_cleanup_ops WHERE kind=? AND resource_id=?',key).fetchone()
            require(row and row['manifest_sha256']==sha and row['identity_sha256']==digest(expected),'reservation_conflict')
            db.execute("UPDATE legacy_profile_cleanup_ops SET state='absent' WHERE kind=? AND resource_id=?",key)
            ops.update(self._ops(db,sha,m))
        self._check_credentials(m,expected.get('profile_name',expected.get('name')))

    def execute(self,manifest,*,approved_sha256):
        """Only the guarded startup hook exposes provider deletion; CLI stages review."""
        m=deepcopy(manifest);sha=digest(m);ops={};boot=None;remaining=None;reason=None
        try:
            self._validate(m,approved_sha256);boot=self._authority()
            with self.local.connect() as db:
                db.execute('BEGIN IMMEDIATE');self._schema(db)
                require(self._snapshot(db,m['scope'])==m['local'],'local_changed')
                ops=self._ops(db,sha,m)
            self._current(m,ops)
            retire=getattr(self.local,'retire',None)
            if retire: retire(m,sha,self._authority)
            for target in m['targets']:
                for c in target['connections']:
                    if ops.get(('connection',c['id']),{}).get('state')!='absent':
                        self._step(m,sha,'connection',c,ops)
                p=target['profile']
                require(self.provider.connections(p['name'])==[],'connection_set_changed')
                if ops.get(('profile',p['id']),{}).get('state')!='absent':
                    self._step(m,sha,'profile',p,ops)
            self._current(m,ops)
            remaining=self._inventory(m,{r['resource_id'] for r in ops.values() if r['kind']=='profile' and r['state']=='absent'})
            require(remaining==4,'inventory_changed')
        except Exception as error:
            reason=error.code if isinstance(error,Refused) else 'metadata_unavailable'
            # Load committed receipts even if dispatch or validation aborted.
            try:
                with self.local.connect() as db: ops=self._ops(db,sha,m)
            except Exception: pass
        completed=lambda kind:sum(r['kind']==kind and r['state']=='absent' for r in ops.values())
        unknown=sum(r['state']=='unknown' for r in ops.values())
        return dict(status=('complete' if reason is None else 'partial' if ops else 'refused'),
            manifest_sha256=sha,gateway_boot=boot,profiles_deleted=completed('profile'),
            connections_deleted=completed('connection'),unknown=unknown,
            remaining_profiles=remaining,reason=reason)


class GatewayMaintenance:
    def __init__(self,home,policy):self.home,self.policy=Path(home).resolve(),policy
    def check(self):
        import os
        from gateway import status
        require(getattr(self.policy,'vault_service',None) is None,'vault_already_admitted')
        require(status.owns_gateway_runtime_lock() and status.live_gateway_pid_for_home(self.home)==os.getpid()
                and status._get_process_hermes_home().resolve()==self.home,'maintenance_unavailable')
        return 'gateway-'+str(os.getpid())


def read_protected(path):
    import os,stat
    path=Path(path)
    require(not path.is_symlink() and not path.parent.is_symlink(),'unsafe_manifest')
    info=path.stat()
    require(stat.S_ISREG(info.st_mode) and not info.st_mode&0o077 and info.st_uid==os.getuid()
            and info.st_size<=2_000_000,'unsafe_manifest')
    def unique(rows):
        result={}
        for k,v in rows:require(k not in result,'duplicate_field');result[k]=v
        return result
    return json.loads(path.read_text(),object_pairs_hook=unique)


def verify_acceptance(acceptance,canonical):
    """Bind the review to real preserved local evidence, never an arbitrary SHA."""
    fields(acceptance,'version canonical checks')
    require(acceptance['version']==1 and acceptance['canonical']==canonical,'replacement_changed')
    required={'github_retained','instamart_retained','personal_multisite','shared_swiggy_isolation','unused_member_empty_profile'}
    require(isinstance(acceptance['checks'],list) and {c.get('kind') for c in acceptance['checks']}==required
            and len(acceptance['checks'])==len(required),'replacement_unverified')
    root=EVIDENCE_ROOT
    for check in acceptance['checks']:
        fields(check,'kind complete evidence_path evidence_sha256')
        path=Path(check['evidence_path'])
        require(check['complete'] is True and path.is_absolute() and path.is_file() and not path.is_symlink()
                and path.resolve().is_relative_to(root.resolve()),'replacement_unverified')
        require(path.stat().st_size<=10_000_000 and hashlib.sha256(path.read_bytes()).hexdigest()==check['evidence_sha256'],'replacement_changed')
    return digest(acceptance)


def make_executor(home,scope,*,read_only,maintenance,key):
    from .profile_cleanup_local import CleanupLocal
    from .profile_cleanup_provider import CleanupProvider
    import sqlite3
    database=Path(home)/'.clanker-vault/requests.sqlite'
    with sqlite3.connect(database.resolve().as_uri()+'?mode=ro',uri=True) as db:
        db.row_factory=sqlite3.Row
        canonical=[dict(id=r['profile_id'],name=r['profile_name'],owner=r['owner']) for r in db.execute('SELECT * FROM browser_profile_principals')]
        vaults=[r[0] for r in db.execute('SELECT vault_id FROM kernel_owner_vaults UNION SELECT vault_id FROM kernel_credential_vaults')]
    owners={(r['id'],r['name']):r['owner'] for r in scope['delete_profiles']+canonical}
    provider=CleanupProvider(key,scope['provider_project'],owners,vaults)
    local=CleanupLocal(home,scope,provider,read_only=read_only)
    return Executor(local,provider,maintenance)


def stage(home,review,approved_sha256):
    from .profile_cleanup_local import write_private
    fields(review,'manifest acceptance')
    require(digest(review)==approved_sha256,'approval_mismatch')
    require(verify_acceptance(review['acceptance'],review['manifest']['local']['canonical'])==review['manifest']['acceptance_sha256'],'replacement_changed')
    path=Path(home)/'.clanker-cloud/profile-cleanup.json'
    payload=dict(review=review,approved_sha256=approved_sha256)
    require(not path.exists() or read_protected(path)==payload,'staged_manifest_changed')
    if not path.exists():write_private(path,(json.dumps(payload,sort_keys=True)+'\n').encode())
    return dict(status='staged',approved_sha256=approved_sha256,provider_mutations=0)


def apply_startup(service):
    import os,time
    from .profile_cleanup_local import write_private
    path=service.policy.home/'.clanker-cloud/profile-cleanup.json'
    if not path.exists():return None
    gate=GatewayMaintenance(service.policy.home,service.policy)
    gate.check()
    result=None;executor=None;approved=None
    try:
        staged=read_protected(path);fields(staged,'review approved_sha256')
        review=staged['review'];fields(review,'manifest acceptance')
        approved=staged['approved_sha256'];require(digest(review)==approved,'approval_mismatch')
        m=review['manifest']
        # Consumption is historical authority only. Normal later startups do not
        # repeat destructive work or revalidate an old user's grant authority.
        with service.store.connection() as db:
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='legacy_profile_cleanup_completion'").fetchone():
                done=db.execute('SELECT approved_sha256 FROM legacy_profile_cleanup_completion WHERE manifest_sha256=?',(digest(m),)).fetchone()
                if done:
                    require(done['approved_sha256']==approved,'approval_mismatch')
                    result=dict(status='previously_completed',manifest_sha256=digest(m),historical=True)
                    return result
        require(verify_acceptance(review['acceptance'],m['local']['canonical'])==m['acceptance_sha256'],'replacement_changed')
        executor=make_executor(service.policy.home,m['scope'],read_only=False,maintenance=gate,key=service.cloud_browser.client.key)
        result=executor.execute(m,approved_sha256=digest(m))
        if result['status']=='complete':
            with service.store.connection() as db:
                db.execute('BEGIN IMMEDIATE');gate.check()
                db.execute('CREATE TABLE IF NOT EXISTS legacy_profile_cleanup_completion(manifest_sha256 TEXT PRIMARY KEY,approved_sha256 TEXT NOT NULL,completed REAL NOT NULL)')
                db.execute('INSERT INTO legacy_profile_cleanup_completion VALUES (?,?,?)',(digest(m),approved,time.time()))
        else:raise Refused('cleanup_incomplete')
        return result
    except Exception:
        if result is None:result=dict(status='refused',reason='cleanup_preflight_refused',approved_sha256=approved)
        raise Refused('Reviewed profile cleanup did not complete; inspect its protected outcome.') from None
    finally:
        if executor:executor.provider.close()
        if result is not None:
            write_private(path.parent/'profile-cleanup-outcome.json',(json.dumps(dict(result,gateway_pid=os.getpid(),recorded_at=time.time()),sort_keys=True)+'\n').encode())
