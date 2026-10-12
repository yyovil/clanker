"""Owner-checked local retirement journal; no credentials or account deletion."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
from .profile_cleanup import digest, require, Refused
from vault.kernel_store import expired_unfilled_code_request

PROTECTED_TABLES=('browser_profile_principals','browser_profile_accounts','browser_profile_adoptions',
 'kernel_auth_accounts','kernel_items','kernel_owner_vaults','kernel_credential_vaults','credential_grants')


def write_private(path,data):
    require(not path.is_symlink() and not path.parent.is_symlink(),'unsafe_path')
    temporary=path.parent/('.cleanup-'+secrets.token_hex(12))
    try:
        descriptor=os.open(temporary,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(descriptor,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(temporary,path)
    finally:temporary.unlink(missing_ok=True)


class CleanupLocal:
    def __init__(self,home,scope,provider,*,read_only=False,clock=time.time):
        self.home=Path(home).resolve();self.scope=scope;self.provider=provider
        self.read_only=read_only;self.clock=clock
        self.path=self.home/'.clanker-vault/requests.sqlite'
        self.directory=self.home/'.clanker-cloud/kernel/contexts'
        self.names={r['name']:r for r in scope['delete_profiles']}
        self.connection_ids={c for r in self.names.values() for c in r['connection_ids']}
        self._plan=None

    @contextmanager
    def connect(self):
        db=sqlite3.connect(self.path.as_uri()+('?mode=ro' if self.read_only else '?mode=rw'),uri=True)
        db.row_factory=sqlite3.Row
        try:yield db;db.commit()
        except BaseException:db.rollback();raise
        finally:db.close()

    @staticmethod
    def _rows(db,table):return sorted([dict(r) for r in db.execute('SELECT * FROM '+table)],key=digest)

    def _journal(self,db):
        if not db.execute("SELECT 1 FROM sqlite_master WHERE name='legacy_profile_cleanup_retirement'").fetchone():return None
        rows=db.execute('SELECT * FROM legacy_profile_cleanup_retirement').fetchall()
        require(len(rows)<=1,'retirement_conflict')
        return dict(rows[0]) if rows else None

    def _build(self,db,retired=None):
        membership_path=self.home/'slack_membership.json'
        require(not membership_path.is_symlink(),'unsafe_path')
        membership=json.loads(membership_path.read_text())
        require(membership['workspace_id']==self.scope['team'],'owner_changed')
        for t in self.names.values():
            require(membership['members'].get(t['owner'],{}).get('status')=='ready','owner_changed')
        require(not db.execute('SELECT 1 FROM browser_profile_leases').fetchone(),'active_profile_writer')
        protected={t:self._rows(db,t) for t in PROTECTED_TABLES}
        canonical=[dict(id=r['profile_id'],name=r['profile_name'],owner=r['owner']) for r in protected['browser_profile_principals']]
        require(len(canonical)==4 and all(r['state']=='ready' for r in protected['browser_profile_principals']),'canonical_changed')
        require(not {p['name'] for p in canonical}&set(self.names),'canonical_target')
        owners={r['owner'] for r in self.names.values()}
        requests=self._rows(db,'requests');flows=self._rows(db,'kernel_auth_flows')
        scoped=[r for r in flows if r['profile_name'] in self.names]
        by_request={r['request_id']:r for r in scoped}
        for r in requests:
            if r['team']!=self.scope['team'] or r['owner'] not in owners:continue
            active=(r['status'] in {'kernel_creating','kernel_create_unknown'} or
                r['status']=='saved' or
                r['status']=='waiting' and (r['expires']>self.clock() or
                    r.get('kind')=='code' and not expired_unfilled_code_request(db,r,self.clock())) or
                r['status']=='resumed' and r['resume_delivered'] is None)
            # Unknown auth on another exact profile is preserved; it cannot
            # authorize cleaning a target and is never retired here.
            if active:raise Refused('pending_owner_work')
            if db.execute("SELECT 1 FROM kernel_purchases WHERE request_id=? AND state NOT IN ('completed','cancelled','review')",(r['id'],)).fetchone():
                raise Refused('uncertain_purchase')
        approvals=self._rows(db,'owner_approvals')
        for r in approvals:
            if r['team']==self.scope['team'] and r['user'] in owners:
                require(not ((r['state'] in {'posting','pending'} and r['expires']>self.clock()) or
                    r['state']=='approved' and r.get('resumed') is None),'pending_owner_approval')
        for f in scoped:
            t=self.names[f['profile_name']]
            require(f['team']==self.scope['team'] and f['account_owner']==f['requester']==t['owner'],'owner_changed')
            require(f['connection_id'] in t['connection_ids'] and f['state'] in {'authenticated','failed','expired','canceled'}
                    and not f['principal_key'] and not f['auth_lease'],'unknown_auth_effect')
            r=next((r for r in requests if r['id']==f['request_id']),None)
            require(r and (r['team'],r['owner'])==(f['team'],f['requester']) and
                    r['status'] in {'resumed','cancelled'} and (r['status']!='resumed' or r['resume_delivered'] is not None),'pending_owner_work')
        require({f['connection_id'] for f in scoped}==self.connection_ids,'missing_auth_provenance')
        keys={f['key'] for f in scoped}
        bindings=[r for r in self._rows(db,'kernel_auth_bindings') if r['flow_key'] in keys]
        for b in bindings:
            f=next(f for f in scoped if f['key']==b['flow_key'])
            require((b['team'],b['requester'])==(f['team'],f['requester']),'owner_changed')
        require(not any(r['flow_key'] in keys for r in self._rows(db,'kernel_auth_principal_selections')),'canonical_selection')
        files=[];session_ids=set();session_owners={};profile_contexts={}
        provenance={f['profile_name'] for f in scoped}
        for old in (retired or {}).get('files',[]):
            require(hashlib.sha256(old['before_text'].encode()).hexdigest()==old['before'],'retirement_changed')
            prior=json.loads(old['before_text'])
            for area in ('task_profiles','legacy_profiles','sessions'):
                for entry in prior.get(area,{}).values():
                    for name in (entry.get('name'),(entry.get('task_profile') or {}).get('name'),(entry.get('profile_binding') or {}).get('profile_name')):
                        if name in self.names:profile_contexts.setdefault(name,set()).add(Path(old['name']).stem)
        for path in sorted(self.directory.glob('*.json')):
            require(not path.is_symlink() and not path.parent.is_symlink(),'unsafe_path')
            raw=path.read_bytes();state=json.loads(raw);changed=json.loads(raw)
            touched=False
            for area in ('task_profiles','legacy_profiles','sessions'):
                for key,entry in state.get(area,{}).items():
                    refs=[entry.get('name'),(entry.get('task_profile') or {}).get('name'),(entry.get('profile_binding') or {}).get('profile_name')]
                    matches=[n for n in refs if n in self.names]
                    if not matches:continue
                    require(len(set(matches))==1,'ambiguous_profile')
                    target=self.names[matches[0]]
                    provenance.add(matches[0]);profile_contexts.setdefault(matches[0],set()).add(path.stem)
                    require(state.get('owner')==dict(team=self.scope['team'],requester=target['owner']),'owner_changed')
                    require(isinstance(entry.get('home'),str) and Path(entry['home']).is_absolute() and
                        path.stem==hashlib.sha256(('v2:'+self.scope['team']+':'+target['owner']+':'+entry['home']).encode()).hexdigest(),'context_changed')
                    require(not any(entry.get(k) for k in ('pending','dispatch_unknown','cleanup_pending','profile_principal','profile_lease')),'unknown_browser_effect')
                    if area!='sessions':require(entry.get('id')==target['id'],'profile_changed')
                    if area=='sessions':
                        require(entry.get('profile_id')==target['id'],'profile_changed')
                        sid=entry.get('session_id');require(isinstance(sid,str),'unknown_browser_effect')
                        require(sid not in session_owners or session_owners[sid]==(target['owner'],path.stem),'ambiguous_session_owner')
                        session_ids.add(sid);session_owners[sid]=(target['owner'],path.stem)
                        changed['threads']={thread:selected for thread,selected in changed.get('threads',{}).items() if selected!=key}
                    changed[area].pop(key);touched=True
            if touched:
                files.append(dict(name=path.name,before=hashlib.sha256(raw).hexdigest(),
                    after=digest(changed),before_text=raw.decode(),after_text=json.dumps(changed,sort_keys=True,separators=(',',':'))))
        claims=[]
        for c in self._rows(db,'browser_session_owners'):
            if c['provider']=='KernelTaskProfile' and c['session_id'] in self.names:
                t=self.names[c['session_id']];require((c['team'],c['requester'])==(self.scope['team'],t['owner']) and c['context'] in profile_contexts.get(c['session_id'],set()),'owner_changed');claims.append(c)
            elif c['provider']=='KernelBrowser' and c['session_id'] in session_ids:
                require((c['team'],c['requester'],c['context'])==(self.scope['team'],*session_owners[c['session_id']]),'owner_changed');claims.append(c)
        require(all(any(c['provider']=='KernelBrowser' and c['session_id']==s for c in claims) for s in session_ids),'missing_session_claim')
        rows={'kernel_auth_bindings':bindings,'browser_session_owners':claims}
        return dict(canonical=canonical,protected=protected,membership=digest(membership),requests=digest(requests),
                    approvals=digest(approvals),flows=digest(flows),rows=rows,files=files,sessions=sorted(session_ids),provenance=sorted(provenance))

    def _material(self,db):
        journal=self._journal(db)
        if not journal:return self._build(db)
        saved=json.loads(journal['payload'])
        # Temporarily reconstruct only the read projection from journaled,
        # exact retired rows/files. Never restore their runtime authority.
        for f in saved['files']:
            path=self.directory/f['name'];require(path.name==f['name'] and not path.is_symlink(),'unsafe_path')
            require(hashlib.sha256(path.read_bytes()).hexdigest() in {f['before'],f['after']},'retirement_changed')
        current=self._build(db,retired=saved)
        present_count=0;total_count=0
        for table,rows in saved['rows'].items():
            require(all(row in rows for row in current['rows'][table]),'retirement_changed')
            actual=self._rows(db,table)
            present_count+=sum(row in actual for row in rows);total_count+=len(rows)
            current['rows'][table]=rows
        require(present_count in {0,total_count},'retirement_changed')
        existing={f['name']:f for f in current['files']}
        for f in saved['files']:
            path=self.directory/f['name'];require(not path.is_symlink(),'unsafe_path')
            raw=path.read_bytes();value=hashlib.sha256(raw).hexdigest()
            require(value in {f['before'],f['after']},'retirement_changed')
            existing[f['name']]=f
        current['files']=sorted(existing.values(),key=lambda f:f['name'])
        current['sessions']=saved['sessions']
        current['provenance']=saved['provenance']
        require(digest(current)==digest(saved),'local_changed')
        return saved

    def snapshot(self,db,scope=None):
        if scope is None:scope=self.scope
        require(scope==self.scope,'scope_changed')
        material=self._material(db);self._plan=material
        require(set(material['provenance'])==set(self.names),'missing_profile_provenance')
        return dict(canonical=material['canonical'],local_digest=digest(material),
                    target_blockers={t['id']:[] for t in self.names.values()})

    def retire(self,manifest,sha,authority):
        require(not self.read_only,'read_only')
        authority()
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            require(self.snapshot(db,self.scope)==manifest['local'],'local_changed')
            material=self._plan
            db.execute('CREATE TABLE IF NOT EXISTS legacy_profile_cleanup_retirement(manifest_sha256 TEXT PRIMARY KEY,payload TEXT NOT NULL,state TEXT NOT NULL)')
            old=self._journal(db)
            require(not old or old['manifest_sha256']==sha,'retirement_conflict')
            if old is None:db.execute('INSERT INTO legacy_profile_cleanup_retirement VALUES (?,?,?)',(sha,json.dumps(material,sort_keys=True),'reserved'))
        for sid in material['sessions']:
            require(self.provider.browser_absent(sid),'active_historical_browser')
        for f in material['files']:
            authority();path=self.directory/f['name'];raw=path.read_bytes();current=hashlib.sha256(raw).hexdigest()
            require(current in {f['before'],f['after']},'retirement_changed')
            if current==f['before']:write_private(path,f['after_text'].encode())
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE');authority()
            require(self.snapshot(db,self.scope)==manifest['local'],'local_changed')
            for table,rows in material['rows'].items():
                for row in rows:
                    clause=' AND '.join(k+' IS ?' for k in row)
                    db.execute('DELETE FROM '+table+' WHERE '+clause,tuple(row.values()))
            db.execute("UPDATE legacy_profile_cleanup_retirement SET state='retired' WHERE manifest_sha256=?",(sha,))
