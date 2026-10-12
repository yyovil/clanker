"""Kernel metadata and durable claims; never stores credential values or URLs.

The caller supplies an authenticated Slack scope. This store additionally binds
that scope to one canonical private home and prevents provider IDs, collection
IDs, and dispatched attempts from being adopted by another scope.
"""
import hashlib
import json
from pathlib import Path
import re
import time
from urllib.parse import urlsplit

from .store import AccessError


_ID = re.compile(r'[A-Za-z0-9_.:-]{1,200}\Z')
_FIELD = re.compile(r'[A-Za-z][A-Za-z0-9_.-]{0,79}\Z')
_ITEM_STATES = {'pending', 'ready', 'revoked', 'deleted', 'cancelled', 'failed'}
_COLLECTION_STATES = {'pending', 'ready', 'expired', 'cancelled'}
_FAILURES = {'refused', 'binding_changed', 'input_rejected', 'provider_error',
             'timeout', 'unknown', 'partial', 'cancelled', 'value_not_retained',
             'target_missing', 'target_ambiguous', 'readback_unavailable', 'invalid_code', 'value_mismatch'}


def _id(value):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise AccessError('The Kernel metadata identifier is invalid.')
    return value


def _text(value, limit=200):
    if (not isinstance(value, str) or len(value) > limit or
            any(ord(char) < 32 for char in value)):
        raise AccessError('The Kernel metadata is invalid.')
    return value


def _version(value):
    if type(value) is int and value >= 0:
        value = str(value)
    return _id(value)


def _origin(value):
    try:
        parts = urlsplit(value)
        if (not isinstance(value, str) or parts.scheme != 'https' or
                not parts.hostname or parts.username or parts.password or
                parts.path or parts.query or parts.fragment or
                parts.port not in (None, 443)):
            raise ValueError
        normalized = 'https://' + parts.hostname.lower()
        if value != normalized:
            raise ValueError
        return value
    except (ValueError, TypeError):
        raise AccessError('Kernel access requires one exact HTTPS origin.') from None


def expired_unfilled_code_request(db, request, now):
    """Read-only terminal proof, never an expiry-based resolution of effects.

    The collection must already be terminal. A provider deletion may remain
    unconfirmed, but this form can no longer become ready or dispatch a fill.
    Keep all evidence if any version ever had a fill, resume or other effect.
    Callers that retire the parent hold the same transaction as these checks.
    """
    if (request['kind'] != 'code' or request['status'] != 'waiting' or
            request['expires'] > now or not request['handle'] or
            any(request[key] is not None for key in
                ('resume_attempt','resume_delivered','code_payload','payment_payload','grant_id','approver'))):
        return False
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if not {'kernel_collections','kernel_owner_vaults','kernel_fill_attempts','kernel_fill_outcomes'} <= tables:
        return False
    collection = db.execute('SELECT * FROM kernel_collections WHERE request_id=?', (request['id'],)).fetchone()
    identity = ('team','owner','home','task_id','handle','origin')
    if (not collection or collection['state'] != 'expired' or
            any(collection[key] != request[key] for key in identity) or
            not db.execute('SELECT 1 FROM kernel_owner_vaults WHERE team=? AND owner=? AND home=? AND vault_id=?',
                (request['team'],request['owner'],request['home'],collection['vault_id'])).fetchone()):
        return False
    prefix = 'collection:' + request['id'] + ':'
    for table in ('kernel_fill_attempts','kernel_fill_outcomes'):
        # Equality on the prefix avoids LIKE wildcards and checks all versions,
        # including orphan outcomes and failed/unknown attempts.
        if db.execute('SELECT 1 FROM '+table+' WHERE substr(operation_id,1,?)=? LIMIT 1',
                      (len(prefix),prefix)).fetchone():
            return False
    for table in ('kernel_auth_flows','kernel_purchases'):
        if table in tables and db.execute('SELECT 1 FROM '+table+' WHERE request_id=? LIMIT 1',
                                         (request['id'],)).fetchone():
            return False
    if 'owner_approvals' in tables and db.execute('SELECT 1 FROM owner_approvals WHERE team=? AND user=? AND '
            "(state IN ('posting','pending') OR state='approved' AND resumed IS NULL) LIMIT 1",
            (request['team'],request['owner'])).fetchone():
        return False
    return True


class KernelStore:
    def __init__(self, requests, *, clock=None):
        self.requests = requests
        self.clock = clock or getattr(requests, 'clock', time.time)
        with requests.connection() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS kernel_owner_vaults (
                  team TEXT NOT NULL, owner TEXT NOT NULL, home TEXT NOT NULL UNIQUE,
                  vault_id TEXT NOT NULL UNIQUE, name TEXT NOT NULL, created REAL NOT NULL,
                  PRIMARY KEY(team,owner));
                CREATE TABLE IF NOT EXISTS kernel_credential_vaults (
                  team TEXT NOT NULL, owner TEXT NOT NULL, home TEXT NOT NULL,
                  handle TEXT NOT NULL, vault_id TEXT NOT NULL UNIQUE,
                  name TEXT NOT NULL, created REAL NOT NULL,
                  PRIMARY KEY(team,owner,handle));
                CREATE TABLE IF NOT EXISTS kernel_items (
                  team TEXT NOT NULL, owner TEXT NOT NULL, home TEXT NOT NULL,
                  handle TEXT NOT NULL, vault_id TEXT NOT NULL, item_key TEXT NOT NULL,
                  remote_id TEXT NOT NULL UNIQUE, kind TEXT NOT NULL, label TEXT NOT NULL,
                  origin TEXT NOT NULL, login_method TEXT NOT NULL, identifier TEXT NOT NULL,
                  fields TEXT NOT NULL, status TEXT NOT NULL, version TEXT NOT NULL,
                  created REAL NOT NULL, updated REAL NOT NULL,
                  PRIMARY KEY(team,owner,handle), UNIQUE(vault_id,item_key));
                CREATE TABLE IF NOT EXISTS kernel_collections (
                  request_id TEXT PRIMARY KEY, team TEXT NOT NULL, owner TEXT NOT NULL,
                  home TEXT NOT NULL, task_id TEXT NOT NULL, handle TEXT NOT NULL,
                  origin TEXT NOT NULL, vault_id TEXT NOT NULL, item_key TEXT NOT NULL,
                  item_id TEXT NOT NULL, version TEXT NOT NULL, state TEXT NOT NULL,
                  stable_key TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL);
                CREATE UNIQUE INDEX IF NOT EXISTS kernel_collection_pending
                  ON kernel_collections(stable_key) WHERE state='pending';
                CREATE TABLE IF NOT EXISTS kernel_fill_attempts (
                  operation_id TEXT PRIMARY KEY, team TEXT NOT NULL, owner TEXT NOT NULL,
                  home TEXT NOT NULL, task_id TEXT NOT NULL, handle TEXT NOT NULL,
                  origin TEXT NOT NULL, version TEXT NOT NULL, binding_digest TEXT NOT NULL,
                  state TEXT NOT NULL, failure TEXT, created REAL NOT NULL, updated REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS kernel_fill_outcomes (
                  operation_id TEXT PRIMARY KEY, evidence TEXT NOT NULL);
            ''')

    def _scope(self, team, owner, home, db, *, require=True):
        _id(team); _id(owner)
        supplied = Path(home).absolute()
        try:
            canonical = supplied.resolve(strict=True)
        except (OSError, RuntimeError):
            raise AccessError('The Kernel owner home is unavailable.', 403) from None
        base = self.requests.directory.parent.resolve(strict=True)
        if (not canonical.is_dir() or supplied != canonical or
                canonical != base and not canonical.is_relative_to(base / 'profiles')):
            raise AccessError('The Kernel owner home is not authorized.', 403)
        home = str(canonical)
        existing = db.execute('SELECT * FROM kernel_owner_vaults WHERE '
                              '(team=? AND owner=?) OR home=?', (team, owner, home)).fetchall()
        if any((row['team'], row['owner'], row['home']) != (team, owner, home) for row in existing):
            raise AccessError('The Kernel owner mapping does not match this account.', 403)
        if require and not existing:
            raise AccessError('This owner has no configured Kernel vault.', 409)
        return home

    def vault(self, team, owner, home):
        with self.requests.connection() as db:
            home = self._scope(team, owner, home, db, require=False)
            row = db.execute('SELECT * FROM kernel_owner_vaults WHERE team=? AND owner=? AND home=?',
                             (team, owner, home)).fetchone()
            return dict(row) if row else None

    owner_vault = vault

    def bind_vault(self, team, owner, home, vault_id, name=''):
        _id(vault_id); _text(name)
        with self.requests.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            home = self._scope(team, owner, home, db, require=False)
            if db.execute('SELECT 1 FROM kernel_credential_vaults WHERE vault_id=?', (vault_id,)).fetchone():
                raise AccessError('A credential vault cannot become an account vault.', 403)
            old = db.execute('SELECT * FROM kernel_owner_vaults WHERE vault_id=? OR '
                             '(team=? AND owner=?)', (vault_id, team, owner)).fetchone()
            if old:
                if (old['team'], old['owner'], old['home'], old['vault_id']) != (team, owner, home, vault_id):
                    raise AccessError('This Kernel vault is already bound to another account.', 403)
                return dict(old)
            db.execute('INSERT INTO kernel_owner_vaults VALUES (?,?,?,?,?,?)',
                       (team, owner, home, vault_id, name, self.clock()))
            return dict(db.execute('SELECT * FROM kernel_owner_vaults WHERE team=? AND owner=?',
                                   (team, owner)).fetchone())

    save_owner_vault = bind_vault

    def bind_credential_vault(self, team, owner, home, handle, vault_id, name=''):
        """Bind one dedicated vault to exactly one owner's opaque handle."""
        _id(handle); _id(vault_id); _text(name)
        with self.requests.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            home = self._scope(team, owner, home, db)
            if db.execute('SELECT 1 FROM kernel_owner_vaults WHERE vault_id=?', (vault_id,)).fetchone():
                raise AccessError('An account vault cannot be shared as a credential vault.', 403)
            rows = db.execute('SELECT * FROM kernel_credential_vaults WHERE vault_id=? OR '
                '(team=? AND owner=? AND handle=?)', (vault_id, team, owner, handle)).fetchall()
            if rows:
                if any((r['team'],r['owner'],r['home'],r['handle'],r['vault_id']) !=
                       (team,owner,home,handle,vault_id) for r in rows):
                    raise AccessError('This credential vault is bound to another owner or handle.', 403)
                return dict(rows[0])
            existing = db.execute('SELECT vault_id FROM kernel_items WHERE team=? AND owner=? AND handle=?',
                                 (team, owner, handle)).fetchone()
            if existing and existing['vault_id'] != vault_id:
                raise AccessError('An existing credential cannot be silently moved to another vault.', 403)
            db.execute('INSERT INTO kernel_credential_vaults VALUES (?,?,?,?,?,?,?)',
                       (team,owner,home,handle,vault_id,name,self.clock()))
            return dict(db.execute('SELECT * FROM kernel_credential_vaults WHERE team=? AND owner=? AND handle=?',
                                   (team,owner,handle)).fetchone())

    def credential_vault(self, team, owner, home, handle):
        _id(handle)
        with self.requests.connection() as db:
            home = self._scope(team, owner, home, db)
            row = db.execute('SELECT * FROM kernel_credential_vaults WHERE team=? AND owner=? AND home=? AND handle=?',
                             (team,owner,home,handle)).fetchone()
            return dict(row) if row else None

    def list_credential_vaults(self, team, owner, home):
        with self.requests.connection() as db:
            home = self._scope(team, owner, home, db)
            return [dict(row) for row in db.execute('SELECT * FROM kernel_credential_vaults '
                'WHERE team=? AND owner=? AND home=? ORDER BY handle', (team,owner,home))]

    @staticmethod
    def _item(row):
        if row is None:
            return None
        result = dict(row)
        result['key'] = result.pop('item_key')
        result['id'] = result['handle']
        result['fields'] = json.loads(result['fields'])
        result['has_otp'] = 'totp' in result['fields'] or 'otp_secret' in result['fields']
        result['created_at'] = result['created']
        result['identifier_type'] = ('phone' if result['login_method'] == 'sms' else
                                     'email' if '@' in result['identifier'] else 'username')
        return result

    def put_item(self, team, owner, home, handle, key, remote_id, kind, label,
                 origin, login_method='password', identifier='', fields=(),
                 status='pending', version=1, vault_id=None):
        _id(handle); _id(key); _id(remote_id); _text(label, 120); _text(identifier, 320)
        origin = _origin(origin); version = _version(version)
        if kind not in {'login', 'personal', 'api_key'} or login_method not in {'password', 'sms'}:
            raise AccessError('The Kernel item kind is unsupported.')
        if status not in _ITEM_STATES:
            raise AccessError('The Kernel item state is invalid.')
        if (not isinstance(fields, (list, tuple)) or len(fields) > 40 or
                any(not isinstance(field, str) or not _FIELD.fullmatch(field) for field in fields) or
                len(set(fields)) != len(fields)):
            raise AccessError('Kernel field metadata contains names only.')
        if login_method == 'sms' and identifier and not any(char in identifier for char in ('*', '•')):
            raise AccessError('SMS identifiers must remain masked.')
        with self.requests.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            home = self._scope(team, owner, home, db)
            own_vault = db.execute('SELECT vault_id FROM kernel_owner_vaults WHERE team=? AND owner=?',
                               (team, owner)).fetchone()['vault_id']
            vault = own_vault if vault_id is None else _id(vault_id)
            dedicated = db.execute('SELECT vault_id FROM kernel_credential_vaults '
                'WHERE team=? AND owner=? AND home=? AND handle=?', (team,owner,home,handle)).fetchone()
            if dedicated:
                if vault != dedicated['vault_id'] or kind == 'personal':
                    raise AccessError('This credential requires its exact dedicated vault.', 403)
            elif vault != own_vault:
                raise AccessError('This credential vault has no exact owner and handle binding.', 403)
            conflict = db.execute('SELECT * FROM kernel_items WHERE remote_id=? OR '
                                  '(vault_id=? AND item_key=?)', (remote_id, vault, key)).fetchall()
            if any((r['team'],r['owner'],r['home'],r['handle']) != (team,owner,home,handle) for r in conflict):
                raise AccessError('This Kernel item is assigned to another handle.', 403)
            old = db.execute('SELECT * FROM kernel_items WHERE team=? AND owner=? AND handle=?',
                             (team, owner, handle)).fetchone()
            if old and (old['remote_id'],old['vault_id'],old['item_key']) != (remote_id,vault,key):
                raise AccessError('Kernel item identity cannot be silently replaced.', 403)
            if old and (old['kind'],old['origin'],old['login_method']) != (kind,origin,login_method):
                raise AccessError('Kernel item authorization cannot be silently replaced.', 403)
            if old and old['status'] == 'deleted':
                raise AccessError('This Kernel item was deleted.', 410)
            now = self.clock()
            db.execute('INSERT INTO kernel_items VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) '
                       'ON CONFLICT(team,owner,handle) DO UPDATE SET label=excluded.label, '
                       'origin=excluded.origin,login_method=excluded.login_method,identifier=excluded.identifier,'
                       'fields=excluded.fields,status=excluded.status,version=excluded.version,updated=excluded.updated',
                       (team,owner,home,handle,vault,key,remote_id,kind,label,origin,login_method,
                        identifier,json.dumps(list(fields)),status,version,old['created'] if old else now,now))
            return self._item(db.execute('SELECT * FROM kernel_items WHERE team=? AND owner=? AND handle=?',
                                        (team,owner,handle)).fetchone())

    upsert_item = put_item

    def item(self, team, owner, home, handle, *, include_deleted=False):
        _id(handle)
        with self.requests.connection() as db:
            home = self._scope(team, owner, home, db)
            row = db.execute('SELECT * FROM kernel_items WHERE team=? AND owner=? AND home=? AND handle=?',
                             (team, owner, home, handle)).fetchone()
            return self._item(row) if row and (include_deleted or row['status'] != 'deleted') else None

    get_item = item

    def list_items(self, team, owner, home, *, include_deleted=False):
        with self.requests.connection() as db:
            home = self._scope(team, owner, home, db)
            return [self._item(row) for row in db.execute('SELECT * FROM kernel_items WHERE '
                    'team=? AND owner=? AND home=? ORDER BY created,handle', (team,owner,home))
                    if include_deleted or row['status'] != 'deleted']

    def update_item_status(self, team, owner, home, handle, status, *, version=None):
        if status not in _ITEM_STATES:
            raise AccessError('The Kernel item state is invalid.')
        with self.requests.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            home = self._scope(team,owner,home,db)
            row = db.execute('SELECT * FROM kernel_items WHERE team=? AND owner=? AND home=? AND handle=?',
                             (team,owner,home,_id(handle))).fetchone()
            if row is None or row['status'] == 'deleted':
                raise AccessError('This Kernel item is unavailable.', 410)
            db.execute('UPDATE kernel_items SET status=?,version=?,updated=? WHERE team=? AND owner=? AND handle=?',
                       (status,_version(version) if version is not None else row['version'],self.clock(),team,owner,handle))
            if status in {'revoked','deleted','cancelled'}:
                db.execute("UPDATE kernel_collections SET state='cancelled',updated=? WHERE team=? AND owner=? AND handle=? AND state IN ('pending','ready')",(self.clock(),team,owner,handle))
            return self._item(db.execute('SELECT * FROM kernel_items WHERE team=? AND owner=? AND handle=?',
                                        (team,owner,handle)).fetchone())

    def delete_item(self, team, owner, home, handle):
        return self.update_item_status(team,owner,home,handle,'deleted')

    def _request(self, db, request_id, team, owner, home, task_id=None, handle=None, origin=None):
        row = db.execute('SELECT * FROM requests WHERE id=?', (_id(request_id),)).fetchone()
        if (row is None or (row['team'],row['owner'],row['home']) != (team,owner,home) or
                task_id is not None and row['task_id'] != task_id or
                handle is not None and row['handle'] not in (None,handle) or
                origin is not None and row['origin'] != origin):
            raise AccessError('The Kernel collection does not belong to this task.', 403)
        return row

    def put_collection(self, request_id, team, owner, home, task_id, handle,
                       origin, vault_id, key, item_id, version):
        for value in (task_id,handle,vault_id,key,item_id):_id(value)
        origin=_origin(origin); version=_version(version)
        with self.requests.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            home=self._scope(team,owner,home,db)
            vault=db.execute('SELECT vault_id FROM kernel_owner_vaults WHERE team=? AND owner=?',(team,owner)).fetchone()
            if vault['vault_id'] != vault_id:
                raise AccessError('The collection vault does not belong to this owner.',403)
            request=self._request(db,request_id,team,owner,home,task_id,handle,origin)
            if request['kind'] not in {'login','code','api_key'} or request['status'] != 'waiting' or request['expires'] <= self.clock():
                raise AccessError('This Kernel collection request is no longer waiting.',410)
            stable=hashlib.sha256(json.dumps([team,owner,home,task_id,handle,origin,request['kind']],separators=(',',':')).encode()).hexdigest()
            existing=db.execute('SELECT * FROM kernel_collections WHERE request_id=? OR '
                                "(stable_key=? AND state='pending')",(request_id,stable)).fetchall()
            for row in existing:
                prior=self._request(db,row['request_id'],team,owner,home,task_id,handle,origin)
                if prior['expires'] <= self.clock() or prior['status'] != 'waiting':
                    db.execute("UPDATE kernel_collections SET state='expired',updated=? WHERE request_id=? AND state='pending'",(self.clock(),row['request_id']))
                    continue
                if (row['vault_id'],row['item_key'],row['item_id'],row['version']) != (vault_id,key,item_id,version):
                    raise AccessError('A different Kernel collection is already pending for this task.',409)
                return dict(row) | {'key':row['item_key']}
            old=db.execute('SELECT * FROM kernel_collections WHERE request_id=?',(request_id,)).fetchone()
            if old:
                raise AccessError('This Kernel collection request has already been used.',410)
            now=self.clock()
            db.execute('INSERT INTO kernel_collections VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                       (request_id,team,owner,home,task_id,handle,origin,vault_id,key,item_id,version,'pending',stable,now,now))
            return dict(db.execute('SELECT * FROM kernel_collections WHERE request_id=?',(request_id,)).fetchone()) | {'key':key}

    def collection(self, request_id, *, team, owner, home):
        with self.requests.connection() as db:
            home=self._scope(team,owner,home,db)
            self._request(db,request_id,team,owner,home)
            row=db.execute('SELECT * FROM kernel_collections WHERE request_id=? AND team=? AND owner=? AND home=?',
                           (request_id,team,owner,home)).fetchone()
            return dict(row) | {'key':row['item_key']} if row else None

    def list_collections(self, team, owner, home, *, state=None):
        if state is not None and state not in _COLLECTION_STATES:
            raise AccessError('The Kernel collection state is invalid.')
        with self.requests.connection() as db:
            home=self._scope(team,owner,home,db)
            return [dict(row) | {'key':row['item_key']} for row in db.execute('SELECT * FROM kernel_collections WHERE team=? AND owner=? AND home=? ORDER BY created', (team,owner,home)) if state is None or row['state']==state]

    def update_collection_state(self, request_id, state, *, team, owner, home):
        if state not in _COLLECTION_STATES:
            raise AccessError('The Kernel collection state is invalid.')
        with self.requests.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            home=self._scope(team,owner,home,db)
            self._request(db,request_id,team,owner,home)
            row=db.execute('SELECT * FROM kernel_collections WHERE request_id=?',(request_id,)).fetchone()
            if row is None or row['state'] in {'expired','cancelled'} or state == 'pending' and row['state'] != 'pending':
                raise AccessError('This Kernel collection is no longer pending.',410)
            if row['state'] == state:
                return dict(row) | {'key':row['item_key']}
            db.execute('UPDATE kernel_collections SET state=?,updated=? WHERE request_id=?',(state,self.clock(),request_id))
            return dict(row) | {'state':state,'key':row['item_key']}

    def update_collection_ready(self, request_id, *, team, owner, home, version):
        version=_version(version)
        with self.requests.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            home=self._scope(team,owner,home,db)
            request=self._request(db,request_id,team,owner,home)
            row=db.execute('SELECT * FROM kernel_collections WHERE request_id=?',(request_id,)).fetchone()
            if (row is None or row['state'] not in {'pending','ready'} or
                    request['status'] not in {'waiting','saved','resumed'} or request['expires'] <= self.clock()):
                raise AccessError('This Kernel collection is no longer pending.',410)
            if row['state'] == 'ready':
                if row['version'] != version:
                    raise AccessError('This Kernel collection already has a confirmed version.',409)
                db.execute("UPDATE requests SET status='saved' WHERE id=? AND status='waiting'", (request_id,))
                return dict(row) | {'key':row['item_key']}
            now=self.clock()
            db.execute("UPDATE kernel_collections SET state='ready',version=?,updated=? WHERE request_id=?",(version,now,request_id))
            db.execute("UPDATE requests SET status='saved' WHERE id=? AND status='waiting'", (request_id,))
            return dict(row) | {'state':'ready','version':version,'updated':now,'key':row['item_key']}

    def retire_expired_code_request(self, request_id, *, team, owner, home):
        """Retire only a proven unused terminal form; preserve its audit rows."""
        with self.requests.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            home = self._scope(team,owner,home,db)
            request = self._request(db,request_id,team,owner,home)
            if not expired_unfilled_code_request(db,request,self.clock()):
                return False
            return bool(db.execute("UPDATE requests SET status='expired' WHERE id=? AND status='waiting'",
                                   (request_id,)).rowcount)

    def _begin(self, db, operation_id, *, team, owner, home, task_id, handle, origin, version, binding_digest):
        for value in (operation_id,task_id,handle):_id(value)
        origin=_origin(origin); version=_version(version)
        if binding_digest and not re.fullmatch(r'[0-9a-f]{64}',binding_digest):
            raise AccessError('The Kernel browser binding digest is invalid.')
        old=db.execute('SELECT 1 FROM kernel_fill_attempts WHERE operation_id=?',(operation_id,)).fetchone()
        if old:
            raise AccessError('This Kernel fill attempt was already dispatched. Inspect its outcome; it cannot be replayed.',409)
        now=self.clock()
        db.execute('INSERT INTO kernel_fill_attempts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
                   (operation_id,team,owner,home,task_id,handle,origin,version,binding_digest,'dispatched',None,now,now))
        return dict(db.execute('SELECT * FROM kernel_fill_attempts WHERE operation_id=?',(operation_id,)).fetchone())

    def _granted_item(self, db, team, requester, grant_id, origin, *, approver=None):
        from .delegation import credential_binding
        from .kernel_service import public_meta
        grant = db.execute('SELECT * FROM credential_grants WHERE id=? AND team=? AND recipient=? '
            'AND revoked IS NULL', (_id(grant_id),team,requester)).fetchone()
        item = db.execute("SELECT * FROM kernel_items WHERE team=? AND owner=? AND handle=? AND status='ready'",
            (team,grant['owner'],grant['handle'])).fetchone() if grant else None
        dedicated = db.execute('SELECT * FROM kernel_credential_vaults WHERE team=? AND owner=? AND handle=?',
            (team,grant['owner'],grant['handle'])).fetchone() if grant else None
        if (not grant or grant['owner'] == requester or not item or not dedicated or
                approver is not None and grant['owner'] != approver or
                item['home'] != dedicated['home'] or item['kind'] not in {'login','api_key'} or
                item['vault_id'] != dedicated['vault_id'] or item['origin'] != origin or
                credential_binding(public_meta(self._item(item))) != grant['binding']):
            raise AccessError('This invited credential is not authorized for the current browser fill.', 403)
        self._scope(team, grant['owner'], item['home'], db)
        return item

    def begin_attempt(self, operation_id, *, team, owner, home, task_id, handle, origin, version=1, binding_digest='', grant_id=None):
        with self.requests.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            home=self._scope(team,owner,home,db)
            if grant_id is not None:
                if grant_id != handle:
                    raise AccessError('The invited fill handle does not match its authorization.', 403)
                item = self._granted_item(db, team, owner, grant_id, origin)
            else:
                item=db.execute("SELECT * FROM kernel_items WHERE team=? AND owner=? AND home=? AND handle=? AND status='ready'",(team,owner,home,handle)).fetchone()
            if not item or item['kind'] != 'personal' and item['origin'] != origin or item['version'] != _version(version):
                raise AccessError('The Kernel item is not ready for this origin and version.',409)
            return self._begin(db,operation_id,team=team,owner=owner,home=home,task_id=task_id,handle=handle,origin=origin,version=version,binding_digest=binding_digest)

    def claim_fill(self, request_id, version, *, team, owner, home, task_id, handle, origin, binding_digest=''):
        with self.requests.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            home=self._scope(team,owner,home,db)
            request=self._request(db,request_id,team,owner,home,task_id,handle,origin)
            if request['grant_id'] is not None:
                if request['kind'] != 'code' or request['grant_id'] != handle or not request['approver']:
                    raise AccessError('This invited collection has no exact owner approval binding.', 403)
                self._granted_item(db, team, owner, handle, origin, approver=request['approver'])
            collection=db.execute('SELECT * FROM kernel_collections WHERE request_id=?',(request_id,)).fetchone()
            if (collection is None or collection['state'] != 'ready' or collection['version'] != _version(version) or
                    (collection['team'],collection['owner'],collection['home'],collection['task_id'],collection['handle'],collection['origin']) !=
                    (team,owner,home,task_id,handle,origin) or
                    request['status'] not in {'saved','resumed'} or request['expires'] <= self.clock() or
                    request['kind'] == 'code' and collection['updated'] + 90 <= self.clock()):
                raise AccessError('The Kernel collection is not ready for a fill.',409)
            return self._begin(db,'collection:'+request_id+':'+_version(version),team=team,owner=owner,home=home,task_id=task_id,handle=handle,origin=origin,version=version,binding_digest=binding_digest)

    def finish_attempt(self, operation_id, *, team, owner, home, success, failure=None, outcome=None):
        if type(success) is not bool or (success and failure is not None) or (not success and failure not in _FAILURES):
            raise AccessError('The Kernel fill outcome is invalid.')
        if outcome is not None:
            from .fill_outcome import validate_outcome
            outcome = validate_outcome(outcome)
            if success and not (outcome['provider'] is not None and
                    outcome['provider']['status'] == 'completed' and outcome['readback']['stage'] == 'retained'):
                raise AccessError('The Kernel fill success evidence is invalid.')
        with self.requests.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            home=self._scope(team,owner,home,db)
            row=db.execute('SELECT * FROM kernel_fill_attempts WHERE operation_id=? AND team=? AND owner=? AND home=?',
                           (_id(operation_id),team,owner,home)).fetchone()
            if not row or row['state'] != 'dispatched':
                raise AccessError('This Kernel fill attempt cannot be completed again.',409)
            if outcome is not None:
                db.execute('INSERT INTO kernel_fill_outcomes VALUES (?,?)',
                           (operation_id, json.dumps(outcome, separators=(',', ':'))))
            state='complete' if success else 'failed'
            db.execute('UPDATE kernel_fill_attempts SET state=?,failure=?,updated=? WHERE operation_id=?',
                       (state,failure,self.clock(),operation_id))
            return dict(row) | {'state':state,'failure':failure}

    def attempt(self, operation_id, *, team, owner, home):
        with self.requests.connection() as db:
            home=self._scope(team,owner,home,db)
            row=db.execute('SELECT * FROM kernel_fill_attempts WHERE operation_id=? AND team=? AND owner=? AND home=?',
                           (_id(operation_id),team,owner,home)).fetchone()
            if row is None:
                return None
            result = dict(row)
            evidence = db.execute('SELECT evidence FROM kernel_fill_outcomes WHERE operation_id=?',
                                  (operation_id,)).fetchone()
            if evidence:
                from .fill_outcome import validate_outcome
                result['fill_outcome'] = validate_outcome(json.loads(evidence['evidence']))
            return result
