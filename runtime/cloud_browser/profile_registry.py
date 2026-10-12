"""Persistent browser identities, separate from task and CDP ownership.

Only opaque provider references and existing credential metadata live here.
Profile writers are durably reserved before dispatch and never expire by time.
Unknown provider outcomes must be reconciled, not retried with another writer.
"""
import hashlib
import json
import re
import secrets

from vault.delegation import credential_binding
from vault.store import AccessError


_PRINCIPAL_FIELDS = ('key', 'profile_name', 'kind', 'team', 'owner',
                     'account_handle', 'origin', 'binding', 'generation')
_LEASE_IDENTITY = ('id', 'principal_key', 'writer_key', 'kind', 'team',
                   'requester', 'home', 'thread')


class ProfileBusy(AccessError):
    def __init__(self, lease):
        super().__init__('This browser profile is in use by another task or sign-in. '
                         'Wait for that work to finish; do not sign in again or create another profile.', 409)
        self.lease = dict(lease)


class ProfileRegistry:
    def __init__(self, service):
        self.service = service
        self.store = service.store
        with self.store.connection() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS browser_profile_principals (
                    key TEXT PRIMARY KEY, profile_name TEXT NOT NULL UNIQUE,
                    kind TEXT NOT NULL, team TEXT NOT NULL, owner TEXT NOT NULL,
                    account_handle TEXT NOT NULL, origin TEXT NOT NULL, binding TEXT NOT NULL,
                    generation INTEGER NOT NULL, profile_id TEXT, state TEXT NOT NULL,
                    created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS browser_profile_selections (
                    team TEXT NOT NULL, requester TEXT NOT NULL, home TEXT NOT NULL,
                    thread TEXT NOT NULL, principal_key TEXT NOT NULL, access_handle TEXT,
                    PRIMARY KEY(team,requester,home,thread));
                CREATE TABLE IF NOT EXISTS browser_profile_accounts (
                    principal_key TEXT NOT NULL, origin TEXT NOT NULL,
                    owner TEXT NOT NULL, account_handle TEXT NOT NULL, binding TEXT NOT NULL,
                    PRIMARY KEY(principal_key,origin));
                CREATE TABLE IF NOT EXISTS browser_profile_leases (
                    id TEXT PRIMARY KEY, principal_key TEXT NOT NULL UNIQUE,
                    writer_key TEXT NOT NULL, kind TEXT NOT NULL, team TEXT NOT NULL,
                    requester TEXT NOT NULL, home TEXT NOT NULL, thread TEXT NOT NULL,
                    remote_id TEXT, state TEXT NOT NULL, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS browser_profile_adoptions (
                    principal_key TEXT PRIMARY KEY, profile_name TEXT NOT NULL UNIQUE,
                    profile_id TEXT NOT NULL UNIQUE, flow_key TEXT NOT NULL UNIQUE,
                    manifest_sha256 TEXT NOT NULL, adopted REAL NOT NULL);
            ''')

    def _context(self, turn):
        self.service.assert_private(turn)
        self.service.delegations.check_execution(turn)
        return (turn.source.scope_id, turn.source.user_id, str(turn.home.resolve()),
                turn.source.chat_id + ':' + str(turn.source.thread_id or ''))

    def _access(self, turn, access):
        if access is None:
            return None
        current = self.service.delegations.resolve(turn, access.handle)
        if (current.owner != access.owner or current.meta.id != access.meta.id or
                current.grant_id != access.grant_id or
                credential_binding(current.meta) != credential_binding(access.meta) or
                current.meta.kind != 'login'):
            raise AccessError('The saved browser account or invitation changed.', 403)
        return current

    @staticmethod
    def _key(kind, team, owner, handle=''):
        return hashlib.sha256(json.dumps(['browser-principal-v1', kind, team, owner, handle],
                                        separators=(',', ':')).encode()).hexdigest()

    @staticmethod
    def _principal(row):
        return {field: row[field] for field in _PRINCIPAL_FIELDS}

    def get(self, key):
        """Internal metadata read; callers still need authorize before use."""
        with self.store.connection() as db:
            row = db.execute('SELECT * FROM browser_profile_principals WHERE key=?', (key,)).fetchone()
        return self._principal(row) if row else None

    def _verified_principal(self, principal):
        if not isinstance(principal, dict) or not isinstance(principal.get('key'), str):
            raise AccessError('The saved browser profile has no verified identity.', 403)
        current = self.get(principal['key'])
        if current is None or any(principal.get(field) != current[field] for field in _PRINCIPAL_FIELDS):
            raise AccessError('The saved browser profile identity changed.', 403)
        with self.store.connection() as db:
            row = db.execute('SELECT state FROM browser_profile_principals WHERE key=?',
                             (current['key'],)).fetchone()
        if row['state'] == 'quarantined':
            raise AccessError('This browser profile needs account-session cleanup before it can be used again.', 409)
        return current

    def resolve(self, turn, access=None):
        context = self._context(turn)
        access = self._access(turn, access)
        kind, owner, handle, origin, bound = 'personal', context[1], '', '', ''
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            if access is not None:
                shared_key = self._key('shared', context[0], access.owner, access.meta.id)
                shared = db.execute('SELECT 1 FROM browser_profile_principals WHERE key=?',
                                    (shared_key,)).fetchone()
                granted = db.execute('SELECT 1 FROM credential_grants WHERE team=? AND owner=? '
                    'AND handle=? AND revoked IS NULL LIMIT 1',
                    (context[0], access.owner, access.meta.id)).fetchone()
                if access.grant_id or shared or granted:
                    kind, owner, handle = 'shared', access.owner, access.meta.id
                    origin, bound = access.meta.origin, credential_binding(access.meta)
                elif access.owner != context[1]:
                    raise AccessError('This personal browser account belongs to another user.', 403)
            key = self._key(kind, context[0], owner, handle)
            profile_name = 'clanker-' + kind + '-' + key[:40]
            expected = dict(key=key, profile_name=profile_name, kind=kind, team=context[0],
                owner=owner, account_handle=handle, origin=origin, binding=bound, generation=1)
            row = db.execute('SELECT * FROM browser_profile_principals WHERE key=?', (key,)).fetchone()
            if row:
                if row['state'] == 'quarantined':
                    raise AccessError('This browser profile needs account-session cleanup before it can be used again.', 409)
                if kind == 'personal' and row['profile_name'] != profile_name:
                    adopted = db.execute('SELECT profile_name,profile_id FROM browser_profile_adoptions '
                        'WHERE principal_key=?', (key,)).fetchone()
                    if (not adopted or tuple(adopted) != (row['profile_name'], row['profile_id']) or
                            row['state'] != 'ready'):
                        raise AccessError('The legacy browser profile has no verified adoption receipt.', 409)
                    expected['profile_name'] = row['profile_name']
                if self._principal(row) != expected:
                    raise AccessError('This saved browser identity changed. Reconcile its old session before replacing it.', 409)
                return expected
            db.execute('INSERT INTO browser_profile_principals VALUES (?,?,?,?,?,?,?,?,?,NULL,?,?)',
                (*expected.values(), 'reserved', self.store.clock()))
        return expected

    def selection_handle(self, turn):
        context = self._context(turn)
        with self.store.connection() as db:
            row = db.execute('SELECT access_handle FROM browser_profile_selections WHERE '
                'team=? AND requester=? AND home=? AND thread=?', context).fetchone()
        return row['access_handle'] if row else None

    def authorize(self, turn, principal, access=None):
        context = self._context(turn)
        principal = self._verified_principal(principal)
        if principal['team'] != context[0]:
            raise AccessError('This saved browser profile belongs to another workspace.', 403)
        access = self._access(turn, access)
        if principal['kind'] == 'personal':
            if principal['owner'] != context[1]:
                raise AccessError('This personal browser profile belongs to another requester.', 403)
            if access is not None and self.resolve(turn, access) != principal:
                raise AccessError('This credential must use its dedicated shared browser profile.', 403)
        elif principal['kind'] == 'shared':
            if access is None:
                handle = self.selection_handle(turn)
                if handle is None and principal['owner'] == context[1]:
                    handle = principal['account_handle']
                if handle is None:
                    raise AccessError('Select the exact shared account before opening its browser.', 403)
                access = self.service.delegations.resolve(turn, handle)
            if (access.owner != principal['owner'] or access.meta.id != principal['account_handle'] or
                    access.meta.origin != principal['origin'] or
                    credential_binding(access.meta) != principal['binding'] or
                    self.resolve(turn, access) != principal):
                raise AccessError('This invitation does not authorize the shared browser profile.', 403)
        else:
            raise AccessError('The saved browser profile kind is unsupported.', 403)
        return principal

    def select(self, turn, access=None):
        context = self._context(turn)
        access = self._access(turn, access)
        principal = self.resolve(turn, access)
        self.authorize(turn, principal, access)
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            if access is not None:
                self._check_grant(db, turn, access)
                existing = db.execute('SELECT owner,account_handle,binding FROM browser_profile_accounts '
                    'WHERE principal_key=? AND origin=?', (principal['key'], access.meta.origin)).fetchone()
                identity = (access.owner, access.meta.id, credential_binding(access.meta))
                if existing and tuple(existing) != identity:
                    raise AccessError('This profile already holds another account for this site. '
                                      'An explicit account switch must clear that site session first.', 409)
                db.execute('INSERT OR IGNORE INTO browser_profile_accounts VALUES (?,?,?,?,?)',
                    (principal['key'], access.meta.origin, *identity))
            db.execute('INSERT OR REPLACE INTO browser_profile_selections VALUES (?,?,?,?,?,?)',
                (*context, principal['key'], access.handle if access else None))
        return principal

    def selected(self, turn):
        context = self._context(turn)
        with self.store.connection() as db:
            row = db.execute('SELECT principal_key,access_handle FROM browser_profile_selections '
                'WHERE team=? AND requester=? AND home=? AND thread=?', context).fetchone()
        if row is None:
            return self.resolve(turn)
        principal = self.get(row['principal_key'])
        access = self.service.delegations.resolve(turn, row['access_handle']) if row['access_handle'] else None
        if self.resolve(turn, access) != principal:
            raise AccessError('The selected browser account changed. Select its current authorized profile.', 409)
        return self.authorize(turn, principal, access)

    def release_selection(self, turn):
        context = self._context(turn)
        with self.store.connection() as db:
            db.execute('DELETE FROM browser_profile_selections WHERE '
                       'team=? AND requester=? AND home=? AND thread=?', context)

    def invalidate_account(self, team, owner, handle):
        """Block residual cookies when an account is explicitly disconnected.

        Removing a single credential must not silently delete other sites from
        a personal profile. Until scoped session cleanup is verified, its old
        cookie snapshot cannot authorize another browser, even via a default
        personal selection. Existing leases remain available for safe closure.
        """
        self.service.validate_member(team, owner)
        if not isinstance(handle, str) or not handle:
            raise AccessError('Choose the exact account to disconnect.', 403)
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            rows = db.execute('SELECT p.key FROM browser_profile_principals p WHERE p.team=? '
                'AND (p.kind=? AND p.owner=? AND p.account_handle=? OR EXISTS ('
                'SELECT 1 FROM browser_profile_accounts a WHERE a.principal_key=p.key '
                'AND a.owner=? AND a.account_handle=?))',
                (team, 'shared', owner, handle, owner, handle)).fetchall()
            keys = [row['key'] for row in rows]
            db.executemany("UPDATE browser_profile_principals SET state='quarantined' WHERE key=?",
                           [(key,) for key in keys])
        return keys

    @staticmethod
    def _check_grant(db, turn, access):
        ProfileRegistry._grant_row(db, turn.source.scope_id, turn.source.user_id, access)

    @staticmethod
    def _grant_row(db, team, requester, access):
        if access.grant_id is None:
            return
        row = db.execute('SELECT * FROM credential_grants WHERE id=? AND revoked IS NULL',
                         (access.grant_id,)).fetchone()
        if (not row or (row['team'], row['recipient'], row['owner'], row['handle'], row['binding']) !=
                (team, requester, access.owner, access.meta.id,
                 credential_binding(access.meta))):
            raise AccessError('The shared account invitation changed before browser use.', 403)

    def current_lease(self, principal_key):
        with self.store.connection() as db:
            row = db.execute('SELECT * FROM browser_profile_leases WHERE principal_key=?',
                             (principal_key,)).fetchone()
        return dict(row) if row else None

    def get_lease(self, lease_id):
        with self.store.connection() as db:
            row = db.execute('SELECT * FROM browser_profile_leases WHERE id=?', (lease_id,)).fetchone()
        return dict(row) if row else None

    def acquire(self, turn, principal, writer_key, *, kind='browser'):
        context = self._context(turn)
        self.authorize(turn, principal)
        if (kind not in {'browser', 'auth'} or not isinstance(writer_key, str) or
                not writer_key or len(writer_key) > 300):
            raise AccessError('The browser profile writer identity is invalid.', 403)
        handle = self.selection_handle(turn)
        access = self.service.delegations.resolve(turn, handle) if handle else None
        if principal['kind'] == 'shared' and access is None:
            access = self.service.delegations.resolve(turn, principal['account_handle'])
        if access is not None:
            # Revocation cleanup needs every recipient execution home, even
            # when browser creation later has an uncertain response.
            self.service.delegations.record_browser_use(turn, access)
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            if access is not None:
                self._check_grant(db, turn, access)
            row = db.execute('SELECT * FROM browser_profile_leases WHERE principal_key=?',
                             (principal['key'],)).fetchone()
            if row:
                expected = (writer_key, kind, *context)
                if tuple(row[field] for field in ('writer_key', 'kind', 'team', 'requester', 'home', 'thread')) != expected:
                    raise ProfileBusy(row)
                return dict(row)
            lease = dict(id=secrets.token_hex(24), principal_key=principal['key'], writer_key=writer_key,
                kind=kind, team=context[0], requester=context[1], home=context[2], thread=context[3],
                remote_id=None, state='reserved', created=self.store.clock())
            db.execute('INSERT INTO browser_profile_leases VALUES (?,?,?,?,?,?,?,?,?,?,?)', tuple(lease.values()))
        return lease

    @staticmethod
    def _lease(db, lease):
        if not isinstance(lease, dict) or not isinstance(lease.get('id'), str):
            raise AccessError('The browser writer lease is invalid.', 403)
        row = db.execute('SELECT * FROM browser_profile_leases WHERE id=?', (lease['id'],)).fetchone()
        if not row or any(lease.get(field) != row[field] for field in _LEASE_IDENTITY):
            raise AccessError('The browser writer lease changed.', 403)
        return dict(row)

    def dispatched(self, lease):
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            current = self._lease(db, lease)
            if current['state'] != 'reserved':
                raise AccessError('This browser writer was already dispatched. Reconcile it before retrying.', 409)
            self._dispatch_access(db, current)
            db.execute("UPDATE browser_profile_leases SET state='dispatching' WHERE id=?", (current['id'],))
        return dict(current, state='dispatching')

    def _dispatch_access(self, db, lease):
        """Recheck authority after profile/provider reads, before a writer POST."""
        self.service.validate_member(lease['team'], lease['requester'])
        principal = db.execute('SELECT * FROM browser_profile_principals WHERE key=?',
                               (lease['principal_key'],)).fetchone()
        if principal is None or principal['team'] != lease['team'] or principal['state'] == 'quarantined':
            raise AccessError('The browser profile writer lost its authorized principal.', 403)
        selection = db.execute('SELECT principal_key,access_handle FROM browser_profile_selections '
            'WHERE team=? AND requester=? AND home=? AND thread=?',
            tuple(lease[field] for field in ('team', 'requester', 'home', 'thread'))).fetchone()
        if selection and selection['principal_key'] != principal['key']:
            raise AccessError('The browser account selection changed before dispatch.', 403)
        handle = selection['access_handle'] if selection else None
        if principal['kind'] == 'shared' and handle is None:
            if principal['owner'] != lease['requester']:
                raise AccessError('The shared account selection ended before dispatch.', 403)
            handle = principal['account_handle']
        access = self.service.delegations.lookup(lease['team'], lease['requester'], handle) if handle else None
        if access is not None:
            self._grant_row(db, lease['team'], lease['requester'], access)
        if principal['kind'] == 'shared':
            if (access is None or access.meta.kind != 'login' or access.owner != principal['owner'] or
                    access.meta.id != principal['account_handle'] or access.meta.origin != principal['origin'] or
                    credential_binding(access.meta) != principal['binding']):
                raise AccessError('The shared account changed before browser dispatch.', 403)
        elif principal['kind'] != 'personal' or principal['owner'] != lease['requester'] or (
                access is not None and (access.grant_id or access.owner != lease['requester'])):
            raise AccessError('The personal browser writer lost its owner authorization.', 403)
        if access is not None:
            selected_account = db.execute('SELECT owner,account_handle,binding FROM browser_profile_accounts '
                'WHERE principal_key=? AND origin=?', (principal['key'], access.meta.origin)).fetchone()
            if selected_account is not None and tuple(selected_account) != (
                    access.owner, access.meta.id, credential_binding(access.meta)):
                raise AccessError('The browser account changed before dispatch.', 403)

    def not_dispatched(self, lease, *, evidence):
        """Release only a trusted client's confirmed preflight non-dispatch."""
        if not isinstance(evidence, AccessError) or getattr(evidence, 'browser_dispatch_attempted', None) is not False:
            raise AccessError('The browser dispatch outcome has not been confirmed absent.', 409)
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            current = self._lease(db, lease)
            if current['state'] != 'dispatching' or current['remote_id'] is not None:
                raise AccessError('This browser writer cannot return to pre-dispatch state.', 409)
            db.execute("UPDATE browser_profile_leases SET state='reserved' WHERE id=?", (current['id'],))
        return dict(current, state='reserved')

    def confirm(self, lease, remote_id):
        if not isinstance(remote_id, str) or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}', remote_id) is None:
            raise AccessError('The browser writer has no verified remote identity.', 403)
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            current = self._lease(db, lease)
            if current['state'] not in {'dispatching', 'active'} or current['remote_id'] not in (None, remote_id):
                raise AccessError('The browser writer confirmation changed.', 403)
            db.execute("UPDATE browser_profile_leases SET state='active',remote_id=? WHERE id=?",
                       (remote_id, current['id']))
        return dict(current, state='active', remote_id=remote_id)

    def release(self, lease, *, verified_closed=False):
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            if not isinstance(lease, dict) or not isinstance(lease.get('id'), str):
                raise AccessError('The browser writer lease is invalid.', 403)
            if db.execute('SELECT 1 FROM browser_profile_leases WHERE id=?', (lease['id'],)).fetchone() is None:
                # A crash can occur after release but before the caller saves
                # its own cleanup receipt. No other writer has this nonce.
                return False
            current = self._lease(db, lease)
            if current['remote_id'] != lease.get('remote_id'):
                raise AccessError('The browser writer close names another remote session.', 403)
            if current['state'] == 'dispatching' and current['remote_id'] is None:
                raise AccessError('Reconcile the unknown browser writer before releasing its profile.', 409)
            if current['state'] != 'reserved' and verified_closed is not True:
                raise AccessError('The browser writer outcome is still unconfirmed. Keep its profile reserved.', 409)
            db.execute('DELETE FROM browser_profile_leases WHERE id=?', (current['id'],))
        return True

    def ensure_profile(self, principal, client):
        """One durable create reservation; later calls only reconcile by name."""
        principal = self._verified_principal(principal)
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = dict(db.execute('SELECT * FROM browser_profile_principals WHERE key=?',
                                  (principal['key'],)).fetchone())
            create = row['state'] == 'reserved'
            if create:
                db.execute("UPDATE browser_profile_principals SET state='creating' WHERE key=?", (row['key'],))
            elif row['state'] not in {'creating', 'ready'}:
                raise AccessError('The persistent browser profile requires reconciliation.', 409)
        remote = client.create_profile(row['profile_name']) if create else client.get_profile(row['profile_name'])
        if (not isinstance(remote, dict) or remote.get('name') != row['profile_name'] or
                not isinstance(remote.get('id'), str) or
                re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}', remote['id']) is None or
                row['profile_id'] is not None and remote['id'] != row['profile_id']):
            raise AccessError('The persistent browser profile could not be reconciled. No replacement was created.', 409)
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            current = db.execute('SELECT profile_id,state FROM browser_profile_principals WHERE key=?',
                                 (row['key'],)).fetchone()
            if (current['state'] not in {'creating', 'ready'} or
                    current['profile_id'] not in (None, remote['id'])):
                raise AccessError('The persistent browser profile changed during reconciliation.', 409)
            db.execute("UPDATE browser_profile_principals SET state='ready',profile_id=? WHERE key=?",
                       (remote['id'], row['key']))
        return {'name': row['profile_name'], 'id': remote['id']}

    def handoff(self, lease, turn, writer_key, *, closure):
        """Transfer a confirmed closed personal browser directly to login.

        The reset broker owns the durable operation receipt. Keeping one SQL
        transaction across nonce replacement prevents a second browser from
        loading and saving this profile between reset and authentication.
        """
        from .site_reset import VerifiedBrowserClosure
        context = self._context(turn)
        if (not isinstance(closure, VerifiedBrowserClosure) or
                not closure.matches(lease, turn) or
                not isinstance(writer_key, str) or not writer_key.startswith('auth:') or
                not 5 < len(writer_key) <= 300):
            raise AccessError('The browser-to-login transfer has no verified closure.', 409)
        principal = self.selected(turn)
        if (principal['kind'] != 'personal' or principal['owner'] != context[1] or
                principal['key'] != lease.get('principal_key')):
            raise AccessError('Site reset requires the current owner\'s personal browser.', 403)
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            current = self._lease(db, lease)
            if (current['kind'] != 'browser' or current['state'] != 'active' or
                    not current['remote_id'] or current['remote_id'] != lease.get('remote_id') or
                    tuple(current[field] for field in ('team', 'requester', 'home', 'thread')) != context):
                raise AccessError('The closed browser writer does not match this authentication task.', 409)
            self._dispatch_access(db, current)
            replacement = dict(id=secrets.token_hex(24), principal_key=current['principal_key'],
                writer_key=writer_key, kind='auth', team=context[0], requester=context[1],
                home=context[2], thread=context[3], remote_id=None, state='reserved',
                created=self.store.clock())
            db.execute('DELETE FROM browser_profile_leases WHERE id=?', (current['id'],))
            db.execute('INSERT INTO browser_profile_leases VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                       tuple(replacement.values()))
        return replacement
