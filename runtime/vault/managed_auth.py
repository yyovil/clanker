"""Kernel-hosted login and explicitly selected authenticated profiles.

Only account/flow references live here. Kernel collects credentials and fresh
codes, orchestrates login, and saves the profile. No DOM login writer is used.
"""
import asyncio
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import secrets
import threading
from urllib.parse import urlsplit

from .store import AccessError
from .kernel_store import _origin


def _allowed_domains(origin):
    """Credential destinations for known native Google apps, never page input."""
    host = urlsplit(origin).hostname
    domains = [host]
    if host in {'docs.google.com', 'drive.google.com', 'sheets.google.com',
                'slides.google.com', 'calendar.google.com', 'mail.google.com'}:
        domains.append('accounts.google.com')
    return domains


class ManagedAuth:
    def __init__(self, service):
        from cloud_browser.kernel_auth_client import KernelAuthClient
        self.service = service
        self.store = service.store
        self.client = KernelAuthClient(service.cloud_browser.client)
        from .managed_auth_principals import PrincipalAuth
        self.principal_auth = PrincipalAuth(self)
        with self.store.connection() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS kernel_auth_accounts (
                  team TEXT NOT NULL, owner TEXT NOT NULL, handle TEXT NOT NULL,
                  origin TEXT NOT NULL, created REAL NOT NULL, credential_name TEXT,
                  PRIMARY KEY(team,owner,handle));
                CREATE TABLE IF NOT EXISTS kernel_auth_flows (
                  key TEXT PRIMARY KEY, team TEXT NOT NULL, requester TEXT NOT NULL,
                  home TEXT NOT NULL, thread TEXT NOT NULL, account_owner TEXT NOT NULL,
                  account_handle TEXT NOT NULL, handle TEXT NOT NULL, binding TEXT NOT NULL,
                  origin TEXT NOT NULL, profile_name TEXT NOT NULL,
                  connection_id TEXT UNIQUE, request_id TEXT NOT NULL UNIQUE,
                  state TEXT NOT NULL, event_id TEXT, proxy_id TEXT,
                  created REAL NOT NULL, updated REAL NOT NULL, flow_expires_at TEXT, flow_digest TEXT);
            ''')
            if 'flow_expires_at' not in {row['name'] for row in db.execute('PRAGMA table_info(kernel_auth_flows)')}:
                db.execute('ALTER TABLE kernel_auth_flows ADD COLUMN flow_expires_at TEXT')
            if 'flow_digest' not in {row['name'] for row in db.execute('PRAGMA table_info(kernel_auth_flows)')}:
                db.execute('ALTER TABLE kernel_auth_flows ADD COLUMN flow_digest TEXT')
            # Keep code forms for ready, owner-bound Vault logins usable. They
            # remain provider-hosted and are not Managed Auth credentials.
            vault_code = "0"
            if all(db.execute("SELECT 1 FROM sqlite_master WHERE name=?", (table,)).fetchone()
                   for table in ('kernel_collections', 'kernel_items')):
                vault_code = ("r.kind='code' AND r.grant_id IS NULL AND EXISTS (SELECT 1 FROM kernel_collections c "
                    "JOIN kernel_items i ON i.team=c.team AND i.owner=c.owner AND i.handle=c.handle "
                    "WHERE c.request_id=r.id AND c.team=r.team AND c.owner=r.owner AND c.home=r.home "
                    "AND c.handle=r.handle AND c.origin=r.origin AND i.origin=r.origin "
                    "AND i.kind='login' AND i.status='ready')")
            if db.execute("SELECT 1 FROM requests r WHERE kind IN ('login','code') "
                "AND (status IN ('kernel_creating','kernel_create_unknown') OR status='waiting' AND expires>?) "
                "AND NOT (" + vault_code + ") AND NOT EXISTS (SELECT 1 FROM kernel_auth_flows f WHERE f.request_id=r.id) LIMIT 1",
                (self.store.clock(),)).fetchone():
                raise AccessError('A legacy private login form is still active or unconfirmed. Reconcile it before activating Managed Auth.', 409)
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='kernel_collections'").fetchone():
                db.execute("UPDATE requests AS r SET status='cancelled' WHERE kind IN ('login','code') "
                    "AND status IN ('waiting','saved','kernel_creating','kernel_create_unknown') "
                    "AND NOT (" + vault_code + ") AND id IN (SELECT request_id FROM kernel_collections)")
                db.execute("UPDATE kernel_collections SET state='cancelled' WHERE request_id IN "
                    "(SELECT id FROM requests WHERE kind IN ('login','code') AND status='cancelled')")
            db.commit()
            db.execute('BEGIN IMMEDIATE')
            # One durable identity can hold separate auth connections for many
            # sites. Preserve every legacy row; migration does no provider I/O.
            unique_profile = any(index['unique'] and
                [column['name'] for column in db.execute('PRAGMA index_info(' + index['name'] + ')')] == ['profile_name']
                for index in db.execute('PRAGMA index_list(kernel_auth_flows)'))
            if unique_profile:
                db.execute('ALTER TABLE kernel_auth_flows RENAME TO kernel_auth_flows_legacy_principals')
                db.execute('''CREATE TABLE kernel_auth_flows (
                  key TEXT PRIMARY KEY, team TEXT NOT NULL, requester TEXT NOT NULL,
                  home TEXT NOT NULL, thread TEXT NOT NULL, account_owner TEXT NOT NULL,
                  account_handle TEXT NOT NULL, handle TEXT NOT NULL, binding TEXT NOT NULL,
                  origin TEXT NOT NULL, profile_name TEXT NOT NULL,
                  connection_id TEXT UNIQUE, request_id TEXT NOT NULL UNIQUE,
                  state TEXT NOT NULL, event_id TEXT, proxy_id TEXT,
                  created REAL NOT NULL, updated REAL NOT NULL, flow_expires_at TEXT, flow_digest TEXT,
                  principal_key TEXT, auth_lease TEXT)''')
                old_columns = [column['name'] for column in
                    db.execute('PRAGMA table_info(kernel_auth_flows_legacy_principals)')]
                names = ','.join(old_columns)
                db.execute('INSERT INTO kernel_auth_flows (' + names + ') SELECT ' + names +
                    ' FROM kernel_auth_flows_legacy_principals')
                db.execute('DROP TABLE kernel_auth_flows_legacy_principals')
            columns = {column['name'] for column in db.execute('PRAGMA table_info(kernel_auth_flows)')}
            for name in ('principal_key', 'auth_lease'):
                if name not in columns:
                    db.execute('ALTER TABLE kernel_auth_flows ADD COLUMN ' + name + ' TEXT')
            db.execute('''CREATE TABLE IF NOT EXISTS kernel_auth_principal_selections (
                team TEXT NOT NULL, requester TEXT NOT NULL, home TEXT NOT NULL,
                thread TEXT NOT NULL, flow_key TEXT NOT NULL, handle TEXT NOT NULL,
                PRIMARY KEY(team,requester,home,thread))''')
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                    "AND name='kernel_auth_bindings'").fetchone():
                # Create and backfill atomically after the legacy guard. A failed
                # startup must not leave a migration marker without selections.
                db.execute('''CREATE TABLE kernel_auth_bindings (
                    team TEXT NOT NULL, requester TEXT NOT NULL, home TEXT NOT NULL,
                    thread TEXT NOT NULL, flow_key TEXT NOT NULL, created REAL NOT NULL,
                    PRIMARY KEY(team,requester,home,thread))''')
                # Migrate only unambiguous original selections once. A restart
                # must not restore a selection deliberately released later.
                db.execute('''INSERT INTO kernel_auth_bindings
                    SELECT f.team,f.requester,f.home,f.thread,f.key,f.created
                    FROM kernel_auth_flows f WHERE f.state!='deleted' AND
                      (SELECT COUNT(*) FROM kernel_auth_flows other WHERE
                        other.team=f.team AND other.requester=f.requester AND
                        other.home=f.home AND other.thread=f.thread AND
                        other.state!='deleted')=1''')

    def accounts(self, team, owner):
        self.service.private_home(team, owner)
        with self.store.connection() as db:
            return [dict(row) for row in db.execute(
                'SELECT * FROM kernel_auth_accounts WHERE team=? AND owner=? ORDER BY created', (team, owner))]

    def account(self, team, owner, handle):
        return next((row for row in self.accounts(team, owner) if row['handle'] == handle), None)

    def meta(self, account):
        from agent.vault_store import VaultItemMeta
        return VaultItemMeta(id=account['handle'], kind='login', label=urlsplit(account['origin']).hostname,
            origin=account['origin'], created_at=str(account['created']), login_method='password')

    def _account(self, turn, origin, access=None):
        team = turn.source.scope_id
        owner = access.owner if access else turn.source.user_id
        handle = access.meta.id if access else 'auth-' + secrets.token_hex(16)
        with self.store.connection() as db:
            db.execute('INSERT OR IGNORE INTO kernel_auth_accounts VALUES (?,?,?,?,?,NULL)',
                (team, owner, handle, origin, self.store.clock()))
        account = self.account(team, owner, handle)
        if account['origin'] != origin:
            raise AccessError('The account origin changed.', 403)
        return account

    def _context(self, turn):
        self.service.assert_private(turn)
        self.service.delegations.check_execution(turn)
        return (turn.source.scope_id, turn.source.user_id, str(turn.home.resolve()),
                self.service.cloud_browser.thread(turn))

    def saved_vault_access(self, turn, handle):
        """Select existing opaque Vault fields without extracting or copying them."""
        context = self._context(turn)
        access = self.service.delegations.resolve(turn, handle)
        profiles = getattr(self.service.cloud_browser, 'profiles', None)
        if access.meta.kind != 'login' or profiles is None and (access.grant_id or access.owner != context[1]):
            return None
        kernel = self.service.kernel_vault
        scope = kernel.scope(context[0], access.owner)
        if kernel.metadata.vault(*scope) is None:
            return None
        record = kernel.metadata.item(*scope, access.meta.id)
        account = self.account(context[0], access.owner, access.meta.id)
        if (not record or record['kind'] != 'login' or record['status'] != 'ready' or
                record['origin'] != access.meta.origin or account and account['credential_name'] or
                self._selection(context, turn=turn) is not None):
            return None
        if profiles is not None:
            principal = profiles.resolve(turn, access)
            profiles.authorize(turn, principal, access)
            if principal['kind'] == 'shared':
                dedicated = kernel.metadata.credential_vault(*scope, access.meta.id)
                if not dedicated or dedicated['vault_id'] != record['vault_id']:
                    raise AccessError('The shared login requires its dedicated credential vault.', 403)
        return access

    def _flows(self, context):
        with self.store.connection() as db:
            return [dict(row) for row in db.execute('SELECT * FROM kernel_auth_flows WHERE '
                'team=? AND requester=? AND home=? AND thread=? AND state!=? ORDER BY created DESC',
                (*context, 'deleted'))]

    def authenticator_status(self, identity, handle):
        self.service.validate_member(identity['team'], identity['owner'])
        account = self.account(identity['team'], identity['owner'], handle)
        if not account or not account['credential_name']:
            raise AccessError('Complete a saved account sign-in before connecting an authenticator.', 409)
        remote = self.client.credential_metadata(account['credential_name'])
        if (remote['name'] != account['credential_name'] or
                remote['domain'] != urlsplit(account['origin']).hostname or not remote['has_values']):
            raise AccessError('This saved login could not be verified for authenticator setup.', 403)
        self.service.validate_member(identity['team'], identity['owner'])
        return account, remote

    def configure_totp(self, identity, handle, secret):
        """Forward an owner-entered setup key; never persist or return its value."""
        home = self.service.private_home(identity['team'], identity['owner'])
        with self.service.lock_for(home):
            account, before = self.authenticator_status(identity, handle)
            after = self.client.set_totp(before['id'], secret)
            self.service.validate_member(identity['team'], identity['owner'])
            current = self.account(identity['team'], identity['owner'], handle)
            if (not current or current['credential_name'] != account['credential_name'] or
                    any(after[key] != before[key] for key in ('id', 'name', 'domain')) or
                    not after['has_totp_secret'] or not after['has_values']):
                raise AccessError('Authenticator setup could not be confirmed. Check the saved account before retrying.', 409)
            return {'saved': True, 'has_totp': True}

    def _selection(self, context, *, turn=None):
        with self.store.connection() as db:
            binding = db.execute('SELECT flow_key FROM kernel_auth_bindings WHERE '
                'team=? AND requester=? AND home=? AND thread=?', context).fetchone()
            if binding is None:
                return None
            row = db.execute('SELECT * FROM kernel_auth_flows WHERE key=?',
                (binding['flow_key'],)).fetchone()
        if not row or row['state'] == 'deleted':
            raise AccessError('This saved sign-in selection has no verified requester ownership.', 403)
        row = dict(row)
        if row.get('principal_key'):
            if row['team'] != context[0]:
                raise AccessError('This saved sign-in belongs to another workspace.', 403)
            self.principal_auth.principal(row)
            if turn is not None:
                access = self.principal_auth.caller_access(turn, row)
                row['_selected_handle'] = access.handle
            return row
        if (row['team'], row['requester'], row['home']) != context[:3]:
            raise AccessError('This saved sign-in selection has no verified requester ownership.', 403)
        if row['thread'] != context[3] and not self._own_private_profile(row):
            raise AccessError('This account profile cannot be shared with another task.', 403)
        return row

    def _own_private_profile(self, row):
        return (row['account_owner'] == row['requester'] and row['handle'] == row['account_handle'] and
            row['home'] == str(self.service.private_home(row['team'], row['requester'])) and
            self._request_row(row)['grant_id'] is None)

    @staticmethod
    def _same_account(row, access, binding, proxy_id):
        return (row['account_owner'], row['account_handle'], row['handle'], row['origin'],
            row['binding'], row['proxy_id']) == (access.owner, access.meta.id, access.handle,
            access.meta.origin, binding, proxy_id)

    def _select_authenticated(self, context, row):
        remote = self._observe(row)
        if remote.get('flow_status') != 'SUCCESS' or remote['status'] != 'AUTHENTICATED':
            return False
        self._access(row)
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            current = db.execute('SELECT * FROM kernel_auth_flows WHERE key=?', (row['key'],)).fetchone()
            request = db.execute('SELECT * FROM requests WHERE id=?', (row['request_id'],)).fetchone()
            selected = db.execute('SELECT flow_key FROM kernel_auth_bindings WHERE '
                'team=? AND requester=? AND home=? AND thread=?', context).fetchone()
            slots = ('team', 'requester', 'home', 'account_owner', 'account_handle', 'handle', 'binding',
                'origin', 'proxy_id', 'profile_name', 'connection_id', 'request_id', 'flow_digest', 'flow_expires_at')
            if (not current or current['state'] != 'authenticated' or
                    any(current[name] != row[name] for name in slots) or
                    not request or request['status'] not in {'waiting', 'saved', 'resumed'} or
                    request['grant_id'] is not None or selected and selected['flow_key'] != row['key']):
                raise AccessError('The saved sign-in changed while its profile was being selected.', 409)
            db.execute('INSERT OR IGNORE INTO kernel_auth_bindings VALUES (?,?,?,?,?,?)',
                (*context, row['key'], self.store.clock()))
        return True

    def _reusable_flow(self, context, access, binding, proxy_id):
        if (access.grant_id or access.owner != context[1] or
                context[2] != str(self.service.private_home(context[0], context[1]))):
            return None
        with self.store.connection() as db:
            rows = [dict(row) for row in db.execute('SELECT * FROM kernel_auth_flows WHERE '
                'team=? AND requester=? AND home=? AND account_owner=? AND account_handle=? '
                "AND state IN ('authenticated','reauth_required') ORDER BY created DESC",
                (*context[:3], access.owner, access.meta.id))]
        for row in rows:
            if self._same_account(row, access, binding, proxy_id) and self._own_private_profile(row):
                return row
        return None

    def _renew_retained(self, turn, context, row, *, fresh_login=False):
        """One new owner request reserves an isolated login generation."""
        if fresh_login:
            event, previous = turn.message_id, row['event_id']
            if (not self._fresh_login_request(turn) or event == previous or
                    re.fullmatch(r'[0-9]{10,}\.[0-9]{6}', previous or '') and
                    tuple(map(int, event.split('.'))) <= tuple(map(int, previous.split('.')))):
                raise AccessError('Fresh sign-in requires a new explicit request from this account owner.', 409)
        else:
            self._retry(turn, row)
        self._access(row)
        if not self._own_private_profile(row):
            raise AccessError('This account profile cannot authorize a saved-session retry.', 403)
        # The old request is not browser authorization. Verify its immutable
        # provider generation, then require a new current owner request below.
        self._remote(row)
        self._access(row)
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            current = db.execute('SELECT * FROM kernel_auth_flows WHERE key=?', (row['key'],)).fetchone()
            request = db.execute('SELECT * FROM requests WHERE id=?', (row['request_id'],)).fetchone()
            selected = db.execute('SELECT flow_key FROM kernel_auth_bindings WHERE '
                'team=? AND requester=? AND home=? AND thread=?', context).fetchone()
            slots = ('team', 'requester', 'home', 'account_owner', 'account_handle', 'handle', 'origin',
                'binding', 'proxy_id', 'profile_name', 'connection_id', 'request_id', 'event_id', 'flow_digest', 'flow_expires_at')
            if (not current or current['state'] != ('authenticated' if fresh_login else 'reauth_required') or
                    any(current[name] != row[name] for name in slots) or
                    not request or request['status'] not in {'waiting', 'saved', 'resumed'} or
                    request['grant_id'] is not None or selected and selected['flow_key'] != row['key']):
                raise AccessError('The saved sign-in changed before its owner retry.', 409)
            db.execute('DELETE FROM kernel_auth_bindings WHERE team=? AND requester=? AND home=? AND thread=?', context)
        return hashlib.sha256(json.dumps((*context, row['handle'], row['binding'], row['proxy_id'],
            'owner-reauth', row['key'], turn.message_id)).encode()).hexdigest()

    @staticmethod
    def _authenticated_response(handle, *, reused=False):
        return {'status': 'authenticated', 'provider': 'kernel_managed_auth', 'handle': handle,
            'session_reused': reused, 'authentication_scope': 'saved_profile',
            'next': 'Kernel reports a successful saved profile. Inspect the current website and verify the account before continuing; '
                    'this result does not check its live login state. If the owner explicitly requested fresh sign-in, '
                    'call clanker_authenticate with fresh_login=true and this handle. Retain all confirmed task choices.'}

    def _update(self, key, **values):
        allowed = {'connection_id', 'request_id', 'state', 'event_id', 'flow_expires_at', 'flow_digest'}
        if not values or not set(values) <= allowed:
            raise AccessError('Invalid auth state transition.', 500)
        with self.store.connection() as db:
            db.execute('UPDATE kernel_auth_flows SET ' + ','.join(name+'=?' for name in values) +
                ',updated=? WHERE key=?', (*values.values(), self.store.clock(), key))

    def _access(self, row):
        if row.get('principal_key'):
            return self.principal_auth.owner_access(row)
        from .delegation import credential_binding
        self.service.validate_member(row['team'], row['requester'])
        access = self.service.delegations.lookup(row['team'], row['requester'], row['handle'])
        if (access.owner != row['account_owner'] or access.meta.id != row['account_handle'] or
                access.meta.origin != row['origin'] or credential_binding(access.meta) != row['binding']):
            raise AccessError('The login account or invitation changed.', 403)
        return access

    @staticmethod
    def _dispatch_error(message, cause):
        # Preserve the bounded operator reference, never the provider payload or
        # exception message. The transport already logged its sanitized cause.
        error = AccessError(message, 503)
        reference = getattr(cause, 'diagnostic_ref', None)
        if isinstance(reference, str) and re.fullmatch(r'[0-9a-f]{32}', reference):
            error = AccessError(message + ' Reference: ' + reference + '.', 503)
            error.diagnostic_ref = reference
        return error

    @staticmethod
    def _connection_matches(row, remote):
        proxy = (remote or {}).get('browser', {}).get('proxy', {})
        return bool(remote and remote.get('id') and
            remote['domain'] == urlsplit(row['origin']).hostname and
            remote['profile_name'] == row['profile_name'] and
            (proxy.get('id') or remote.get('proxy_id')) == row['proxy_id'] and
            proxy.get('mode') in (None, 'default') and
            remote.get('record_session') is False and remote.get('save_credentials') is True and
            remote.get('health_checks') is not True and remote.get('auto_reauth') is not True and
            # A pre-upgrade singleton is narrower and remains safe to inspect
            # or retire. Never accept arbitrary added credential destinations.
            remote.get('allowed_domains') in (
                _allowed_domains(row['origin']), [urlsplit(row['origin']).hostname]))

    @classmethod
    def _unused_connection(cls, row, remote):
        return bool(cls._connection_matches(row, remote) and remote['status'] == 'NEEDS_AUTH' and
            all(remote.get(name) is None for name in
                ('flow_status', 'flow_type', 'flow_expires_at', 'hosted_url', 'last_auth_at')))

    def _recover_creation(self, row):
        """Find a timed-out create using reads; never replay it or adopt a login.

        The profile name is derived from the authenticated task/account binding.
        Kernel creates at most one connection for that profile/domain pair. An
        inert, exact match can therefore recover the missing acknowledgement,
        but only a new owner retry event may start its first login. Complete
        connection and profile absence after expiry leaves a local tombstone;
        recreating also requires a fresh owner retry and new absence checks.
        """
        self._access(row)
        request = self._request_row(row)
        request_status = 'cancelled' if row['state'] == 'absent' else 'waiting'
        if (row['state'] not in {'creating', 'create_unknown', 'absent'} or row['connection_id'] or
                request['status'] != request_status):
            raise AccessError('This sign-in creation cannot be reconciled.', 409)
        remote = self.client.find_connection(urlsplit(row['origin']).hostname, row['profile_name'])
        if not remote:
            # A transient empty list during the original request's lifetime
            # cannot authorize another POST. After expiry, independently check
            # the exact profile resource too before recording local absence.
            if request['expires'] > self.store.clock():
                raise AccessError('Kernel sign-in creation is still unconfirmed. Its connection was not recreated.', 409)
            if self.client.get_profile(row['profile_name']) is not None:
                raise AccessError('The unconfirmed Kernel profile still exists. Its connection was not recreated.', 409)
            target = 'absent'
        elif row['state'] == 'absent' or not self._unused_connection(row, remote):
            raise AccessError('The unconfirmed Kernel connection is not an unused login for this task.', 403)
        else:
            target = 'idle'
        self._access(row)
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            current = db.execute('SELECT * FROM kernel_auth_flows WHERE key=?', (row['key'],)).fetchone()
            request = db.execute('SELECT * FROM requests WHERE id=?', (row['request_id'],)).fetchone()
            slots = ('connection_id', 'request_id', 'state', 'binding', 'profile_name', 'event_id')
            if (not current or any(current[name] != row[name] for name in slots) or
                    not request or request['status'] != request_status or
                    target == 'absent' and request['expires'] > self.store.clock()):
                raise AccessError('The sign-in request changed while its creation was checked.', 409)
            if request['grant_id']:
                grant = db.execute('SELECT * FROM credential_grants WHERE id=? AND revoked IS NULL',
                    (request['grant_id'],)).fetchone()
                if (not grant or grant['team'] != row['team'] or grant['recipient'] != row['requester'] or
                        grant['owner'] != row['account_owner'] or grant['handle'] != row['account_handle'] or
                        grant['binding'] != row['binding']):
                    raise AccessError('The account invitation changed while its creation was checked.', 403)
            connection_id = remote['id'] if remote else None
            db.execute('UPDATE kernel_auth_flows SET connection_id=?,state=?,updated=? WHERE key=?',
                (connection_id, target, self.store.clock(), row['key']))
            if target == 'absent':
                db.execute("UPDATE requests SET status='cancelled' WHERE id=? AND status='waiting'",
                    (row['request_id'],))
        return dict(row, connection_id=connection_id, state=target)

    def _retire_absent_creation(self, turn, row):
        self._retry(turn, row)
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            current = db.execute('SELECT * FROM kernel_auth_flows WHERE key=?', (row['key'],)).fetchone()
            slots = ('connection_id', 'request_id', 'state', 'binding', 'event_id')
            if not current or any(current[name] != row[name] for name in slots):
                raise AccessError('The absent sign-in creation changed before its retry.', 409)
            db.execute("UPDATE kernel_auth_flows SET state='deleted',updated=? WHERE key=?",
                (self.store.clock(), row['key']))
            db.execute('DELETE FROM kernel_auth_bindings WHERE flow_key=?', (row['key'],))

    def _retry_recovered(self, turn, row, account, access, *, cancelled=None):
        self._retry(turn, row)
        remote = self.client.get_connection(row['connection_id'])
        if not self._unused_connection(row, remote) or remote['id'] != row['connection_id']:
            raise AccessError('The recovered connection changed before its first login. No login was started.', 409)
        self._access(row)
        self._check_dispatch(cancelled)
        request = self._request(turn, account, access)
        try:
            with self.store.connection() as db:
                db.execute('BEGIN IMMEDIATE')
                current = db.execute('SELECT * FROM kernel_auth_flows WHERE key=?', (row['key'],)).fetchone()
                previous = db.execute('SELECT * FROM requests WHERE id=?', (row['request_id'],)).fetchone()
                slots = ('connection_id', 'request_id', 'state', 'binding', 'event_id')
                if (not current or any(current[name] != row[name] for name in slots) or
                        not previous or previous['status'] != 'waiting'):
                    raise AccessError('The recovered sign-in request changed before its first login.', 409)
                if previous['grant_id']:
                    grant = db.execute('SELECT * FROM credential_grants WHERE id=? AND revoked IS NULL',
                        (previous['grant_id'],)).fetchone()
                    if (not grant or grant['team'] != row['team'] or grant['recipient'] != row['requester'] or
                            grant['owner'] != row['account_owner'] or grant['handle'] != row['account_handle'] or
                            grant['binding'] != row['binding']):
                        raise AccessError('The account invitation changed before its first login.', 403)
                db.execute("UPDATE kernel_auth_flows SET request_id=?,state='starting',event_id=?,updated=? WHERE key=?",
                    (request['id'], turn.message_id, self.store.clock(), row['key']))
                db.execute("UPDATE requests SET status='cancelled' WHERE id=? AND id!=? AND status='waiting'",
                    (row['request_id'], request['id']))
        except Exception:
            with self.store.connection() as db:
                db.execute("UPDATE requests SET status='cancelled' WHERE id=? AND id!=? AND status='waiting'",
                    (request['id'], row['request_id']))
            raise
        row.update(request_id=request['id'], state='starting', event_id=turn.message_id)
        self._start(row, cancelled=cancelled)
        return request

    def _remote(self, row):
        if not row['connection_id'] or row['state'] not in {'pending', 'authenticated', 'reauth_required', 'failed', 'expired', 'canceled'}:
            raise AccessError('A Kernel login dispatch is unconfirmed. It will not be repeated automatically.', 409)
        remote = self.client.get_connection(row['connection_id'])
        try:
            # Kernel's login response carries nanoseconds, while GET rounds to
            # microseconds. Python truncates extra digits during parsing. Allow
            # one representational tick; meaningful expiry changes still fail.
            expiry_matches = abs(
                datetime.fromisoformat(remote['flow_expires_at'].replace('Z', '+00:00')) -
                datetime.fromisoformat(row['flow_expires_at'].replace('Z', '+00:00'))
            ) <= datetime.resolution
        except (TypeError, ValueError, KeyError, AttributeError):
            expiry_matches = False
        # Kernel removes the hosted capability after a terminal result. The
        # immutable owner/profile plus normalized expiry bind that generation.
        hosted = (remote or {}).get('hosted_url')
        terminal = (remote or {}).get('flow_status') in {'SUCCESS', 'FAILED', 'EXPIRED', 'CANCELED'}
        flow_matches = expiry_matches and bool(row.get('flow_digest')) and (
            hosted is None and terminal or isinstance(hosted, str) and
            hashlib.sha256(hosted.encode()).hexdigest() == row['flow_digest'])
        if (not self._connection_matches(row, remote) or remote['id'] != row['connection_id'] or
                not flow_matches):
            raise AccessError('Kernel login ownership or proxy binding could not be verified.', 403)
        return remote

    def _observe(self, row):
        self._access(row)
        request = self._request_row(row)
        retained = bool(row.get('principal_key') and row['state'] == 'authenticated')
        if not retained and (request['status'] not in {'waiting', 'saved', 'resumed'} or (
                row['state'] != 'authenticated' and request['expires'] <= self.store.clock())):
            raise AccessError('The sign-in request expired or was cancelled. It cannot authorize this browser.', 410)
        remote = self._remote(row)
        # Cancellation/revocation can occur while the provider GET is pending.
        # Revalidate and atomically compare the same local flow generation.
        self._access(row)
        status = remote.get('flow_status')
        target = ('reauth_required' if row['state'] == 'reauth_required' or
                  row['state'] == 'authenticated' and (status != 'SUCCESS' or remote['status'] != 'AUTHENTICATED') else
                  'authenticated' if status == 'SUCCESS' and remote['status'] == 'AUTHENTICATED'
                  else status.lower() if status in {'FAILED', 'EXPIRED', 'CANCELED'} else row['state'])
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            current = db.execute('SELECT * FROM kernel_auth_flows WHERE key=?', (row['key'],)).fetchone()
            request = db.execute('SELECT * FROM requests WHERE id=?', (row['request_id'],)).fetchone()
            slots = ('connection_id', 'request_id', 'state', 'flow_digest', 'flow_expires_at', 'binding')
            if (not current or any(current[name] != row[name] for name in slots) or
                    current['state'] not in {'pending', 'authenticated', 'reauth_required', 'failed', 'expired', 'canceled'} or
                    not request or not retained and request['status'] not in {'waiting', 'saved', 'resumed'} or
                    not retained and current['state'] != 'authenticated' and request['expires'] <= self.store.clock() or
                    current['state'] in {'failed', 'expired', 'canceled'} and target != current['state']):
                raise AccessError('The sign-in request changed or ended while Kernel was being checked.', 409)
            if request['grant_id'] and not retained:
                grant = db.execute('SELECT * FROM credential_grants WHERE id=? AND revoked IS NULL',
                    (request['grant_id'],)).fetchone()
                if (not grant or grant['team'] != row['team'] or grant['recipient'] != row['requester'] or
                        grant['owner'] != row['account_owner'] or grant['handle'] != row['account_handle'] or
                        grant['binding'] != row['binding']):
                    raise AccessError('The account invitation changed while Kernel was being checked.', 403)
            db.execute('UPDATE kernel_auth_flows SET state=?,updated=? WHERE key=?',
                (target, self.store.clock(), row['key']))
            if target == 'authenticated':
                credential = remote.get('credential', {}).get('name')
                if credential:
                    db.execute('UPDATE kernel_auth_accounts SET credential_name=? WHERE '
                        'team=? AND owner=? AND handle=?',
                        (credential, row['team'], row['account_owner'], row['account_handle']))
            if target in {'authenticated', 'failed', 'expired', 'canceled'}:
                # Resume the task with success or a truthful blocker, never a retry.
                db.execute("UPDATE requests SET status='saved' WHERE id=? AND status='waiting' AND expires>?",
                    (row['request_id'], self.store.clock()))
        if row.get('principal_key') and target in {'authenticated', 'failed', 'expired', 'canceled'}:
            self.principal_auth.terminal(row)
        return remote

    def _request(self, turn, account, access, *, previous=None):
        return self.store.create(team=turn.source.scope_id, owner=turn.source.user_id,
            home=self.service.private_home(turn.source.scope_id, turn.source.user_id), task_id=turn.task_id,
            source=turn.source.to_dict(), task=previous['task'] if previous else self.service.channel_tasks.request_context(turn),
            kind='login', label=urlsplit(account['origin']).hostname, origin=account['origin'],
            handle=access.handle, grant_id=access.grant_id,
            approver=access.owner if access.grant_id else None, gateway_event_id=turn.message_id)

    def _retry(self, turn, row, *, allow_signin=True):
        from .owner_approval import OwnerApprovalRequired
        from .verification_retry import affirmative, answering_retry_prompt, retry_request
        event = turn.message_id
        message = turn.owner_message
        # The flow generation (its last event) is part of what the owner approves.
        details = {'flow': row['key'], 'generation': row['event_id'],
                   'handle': row['handle'], 'origin': row['origin']}
        if isinstance(event, str) and event != row['event_id']:
            if re.fullmatch(r'[0-9]{10,}\.[0-9]{6}', event) and (retry_request(message) or
                    affirmative(message) and answering_retry_prompt(turn.conversation) or
                    allow_signin and self._signin_request(message)):
                return
            if self.service.approvals.consume(turn, 'signin_retry', details):
                return
        raise OwnerApprovalRequired('signin_retry', details,
            'This login ended. A new owner retry request is needed; ordinary wording is accepted.', 409)

    @staticmethod
    def _signin_request(message):
        from .verification_retry import _command
        words = _command(message)
        return bool(words and (words[0] in {'login', 'signin', 'authenticate'} or
            words[0] in {'sign', 'log'} and 'in' in words[1:]))

    @staticmethod
    def _fresh_login_request(turn):
        from .verification_retry import _command, _text
        if not isinstance(turn.message_id, str) or not re.fullmatch(r'[0-9]{10,}\.[0-9]{6}', turn.message_id):
            return False
        text = _text(turn.owner_message)
        if not text:
            return False
        # This exceptional path needs understood authority for the whole request.
        # Unknown clauses refuse rather than dropping a condition/withdrawal or
        # trying to enumerate every way the owner could say "not yet".
        browser = r'(?:this|the current|my current|the task) browser(?: session)?'
        credentials = r'(?:my )?saved (?:login|credentials|password)(?: and (?:my )?(?:saved )?authenticator)?'
        use_saved = rf'use {credentials}(?: automatically)?'
        logout = rf'(?:sign|log) (?:(?:me|it) )?out(?: of)? {browser}(?: only)?'
        condition = rf'if {browser}(?: is)?(?: already)? (?:signed|logged) in,? (?:then )?{logout}(?:,? then {use_saved})?'
        preserve = r'(?:security settings|saved credentials|credentials|saved password|password)'
        other_devices = r'(?:sign|log) me out (?:on|of) (?:my |any )?other (?:devices|sessions)'
        scopes = (
            condition, logout, use_saved,
            rf"(?:do not|don't|never) change (?:my |the )?{preserve}(?: (?:or|and) (?:my |the )?{preserve})*",
            rf"(?:do not|don't|never) {other_devices}",
            rf"(?:do not|don't|never) ask me for (?:a |an |the )?(?:code|password|credentials|authenticator code)(?: or {other_devices})?",
        )
        intent = False
        for sentence in filter(None, re.split(r'[.!?:;](?:\s+|$)', text)):
            words = _command(sentence)
            # "in" has no target; "into" takes one site label. An open word
            # slot here would swallow timing restrictions such as "in later"
            # or "into GitHub tomorrow" and incorrectly authorize dispatch.
            signin = bool(words and re.fullmatch(
                rf'(?:sign|log)(?: me)? (?:in|into [a-z][a-z0-9]*) using {credentials}', ' '.join(words)))
            if words[:2] in (['i', 'need'], ['i', 'want']):
                words = words[2:]
            elif words[:1] in (['start'], ['use'], ['perform']):
                words = words[1:]
            if words[:1] == ['a']:
                words = words[1:]
            end = (2 if words[1:2] in (['login'], ['signin'], ['authentication']) else
                   3 if words[1:3] == ['sign', 'in'] else 0)
            if (words[:1] in (['fresh'], ['new']) and end and
                    set(words[end:]) <= {'this', 'time', 'now', 'please', 'plz', 'pls'}):
                intent = True
            elif not signin and not any(re.fullmatch(pattern, sentence) for pattern in scopes):
                return False
        return intent

    def _observed_origin(self, turn):
        from tools import browser_vault_tool as native
        cloud = self.service.cloud_browser
        cloud.prepare(turn)
        result = native._eval_js(cloud.native_task_id(turn), 'window.location.href')
        value = result.get('result') if result.get('success') else None
        if not isinstance(value, str):
            raise AccessError('Open the intended HTTPS site before signing in.', 409)
        parts = urlsplit(value)
        origin = _origin('https://' + (parts.hostname or '')) if parts.scheme == 'https' else None
        if not origin or parts.username or parts.password or parts.port not in (None, 443):
            raise AccessError('Sign-in requires an exact HTTPS site.', 409)
        # No query/fragment is sent into a new authentication context.
        return origin

    async def authenticate(self, turn, *, handle=None, origin=None, resend_link=False, fresh_login=False, reset_site=False):
        # HTTP and the owner RLock are synchronous. Keep both on one worker;
        # acquiring a threading lock or making a request on the gateway loop
        # would stall Slack handling, the hosted vault and every other owner.
        cancelled = threading.Event()
        try:
            prepared = await asyncio.to_thread(self._prepare_authenticate, turn,
                handle=handle, origin=origin, resend_link=resend_link, fresh_login=fresh_login, reset_site=reset_site, cancelled=cancelled)
        except asyncio.CancelledError:
            # A running HTTP request cannot be stopped by cancelling to_thread.
            # Its worker must not start another login or accept a late result.
            cancelled.set()
            raise
        if isinstance(prepared, dict):
            return prepared
        request, access = prepared
        delivery = await self.service.deliver_link(request, delivery_event_id=turn.message_id if resend_link else None)
        delivery_note = ('The private Kernel sign-in message was posted to Slack.' if delivery['status'] == 'sent' else
                         'The private Kernel sign-in message was already sent; this call did not resend it.')
        owns_response = self.service.private_link_response_owned(turn.source, turn.message_id)
        if owns_response:
            from gateway.private_access_response import mark_private_access_response
            mark_private_access_response(turn.source, turn.message_id)
        response_note = ('The sign-in card is already the reply to this request. Do not add another sign-in notice or link. '
                         if owns_response else
                         'For an invited account, tell the requester that the account owner must sign in in their own DM. '
                         if delivery['recipient'] == 'account_owner' else
                         'If needed to answer the current request, use link_delivery.message_url to locate the existing sign-in message. ')
        return {'status': 'waiting_for_owner', 'provider': 'kernel_managed_auth', 'request_id': request['id'],
                'handle': access.handle, 'link_delivery': delivery,
                'next': delivery_note + ' ' + response_note +
                        'If the requester cannot find it, call clanker_authenticate with resend_link=true to post the same pending link again. '
                        'End this turn. Kernel handles login and fresh codes; the task resumes only after its result. Do not request another OTP or fill login controls.'}

    @staticmethod
    def _check_dispatch(cancelled):
        if cancelled is not None and cancelled.is_set():
            raise AccessError('The login dispatch was cancelled. It will not be repeated automatically.', 503)

    def _prepare_authenticate(self, turn, *, handle=None, origin=None, resend_link=False, fresh_login=False, reset_site=False, cancelled=None):
        self._check_dispatch(cancelled)
        self._context(turn)
        # Account discovery and dispatch must share the owner lock now that
        # two gateway coroutines can prepare their accounts on parallel workers.
        with self.service.lock_for(turn.home):
            self._check_dispatch(cancelled)
            result = self._prepare_authenticate_locked(turn, handle=handle, origin=origin,
                resend_link=resend_link, fresh_login=fresh_login, reset_site=reset_site, cancelled=cancelled)
        from .managed_auth_principals import PreparedPrincipalAuth
        return result.run() if isinstance(result, PreparedPrincipalAuth) else result

    def _prepare_authenticate_locked(self, turn, *, handle=None, origin=None, resend_link=False, fresh_login=False, reset_site=False, cancelled=None):
        self._check_dispatch(cancelled)
        if type(resend_link) is not bool:
            raise AccessError('Choose whether to resend the existing private sign-in link.')
        if type(reset_site) is not bool or reset_site and (not fresh_login or resend_link or not handle):
            raise AccessError('Site reset requires fresh sign-in and an explicitly selected owner credential.', 409)
        if type(fresh_login) is not bool or fresh_login and (resend_link or not reset_site and not self._fresh_login_request(turn)):
            raise AccessError('Fresh sign-in requires an explicit current owner request; it cannot resend a pending link.', 409)
        if resend_link and (not isinstance(turn.message_id, str) or
                not re.fullmatch(r'[0-9]{10,}\.[0-9]{6}', turn.message_id)):
            raise AccessError('Resending a private link requires a current Slack request.', 409)
        try:
            context = self._context(turn)
        except AccessError:
            self.service.assert_private(turn)  # do not turn an ACL refusal into a handoff
            raise
        if origin is not None:
            origin = _origin(origin)
        access = self.service.delegations.resolve(turn, handle) if handle else None
        if access:
            if access.meta.kind != 'login' or origin and origin != access.meta.origin:
                raise AccessError('Choose a login for the exact intended site.', 403)
            origin = access.meta.origin
        else:
            origin = origin or self._observed_origin(turn)
            self._check_dispatch(cancelled)
            items = [item for item in self.service.delegations.items(context[0], context[1])
                     if item['kind'] == 'login' and item['origin'] == origin]
            if len(items) > 1:
                return {'status': 'account_choice_required', 'handles': [item['id'] for item in items],
                        'next': 'Ask which saved account to use.'}
            if items:
                access = self.service.delegations.resolve(turn, items[0]['id'])
        if fresh_login and (access is None or access.grant_id or access.owner != context[1]):
            raise AccessError('Fresh sign-in requires this requester\'s own saved account.', 403)
        if reset_site:
            from cloud_browser.site_reset import reset_requested
            if not reset_requested(self, turn, origin):
                raise AccessError('Site reset requires a current explicit owner request for this exact origin.', 409)
            if getattr(self.service.cloud_browser, 'profiles', None) is None:
                raise AccessError('Site reset requires a persistent personal browser profile.', 409)
        if access and self.saved_vault_access(turn, access.handle) is not None:
            if fresh_login:
                raise AccessError('Fresh Managed Auth requires an existing saved login credential.', 409)
            cloud = self.service.cloud_browser
            cloud.select_saved_account(turn, access)
            # Selecting a retained account can retire the anonymous browser.
            # Read owned state again before telling the agent to use its form.
            _, state = cloud.state(turn)
            try:
                _, entry = cloud.selected(turn, state)
            except AccessError as exc:
                if exc.status != 409 or str(exc) != 'Open this thread\'s Kernel browser before using saved access.':
                    raise
                entry = {}
            browser_reopen_required = not bool(entry.get('session_id'))
            browser_next = (
                f'The selected saved account has no active task browser. Call browser_navigate to {origin}, '
                'then take a fresh browser snapshot. Do not use old form references. '
                'Recheck the selected account and current cart; the previous cart may belong to a different '
                'browser profile and must be reconciled before continuing. '
                if browser_reopen_required else 'Use the current task browser. ')
            return {'status': 'saved_login_available', 'provider': 'kernel_vault', 'handle': access.handle,
                'origin': origin, 'authenticated': False, 'browser_reopen_required': browser_reopen_required,
                'next': browser_next + 'Inspect the site; if already signed in, verify the account and continue. '
                        'Otherwise open its login form and call clanker_vault_fill with this handle. Kernel fills saved fields without exposing values. '
                        'Submit the intended login step once and inspect the result. Use clanker_vault_enter_code for a displayed verification step; '
                        'it uses saved TOTP or privately collects a fresh code. Never type credentials or ask for codes in chat. '
                        'A filled form is not confirmed sign-in. Preserve the cart and verify website acceptance.'}
        account = self._account(turn, origin, access)
        if fresh_login and not account['credential_name']:
            raise AccessError('Fresh Managed Auth requires an existing saved login credential.', 409)
        access = access or self.service.delegations.resolve(turn, account['handle'])
        if getattr(self.service.cloud_browser, 'profiles', None) is not None:
            from .managed_auth_principals import PreparedPrincipalAuth
            return PreparedPrincipalAuth(self.principal_auth, turn, account, access, fresh_login=fresh_login,
                resend_link=resend_link, reset_site=reset_site, cancelled=cancelled)
        from .delegation import credential_binding
        binding = credential_binding(access.meta)
        cloud = self.service.cloud_browser
        policy = getattr(cloud.client, 'proxy_policy', None)
        proxy_id = policy['id'] if policy else None
        key = hashlib.sha256(json.dumps((*context, access.handle, binding, proxy_id)).encode()).hexdigest()
        previous_request = None
        with self.service.lock_for(turn.home):
            self._check_dispatch(cancelled)
            row = self._selection(context, turn=turn)
            if row and not self._same_account(row, access, binding, proxy_id):
                raise AccessError('This task is bound to another login account. Stop its browser before switching accounts.', 409)
            if row and fresh_login and row['state'] == 'authenticated' and row['event_id'] != turn.message_id:
                key = self._renew_retained(turn, context, row, fresh_login=True)
                row = None
                # The previous flow remains valid for other task bindings.
                # Skip discovery so it cannot immediately be selected again.
                fresh_reserved = True
            else:
                fresh_reserved = False
            if row is None and not fresh_reserved:
                local = [item for item in self._flows(context)
                    if item['state'] not in {'authenticated', 'reauth_required'}]
                if (len(local) == 1 and local[0]['key'] == key and
                        local[0]['state'] in {'failed', 'expired', 'canceled'}):
                    # A released original thread can explicitly retry its own
                    # ended flow. Retained historical rows never select an
                    # account merely because another browser was opened.
                    self._retry(turn, local[0])
                    row = local[0]
                    self._access(row)
                    with self.store.connection() as db:
                        db.execute('BEGIN IMMEDIATE')
                        current = db.execute('SELECT * FROM kernel_auth_flows WHERE key=?', (row['key'],)).fetchone()
                        request = db.execute('SELECT * FROM requests WHERE id=?', (row['request_id'],)).fetchone()
                        slots = ('state', 'binding', 'profile_name', 'connection_id', 'request_id', 'flow_digest', 'flow_expires_at')
                        if (not current or any(current[name] != row[name] for name in slots) or
                                not request or request['status'] not in {'waiting', 'saved', 'resumed'}):
                            raise AccessError('The released sign-in changed before its owner retry.', 409)
                        db.execute('INSERT INTO kernel_auth_bindings VALUES (?,?,?,?,?,?)',
                            (*context, row['key'], self.store.clock()))
                elif local:
                    raise AccessError('This task has an unconfirmed sign-in without a verified account selection.', 409)
                if row is None:
                    retained = self._reusable_flow(context, access, binding, proxy_id)
                    if retained is not None:
                        if fresh_login and retained['state'] == 'authenticated' and retained['event_id'] != turn.message_id:
                            key = self._renew_retained(turn, context, retained, fresh_login=True)
                        elif retained['state'] == 'authenticated' and self._select_authenticated(context, retained):
                            from gateway.private_access_response import release_private_access_response
                            release_private_access_response(turn.source, turn.message_id)
                            return self._authenticated_response(access.handle, reused=True)
                        else:
                            if resend_link:
                                raise AccessError('The saved session ended. A new owner retry request is needed.', 409)
                            with self.store.connection() as db:
                                retained = dict(db.execute('SELECT * FROM kernel_auth_flows WHERE key=?',
                                    (retained['key'],)).fetchone())
                            key = self._renew_retained(turn, context, retained)
            self.service.delegations.record_browser_use(turn, access)
            if row and row['state'] == 'reauth_required':
                if resend_link:
                    raise AccessError('The saved session ended. A new owner retry request is needed.', 409)
                key = self._renew_retained(turn, context, row)
                row = None
            if row and row['state'] in {'creating', 'create_unknown', 'absent'}:
                row = self._recover_creation(row)
            if row and row['state'] == 'absent':
                if resend_link:
                    raise AccessError('The expired sign-in connection was absent. A new owner retry request is needed.', 409)
                self._retire_absent_creation(turn, row)
                row = None
            if row and row['state'] in {'pending', 'failed', 'expired', 'canceled'}:
                request = self._request_row(row)
                remote = self._remote(row)
                stale_domains = (remote.get('flow_status') == 'FAILED' and
                    remote.get('error_code') == 'domain_not_allowed' and
                    remote.get('allowed_domains') != _allowed_domains(row['origin']))
                if request['status'] in {'waiting', 'saved', 'resumed'} and (
                        request['expires'] <= self.store.clock() or stale_domains):
                    if resend_link:
                        raise AccessError('This sign-in link ended. Ask to retry sign-in so a fresh link can be created.', 409)
                    self._retry(turn, row, allow_signin=False)
                    # Recover only on a fresh owner event. Verify the exact
                    # provider generation and confirm cleanup before creating
                    # another flow; never adopt an expired late success.
                    self._access(row)
                    self._remote(row)
                    self._access(row)
                    current = self._request_row(row)
                    if current['status'] != request['status'] or current['expires'] != request['expires']:
                        raise AccessError('The sign-in changed during recovery. Check its current status before retrying.', 409)
                    self._cleanup(row)
                    previous_request = request
                    row = None
            if row and row['state'] == 'idle':
                if resend_link:
                    raise AccessError('The connection was recovered, but no sign-in link exists. A new owner retry request is needed.', 409)
                if self._request_row(row)['status'] != 'waiting':
                    raise AccessError('The sign-in request was cancelled.', 410)
                request = self._retry_recovered(turn, row, account, access, cancelled=cancelled)
            elif row:
                remote = self._observe(row)
                if remote.get('flow_status') == 'SUCCESS' and remote['status'] == 'AUTHENTICATED':
                    from gateway.private_access_response import release_private_access_response
                    release_private_access_response(turn.source, turn.message_id)
                    return self._authenticated_response(access.handle,
                        reused=row['thread'] != context[3])
                if row['state'] == 'authenticated':
                    if resend_link:
                        raise AccessError('The saved session ended. A new owner retry request is needed.', 409)
                    with self.store.connection() as db:
                        retained = dict(db.execute('SELECT * FROM kernel_auth_flows WHERE key=?',
                            (row['key'],)).fetchone())
                    key = self._renew_retained(turn, context, retained)
                    row = None
                elif remote.get('flow_status') == 'IN_PROGRESS':
                    request = self._request_row(row)
                    if request['status'] != 'waiting' or request['expires'] <= self.store.clock():
                        raise AccessError('The private sign-in request expired or was cancelled.', 410)
                else:
                    if resend_link:
                        raise AccessError('The sign-in ended. Its link cannot be resent; a new sign-in needs an owner retry request.', 409)
                    self._retry(turn, row)
                    self._check_dispatch(cancelled)
                    request = self._request(turn, account, access, previous=self._request_row(row))
                    self._update(row['key'], request_id=request['id'], state='starting', event_id=turn.message_id)
                    row.update(request_id=request['id'], state='starting', event_id=turn.message_id)
                    self._start(row, cancelled=cancelled)
            if row is None:
                if resend_link:
                    raise AccessError('There is no pending sign-in link to resend.', 409)
                self._check_dispatch(cancelled)
                request = self._request(turn, account, access, previous=previous_request)
                now = self.store.clock()
                row = dict(key=key, team=context[0], requester=context[1], home=context[2], thread=context[3],
                    account_owner=access.owner, account_handle=access.meta.id, handle=access.handle, binding=binding,
                    origin=origin, profile_name='clanker-auth-' + key[:40], connection_id=None,
                    request_id=request['id'], state='creating', event_id=turn.message_id, proxy_id=proxy_id)
                with self.store.connection() as db:
                    db.execute('BEGIN IMMEDIATE')
                    previous = db.execute('SELECT state FROM kernel_auth_flows WHERE key=?', (key,)).fetchone()
                    if previous and previous['state'] != 'deleted':
                        raise AccessError('This sign-in is already being dispatched.', 409)
                    if previous:
                        db.execute('DELETE FROM kernel_auth_flows WHERE key=? AND state=?', (key, 'deleted'))
                    db.execute('INSERT INTO kernel_auth_flows (key,team,requester,home,thread,account_owner,'
                        'account_handle,handle,binding,origin,profile_name,connection_id,request_id,state,event_id,'
                        'proxy_id,created,updated,flow_expires_at,flow_digest) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                        (*row.values(), now, now, None, None))
                    db.execute('INSERT INTO kernel_auth_bindings VALUES (?,?,?,?,?,?)',
                        (*context, key, now))
                try:
                    self._check_dispatch(cancelled)
                    remote = self.client.create_connection(urlsplit(origin).hostname, row['profile_name'],
                        login_url=origin, proxy_id=proxy_id, credential_name=account['credential_name'],
                        allowed_domains=_allowed_domains(origin), health_checks=False, auto_reauth=False)
                    if remote['domain'] != urlsplit(origin).hostname or remote['profile_name'] != row['profile_name']:
                        raise AccessError('Kernel returned another account profile.', 403)
                    self._check_dispatch(cancelled)
                    self._update(key, connection_id=remote['id'], state='starting')
                    row.update(connection_id=remote['id'], state='starting')
                    self._start(row, cancelled=cancelled)
                except Exception as error:
                    self._update(key, state='create_unknown' if row['connection_id'] is None else 'login_unknown')
                    raise self._dispatch_error('Kernel sign-in creation could not be confirmed. It will not be repeated automatically.', error) from None
        return request, access

    def _start(self, row, *, cancelled=None):
        browser = self.service.cloud_browser
        if not row.get('principal_key') and hasattr(browser, 'prepare_authentication'):
            browser.prepare_authentication(row)
        try:
            request = self._request_row(row)
            if request['status'] != 'waiting' or request['expires'] <= self.store.clock():
                raise AccessError('The login request was cancelled or expired.', 410)
            self._check_dispatch(cancelled)
            if row.get('principal_key'):
                self.principal_auth.dispatch(row)
            login = self.client.start_login(row['connection_id'], proxy_id=row['proxy_id'])
            self._check_dispatch(cancelled)
            if login['id'] != row['connection_id']:
                raise AccessError('Kernel returned another sign-in flow.', 403)
            if not login.get('flow_expires_at'):
                raise AccessError('Kernel did not bind this sign-in attempt.', 502)
            flow = dict(state='pending', flow_expires_at=login['flow_expires_at'],
                flow_digest=hashlib.sha256(login['hosted_url'].encode()).hexdigest())
            self._update(row['key'], **flow)
            row.update(flow)
        except Exception as error:
            self._update(row['key'], state='login_unknown')
            raise self._dispatch_error('Kernel login dispatch is unconfirmed. It will not be repeated automatically.', error) from None

    def _request_row(self, row):
        with self.store.connection() as db:
            request = db.execute('SELECT * FROM requests WHERE id=?', (row['request_id'],)).fetchone()
        if not request:
            raise AccessError('The login request is unavailable.', 410)
        return dict(request)

    def flow_for_request(self, request_id, *, include_ended=False):
        with self.store.connection() as db:
            row = db.execute('SELECT * FROM kernel_auth_flows WHERE request_id=?' +
                ('' if include_ended else " AND state!='deleted'"), (request_id,)).fetchone()
        return dict(row) if row else None

    def hosted_view(self, request):
        """Show a bound attempt's result without replaying login or returning a stale capability."""
        row = self.flow_for_request(request['id'], include_ended=True)
        if not row or request['status'] not in {'waiting', 'saved', 'resumed'} or request['expires'] <= self.store.clock():
            raise AccessError('This sign-in request is no longer available.', 410)
        self._access(row)
        states = {'authenticated': 'completed', 'failed': 'failed', 'expired': 'expired',
                  'canceled': 'canceled', 'deleted': 'ended', 'reauth_required': 'ended'}
        state = states.get(row['state'])
        if state:
            return {'provider': 'kernel_managed_auth', 'auth_status': state}
        remote = self._remote(row)
        state = {'SUCCESS': 'completed', 'FAILED': 'failed', 'EXPIRED': 'expired', 'CANCELED': 'canceled'}.get(remote.get('flow_status'))
        if state == 'completed' and remote.get('status') != 'AUTHENTICATED':
            state = 'ended'
        if state:
            return {'provider': 'kernel_managed_auth', 'auth_status': state}
        if request['status'] != 'waiting' or remote.get('flow_status') != 'IN_PROGRESS' or not remote.get('hosted_url'):
            raise AccessError('This sign-in request is no longer available.', 410)
        return {'provider': 'kernel_managed_auth', 'collection_url': remote['hosted_url']}

    def hosted_link(self, request):
        row = self.flow_for_request(request['id'])
        if not row or request['status'] != 'waiting' or request['expires'] <= self.store.clock():
            raise AccessError('This sign-in request is no longer waiting.', 410)
        self._access(row)
        remote = self._remote(row)
        if remote.get('flow_status') != 'IN_PROGRESS' or not remote.get('hosted_url'):
            raise AccessError('The Kernel sign-in flow has ended. Return to Clanker for its result.', 410)
        return remote['hosted_url']

    def browser_binding(self, turn):
        # Public browsing has no authenticated profile; owner/account work is
        # handed to the private worker before creating an auth flow.
        context = (turn.source.scope_id, turn.source.user_id, str(turn.home.resolve()),
                   self.service.cloud_browser.thread(turn))
        row = self._selection(context, turn=turn)
        if row is None:
            return None
        self._context(turn)
        if row['state'] == 'reauth_required':
            raise AccessError('The saved session ended. A new owner retry request is needed.', 409)
        remote = self._observe(row)
        if remote.get('flow_status') != 'SUCCESS' or remote['status'] != 'AUTHENTICATED':
            raise AccessError('Complete the private Kernel sign-in before continuing browser automation.', 409)
        if row.get('principal_key'):
            # The connection's creator is not the current recipient. Provider
            # observation can race removal of that recipient or their grant.
            self.principal_auth.caller_access(turn, row)
        return {'connection_id': row['connection_id'], 'profile_name': row['profile_name'],
                'handle': row.get('_selected_handle', row['handle'])}

    def legacy_adoption_evidence(self, turn, candidate):
        from .managed_auth_adoption import evidence
        return evidence(self, turn, candidate)

    def commit_legacy_adoption(self, db, turn, evidence, principal):
        from .managed_auth_adoption import commit
        return commit(self, db, turn, evidence, principal)

    def resume_prefix(self, request):
        row = self.flow_for_request(request['id'])
        if not row:
            return None
        remote = self._observe(row)
        if remote.get('flow_status') == 'SUCCESS' and remote['status'] == 'AUTHENTICATED':
            return ('Kernel Managed Auth confirmed sign-in. Use the authenticated task browser and continue '
                    'the original goal with its confirmed selections. Do not fill login fields or request another code. '
                    'Inspect the current website and rebuild an anonymous cart from the saved choices if necessary. '
                    'Sign-in grants no payment or purchase approval.')
        reasons = {
            'awaiting_input_timeout': 'The private sign-in expired while waiting for input.',
            'credentials_invalid': 'The provider reports that the site rejected the supplied credentials.',
            'totp_code_rejected': 'The provider reports that the authenticator code was rejected.',
            'captcha_blocked': 'The provider reports a CAPTCHA blocking sign-in.',
            'bot_detected': 'The provider reports that the site blocked the automated browser.',
            'unsupported_auth_method': 'The provider reports an unsupported authentication method.',
            'domain_not_allowed': 'The configured allowed sign-in domains blocked a login redirect. '
                'This is an integration configuration failure, not proof of invalid credentials. '
                'The configuration must be corrected before another attempt.',
            'timeout': 'The provider reports that sign-in timed out.',
            'flow_failed': 'The provider reports that its sign-in flow failed without a detailed reason.',
        }
        reason = reasons.get(remote.get('error_code'), 'The provider did not supply a specific supported failure reason.')
        return ('Kernel Managed Auth ended without confirming sign-in. ' + reason + ' Explain this blocker privately. '
                'Do not infer any other rejected value. Do not restart or request another SMS automatically. '
                'Preserve the original task choices for an owner-directed retry.')

    def poll(self):
        with self.store.connection() as db:
            rows = [dict(row) for row in db.execute("SELECT f.* FROM kernel_auth_flows f JOIN requests r "
                "ON r.id=f.request_id WHERE f.state IN ('pending','cleanup_pending')")]
        for row in rows:
            try:
                with self.service.lock_for(Path(row['home'])):
                    request = self._request_row(row)
                    if row['state'] == 'cleanup_pending' or request['expires'] <= self.store.clock() or request['status'] == 'cancelled':
                        self._cleanup(row)
                    else:
                        self._observe(row)
            except Exception:
                pass  # no capabilities or upstream payloads in gateway logs

    def _cleanup(self, row):
        # Stop attachment immediately; only acknowledge deletion after both
        # connection and persisted authenticated profile are verified absent.
        with self.service.lock_for(Path(row['home'])):
            slots = ('connection_id', 'request_id', 'flow_digest', 'flow_expires_at', 'binding', 'profile_name')
            with self.store.connection() as db:
                db.execute('BEGIN IMMEDIATE')
                current = db.execute('SELECT * FROM kernel_auth_flows WHERE key=?', (row['key'],)).fetchone()
                if not current or any(current[name] != row[name] for name in slots):
                    raise AccessError('This login generation changed before cleanup. Its profile was not deleted.', 409)
                if current['state'] == 'deleted':
                    return
                if current['state'] != row['state']:
                    raise AccessError('This login changed before cleanup. Its profile was not deleted.', 409)
                db.execute("UPDATE kernel_auth_flows SET state='cleanup_pending',updated=? WHERE key=?",
                    (self.store.clock(), row['key']))
                db.execute("UPDATE requests SET status='cancelled' WHERE id=? AND status IN ('waiting','saved')",
                    (row['request_id'],))
            if not row['connection_id']:
                raise AccessError('The unconfirmed Kernel connection requires reconciliation before cleanup.', 409)
            self.client.delete_connection(row['connection_id'])
            if row.get('principal_key'):
                self.principal_auth.terminal(row)
            else:
                self.client.delete_profile(row['profile_name'])
            with self.store.connection() as db:
                db.execute('BEGIN IMMEDIATE')
                current = db.execute('SELECT * FROM kernel_auth_flows WHERE key=?', (row['key'],)).fetchone()
                if (not current or current['state'] != 'cleanup_pending' or
                        any(current[name] != row[name] for name in slots)):
                    raise AccessError('This login changed during cleanup. Completion was not recorded.', 409)
                db.execute("UPDATE kernel_auth_flows SET state='deleted',updated=? WHERE key=?",
                    (self.store.clock(), row['key']))
                db.execute('DELETE FROM kernel_auth_bindings WHERE flow_key=?', (row['key'],))
                db.execute('DELETE FROM kernel_auth_principal_selections WHERE flow_key=?', (row['key'],))

    def release_context(self, team, requester, home, *, thread=None):
        """Stop a task without signing an owner out of their saved DM account."""
        home = str(Path(home).resolve(strict=True))
        self.service.validate_member(team, requester)
        with self.service.lock_for(Path(home)):
            with self.store.connection() as db:
                contexts = [tuple(row) for row in db.execute('SELECT team,requester,home,thread '
                    'FROM kernel_auth_bindings WHERE team=? AND requester=? AND home=? '
                    'AND (? IS NULL OR thread=?)', (team, requester, home, thread, thread))]
                originals = [dict(row) for row in db.execute('SELECT * FROM kernel_auth_flows WHERE '
                    'team=? AND requester=? AND home=? AND (? IS NULL OR thread=?) AND state!=?',
                    (team, requester, home, thread, thread, 'deleted'))]
            selected = [self._selection(context) for context in contexts]
            rows = {row['key']: row for row in originals + selected if row is not None}
            for row in rows.values():
                if row['state'] == 'authenticated' and (row.get('principal_key') or self._own_private_profile(row)):
                    remote = self._observe(row)
                    if remote.get('flow_status') == 'SUCCESS' and remote['status'] == 'AUTHENTICATED':
                        continue
                    with self.store.connection() as db:
                        current = db.execute('SELECT * FROM kernel_auth_flows WHERE key=?', (row['key'],)).fetchone()
                    slots = ('request_id', 'connection_id', 'profile_name', 'flow_digest', 'flow_expires_at', 'binding')
                    if not current or any(current[name] != row[name] for name in slots):
                        raise AccessError('The sign-in generation changed before task release.', 409)
                    row = dict(current)
                self._cleanup(row)
            with self.store.connection() as db:
                db.execute('DELETE FROM kernel_auth_bindings WHERE team=? AND requester=? AND home=? '
                    'AND (? IS NULL OR thread=?)', (team, requester, home, thread, thread))
                db.execute('DELETE FROM kernel_auth_principal_selections WHERE team=? AND requester=? AND home=? '
                    'AND (? IS NULL OR thread=?)', (team, requester, home, thread, thread))

    def cleanup_context(self, team, requester, home, *, thread=None):
        home = str(Path(home).resolve(strict=True))
        self.service.validate_member(team, requester)
        with self.service.lock_for(Path(home)):
            with self.store.connection() as db:
                contexts = [tuple(row) for row in db.execute('SELECT team,requester,home,thread '
                    'FROM kernel_auth_bindings WHERE team=? AND requester=? AND home=? '
                    'AND (? IS NULL OR thread=?)', (team, requester, home, thread, thread))]
                originals = [dict(row) for row in db.execute('SELECT * FROM kernel_auth_flows WHERE '
                    'team=? AND requester=? AND home=? AND (? IS NULL OR thread=?) AND state!=?',
                    (team, requester, home, thread, thread, 'deleted'))]
            selected = [self._selection(context) for context in contexts]
            rows = {row['key']: row for row in originals + selected if row is not None}
            for row in rows.values():
                if row.get('principal_key') and row['state'] == 'authenticated':
                    # Task cancellation closes its browser, not another task's
                    # durable account connection. Account removal is explicit.
                    continue
                self._cleanup(row)
            with self.store.connection() as db:
                db.execute('DELETE FROM kernel_auth_bindings WHERE team=? AND requester=? AND home=? '
                    'AND (? IS NULL OR thread=?)', (team, requester, home, thread, thread))
                db.execute('DELETE FROM kernel_auth_principal_selections WHERE team=? AND requester=? AND home=? '
                    'AND (? IS NULL OR thread=?)', (team, requester, home, thread, thread))

    def cleanup_home(self, home):
        home = str(Path(home).resolve(strict=True))
        with self.store.connection() as db:
            owners = db.execute('SELECT DISTINCT team,requester FROM kernel_auth_flows WHERE home=?', (home,)).fetchall()
        if len(owners) > 1:
            raise AccessError('This profile has conflicting requester ownership.', 403)
        for team, requester in owners:
            self.cleanup_context(team, requester, home)

    def remove_account(self, team, owner, handle):
        profiles = getattr(self.service.cloud_browser, 'profiles', None)
        if profiles is not None:
            # Disconnect cannot leave that account's cookies usable through a
            # multi-site profile. Quarantine pending verified site cleanup;
            # deleting one login must not erase every other site's state.
            profiles.invalidate_account(team, owner, handle)
        account = self.account(team, owner, handle)
        with self.store.connection() as db:
            rows = [dict(row) for row in db.execute('SELECT * FROM kernel_auth_flows WHERE '
                'team=? AND account_owner=? AND account_handle=? AND state!=?', (team, owner, handle, 'deleted'))]
        for row in rows:
            self._cleanup(row)
        if account and account['credential_name']:
            self.client.delete_credential(account['credential_name'])
        with self.store.connection() as db:
            db.execute('DELETE FROM kernel_auth_accounts WHERE team=? AND owner=? AND handle=?', (team, owner, handle))
