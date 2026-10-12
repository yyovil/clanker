"""Managed Auth connections within durable, explicitly authorized browser identities.

Execution homes remain task-scoped. A persistent profile never authorizes a
caller: the current turn's own credential access and profile lease do that.
"""
import hashlib
import json

from .store import AccessError
from .delegation import credential_binding


class PreparedPrincipalAuth:
    """Dispatch after account discovery releases the execution-home lock."""
    def __init__(self, owner, turn, account, access, **options):
        self.owner, self.turn, self.account, self.access = owner, turn, account, access
        self.options = options

    def run(self):
        return self.owner.prepare(self.turn, self.account, self.access, **self.options)


class PrincipalAuth:
    def __init__(self, auth):
        self.auth, self.service, self.store = auth, auth.service, auth.store

    @property
    def profiles(self):
        return self.service.cloud_browser.profiles

    def principal(self, row):
        principal = self.profiles.get(row['principal_key'])
        if (not principal or principal['team'] != row['team'] or
                principal['owner'] != row['account_owner'] or
                principal['profile_name'] != row['profile_name'] or
                principal['kind'] == 'shared' and (
                    principal['account_handle'] != row['account_handle'] or
                    principal['origin'] != row['origin'] or principal['binding'] != row['binding'])):
            raise AccessError('The saved authentication profile identity changed.', 403)
        return principal

    def owner_access(self, row):
        self.principal(row)
        access = self.service.delegations.lookup(row['team'], row['account_owner'], row['account_handle'])
        if (access.grant_id or access.owner != row['account_owner'] or
                access.meta.origin != row['origin'] or credential_binding(access.meta) != row['binding']):
            raise AccessError('The saved authentication account changed.', 403)
        return access

    def caller_access(self, turn, row, handle=None):
        context = self.auth._context(turn)
        if handle is None:
            with self.store.connection() as db:
                selected = db.execute('SELECT handle FROM kernel_auth_principal_selections WHERE '
                    'team=? AND requester=? AND home=? AND thread=? AND flow_key=?',
                    (*context, row['key'])).fetchone()
            if not selected:
                raise AccessError('Select this saved account in the current task.', 403)
            handle = selected['handle']
        access = self.service.delegations.resolve(turn, handle)
        if (access.owner != row['account_owner'] or access.meta.id != row['account_handle'] or
                access.meta.origin != row['origin'] or credential_binding(access.meta) != row['binding']):
            raise AccessError('This task selected a different saved account.', 403)
        self.profiles.authorize(turn, self.principal(row), access)
        return access

    def bind(self, turn, row, access):
        context = self.auth._context(turn)
        self.caller_access(turn, row, access.handle)
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            current = db.execute('SELECT * FROM kernel_auth_flows WHERE key=?', (row['key'],)).fetchone()
            if not current or any(current[k] != row[k] for k in
                    ('principal_key', 'binding', 'request_id', 'connection_id', 'state', 'flow_digest', 'flow_expires_at')):
                raise AccessError('The sign-in generation changed before task selection.', 409)
            previous = db.execute('SELECT flow_key FROM kernel_auth_bindings WHERE '
                'team=? AND requester=? AND home=? AND thread=?', context).fetchone()
            if previous and previous['flow_key'] != row['key']:
                raise AccessError('Stop this task browser before selecting another account.', 409)
            db.execute('INSERT OR IGNORE INTO kernel_auth_bindings VALUES (?,?,?,?,?,?)',
                (*context, row['key'], self.store.clock()))
            db.execute('INSERT OR REPLACE INTO kernel_auth_principal_selections VALUES (?,?,?,?,?,?)',
                (*context, row['key'], access.handle))

    def reserve(self, turn, row):
        principal = self.principal(row)
        access = self.caller_access(turn, row, row.get('_caller_handle') or row['handle'])
        self.profiles.authorize(turn, principal, access)
        browser = self.service.cloud_browser
        # The browser integration drains only a verified idle writer belonging
        # to this task, never another live task or another requester.
        prepare = getattr(browser, 'prepare_authentication', None)
        lease = prepare(row, turn=turn) if prepare else None
        if lease is None:
            lease = self.profiles.acquire(turn, principal, 'auth:' + row['key'], kind='auth')
        self.save_lease(row, lease)
        return lease

    def save_lease(self, row, lease):
        with self.store.connection() as db:
            db.execute('UPDATE kernel_auth_flows SET auth_lease=? WHERE key=?',
                (json.dumps(lease, sort_keys=True), row['key']))
        row['auth_lease'] = json.dumps(lease, sort_keys=True)

    def dispatch(self, row):
        lease = self.lease(row)
        if not lease:
            raise AccessError('Authentication has no exclusive profile writer lease.', 409)
        if lease['state'] == 'reserved':
            lease = self.profiles.dispatched(lease)
            self.save_lease(row, lease)
            if row['connection_id']:
                lease = self.profiles.confirm(lease, row['connection_id'])
                self.save_lease(row, lease)
        elif lease['state'] != 'active' or lease['remote_id'] != row['connection_id']:
            raise AccessError('The authentication writer outcome is unconfirmed.', 409)
        return lease

    def lease(self, row):
        value = row.get('auth_lease')
        return json.loads(value) if value else None

    def terminal(self, row):
        lease = self.lease(row)
        if lease:
            self.profiles.release(lease, verified_closed=True)
            with self.store.connection() as db:
                db.execute('UPDATE kernel_auth_flows SET auth_lease=NULL WHERE key=? AND auth_lease=?',
                    (row['key'], row['auth_lease']))

    def abandon_unstarted(self, row):
        lease = self.lease(row)
        if lease:
            self.profiles.release(lease)
        with self.store.connection() as db:
            db.execute('DELETE FROM kernel_auth_bindings WHERE flow_key=?', (row['key'],))
            db.execute('DELETE FROM kernel_auth_principal_selections WHERE flow_key=?', (row['key'],))
            db.execute('DELETE FROM kernel_auth_flows WHERE key=? AND state=?', (row['key'], 'creating'))
            db.execute("UPDATE requests SET status='cancelled' WHERE id=?", (row['request_id'],))

    def prepare(self, turn, account, access, *, fresh_login=False, resend_link=False, reset_site=False, cancelled=None):
        auth = self.auth
        selected = auth._selection(auth._context(turn), turn=turn)
        if selected and (not selected.get('principal_key') or
                (selected['account_owner'], selected['account_handle'], selected['origin'], selected['binding']) !=
                (access.owner, access.meta.id, access.meta.origin, credential_binding(access.meta))):
            raise AccessError('Close or reconcile this task browser before selecting another authentication profile.', 409)
        principal = self.profiles.select(turn, access)
        self.profiles.authorize(turn, principal, access)
        policy = getattr(self.service.cloud_browser.client, 'proxy_policy', None)
        proxy = policy['id'] if policy else None
        binding = credential_binding(access.meta)
        with self.store.connection() as db:
            rows = [dict(r) for r in db.execute('SELECT * FROM kernel_auth_flows WHERE '
                'principal_key=? AND account_owner=? AND account_handle=? AND state!=?',
                (principal['key'], access.owner, access.meta.id, 'deleted'))]
        if len(rows) > 1:
            raise AccessError('This saved account has ambiguous authentication generations.', 409)
        row = rows[0] if rows else None
        if row:
            self.caller_access(turn, row, access.handle)
            if row['proxy_id'] != proxy:
                raise AccessError('This authentication uses a different proxy policy.', 403)
            if row['state'] in {'creating', 'create_unknown', 'starting', 'login_unknown', 'cleanup_pending'}:
                raise AccessError('The login dispatch is unconfirmed. It will not be repeated automatically.', 409)
            previous_request = auth._request_row(row)
            ended_request = row['state'] != 'authenticated' and (
                previous_request['status'] not in {'waiting', 'saved', 'resumed'} or
                previous_request['expires'] <= self.store.clock())
            if ended_request:
                # An ended request never adopts a late success. The current
                # authorized owner may renew only after the old writer ended.
                remote = auth._remote(row)
                if remote.get('flow_status') not in {'SUCCESS', 'FAILED', 'EXPIRED', 'CANCELED'}:
                    raise AccessError('The old sign-in writer has not ended. Do not start another login.', 409)
                self.terminal(row)
            else:
                remote = auth._observe(row)
            with self.store.connection() as db:
                row = dict(db.execute('SELECT * FROM kernel_auth_flows WHERE key=?', (row['key'],)).fetchone())
            same_task = (row['requester'] == turn.source.user_id and
                row['home'] == str(turn.home.resolve()) and row['thread'] == self.service.cloud_browser.thread(turn))
            same_event = same_task and row['event_id'] == turn.message_id
            if not ended_request and row['state'] == 'authenticated' and (not fresh_login or same_event):
                self.bind(turn, row, access)
                return auth._authenticated_response(access.handle, reused=True)
            if not ended_request and row['state'] == 'pending':
                if not same_task:
                    raise AccessError('This saved browser identity is waiting for another sign-in task.', 409)
                self.bind(turn, row, access)
                return auth._request_row(row), access
            if resend_link:
                raise AccessError('This login ended. A new owner request is required.', 409)
            if fresh_login:
                from cloud_browser.site_reset import reset_requested
                current_intent = reset_requested(auth, turn, access.meta.origin) if reset_site else auth._fresh_login_request(turn)
                if (not current_intent or same_event or access.grant_id or
                        access.owner != turn.source.user_id or
                        tuple(map(int, turn.message_id.split('.'))) <= tuple(map(int, row['event_id'].split('.')))):
                    raise AccessError('Fresh sign-in requires a new explicit request from the account owner.', 409)
            else:
                auth._retry(turn, row)
            # Keep the same connection/profile; only a new explicitly authorized
            # provider generation may replace the previous completed attempt.
            lease_row = dict(row, _caller_handle=access.handle)
            if reset_site:
                auth._check_dispatch(cancelled)
                from cloud_browser.site_reset import reset_for_auth
                lease = reset_for_auth(auth, turn, lease_row, access)
                self.save_lease(lease_row, lease)
            else:
                lease = self.reserve(turn, lease_row)
            try:
                auth._check_dispatch(cancelled)
            except AccessError:
                # No new request or provider operation exists yet; preserve the
                # previous successful generation and release only this nonce.
                self.profiles.release(lease)
                with self.store.connection() as db:
                    db.execute('UPDATE kernel_auth_flows SET auth_lease=NULL WHERE key=? AND auth_lease=?',
                        (row['key'], lease_row['auth_lease']))
                raise
            request = auth._request(turn, account, access)
            with self.store.connection() as db:
                db.execute('BEGIN IMMEDIATE')
                current = db.execute('SELECT * FROM kernel_auth_flows WHERE key=?', (row['key'],)).fetchone()
                if not current or any(current[k] != row[k] for k in
                        ('request_id', 'connection_id', 'state', 'flow_digest', 'flow_expires_at', 'event_id')):
                    raise AccessError('The login generation changed before renewal.', 409)
                db.execute('UPDATE kernel_auth_flows SET requester=?,home=?,thread=?,handle=?,request_id=?, '
                    'state=?,event_id=?,auth_lease=?,updated=? WHERE key=?',
                    (turn.source.user_id, str(turn.home.resolve()), self.service.cloud_browser.thread(turn),
                     access.handle, request['id'], 'starting', turn.message_id, lease_row['auth_lease'],
                     self.store.clock(), row['key']))
            row.update(requester=turn.source.user_id, home=str(turn.home.resolve()),
                thread=self.service.cloud_browser.thread(turn), handle=access.handle, request_id=request['id'],
                state='starting', event_id=turn.message_id, auth_lease=lease_row['auth_lease'])
            self.bind(turn, row, access)
            auth._start(row, cancelled=cancelled)
            return request, access
        if reset_site:
            raise AccessError('Site reset requires an existing saved Managed Auth connection.', 409)
        if resend_link:
            raise AccessError('There is no pending sign-in link to resend.', 409)
        key = hashlib.sha256(json.dumps((principal['key'], access.owner, access.meta.id,
            access.meta.origin, binding, proxy, turn.message_id)).encode()).hexdigest()
        now = self.store.clock()
        request = auth._request(turn, account, access)
        row = dict(key=key, team=turn.source.scope_id, requester=turn.source.user_id,
            home=str(turn.home.resolve()), thread=self.service.cloud_browser.thread(turn),
            account_owner=access.owner, account_handle=access.meta.id, handle=access.handle,
            binding=binding, origin=access.meta.origin, profile_name=principal['profile_name'],
            connection_id=None, request_id=request['id'], state='creating', event_id=turn.message_id,
            proxy_id=proxy, created=now, updated=now, flow_expires_at=None, flow_digest=None,
            principal_key=principal['key'], auth_lease=None)
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            previous = db.execute('SELECT state FROM kernel_auth_flows WHERE key=?', (key,)).fetchone()
            if previous:
                raise AccessError('This authentication generation requires explicit reconciliation.', 409)
            db.execute('INSERT INTO kernel_auth_flows (' + ','.join(row) + ') VALUES (' +
                ','.join('?' for _ in row) + ')', tuple(row.values()))
        self.bind(turn, row, access)
        try:
            self.reserve(turn, row)
        except Exception:
            # No provider operation was attempted. A busy identity must not
            # manufacture an unknown remote generation or strand a login card.
            self.abandon_unstarted(row)
            raise
        try:
            auth._check_dispatch(cancelled)
            from urllib.parse import urlsplit
            from .managed_auth import _allowed_domains
            self.profiles.ensure_profile(principal, self.service.cloud_browser.client)
            lease = self.profiles.dispatched(self.lease(row))
            self.save_lease(row, lease)
            remote = auth.client.create_connection(urlsplit(row['origin']).hostname, row['profile_name'],
                login_url=row['origin'], proxy_id=proxy, credential_name=account['credential_name'],
                allowed_domains=_allowed_domains(row['origin']), health_checks=False, auto_reauth=False)
            if not auth._connection_matches(row, remote):
                raise AccessError('Kernel returned another authentication identity.', 403)
            auth._check_dispatch(cancelled)
            auth._update(key, connection_id=remote['id'], state='starting')
            row.update(connection_id=remote['id'], state='starting')
            lease = self.profiles.confirm(lease, remote['id'])
            self.save_lease(row, lease)
            auth._start(row, cancelled=cancelled)
        except Exception as error:
            if row['connection_id'] is None and (self.lease(row) or {}).get('state') == 'reserved':
                # Profile creation is separately reconciled by the registry.
                # No auth connection or login has been dispatched yet.
                self.abandon_unstarted(row)
                raise
            auth._update(key, state='create_unknown' if row['connection_id'] is None else 'login_unknown')
            raise auth._dispatch_error('Kernel sign-in creation could not be confirmed. It will not be repeated automatically.', error) from None
        return request, access
