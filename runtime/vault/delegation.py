"""Owner-created credential invitations. Models receive handles, never secrets.

An invitation grants credential use, not ownership, onward sharing or purchase
approval. Shared credentials use an isolated Kernel vault. Usage is
recorded before browser handoff so revoked cookies cannot be silently reused.
"""
from dataclasses import dataclass
import json
import secrets
from pathlib import Path
from urllib.parse import urlsplit

from .store import AccessError


def credential_binding(meta):
    bound = {k: meta.to_dict().get(k) for k in ('kind', 'origin', 'identifier', 'created_at')}
    if meta.login_method=='sms':bound['login_method']='sms'
    return json.dumps(bound, sort_keys=True)


def invitation_origin(meta):
    parsed = urlsplit(meta.origin or '')
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.port not in (None, 443):
        raise AccessError('Invitations require a credential bound to an exact HTTPS origin.', 403)


@dataclass(frozen=True)
class CredentialAccess:
    meta: object
    home: Path
    owner: str
    handle: str
    grant_id: str | None = None

    def public(self):
        result = self.meta.to_dict() | {'id': self.handle}
        if self.grant_id:
            result.update(access='invited', shared_by=self.owner,
                          owner_approval_required=self.meta.kind == 'payment')
        return result

    def secret(self):
        raise AccessError('Kernel credentials are opaque and cannot be resolved locally.', 403)


class Delegations:
    def __init__(self, service):
        self.service = service
        with self.store.connection() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS credential_grants (
                  id TEXT PRIMARY KEY, team TEXT NOT NULL, owner TEXT NOT NULL,
                  recipient TEXT NOT NULL, handle TEXT NOT NULL, binding TEXT NOT NULL,
                  created REAL NOT NULL, revoked REAL);
                CREATE UNIQUE INDEX IF NOT EXISTS credential_grant_active
                  ON credential_grants(team,owner,recipient,handle) WHERE revoked IS NULL;
                CREATE TABLE IF NOT EXISTS credential_grant_usage (
                  grant_id TEXT NOT NULL, team TEXT NOT NULL, recipient TEXT NOT NULL,
                  home TEXT NOT NULL, source TEXT NOT NULL,
                  PRIMARY KEY(grant_id,team,recipient,home));
                CREATE TABLE IF NOT EXISTS browser_session_owners (
                  provider TEXT NOT NULL, session_id TEXT NOT NULL,
                  team TEXT NOT NULL, requester TEXT NOT NULL, context TEXT NOT NULL,
                  PRIMARY KEY(provider,session_id));
            ''')
            # Older installations recorded only the latest guest home. Preserve
            # that marker while allowing every new task context to be retained.
            primary = [row['name'] for row in sorted(db.execute('PRAGMA table_info(credential_grant_usage)'),
                                                    key=lambda row: row['pk']) if row['pk']]
            if primary != ['grant_id', 'team', 'recipient', 'home']:
                db.executescript('''
                    BEGIN IMMEDIATE;
                    ALTER TABLE credential_grant_usage RENAME TO credential_grant_usage_legacy;
                    CREATE TABLE credential_grant_usage (
                      grant_id TEXT NOT NULL, team TEXT NOT NULL, recipient TEXT NOT NULL,
                      home TEXT NOT NULL, source TEXT NOT NULL,
                      PRIMARY KEY(grant_id,team,recipient,home));
                    INSERT INTO credential_grant_usage SELECT * FROM credential_grant_usage_legacy;
                    DROP TABLE credential_grant_usage_legacy;
                    COMMIT;
                ''')

    @property
    def store(self):
        return self.service.store

    def own_meta(self, team, owner, handle):
        home = self.service.private_home(team, owner)
        if not isinstance(handle, str):
            raise AccessError('Choose one of your saved credentials.', 403)
        meta = self.service.credential_store(team, owner).get_meta(handle)
        if meta is None or meta.kind not in ('login', 'api_key', 'payment'):
            raise AccessError('This credential does not belong to your vault.', 403)
        return home, meta

    def lookup(self, team, requester, handle):
        home = self.service.private_home(team, requester)
        if not isinstance(handle, str) or len(handle) > 100:
            raise AccessError('Choose a saved or invited credential.', 403)
        meta = self.service.credential_store(team, requester).get_meta(handle)
        if meta is not None:
            return CredentialAccess(meta, home, requester, handle)
        with self.store.connection() as db:
            row = db.execute('SELECT * FROM credential_grants WHERE id=? AND team=? AND recipient=? AND revoked IS NULL',
                             (handle, team, requester)).fetchone()
        if not row:
            raise AccessError('This credential is not available to your Slack account.', 403)
        owner_home = self.service.private_home(team, row['owner'])
        meta = self.service.credential_store(team, row['owner']).get_meta(row['handle'])
        if meta is None or credential_binding(meta) != row['binding']:
            raise AccessError('The invited credential was removed or changed. Ask its owner for a new invitation.', 403)
        return CredentialAccess(meta, owner_home, row['owner'], row['id'], row['id'])

    def resolve(self, turn, handle):
        self.service.assert_private(turn)
        return self.lookup(turn.source.scope_id, turn.source.user_id, handle)

    def items(self, team, requester):
        home = self.service.private_home(team, requester)
        items = [meta.to_dict() for meta in self.service.credential_store(team, requester).list_items()]
        with self.store.connection() as db:
            handles = [row[0] for row in db.execute(
                'SELECT id FROM credential_grants WHERE team=? AND recipient=? AND revoked IS NULL ORDER BY created DESC',
                (team, requester))]
        for handle in handles:
            try:
                items.append(self.lookup(team, requester, handle).public())
            except AccessError:
                continue
        return items

    def invite(self, identity, handle, recipient):
        team, owner = identity['team'], identity['owner']
        home, meta = self.own_meta(team, owner, handle)
        if not isinstance(recipient, str) or recipient == owner:
            raise AccessError('Choose another current Slack member.')
        self.service.validate_member(team, recipient)
        invitation_origin(meta)
        self._shareable(team, owner, home, handle)
        with self.service.lock_for(home), self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            # Recheck while holding the same owner lock as disconnect and fills.
            _, current = self.own_meta(team, owner, handle)
            row = db.execute('SELECT * FROM credential_grants WHERE team=? AND owner=? AND recipient=? AND handle=? AND revoked IS NULL',
                             (team, owner, recipient, handle)).fetchone()
            if row and row['binding'] == credential_binding(current):
                return dict(row)
            if row:
                raise AccessError('Revoke the previous invitation before inviting this changed credential.', 409)
            grant_id = 'grant_' + secrets.token_hex(16)
            db.execute('INSERT INTO credential_grants VALUES (?,?,?,?,?,?,?,NULL)',
                       (grant_id, team, owner, recipient, handle, credential_binding(current), self.store.clock()))
            return dict(db.execute('SELECT * FROM credential_grants WHERE id=?', (grant_id,)).fetchone())

    def set_access(self, identity, recipient, handles):
        """Save one member's complete selection atomically; future items stay private."""
        team, owner = identity['team'], identity['owner']
        home = self.service.private_home(team, owner)
        if not isinstance(recipient, str) or recipient == owner:
            raise AccessError('Choose another Slack member.')
        if (not isinstance(handles, list) or len(handles) > 100 or
                any(not isinstance(handle, str) or len(handle) > 100 for handle in handles) or
                len(set(handles)) != len(handles)):
            raise AccessError('Select the credentials to share.')
        if handles:
            self.service.validate_member(team, recipient)
        with self.service.lock_for(home), self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            # Validate the entire selection before writing any permission.
            selected = {}
            for handle in handles:
                _, meta = self.own_meta(team, owner, handle)
                invitation_origin(meta)
                self._shareable(team, owner, home, handle)
                selected[handle] = credential_binding(meta)
            previous = [dict(row) for row in db.execute(
                'SELECT * FROM credential_grants WHERE team=? AND owner=? AND recipient=?',
                (team, owner, recipient))]
            if not handles and not previous:
                raise AccessError('This member has no access to your vault.', 403)
            retained, revoked = {}, []
            for row in previous:
                if row['revoked'] is None:
                    if selected.get(row['handle']) == row['binding']:
                        retained[row['handle']] = row
                    else:
                        db.execute('UPDATE credential_grants SET revoked=? WHERE id=?', (self.store.clock(), row['id']))
                        db.execute("UPDATE requests SET status='cancelled',code_payload=NULL,payment_payload=NULL WHERE grant_id=? AND status IN ('waiting','saved','resumed')", (row['id'],))
                        revoked.append(row['id'])
                elif db.execute('SELECT 1 FROM credential_grant_usage WHERE grant_id=?', (row['id'],)).fetchone():
                    revoked.append(row['id'])
            result, added = [], []
            for handle in handles:
                if handle in retained:
                    row = retained[handle]
                else:
                    grant_id = 'grant_' + secrets.token_hex(16)
                    db.execute('INSERT INTO credential_grants VALUES (?,?,?,?,?,?,?,NULL)',
                        (grant_id, team, owner, recipient, handle, selected[handle], self.store.clock()))
                    row = dict(db.execute('SELECT * FROM credential_grants WHERE id=?', (grant_id,)).fetchone())
                    added.append(grant_id)
                result.append(row)
            return {'grants': result, 'revoked': revoked, 'added': added}

    def _shareable(self, team, owner, home, handle):
        managed = getattr(self.service, 'kernel_auth', None)
        account = managed.account(team, owner, handle) if managed else None
        if account and account['credential_name']:
            return  # recipients receive a separate task profile, never this owner's cookies
        kernel = getattr(self.service, 'kernel_vault', None)
        if kernel is None or not kernel.metadata.credential_vault(team, owner, home, handle):
            raise AccessError('This credential needs its own isolated Kernel vault before it can be shared. Its owner vault cannot be attached to another member\'s browser.', 409)

    def invitations(self, identity, handle=None):
        home = self.service.private_home(identity['team'],identity['owner'])
        if handle is not None:
            self.own_meta(identity['team'], identity['owner'], handle)
        with self.store.connection() as db:
            rows = [dict(row) for row in db.execute('''
                SELECT g.*, EXISTS(SELECT 1 FROM credential_grant_usage u WHERE u.grant_id=g.id) AS used
                FROM credential_grants g WHERE team=? AND owner=? AND (? IS NULL OR handle=?)
                AND (revoked IS NULL OR EXISTS(SELECT 1 FROM credential_grant_usage u WHERE u.grant_id=g.id)) ORDER BY created''',
                (identity['team'], identity['owner'], handle, handle))]
        result = []
        for row in rows:
            meta=self.service.credential_store(identity['team'],identity['owner']).get_meta(row['handle'])
            result.append({k:row[k] for k in ('id','recipient','created','revoked')} | {
                'handle':row['handle'],
                'credential':meta.label if meta else 'Removed credential · '+json.loads(row['binding'])['origin'],
                'cleanup_pending':row['revoked'] is not None and bool(row['used'])})
        return result

    def revoke(self, identity, grant_id):
        self.service.validate_member(identity['team'], identity['owner'])
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM credential_grants WHERE id=? AND team=? AND owner=?',
                             (grant_id, identity['team'], identity['owner'])).fetchone()
            if not row:
                raise AccessError('This invitation does not belong to your vault.', 403)
            db.execute('UPDATE credential_grants SET revoked=COALESCE(revoked,?) WHERE id=?',
                       (self.store.clock(), grant_id))
            db.execute("UPDATE requests SET status='cancelled',code_payload=NULL,payment_payload=NULL WHERE grant_id=? AND status IN ('waiting','saved','resumed')",
                       (grant_id,))
            return dict(row)

    def record_browser_use(self, turn, access):
        if not access.grant_id:
            return
        # Record before any secret-bearing browser I/O, including uncertain I/O.
        self.resolve(turn, access.handle)
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            active = db.execute('SELECT binding FROM credential_grants WHERE id=? AND team=? AND recipient=? AND revoked IS NULL',
                                (access.grant_id, turn.source.scope_id, turn.source.user_id)).fetchone()
            if not active or active['binding'] != credential_binding(access.meta):
                raise AccessError('The invitation was revoked or changed before browser access.', 403)
            db.execute('INSERT OR REPLACE INTO credential_grant_usage VALUES (?,?,?,?,?)',
                       (access.grant_id, turn.source.scope_id, turn.source.user_id,
                        str(turn.home.resolve()), json.dumps(turn.source.to_dict())))

    def check_execution(self, turn):
        with self.store.connection() as db:
            handles = [row[0] for row in db.execute(
                'SELECT DISTINCT grant_id FROM credential_grant_usage WHERE team=? AND recipient=?',
                (turn.source.scope_id, turn.source.user_id))]
        for handle in handles:
            try:
                self.lookup(turn.source.scope_id, turn.source.user_id, handle)
            except AccessError:
                raise AccessError('Invited access was revoked or changed. Browser cleanup must finish before this account context can run again.', 403) from None

    def request_access(self, row):
        if not row.get('grant_id'):
            return None
        access = self.lookup(row['team'], row['owner'], row['grant_id'])
        if (row['handle'] != access.handle or row.get('approver') != access.owner or
                row['origin'] != access.meta.origin):
            raise AccessError('The delegated approval does not match this credential.', 403)
        return access

    def fill_local(self, turn, access, *, code=None):
        raise AccessError('Local credential filling was removed. Use Kernel Vault fill.', 403)
