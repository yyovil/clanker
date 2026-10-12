"""Provision only explicitly reviewed missing profile identities at startup.

This creates empty provider profiles through the normal durable registry. It
does not create browsers, authenticate, copy cookies, change grants or delete
legacy state. Unknown create outcomes remain registry reservations.
"""
import hashlib
import json
import os
import secrets
import stat
import time

from vault.delegation import credential_binding
from vault.store import AccessError
from .profile_migration import manifest_digest


class ProfileProvisioning:
    def __init__(self, service):
        self.service = service
        self.profiles = service.cloud_browser.profiles

    @staticmethod
    def _schema(db):
        db.execute('''CREATE TABLE IF NOT EXISTS browser_profile_provisioning_receipts (
            manifest_sha256 TEXT PRIMARY KEY, team TEXT NOT NULL,
            profiles TEXT NOT NULL, completed REAL NOT NULL)''')

    def _registered(self, db, manifest, results):
        """Completion is historical setup evidence, never current use authority."""
        if not isinstance(results, list) or len(results) != len(manifest['targets']):
            raise AccessError('The completed provisioning receipt is invalid.', 409)
        for target, result in zip(manifest['targets'], results):
            if (not isinstance(result, dict) or set(result) != {'kind', 'principal_key', 'profile_name', 'profile_id'} or
                    any(result[k] != target[k] for k in ('kind', 'principal_key', 'profile_name')) or
                    not isinstance(result['profile_id'], str) or not result['profile_id']):
                raise AccessError('The completed provisioning identities changed.', 409)
            row = db.execute('SELECT * FROM browser_profile_principals WHERE key=?',
                             (result['principal_key'],)).fetchone()
            expected = {k: target[k] for k in ('kind', 'team', 'owner', 'account_handle', 'profile_name')}
            expected['profile_id'] = result['profile_id']
            if (not row or any(row[k] != v for k, v in expected.items()) or
                    row['state'] not in {'ready', 'quarantined'}):
                raise AccessError('The completed canonical profile identity changed.', 409)

    def _completed(self, manifest, reviewed):
        with self.service.store.connection() as db:
            self._schema(db)
            row = db.execute('SELECT * FROM browser_profile_provisioning_receipts WHERE manifest_sha256=?',
                             (reviewed,)).fetchone()
            if not row:
                return None
            if row['team'] != manifest.get('team') or row['team'] != self.service.policy.team:
                raise AccessError('The completed provisioning workspace changed.', 403)
            results = json.loads(row['profiles'])
            self._registered(db, manifest, results)
        # Identity-only GETs do not acquire a writer, create a profile or grant
        # access. Current grants, credential generation and leases belong to
        # normal per-request authorization, not this consumed setup manifest.
        for result in results:
            remote = self.service.cloud_browser.client.get_profile(result['profile_name'])
            if remote != {'id': result['profile_id'], 'name': result['profile_name']}:
                raise AccessError('The completed provider profile identity changed.', 409)
        with self.service.store.connection() as db:
            current = db.execute('SELECT * FROM browser_profile_provisioning_receipts WHERE manifest_sha256=?',
                                 (reviewed,)).fetchone()
            if not current or dict(current) != dict(row):
                raise AccessError('The provisioning receipt changed during validation.', 409)
            self._registered(db, manifest, results)
        return {'status': 'already_provisioned', 'manifest_sha256': reviewed, 'profiles': results}

    def _validate(self, manifest):
        from gateway.config import Platform
        from gateway.session import SessionSource
        from vault.service import Binding
        if (not isinstance(manifest, dict) or set(manifest) != {'version', 'team', 'targets'} or
                manifest['version'] != 1 or manifest['team'] != self.service.policy.team or
                not isinstance(manifest['targets'], list) or not 1 <= len(manifest['targets']) <= 4):
            raise AccessError('Use the exact reviewed profile-provisioning manifest.', 400)
        fields = {'kind', 'team', 'owner', 'account_handle', 'principal_key', 'profile_name',
                  'binding_sha256', 'authorized_requesters'}
        prepared, seen = [], set()
        for target in manifest['targets']:
            if (not isinstance(target, dict) or set(target) != fields or
                    target['kind'] not in {'personal', 'shared'} or target['team'] != manifest['team'] or
                    any(not isinstance(target[k], str) for k in fields - {'binding_sha256', 'authorized_requesters'}) or
                    not isinstance(target['authorized_requesters'], list) or
                    any(not isinstance(v, str) for v in target['authorized_requesters'])):
                raise AccessError('A reviewed profile target is invalid.', 400)
            team, owner, handle, kind = (target[k] for k in ('team', 'owner', 'account_handle', 'kind'))
            member = self.service.validate_member(team, owner)
            key = self.profiles._key(kind, team, owner, handle)
            if (key in seen or target['principal_key'] != key or
                    target['profile_name'] != 'clanker-' + kind + '-' + key[:40]):
                raise AccessError('The reviewed profile identity changed.', 403)
            seen.add(key)
            source = SessionSource(Platform.SLACK, member['dm_id'], chat_type='dm',
                user_id=owner, scope_id=team, profile=member['profile'])
            turn = Binding(self.service, source, 'operator-profile-provisioning', '',
                           self.service.private_home(team, owner))
            self.service.assert_private(turn)
            self.service.delegations.check_execution(turn)
            access, requesters = None, {owner}
            if kind == 'personal':
                if handle or target['binding_sha256'] is not None:
                    raise AccessError('A personal profile cannot adopt a credential scope.', 403)
            else:
                if not handle:
                    raise AccessError('A shared profile needs its exact saved credential.', 403)
                access = self.service.delegations.resolve(turn, handle)
                bound = credential_binding(access.meta)
                if (access.grant_id or access.owner != owner or access.meta.kind != 'login' or
                        hashlib.sha256(bound.encode()).hexdigest() != target['binding_sha256']):
                    raise AccessError('The shared profile credential changed.', 403)
                with self.service.store.connection() as db:
                    grants = db.execute('SELECT recipient,binding FROM credential_grants WHERE '
                        'team=? AND owner=? AND handle=? AND revoked IS NULL', (team, owner, handle)).fetchall()
                if not grants or any(row['binding'] != bound for row in grants):
                    raise AccessError('The shared profile invitations changed.', 403)
                requesters.update(row['recipient'] for row in grants)
            if target['authorized_requesters'] != sorted(requesters):
                raise AccessError('The reviewed profile membership changed.', 403)
            for requester in requesters:
                self.service.validate_member(team, requester)
            with self.service.store.connection() as db:
                if db.execute('SELECT 1 FROM browser_profile_leases WHERE principal_key=?', (key,)).fetchone():
                    raise AccessError('A live writer must finish before profile provisioning.', 409)
            prepared.append((target, turn, access))
        return prepared

    def apply(self, manifest, *, reviewed_sha256):
        if manifest_digest(manifest) != reviewed_sha256:
            raise AccessError('The provisioning manifest changed after review.', 403)
        completed = self._completed(manifest, reviewed_sha256)
        if completed is not None:
            return completed
        self._validate(manifest)  # Validate every target before the first POST.
        results = []
        for index in range(len(manifest['targets'])):
            target, turn, access = self._validate(manifest)[index]
            principal = self.profiles.resolve(turn, access)
            if principal['key'] != target['principal_key'] or principal['profile_name'] != target['profile_name']:
                raise AccessError('A different canonical profile already exists.', 409)
            remote = self.profiles.ensure_profile(principal, self.service.cloud_browser.client)
            self._validate(manifest)
            results.append(dict(kind=principal['kind'], principal_key=principal['key'],
                                profile_name=remote['name'], profile_id=remote['id']))
        with self.service.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            self._registered(db, manifest, results)
            db.execute('INSERT INTO browser_profile_provisioning_receipts VALUES (?,?,?,?)',
                (reviewed_sha256, manifest['team'], json.dumps(results, sort_keys=True), self.service.store.clock()))
        return {'status': 'provisioned', 'manifest_sha256': reviewed_sha256, 'profiles': results}


def apply_startup(service):
    path = service.policy.home / '.clanker-cloud' / 'profile-provisioning.json'
    if not path.exists():
        return None
    from gateway import status
    home = service.policy.home.resolve()
    if (not status.owns_gateway_runtime_lock() or status.live_gateway_pid_for_home(home) != os.getpid() or
            status._get_process_hermes_home().resolve() != home):
        raise AccessError('Only authoritative gateway startup may provision reviewed profiles.', 409)
    mode = path.stat().st_mode
    if (path.is_symlink() or path.parent.is_symlink() or not stat.S_ISREG(mode) or mode & 0o077 or
            path.stat().st_uid != os.getuid() or path.stat().st_size > 65536):
        raise AccessError('The provisioning manifest must be a protected ordinary file.', 403)
    digest = None
    try:
        staged = json.loads(path.read_text())
        if not isinstance(staged, dict) or set(staged) != {'manifest', 'reviewed_sha256'}:
            raise ValueError
        digest = manifest_digest(staged['manifest'])
        result = ProfileProvisioning(service).apply(staged['manifest'], reviewed_sha256=staged['reviewed_sha256'])
        _outcome(path.parent, result)
        return result
    except Exception:
        _outcome(path.parent, {'status': 'refused', 'manifest_sha256': digest,
            'error': 'Reviewed profile provisioning did not complete; Vault service remains unavailable.'})
        raise AccessError('Reviewed profile provisioning did not complete. Inspect its protected startup outcome.', 409) from None


def _outcome(directory, result):
    path = directory / 'profile-provisioning-outcome.json'
    if path.is_symlink():
        raise AccessError('The provisioning outcome destination is unsafe.', 403)
    temporary = directory / ('.profile-provisioning-' + secrets.token_hex(12))
    try:
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(dict(result, gateway_pid=os.getpid(), recorded_at=time.time()), stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
