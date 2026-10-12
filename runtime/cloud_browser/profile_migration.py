"""Checked, metadata-only adoption of explicitly reviewed legacy profiles.

No cookie export, browser mutation, login, profile creation or deletion belongs
here. Runtime activation calls this before publishing its Vault service, while
the gateway's exclusive process lock excludes the previous runtime.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time

from vault.store import AccessError


def manifest_digest(manifest):
    return hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def validate_manifest(manifest):
    if (not isinstance(manifest, dict) or set(manifest) not in ({'version', 'team', 'candidates'},
            {'version', 'team', 'candidates', 'browser_exclusions'}) or
            manifest['version'] != 1 or not isinstance(manifest['team'], str) or
            not isinstance(manifest['candidates'], list) or not 1 <= len(manifest['candidates']) <= 3):
        raise AccessError('Use an exact reviewed personal-profile adoption manifest.', 400)
    fields = {'team', 'owner', 'principal_key', 'profile_id', 'profile_name', 'flow_key',
        'connection_id', 'account_handle', 'origin', 'binding_sha256', 'proxy_id', 'allowed_domains'}
    for candidate in manifest['candidates']:
        if (not isinstance(candidate, dict) or set(candidate) != fields or
                candidate['team'] != manifest['team'] or
                any(not isinstance(candidate[k], str) or not candidate[k] for k in fields - {'proxy_id', 'allowed_domains'}) or
                not isinstance(candidate['allowed_domains'], list) or not candidate['allowed_domains'] or
                any(not isinstance(domain, str) or not domain for domain in candidate['allowed_domains']) or
                candidate['proxy_id'] is not None and not isinstance(candidate['proxy_id'], str)):
            raise AccessError('The reviewed adoption candidate is incomplete.', 400)
        for field in ('principal_key', 'flow_key', 'binding_sha256'):
            if not re.fullmatch('[0-9a-f]{64}', candidate[field]):
                raise AccessError('The reviewed adoption fingerprint is invalid.', 400)
    for field in ('owner', 'principal_key', 'profile_id', 'profile_name', 'flow_key', 'connection_id'):
        if len({candidate[field] for candidate in manifest['candidates']}) != len(manifest['candidates']):
            raise AccessError('Adoption candidates overlap or are ambiguous.', 409)
    exclusions = manifest.get('browser_exclusions', [])
    if not isinstance(exclusions, list) or len(exclusions) > 8:
        raise AccessError('Use exact reviewed historical browser exclusions.', 400)
    seen = set()
    for entry in exclusions:
        fields = {'kind', 'context_key', 'context_sha256', 'session_key', 'entry_sha256', 'provenance_sha256'}
        if (not isinstance(entry, dict) or set(entry) != fields or
                entry['kind'] not in {'historical_anonymous_create', 'verified_deleted_browser'} or
                any(not isinstance(entry[k], str) or re.fullmatch('[0-9a-f]{64}', entry[k]) is None
                    for k in fields - {'kind', 'session_key'}) or
                not isinstance(entry['session_key'], str) or re.fullmatch('[0-9a-f]{24}', entry['session_key']) is None or
                (entry['context_key'], entry['session_key']) in seen):
            raise AccessError('A historical browser exclusion is incomplete or ambiguous.', 400)
        seen.add((entry['context_key'], entry['session_key']))
    return manifest


def active_browsers(client):
    """An empty authenticated first page proves no active provider browsers."""
    from .kernel_client import API_URL
    try:
        response = client._request('GET', API_URL + '/browsers',
            params={'status': 'active', 'limit': 1, 'offset': 0},
            headers={'Authorization': 'Bearer ' + client.key()}, timeout=15, allow_redirects=False)
        if response.status_code != 200 or response.json() != []:
            raise ValueError
    except Exception:
        raise AccessError('Profile adoption requires a verified empty active-browser inventory.', 409) from None
    return []


class ProfileMigration:
    def __init__(self, service, *, active_browsers=None, before_commit=None):
        self.service, self.store = service, service.store
        self.cloud, self.auth = service.cloud_browser, service.kernel_auth
        self.active_browsers = active_browsers or (lambda: globals()['active_browsers'](self.cloud.client))
        self.before_commit = before_commit
        self.phase = 'validation'

    def _turn(self, candidate):
        # Trusted operator metadata selects an owner for validation only. This
        # Binding is never dispatched, registered as a task or used to transfer
        # a browser, approval, Slack message or execution claim.
        from gateway.config import Platform
        from gateway.session import SessionSource
        from vault.service import Binding
        member = self.service.validate_member(candidate['team'], candidate['owner'])
        source = SessionSource(Platform.SLACK, member['dm_id'], chat_type='dm',
            user_id=candidate['owner'], scope_id=candidate['team'], profile=member['profile'])
        turn = Binding(self.service, source, 'operator-profile-adoption', '',
            self.service.private_home(candidate['team'], candidate['owner']))
        self.service.assert_private(turn)
        return turn

    def _files(self, manifest):
        files, used = [], set()
        for path in sorted((self.cloud.directory / 'kernel' / 'contexts').glob('*.json')):
            if path.is_symlink():
                raise AccessError('Profile provenance cannot use a symlink.', 403)
            raw = path.read_bytes()
            try:
                state = json.loads(raw)
                owner = state['owner']
                for candidate in manifest['candidates']:
                    entries = (list(state.get('sessions', {}).items()) + list(state.get('task_profiles', {}).items()) +
                               list(state.get('legacy_profiles', {}).items()))
                    for name, entry in entries:
                        if (owner == {'team': candidate['team'], 'requester': candidate['owner']} and
                                (entry.get('dispatch_unknown') or entry.get('cleanup_pending'))):
                            if not self._reviewed_browser_exclusion(path, raw, state, name, entry, manifest):
                                raise AccessError('An owner browser operation must be reconciled before adoption.', 409)
                            used.add((path.stem, name))
                        names = [entry.get('name'), (entry.get('profile_binding') or {}).get('profile_name'),
                                 (entry.get('task_profile') or {}).get('name')]
                        if candidate['profile_name'] in names:
                            if owner != {'team': candidate['team'], 'requester': candidate['owner']}:
                                raise AccessError('Legacy browser provenance names another owner.', 403)
                            if entry.get('dispatch_unknown') or entry.get('cleanup_pending') or entry.get('pending'):
                                raise AccessError('The legacy browser has an unconfirmed operation.', 409)
                files.append((str(path), hashlib.sha256(raw).hexdigest()))
            except (TypeError, KeyError, ValueError):
                raise AccessError('Legacy browser provenance cannot be verified.', 409) from None
        if used != {(e['context_key'], e['session_key']) for e in manifest.get('browser_exclusions', [])}:
            raise AccessError('A reviewed historical browser exclusion no longer matches.', 409)
        return files

    def _reviewed_browser_exclusion(self, path, raw, state, name, entry, manifest):
        # Only an explicitly reviewed manifest can attest the historical
        # anonymous-only implementation. A sparse marker alone proves nothing.
        reviewed = next((e for e in manifest.get('browser_exclusions', [])
            if (e['context_key'], e['session_key']) == (path.stem, name)), None)
        owner, home = state['owner'], entry.get('home')
        if (not reviewed or reviewed['context_sha256'] != hashlib.sha256(raw).hexdigest() or
                reviewed['entry_sha256'] != manifest_digest(entry) or not isinstance(home, str) or
                not Path(home).is_absolute() or
                hashlib.sha256(('v2:' + owner['team'] + ':' + owner['requester'] + ':' + home).encode()).hexdigest() != path.stem or
                state.get('sessions', {}).get(name) != entry or state.get('task_profiles', {}).get(name) or
                state.get('legacy_profiles', {}).get(name)):
            return False
        threads = [thread for thread, selected in state['threads'].items() if selected == name]
        if len(threads) != 1 or hashlib.sha256(threads[0].encode()).hexdigest()[:24] != name:
            return False
        context = owner['team'], owner['requester'], home, threads[0]
        with self.store.connection() as db:
            if reviewed['kind'] == 'historical_anonymous_create':
                if (set(entry) != {'dispatch_unknown', 'home'} or entry['dispatch_unknown'] is not True or
                        db.execute('SELECT 1 FROM kernel_auth_flows WHERE team=? AND requester=? AND home=? AND thread=?', context).fetchone() or
                        db.execute('SELECT 1 FROM kernel_auth_bindings WHERE team=? AND requester=? AND home=? AND thread=?', context).fetchone()):
                    return False
                return True  # Preserve the unresolved anonymous operation.
            if (entry.get('cleanup_pending') is not True or entry.get('dispatch_unknown') or
                    entry.get('profile_binding') is not None or entry.get('task_profile') is not None or
                    entry.get('profile_principal') or entry.get('profile_lease') or
                    not isinstance(entry.get('session_id'), str) or not entry['session_id']):
                return False
            claim = db.execute('SELECT team,requester,context FROM browser_session_owners WHERE provider=? AND session_id=?',
                ('KernelBrowser', entry['session_id'])).fetchone()
            if not claim or tuple(claim) != (*context[:2], path.stem):
                return False
        # GET only. Provider-confirmed absence never clears the stored marker.
        return self.cloud.client.get_session(entry['session_id']) is None

    def _separate_legacy_unknown(self, db, row, manifest):
        """Prove an unresolved create targets another profile, without resolving it.

        Expiry excludes a current human interaction, not a provider effect. This
        exception never changes or cancels the unknown operation. Retaining its
        complete provenance in the caller's CAS closes changes during GETs.
        """
        if (row['state'] != 'create_unknown' or row['connection_id'] is not None or
                row['principal_key'] is not None or row['auth_lease'] is not None or
                row['account_owner'] != row['requester'] or row['handle'] != row['account_handle'] or
                any(row['profile_name'] == c['profile_name'] or row['account_handle'] == c['account_handle']
                    for c in manifest['candidates'])):
            return None
        identity = tuple(row[k] for k in ('team', 'requester', 'home', 'thread', 'handle', 'binding', 'proxy_id'))
        key = hashlib.sha256(json.dumps(identity).encode()).hexdigest()
        if row['key'] != key or row['profile_name'] != 'clanker-auth-' + key[:40]:
            return None
        request = db.execute('SELECT * FROM requests WHERE id=?', (row['request_id'],)).fetchone()
        member = self.service.validate_member(row['team'], row['requester'])
        private_home = str(self.service.private_home(row['team'], row['requester']))
        if (not request or request['status'] != 'waiting' or request['expires'] > self.store.clock() or
                request['resume_delivered'] is not None or request['grant_id'] is not None or
                request['kind'] != 'login' or
                (request['team'], request['owner'], request['home'], request['handle'], request['origin']) !=
                (row['team'], row['requester'], private_home, row['account_handle'], row['origin'])):
            return None
        try:
            source = json.loads(request['source'])
            if (not isinstance(source, dict) or
                    (source.get('platform'), source.get('scope_id'), source.get('user_id'), source.get('chat_id'), source.get('chat_type')) !=
                    ('slack', row['team'], row['requester'], member['dm_id'], 'dm') or
                    not isinstance(source.get('thread_id'), str) or not source['thread_id'] or
                    row['thread'] != source['chat_id'] + ':' + source['thread_id']):
                return None
            transfer = None
            if row['home'] == private_home:
                if source.get('profile') != member['profile']:
                    return None
            else:
                profile = source.get('profile')
                if (not isinstance(profile, str) or not re.fullmatch(r'task-[A-Za-z0-9-]+', profile) or
                        row['home'] != str(self.service.policy.home / 'profiles' / profile)):
                    return None
                transfer = db.execute("SELECT * FROM transfers WHERE id=? AND reply_mode='channel'", (profile[5:],)).fetchone()
                if (not transfer or (transfer['team'], transfer['owner'], transfer['home']) !=
                        (row['team'], row['requester'], private_home)):
                    return None
                saved, original = json.loads(transfer['source']), json.loads(transfer['original_source'])
                fields = ('platform', 'scope_id', 'user_id', 'chat_id', 'chat_type', 'thread_id', 'profile')
                if (not isinstance(saved, dict) or not isinstance(original, dict) or
                        any(saved.get(k) != source.get(k) for k in fields) or
                        (original.get('platform'), original.get('scope_id'), original.get('user_id')) !=
                        ('slack', row['team'], row['requester'])):
                    return None
        except (TypeError, ValueError):
            return None
        bindings = [dict(r) for r in db.execute('SELECT * FROM kernel_auth_bindings WHERE flow_key=?', (row['key'],))]
        context = identity[:4]
        if (len(bindings) != 1 or tuple(bindings[0][k] for k in ('team', 'requester', 'home', 'thread')) != context or
                db.execute('SELECT COUNT(*) FROM kernel_auth_flows WHERE team=? AND requester=? AND home=? AND thread=?', context).fetchone()[0] != 1):
            return None
        return row, dict(request), bindings, dict(transfer) if transfer else None

    def _local(self, db, manifest):
        snapshots = []
        if db.execute('SELECT 1 FROM browser_profile_leases LIMIT 1').fetchone():
            raise AccessError('A profile writer must finish before adoption.', 409)
        for candidate in manifest['candidates']:
            self._turn(candidate)
            team, owner = candidate['team'], candidate['owner']
            if db.execute("SELECT 1 FROM requests WHERE team=? AND owner=? AND ("
                "status IN ('kernel_creating','kernel_create_unknown') OR "
                "status='waiting' AND expires>? OR status='saved' AND resume_delivered IS NULL AND expires>? OR "
                "status='resumed' AND resume_delivered IS NULL) LIMIT 1",
                (team, owner, self.store.clock(), self.store.clock())).fetchone():
                raise AccessError('An owner interaction must finish before adoption.', 409)
            if db.execute("SELECT 1 FROM owner_approvals WHERE team=? AND user=? AND expires>? AND "
                "(state IN ('posting','pending') OR state='approved' AND resumed IS NULL) LIMIT 1",
                (team, owner, self.store.clock())).fetchone():
                raise AccessError('An owner approval must finish before adoption.', 409)
            if db.execute("SELECT 1 FROM kernel_purchases p JOIN requests r ON r.id=p.request_id "
                "WHERE r.team=? AND r.owner=? AND p.state NOT IN ('completed','cancelled','review') LIMIT 1",
                (team, owner)).fetchone():
                raise AccessError('An uncertain purchase must be reconciled before adoption.', 409)
            unknowns = []
            for row in db.execute("SELECT * FROM kernel_auth_flows WHERE team=? AND requester=? AND state IN "
                    "('creating','create_unknown','starting','login_unknown','pending','cleanup_pending') ORDER BY key", (team, owner)):
                separate = self._separate_legacy_unknown(db, dict(row), manifest)
                if separate is None:
                    raise AccessError('An authentication operation must finish before adoption.', 409)
                unknowns.append(separate)
            if db.execute('SELECT 1 FROM browser_profile_principals WHERE key=? OR profile_name=? OR profile_id=?',
                (candidate['principal_key'], candidate['profile_name'], candidate['profile_id'])).fetchone():
                raise AccessError('A canonical profile already exists; it cannot be replaced by adoption.', 409)
            claims = [dict(row) for row in db.execute('SELECT * FROM browser_session_owners WHERE '
                'provider=? AND session_id IN (?,?) ORDER BY session_id',
                ('KernelTaskProfile', candidate['profile_name'], candidate['profile_id']))]
            bindings = [dict(row) for row in db.execute('SELECT * FROM kernel_auth_bindings WHERE flow_key=? '
                'ORDER BY team,requester,home,thread', (candidate['flow_key'],))]
            if any((row['team'], row['requester']) != (team, owner) for row in claims + bindings):
                raise AccessError('The legacy profile has a conflicting local owner claim.', 403)
            if any(row['home'] != str(self.service.private_home(team, owner)) for row in bindings):
                raise AccessError('A legacy task binding requires separate reconciliation.', 409)
            snapshots.append((candidate['flow_key'], claims, bindings, unknowns))
        return snapshots

    def _completed(self, db, manifest, digest):
        found = []
        for candidate in manifest['candidates']:
            row = db.execute('SELECT * FROM browser_profile_adoptions WHERE principal_key=?',
                (candidate['principal_key'],)).fetchone()
            if row is None:
                found.append(False)
                continue
            expected = {'profile_name': candidate['profile_name'], 'profile_id': candidate['profile_id'],
                        'flow_key': candidate['flow_key'], 'manifest_sha256': digest}
            principal = db.execute('SELECT * FROM browser_profile_principals WHERE key=?', (candidate['principal_key'],)).fetchone()
            flow = db.execute('SELECT principal_key FROM kernel_auth_flows WHERE key=?', (candidate['flow_key'],)).fetchone()
            if (any(row[k] != v for k, v in expected.items()) or not principal or
                    (principal['profile_name'], principal['profile_id'], principal['team'], principal['owner']) !=
                    (candidate['profile_name'], candidate['profile_id'], candidate['team'], candidate['owner']) or
                    not flow or flow['principal_key'] != candidate['principal_key']):
                raise AccessError('The adoption receipt conflicts with the reviewed identities.', 409)
            found.append(True)
        if any(found) and not all(found):
            raise AccessError('A partial historical adoption needs explicit reconciliation.', 409)
        return all(found)

    def _prepare(self, manifest):
        self.phase = 'validation'
        validate_manifest(manifest)
        digest = manifest_digest(manifest)
        self.phase = 'local_quiescence'
        with self.store.connection() as db:
            if self._completed(db, manifest, digest):
                return digest, None
            local = self._local(db, manifest)
        self.phase = 'browser_context_provenance'
        files = self._files(manifest)
        self.phase = 'active_browser_inventory'
        if self.active_browsers() != []:
            raise AccessError('Profile adoption requires no active provider browser.', 409)
        checks = []
        for candidate in manifest['candidates']:
            self.phase = 'provider_profile_identity'
            remote = self.cloud.client.get_profile(candidate['profile_name'])
            if remote != {'name': candidate['profile_name'], 'id': candidate['profile_id']}:
                raise AccessError('The reviewed provider profile identity changed.', 409)
            turn = self._turn(candidate)
            self.phase = 'authentication_identity'
            checks.append((turn, self.auth.legacy_adoption_evidence(turn, candidate)))
        self.phase = 'provenance_recheck'
        with self.store.connection() as db:
            if self._local(db, manifest) != local or self._files(manifest) != files:
                raise AccessError('Local profile provenance changed during validation.', 409)
        return digest, (local, files, checks)

    def plan(self, manifest):
        digest, prepared = self._prepare(manifest)
        return {'status': 'ready' if prepared else 'already_adopted', 'manifest_sha256': digest,
                'candidates': len(manifest['candidates']), 'provider_mutations': 0}

    def apply(self, manifest, *, reviewed_sha256):
        validate_manifest(manifest)
        if manifest_digest(manifest) != reviewed_sha256:
            raise AccessError('The adoption manifest does not match its reviewed fingerprint.', 403)
        digest, prepared = self._prepare(manifest)
        if prepared is None:
            return {'status': 'already_adopted', 'manifest_sha256': digest}
        local, files, checks = prepared
        self.phase = 'atomic_registration'
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            if self.before_commit is not None:
                self.before_commit()
            if self._local(db, manifest) != local or self._files(manifest) != files:
                raise AccessError('Local profile provenance changed before adoption.', 409)
            for candidate, (turn, evidence) in zip(manifest['candidates'], checks):
                principal = dict(key=candidate['principal_key'], profile_name=candidate['profile_name'],
                    kind='personal', team=candidate['team'], owner=candidate['owner'],
                    account_handle='', origin='', binding='', generation=1)
                db.execute('INSERT INTO browser_profile_principals VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                    (*principal.values(), candidate['profile_id'], 'ready', self.store.clock()))
                self.auth.commit_legacy_adoption(db, turn, evidence, principal)
                # Retire old selections; a later task must select under its own
                # current authority. Browser/CDP and request approvals are untouched.
                db.execute('DELETE FROM kernel_auth_bindings WHERE flow_key=?', (candidate['flow_key'],))
                db.execute('INSERT INTO browser_profile_adoptions VALUES (?,?,?,?,?,?)',
                    (principal['key'], candidate['profile_name'], candidate['profile_id'],
                     candidate['flow_key'], digest, self.store.clock()))
        return {'status': 'adopted', 'manifest_sha256': digest, 'candidates': len(checks), 'provider_mutations': 0}


def assert_startup_authority(service):
    from gateway import status
    home = service.policy.home.resolve()
    if (not status.owns_gateway_runtime_lock() or status.live_gateway_pid_for_home(home) != os.getpid() or
            status._get_process_hermes_home().resolve() != home):
        raise AccessError('Only the authoritative gateway startup may apply staged profile adoption.', 409)


def apply_startup(service):
    path = service.policy.home / '.clanker-cloud' / 'profile-adoption.json'
    if not path.exists():
        return None
    assert_startup_authority(service)
    if (any(value.is_symlink() for value in (path, path.parent)) or not stat.S_ISREG(path.stat().st_mode) or path.stat().st_mode & 0o077 or
            path.stat().st_uid != os.getuid() or path.stat().st_size > 65536):
        raise AccessError('The staged adoption manifest must be a protected ordinary file.', 403)
    digest, migration = None, None
    try:
        staged = json.loads(path.read_text())
        if set(staged) != {'manifest', 'reviewed_sha256'}:
            raise ValueError
        digest = manifest_digest(staged['manifest'])
        migration = ProfileMigration(service, before_commit=lambda: assert_startup_authority(service))
        result = migration.apply(
            staged['manifest'], reviewed_sha256=staged['reviewed_sha256'])
        _outcome(path.parent, result)
        return result
    except Exception:
        _outcome(path.parent, {'status': 'refused', 'manifest_sha256': digest,
            'phase': migration.phase if migration is not None else 'manifest_loading',
            'error': 'Checked profile adoption did not complete; Vault service remains unavailable.'})
        raise AccessError('Checked profile adoption did not complete. Review its protected startup outcome.', 409) from None


def _outcome(directory, result):
    """Only bounded metadata is persisted; no provider payload or error text."""
    path = directory / 'profile-adoption-outcome.json'
    if path.is_symlink():
        raise AccessError('The adoption outcome path is not a protected ordinary file.', 403)
    temporary = directory / ('.profile-adoption-' + secrets.token_hex(12))
    try:
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(dict(result, gateway_pid=os.getpid(), recorded_at=time.time()), stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
