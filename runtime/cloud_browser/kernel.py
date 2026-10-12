"""Requester-owned Kernel sessions behind Hermes's native browser tools."""
import base64
import hashlib
import json
from pathlib import Path
import re
import time
from urllib.parse import parse_qs, urlsplit

from vault.store import AccessError
from .service import BrowserContext
from . import task_profiles
from .kernel_client import register_provider, valid_session_record, validate_profile_attachment, validate_proxy_policy, validate_vault_attachments


class _ProfileLeaseRetry(Exception):
    pass


class KernelBrowser(BrowserContext):
    uses_native_tools = True
    profile_retained_on_stop = True

    def __init__(self, vault_service, settings, client):
        super().__init__(vault_service, settings, client)
        from .profile_registry import ProfileRegistry
        self.profiles = ProfileRegistry(vault_service)

    def profile_principal(self, turn):
        return task_profiles.private_principal(self, turn)

    def check_access(self, turn, entry):
        super().check_access(turn, entry)
        if entry.get('profile_principal'):
            principal = self.profiles.get(entry['profile_principal'])
            self.profiles.authorize(turn, principal)
            saved = entry.get('profile_lease') or {}
            lease = self.profiles.get_lease(saved.get('id'))
            if (not lease or any(lease.get(field) != saved.get(field) for field in (
                    'id', 'principal_key', 'writer_key', 'kind', 'team', 'requester', 'home', 'thread')) or
                    lease['principal_key'] != principal['key'] or
                    lease['kind'] != 'browser' or lease['team'] != turn.source.scope_id or
                    lease['requester'] != turn.source.user_id or lease['home'] != str(turn.home.resolve()) or
                    lease['thread'] != self.thread(turn) or
                    entry.get('session_id') and (lease['state'] != 'active' or lease['remote_id'] != entry['session_id'])):
                raise AccessError('This task no longer owns its saved browser profile writer.', 403)

    def state(self, turn):
        key = self.context_key(turn)
        path = self.directory / 'kernel' / 'contexts' / (key + '.json')
        return path, self.owned_state(turn, path)

    def driver(self, turn):
        from seatbelt.context import Context
        return Context(turn.home).settings['agent_browser_executable']

    def native_task_id(self, turn):
        value = ':'.join((turn.source.scope_id, turn.source.user_id, str(turn.home.resolve()), turn.task_id))
        return 'ck-' + hashlib.sha256(value.encode()).hexdigest()[:40]

    def check_claim(self, turn, session_id):
        with self.vault.store.connection() as db:
            owner = db.execute('SELECT team,requester,context FROM browser_session_owners WHERE provider=? AND session_id=?',
                ('KernelBrowser', session_id)).fetchone()
        expected = (turn.source.scope_id, turn.source.user_id, self.context_key(turn))
        if not owner or tuple(owner) != expected:
            raise AccessError('This Kernel browser has no verified requester ownership.', 403)

    def endpoint_identity(self, cdp_url, session_id):
        try:
            url = urlsplit(cdp_url)
            query = parse_qs(url.query, strict_parsing=True)
            if (url.scheme != 'wss' or url.username or url.password or url.fragment or
                    not (url.hostname or '').endswith(('.kernel.sh', '.onkernel.com')) or
                    url.path != '/browser/cdp' or set(query) != {'jwt'} or len(query['jwt']) != 1):
                raise ValueError
            encoded = query['jwt'][0].split('.')[1]
            payload = json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
            browser = payload['session']
            checks = {'session ID': browser['id'] == session_id,
                'instance hostname': isinstance(browser['fqdn'], str),
                'instance ID': isinstance(browser['instanceUuid'], str) and bool(browser['instanceUuid']),
                # Zero selects Kernel's default CDP port; an empty WebSocket
                # path similarly selects its browser endpoint.
                'CDP port': isinstance(browser['cdpPort'], int) and 0 <= browser['cdpPort'] < 65536,
                'CDP path': isinstance(browser['cdpWsPath'], str)}
            for field, valid in checks.items():
                if not valid:
                    raise AccessError('Kernel returned an unsupported browser control ' + field + '.', 403)
            # These URLs originate in authenticated Kernel API responses. The
            # decoded fields compare their stable routing identity; this is not
            # signature verification or an independent source of authorization.
            return (browser['id'], browser['instanceUuid'], browser['cdpPort'], browser['cdpWsPath'], browser['fqdn'])
        except (ValueError, KeyError, IndexError, TypeError):
            raise AccessError('Kernel returned an unsupported browser control identity.', 403) from None

    def claim_endpoint(self, turn, cdp_url, session_id):
        owner = (turn.source.scope_id, turn.source.user_id, self.context_key(turn))
        identity = self.endpoint_identity(cdp_url, session_id)
        # A different API session ID must not allow two owners to attach to
        # the same underlying browser instance and CDP target.
        endpoint = hashlib.sha256(json.dumps(identity[1:]).encode()).hexdigest()
        with self.vault.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT team,requester,context FROM browser_session_owners WHERE provider=? AND session_id=?',
                ('KernelCDP', endpoint)).fetchone()
            if row and tuple(row) != owner:
                raise AccessError('Kernel returned a browser endpoint assigned to another requester. This task is quarantined.', 403)
            db.execute('INSERT OR IGNORE INTO browser_session_owners VALUES (?,?,?,?,?)', ('KernelCDP', endpoint, *owner))

    def browser_vault(self, turn):
        principal = self.profile_principal(turn)
        if principal is None:
            return None
        manager = getattr(self.vault, 'kernel_vault', None)
        if manager is None:
            return None
        if hasattr(manager, 'browser_vaults'):
            attachments = manager.browser_vaults(turn, principal=principal)
            return validate_vault_attachments(attachments) if attachments else None
        attachment = manager.browser_vault(turn)
        return validate_vault_attachments([attachment]) if attachment is not None else None

    @staticmethod
    def validate_auth_binding(binding):
        if binding is None:
            return None
        fields = {'connection_id', 'profile_name', 'handle'}
        if (not isinstance(binding, dict) or set(binding) != fields or any(
                not isinstance(value, str) or
                re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}', value) is None
                for value in binding.values())):
            raise AccessError('The authenticated Kernel account binding is unsupported.', 503)
        return dict(binding)

    def browser_binding(self, turn):
        if self.profile_principal(turn) is None:
            return None
        manager = getattr(self.vault, 'kernel_auth', None)
        return self.validate_auth_binding(manager.browser_binding(turn)) if manager is not None else None

    def bind_access(self, turn, access):
        with self.vault.lock_for(turn.home):
            access = self.vault.delegations.resolve(turn, access.handle)
            principal = self.profiles.resolve(turn, access)
            path, state = self.state(turn)
            name, entry = self.selected(turn, state)
            self.check_access(turn, entry)
            if entry.get('profile_principal') != principal['key']:
                raise AccessError('Select this saved account with clanker_authenticate, then reopen its browser before filling.', 409)
            self.profiles.select(turn, access)
            entry['access_handle'] = access.handle
            self.vault.delegations.record_browser_use(turn, access)
            retained = state.get('task_profiles', {}).get(name)
            if retained and retained.get('principal_key') == principal['key']:
                retained['access_handle'] = access.handle
            self.save(path, state)

    def select_saved_account(self, turn, access):
        task_profiles.select_account(self, turn, access)

    def prepare_authentication(self, row, *, turn=None):
        """Authentication and automation serialize on the same profile writer."""
        if not row.get('principal_key'):
            raise AccessError('This legacy sign-in needs an explicit persistent-profile selection.', 409)
        if turn is None:
            from gateway.session import SessionSource
            from vault.service import Binding
            home = Path(row['home']).resolve(strict=True)
            chat, separator, thread = row['thread'].partition(':')
            if not separator:
                raise AccessError('The sign-in has no verified source thread.', 403)
            member = self.vault.validate_member(row['team'], row['requester'])
            profile = member['profile'] if home == self.vault.private_home(row['team'], row['requester']) else home.name
            from gateway.config import Platform
            source = SessionSource(Platform.SLACK, chat, chat_type='dm', user_id=row['requester'],
                                   scope_id=row['team'], profile=profile, thread_id=thread or None)
            self.vault.channel_tasks.restore(source)
            turn = Binding(self.vault, source, 'profile-auth', '', home)
        home = Path(turn.home).resolve(strict=True)
        principal = self.profiles.get(row['principal_key'])
        self.profiles.authorize(turn, principal)
        if principal['profile_name'] != row['profile_name']:
            raise AccessError('The sign-in profile changed.', 403)
        # A fresh login owns the current task's browser too. Close only that
        # exact claimed session; another task must pass the idle-writer checks.
        with self.vault.lock_for(home):
            path, state = self.state(turn)
            name = state['threads'].get(self.thread(turn))
            if name in state['sessions']:
                self.close_entry(path, state, name, cleanup_auth=False)
        return task_profiles.acquire(self, turn, principal, 'auth:' + row['key'], kind='auth')

    def check_remote(self, entry, *, details=False, vault=None, profile=None):
        remote = self.client.get_session(entry['session_id'])
        if remote is None:
            return False
        if (remote.get('session_id') != entry['session_id'] or
                remote.get('name') != entry['session_name'] or
                remote.get('stealth') is not True or
                self.endpoint_identity(remote.get('cdp_ws_url'), entry['session_id']) !=
                    self.endpoint_identity(entry['cdp_url'], entry['session_id'])):
            raise AccessError('Kernel browser identity or profile ownership could not be verified.', 403)
        required_profile = self.validate_auth_binding(profile)
        if self.validate_auth_binding(entry.get('profile_binding')) != required_profile:
            raise AccessError('This Kernel browser uses a different authenticated account binding.', 403)
        remote_profile = remote.get('profile')
        captured = entry.get('task_profile')
        expected_name = captured['name'] if captured else (required_profile or {}).get('profile_name')
        writable = captured is not None
        if expected_name is None:
            if remote_profile:
                raise AccessError('An anonymous Kernel browser cannot adopt a saved profile.', 403)
        else:
            if (not isinstance(remote_profile, dict) or
                    remote_profile.get('name') != expected_name or
                    remote.get('profile_save_changes') is not writable or
                    'save_changes' in remote_profile and remote_profile['save_changes'] is not writable):
                raise AccessError('Kernel browser authenticated profile ownership could not be verified.', 403)
            profile_id = remote_profile.get('id')
            if profile_id is not None and (not isinstance(profile_id, str) or
                    re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}', profile_id) is None):
                raise AccessError('Kernel returned an unsupported authenticated profile identity.', 403)
            if entry.get('profile_id') is not None and entry['profile_id'] != profile_id:
                raise AccessError('Kernel browser authenticated profile identity changed.', 403)
            if captured and captured.get('id') is not None and captured['id'] != profile_id:
                raise AccessError('Kernel browser task profile identity changed.', 403)
            if profile_id is not None:
                entry['profile_id'] = profile_id
        required_vault = validate_vault_attachments([vault] if isinstance(vault, dict) else vault) if vault is not None else None
        captured_vault = entry.get('vault_binding')
        if captured_vault is not None:
            captured_vault = validate_vault_attachments([captured_vault] if isinstance(captured_vault, dict) else captured_vault)
        if captured_vault != required_vault:
            raise AccessError('This Kernel browser uses an outdated vault binding. Stop and reopen it in this task before continuing.', 403)
        remote_vaults = remote.get('vaults', [])
        remote_ids = [item.get('id') if isinstance(item, dict) else None for item in remote_vaults] if isinstance(remote_vaults, list) else None
        required_ids = [item['id'] for item in required_vault or []]
        if (remote_ids is None or any(not isinstance(item, str) for item in remote_ids) or
                len(set(remote_ids)) != len(remote_ids) or sorted(remote_ids) != required_ids):
            raise AccessError('Kernel browser vault ownership could not be verified. Stop and reopen it in this task before continuing.', 403)
        policy = entry.get('proxy_policy')
        if policy is not None:
            policy = validate_proxy_policy(policy)
        required_policy = validate_proxy_policy(self.settings['proxy']) if 'proxy' in self.settings else None
        if policy != required_policy:
            raise AccessError('This Kernel browser uses an outdated proxy policy. Stop and reopen it in this task before continuing.', 403)
        proxy = remote.get('proxy')
        if proxy is not None and not isinstance(proxy, dict):
            raise AccessError('Kernel browser proxy routing could not be verified.', 403)
        modern_id = proxy.get('id') if proxy is not None else None
        legacy_id = remote.get('proxy_id')
        if any(value is not None and (not isinstance(value, str) or
                re.fullmatch(r'[A-Za-z0-9_-]{1,200}', value) is None) for value in (modern_id, legacy_id)):
            raise AccessError('Kernel browser proxy routing could not be verified.', 403)
        if modern_id and legacy_id and modern_id != legacy_id:
            raise AccessError('Kernel browser proxy routing could not be verified.', 403)
        network = remote.get('network')
        if network is not None and not isinstance(network, dict):
            raise AccessError('Kernel browser proxy routing could not be verified.', 403)
        if ((network or {}).get('proxy_routes') or remote.get('bypass_hosts') or
                (proxy or {}).get('bypass_hosts')):
            raise AccessError('Kernel browser has unexpected proxy routing.', 403)
        if policy is None:
            # Default egress is permitted only while the protected policy also
            # selects it. Policy changes require a newly verified browser.
            if modern_id or legacy_id or (proxy is not None and proxy.get('mode') != 'default'):
                raise AccessError('This existing Kernel browser changed its proxy routing.', 403)
        else:
            if (modern_id or legacy_id) != policy['id'] or (proxy is not None and proxy.get('mode') is not None):
                raise AccessError('Kernel browser does not use its captured proxy policy.', 403)
            self.client.verify_proxy(policy)
        return remote if details else True

    def capability_expires_soon(self, cdp_url):
        encoded = parse_qs(urlsplit(cdp_url).query)['jwt'][0].split('.')[1]
        payload = json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
        expires = payload.get('exp')
        return isinstance(expires, (int, float)) and expires <= time.time() + 60

    def native_record(self, turn, entry):
        task_id = self.native_task_id(turn)
        return {'session_name': entry['session_name'], 'bb_session_id': entry['session_id'],
            'cdp_url': entry['cdp_url'], 'features': entry['features'],
            'session_key': task_id, 'owner_task_id': task_id}

    @staticmethod
    def pending_creation_error(entry, message):
        reference = entry.get('diagnostic_ref')
        if isinstance(reference, str) and re.fullmatch(r'[0-9a-f]{32}', reference):
            message += ' Reference: ' + reference + '.'
        return AccessError(message, 409)

    def prepare(self, turn):
        # Waiting here holds no execution-home lock: the preceding task must
        # remain able to close its browser and yield the persistent profile.
        for _ in range(2):
            principal = self.profile_principal(turn)
            lease = (task_profiles.acquire(self, turn, principal,
                     'browser:' + self.context_key(turn) + ':' + self.thread(turn)) if principal else None)
            try:
                return self._prepare_with_lease(turn, principal, lease)
            except _ProfileLeaseRetry:
                continue
            except Exception:
                if lease:
                    current = self.profiles.get_lease(lease['id'])
                    if current and current['state'] == 'reserved':
                        self.profiles.release(current)
                raise
        raise AccessError('The previous browser expired while opening. Reopen this task browser.', 409)

    def _prepare_with_lease(self, turn, principal, lease):
        from tools import browser_tool as native
        from tools.browser_tool_cdp import _ensure_cdp_supervisor
        task_id = self.native_task_id(turn)
        with self.vault.lock_for(turn.home):
            path, state = self.state(turn)
            name = hashlib.sha256(self.thread(turn).encode()).hexdigest()[:24]
            entry = state['sessions'].setdefault(name, {})
            if principal:
                self.profiles.authorize(turn, principal)
            self.check_access(turn, entry)
            if entry.get('dispatch_unknown'):
                raise self.pending_creation_error(entry,
                    'A Kernel creation was not acknowledged. Reconcile it before another browser.')
            profile = self.browser_binding(turn)
            vault = self.browser_vault(turn)
            if entry.get('session_id'):
                self.check_claim(turn, entry['session_id'])
                if (self.validate_auth_binding(entry.get('profile_binding')) != profile or
                        entry.get('profile_principal') != (principal['key'] if principal else None)):
                    # Authentication uses a separate Kernel-owned browser. An
                    # account change gets a fresh automation browser, never an
                    # in-place profile load or copied cookie state.
                    closed_lease = entry.get('profile_lease')
                    self.close_entry(path, state, name, cleanup_auth=False)
                    if lease and closed_lease and closed_lease['id'] == lease['id']:
                        # Closing the existing writer also released this
                        # idempotently acquired lease. Reserve again outside
                        # the home lock before dispatching the replacement.
                        raise _ProfileLeaseRetry()
                    entry = state['sessions'].setdefault(name, {})
                remote = self.check_remote(entry, details=True, vault=vault, profile=profile) if entry.get('session_id') else None
                if not remote and entry.get('session_id'):
                    self.close_entry(path, state, name, cleanup_auth=False, remote_absent=True)
                    raise _ProfileLeaseRetry()
            if not entry.get('session_id'):
                policy = validate_proxy_policy(self.settings['proxy']) if 'proxy' in self.settings else None
                retained = task_profiles.select(self, turn, path, state, name, profile, principal=principal)
                entry.update(dispatch_unknown=True, home=str(turn.home.resolve()), proxy_policy=policy,
                    vault_binding=vault, profile_binding=profile, task_profile=retained,
                    profile_principal=principal['key'] if principal else None, profile_lease=lease,
                    source=turn.source.to_dict())
                saved_access = state.get('task_profiles', {}).get(name, {}).get('access_handle') if profile is None else None
                if saved_access:
                    entry['access_handle'] = saved_access
                state['threads'][self.thread(turn)] = name
                self.save(path, state)
                dispatch_attempted = False
                try:
                    options = {}
                    if vault is not None:
                        options['vault'] = vault
                    if retained:
                        options['profile'] = validate_profile_attachment(
                            {'name': retained['name'], 'save_changes': True})
                    from .kernel_telemetry import TelemetryPlan
                    capture = TelemetryPlan(self).inspect(turn, creating=True)
                    if capture.get('telemetry_allowed'):
                        options['telemetry'] = capture['telemetry']
                    if lease:
                        lease = entry['profile_lease'] = self.profiles.dispatched(lease)
                        self.save(path, state)
                    dispatch_attempted = True
                    created = self.client.create_session('clanker-' + name, **options)
                except AccessError as error:
                    # An API timeout can occur after creation; preserve the
                    # dispatch marker rather than automatically duplicating it.
                    if not dispatch_attempted:
                        # Registry authorization refused before provider I/O.
                        # The outer prepare releases its reserved lease.
                        entry.clear()
                        state['threads'].pop(self.thread(turn), None)
                        self.save(path, state)
                        raise
                    if getattr(error, 'browser_dispatch_attempted', None) is False:
                        # Proxy validation failed before a browser POST. This
                        # is a known non-dispatch, so a later turn may retry.
                        if lease:
                            lease = self.profiles.not_dispatched(lease, evidence=error)
                            self.profiles.release(lease)
                        entry.clear()
                        state['threads'].pop(self.thread(turn), None)
                        self.save(path, state)
                        raise
                    reference = getattr(error, 'diagnostic_ref', None)
                    if isinstance(reference, str) and re.fullmatch(r'[0-9a-f]{32}', reference):
                        entry['diagnostic_ref'] = reference
                        self.save(path, state)
                    raise
                if not valid_session_record(created):
                    raise AccessError('Kernel did not confirm a browser session.', 502)
                session_id = created['bb_session_id']
                self.claim_session(turn, session_id)
                if lease:
                    lease = entry['profile_lease'] = self.profiles.confirm(lease, session_id)
                entry.update(session_id=session_id, cdp_url=created.get('cdp_url'),
                    session_name=created.get('session_name'), features=created.get('features') or {},
                    created_at=time.time(), dispatch_unknown=False)
                if capture.get('telemetry_allowed'):
                    entry['benchmark_telemetry_campaign'] = capture['campaign']
                self.save(path, state)
                remote = self.check_remote(entry, details=True, vault=vault, profile=profile)
                if not remote:
                    raise AccessError('The newly created Kernel browser is unavailable.', 503)
            self.claim_endpoint(turn, entry['cdp_url'], entry['session_id'])
            from .kernel_telemetry import TelemetryPlan
            capture = TelemetryPlan(self).inspect(turn)
            if (capture.get('telemetry_allowed') and
                    entry.get('benchmark_telemetry_campaign') != capture['campaign']):
                self.client.set_telemetry(entry['session_id'], capture['telemetry'])
                entry['benchmark_telemetry_campaign'] = capture['campaign']
                self.save(path, state)
            elif not capture.get('telemetry_allowed') and entry.get('benchmark_telemetry_campaign'):
                self.client.set_telemetry(entry['session_id'], {'enabled': False})
                entry.pop('benchmark_telemetry_campaign', None)
                self.save(path, state)
            state['threads'][self.thread(turn)] = name
            previous_task = entry.get('native_task_id')
            if previous_task and previous_task != task_id:
                self.detach(entry)
            entry.update(native_task_id=task_id, home=str(turn.home.resolve()), last_used=time.time())
            with native._cleanup_lock:
                existing = native._active_sessions.get(task_id)
                if existing and (existing.get('bb_session_id') != entry['session_id'] or
                        existing.get('cdp_url') != entry['cdp_url'] or
                        existing.get('session_key') != task_id or
                        existing.get('owner_task_id') != task_id or
                        existing.get('fallback_from_cloud') or
                        native._session_owner_homes.get(task_id) != str(turn.home.resolve())):
                    raise AccessError('This native browser task is already bound to another browser.', 403)
                refresh = not existing or self.capability_expires_soon(entry['cdp_url'])
                expected_binding = dict(existing) if existing is not None else None
            # detach acquires Hermes's non-reentrant cleanup lock itself. Keep
            # the authenticated owner/home lock while refreshing its capability.
            if refresh and remote['cdp_ws_url'] != entry['cdp_url']:
                self.detach(entry)
                entry['cdp_url'] = remote['cdp_ws_url']
            with native._cleanup_lock:
                replacement = native._active_sessions.get(task_id)
                if replacement is not None and (replacement != expected_binding or
                        native._session_owner_homes.get(task_id) != str(turn.home.resolve())):
                    raise AccessError('The browser binding changed during renewal. Reopen it before proceeding.', 409)
                record = self.native_record(turn, entry)
                native._active_sessions[task_id] = record
                native._session_owner_homes[task_id] = str(turn.home.resolve())
                native._suspect_browser_sessions.pop(task_id, None)
                native._last_active_session_key[task_id] = task_id
                native._cached_agent_browser = self.driver(turn)
                native._agent_browser_resolved = True
            self.save(path, state)
            self.register_redactions(turn, entry)
            _ensure_cdp_supervisor(task_id)
            from tools.browser_supervisor import SUPERVISOR_REGISTRY
            self.assert_supervisor(turn, SUPERVISOR_REGISTRY.get(task_id))
            return record

    def assert_supervisor(self, turn, supervisor):
        if supervisor is None:
            raise AccessError('Open this requester task\'s Kernel browser before using saved access.', 409)
        self._assert_control_binding(turn, supervisor)
        return supervisor

    def _assert_control_binding(self, turn, supervisor):
        """Validate ownership even when a known native timeout removed supervision."""
        from tools import browser_tool as native
        task_id = self.native_task_id(turn)
        with self.vault.lock_for(turn.home):
            path, state = self.state(turn)
            _, entry = self.selected(turn, state)
            self.check_access(turn, entry)
            self.check_claim(turn, entry['session_id'])
            record = native._active_sessions.get(task_id) or {}
            if (entry.get('native_task_id') != task_id or
                    entry.get('home') != str(turn.home.resolve()) or
                    native._session_owner_homes.get(task_id) != str(turn.home.resolve()) or
                    record.get('session_key') != task_id or record.get('owner_task_id') != task_id or
                    record.get('bb_session_id') != entry['session_id'] or
                    record.get('cdp_url') != entry['cdp_url'] or
                    (supervisor is not None and supervisor.cdp_url != entry['cdp_url']) or
                    record.get('fallback_from_cloud')):
                raise AccessError('The browser control endpoint does not belong to this requester task.', 403)
            if not self.check_remote(entry, vault=self.browser_vault(turn), profile=self.browser_binding(turn)):
                raise AccessError('The Kernel browser has expired. Reopen it before using saved access.', 409)
            self.register_redactions(turn, entry)

    def register_redactions(self, turn, entry):
        kernel = getattr(self.vault, 'kernel_vault', None)
        if kernel is None:
            raise AccessError('Kernel Vault is required for private browser observation.', 503)
        kernel.register_values(turn)

    def remember_redactions(self, turn, values):
        kernel = getattr(self.vault, 'kernel_vault', None)
        if kernel is None:
            raise AccessError('Kernel Vault is required for private browser observation.', 503)
        from tools.browser_supervisor import SUPERVISOR_REGISTRY
        supervisor = SUPERVISOR_REGISTRY.get(self.native_task_id(turn))
        self.assert_supervisor(turn, supervisor)
        kernel.remember_values(turn, values)

    def finish(self, turn, result):
        kernel = getattr(self.vault, 'kernel_vault', None)
        if kernel is None:
            raise AccessError('Kernel Vault is required for private browser observation.', 503)
        from tools.browser_supervisor import SUPERVISOR_REGISTRY
        from tools import browser_tool as native
        task_id = self.native_task_id(turn)
        supervisor = SUPERVISOR_REGISTRY.get(task_id)
        if (native._active_sessions.get(task_id) or {}).get('_command_timed_out') is True:
            self._assert_control_binding(turn, supervisor)
            # No page output can be observed without supervision. Return only
            # host-authored timeout information, retaining all privacy guards.
            from tools.browser_tool_session import _COMMAND_OUTCOME_UNKNOWN
            return json.dumps({'success': False, 'code': 'browser_command_outcome_unknown',
                               'error': _COMMAND_OUTCOME_UNKNOWN})
        self.assert_supervisor(turn, supervisor)
        kernel.refresh_privacy(turn)
        from agent.redact import redact_registered_vault_values, redact_sensitive_text
        from agent.vault_store import scrub_secret_from_text
        values = kernel.observation_values(turn)
        def scrub(value, key=None):
            if isinstance(value, str):
                # Native image payloads must remain valid for Hermes's image
                # attachment path. Text and metadata still pass the same scrub.
                if value.startswith('data:image/'):
                    return value
                for secret in sorted(values, key=len, reverse=True):
                    value = (value.replace(secret, '«redacted-vault-secret»') if len(secret) == 1
                             else scrub_secret_from_text(value, {'value': secret}))
                return redact_registered_vault_values(redact_sensitive_text(value, force=True))
            if isinstance(value, dict):
                return {scrub(key): scrub(item, key) for key, item in value.items()}
            if isinstance(value, list):
                return [scrub(item) for item in value]
            if type(value) in (int, float) and str(value) in values:
                return '«redacted-vault-secret»'
            return value
        if isinstance(result, dict) and result.get('_multimodal'):
            return scrub(result)
        if isinstance(result, str):
            try:
                parsed = json.loads(result)
            except (ValueError, TypeError):
                return scrub(result)
            return json.dumps(scrub(parsed))
        return json.dumps(scrub(result))

    def detach(self, entry):
        from tools import browser_tool as native
        from tools.browser_tool_cdp import _stop_cdp_supervisor
        from tools.browser_supervisor import SUPERVISOR_REGISTRY
        from tools.browser_tool_lifecycle import _kill_verified_daemon
        import os
        import shutil
        task_id = entry.get('native_task_id')
        if not task_id:
            return
        # Only remove a process-local binding that still names our exact CDP
        # endpoint. Local checkout supervision may have replaced it.
        with native._cleanup_lock:
            record = native._active_sessions.get(task_id) or {}
            if record.get('bb_session_id') == entry.get('session_id') and record.get('cdp_url') == entry.get('cdp_url'):
                supervisor = SUPERVISOR_REGISTRY.get(task_id)
                if supervisor is not None and supervisor.cdp_url == entry.get('cdp_url'):
                    _stop_cdp_supervisor(task_id)
                socket_dir = os.path.join(native._socket_safe_tmpdir(), 'agent-browser-' + entry['session_name'])
                if os.path.isdir(socket_dir) and _kill_verified_daemon(socket_dir, entry['session_name']):
                    shutil.rmtree(socket_dir, ignore_errors=True)
                native._active_sessions.pop(task_id, None)
                native._session_owner_homes.pop(task_id, None)
                native._last_active_session_key.pop(task_id, None)
                native._session_last_activity.pop(task_id, None)

    def close_entry(self, path, state, name, *, cleanup_auth=True, remote_absent=False):
        entry = state['sessions'][name]
        threads = [key for key, value in state['threads'].items() if value == name]
        if entry.get('dispatch_unknown'):
            raise self.pending_creation_error(entry,
                'A Kernel creation needs reconciliation before cleanup can be confirmed.')
        if entry.get('session_id'):
            with self.vault.store.connection() as db:
                claim = db.execute('SELECT team,requester,context FROM browser_session_owners WHERE provider=? AND session_id=?',
                    ('KernelBrowser', entry['session_id'])).fetchone()
            owner = state['owner']
            if not claim or tuple(claim) != (owner['team'], owner['requester'], path.stem):
                raise AccessError('Kernel cleanup is not authorized for this browser owner.', 403)
            from .kernel_replay import ReplayCapture
            ReplayCapture(self).close_entry(entry)
        if entry.get('session_id') and not remote_absent and not self.client.close_verified(entry['session_id']):
            entry['cleanup_pending'] = True
            self.save(path, state)
            raise AccessError('Kernel browser deletion could not be verified. This account remains blocked.', 503)
        if entry.get('profile_lease'):
            self.profiles.release(entry['profile_lease'], verified_closed=True)
        self.detach(entry)
        state['sessions'].pop(name)
        state['threads'] = {key: value for key, value in state['threads'].items() if value != name}
        self.save(path, state)
        manager = getattr(self.vault, 'kernel_auth', None)
        if cleanup_auth and manager is not None:
            owner = state['owner']
            for thread in threads or [None]:
                manager.cleanup_context(owner['team'], owner['requester'], entry['home'], thread=thread)

    def stop(self, turn, session=None, *, purge=False):
        if session is not None:
            raise AccessError('Kernel browser selection belongs to the authenticated thread.', 403)
        with self.vault.lock_for(turn.home):
            path, state = self.state(turn)
            names = list(state['sessions']) if purge else [state['threads'].get(self.thread(turn))]
            errors = []
            for name in names:
                if name not in state['sessions']:
                    continue
                try:
                    entry = state['sessions'][name]
                    if entry.get('session_id'):
                        self.check_claim(turn, entry['session_id'])
                    self.close_entry(path, state, name, cleanup_auth=False)
                except AccessError as error:
                    errors.append(error)
            if errors:
                raise errors[0]
            if purge:
                task_profiles.purge(self, path, state)
            manager = getattr(self.vault, 'kernel_auth', None)
            if manager is not None:
                if purge:
                    manager.cleanup_context(turn.source.scope_id, turn.source.user_id,
                        str(turn.home.resolve()))
                else:
                    manager.release_context(turn.source.scope_id, turn.source.user_id,
                        str(turn.home.resolve()), thread=self.thread(turn))

    def stop_by_home(self, home):
        home = str(Path(home).resolve(strict=True))
        with self.vault.lock_for(Path(home)):
            errors = []
            for path in (self.directory / 'kernel' / 'contexts').glob('*.json'):
                state = json.loads(path.read_text())
                if not any(entry.get('home') == home for entry in (
                        list(state['sessions'].values()) + list(state.get('task_profiles', {}).values()))):
                    continue
                owner = state['owner']
                expected = hashlib.sha256(('v2:' + owner['team'] + ':' + owner['requester'] + ':' + home).encode()).hexdigest()
                if path.stem != expected:
                    raise AccessError('Kernel cleanup has no verified execution-home ownership.', 403)
                self.vault.validate_member(owner['team'], owner['requester'])
                for name, entry in list(state['sessions'].items()):
                    if entry.get('home') == home:
                        try:
                            self.close_entry(path, state, name, cleanup_auth=False)
                        except AccessError as error:
                            errors.append(error)
                if not errors:
                    task_profiles.purge(self, path, state)
            if errors:
                raise errors[0]
            manager = getattr(self.vault, 'kernel_auth', None)
            if manager is not None:
                manager.cleanup_home(home)
