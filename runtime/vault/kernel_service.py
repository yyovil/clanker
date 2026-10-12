"""Kernel owns credential collection, storage and browser writes.

Clanker retains authenticated Slack ownership, exact-origin authorization and
durable task continuation. Local tables contain metadata and dispatch claims
only. There is deliberately no local-secret or JavaScript writer fallback.
"""
import asyncio
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import secrets
from urllib.parse import urlsplit

from .store import AccessError
from .kernel_store import KernelStore


def public_meta(record):
    from agent.vault_store import VaultItemMeta
    return VaultItemMeta(id=record['handle'], kind=record['kind'], label=record['label'],
        origin=record['origin'], created_at=str(record['created_at']),
        identifier=record.get('identifier') or None,
        identifier_type=record.get('identifier_type'), has_otp=record.get('has_otp', False),
        login_method=record['login_method'])


class KernelAccountStore:
    """Metadata-only compatibility with Clanker's existing invitation ACLs."""
    def __init__(self, kernel, team, owner):
        self.kernel, self.team, self.owner = kernel, team, owner
        self.home = kernel.scope(team, owner)[2]

    def list_items(self):
        # Inventory is a metadata read, not authorization to provision a vault.
        # Existing item use still goes through the fresh Kernel checks below.
        managed = getattr(self.kernel.service, 'kernel_auth', None)
        items = ([public_meta(item) for item in self.kernel.metadata.list_items(
            self.team, self.owner, self.home) if item['kind'] != 'personal' and item['status'] == 'ready']
            if self.kernel.metadata.vault(self.team, self.owner, self.home) is not None else [])
        if managed:
            known = {item.id for item in items}
            items += [managed.meta(account) for account in managed.accounts(self.team, self.owner)
                      if account['handle'] not in known]
        return items

    def get_meta(self, handle):
        record = (self.kernel.metadata.item(self.team, self.owner, self.home, handle)
                  if self.kernel.metadata.vault(self.team, self.owner, self.home) else None)
        if record and record['status'] == 'ready' and record['kind'] != 'personal':
            return public_meta(record)
        managed = getattr(self.kernel.service, 'kernel_auth', None)
        account = managed.account(self.team, self.owner, handle) if managed else None
        return managed.meta(account) if account else None

    def remove_item(self, handle):
        managed = getattr(self.kernel.service, 'kernel_auth', None)
        if managed:
            managed.remove_account(self.team, self.owner, handle)
        record = (self.kernel.metadata.item(self.team, self.owner, self.home, handle)
                  if self.kernel.metadata.vault(self.team, self.owner, self.home) else None)
        if record:
            self.kernel.client.delete_credential(record['vault_id'], record['key'])
            self.kernel.metadata.delete_item(self.team, self.owner, self.home, handle)

    def resolve_secret(self, handle):
        raise AccessError('Raw credential resolution is unavailable. Use Kernel fill or authenticated API requests.', 403)


@dataclass(frozen=True)
class FormPlan:
    task_id: str
    origin: str
    page_url: str
    marker: str
    nonce: str
    controls: tuple
    supervisor: object
    browser_id: str
    phone_context: dict | None = None


class KernelVaultService:
    def __init__(self, service):
        from cloud_browser.kernel_vault_client import KernelVaultClient
        self.service = service
        self.metadata = KernelStore(service.store)
        self.client = KernelVaultClient(service.cloud_browser.client)
        self._volatile_redactions = {}
        self._split_redactions = {}

    def remember_values(self, turn, values):
        """Privacy filtering only; filled secrets never enter local storage."""
        from agent.redact import register_vault_redaction_value
        key = (turn.source.scope_id, turn.source.user_id, str(turn.home.resolve()))
        stored = self._volatile_redactions.setdefault(key, set())
        for value in values:
            if isinstance(value, str) and value:
                stored.add(value)
                register_vault_redaction_value(value)

    def redaction_values(self, turn):
        key = (turn.source.scope_id, turn.source.user_id, str(turn.home.resolve()))
        return tuple(self._volatile_redactions.get(key, ()))

    def observation_values(self, turn):
        key = (turn.source.scope_id, turn.source.user_id, str(turn.home.resolve()))
        return self.redaction_values(turn) + self._split_redactions.get(key, ())

    def register_values(self, turn):
        from agent.redact import register_vault_redaction_value
        for value in self.redaction_values(turn):
            register_vault_redaction_value(value)

    def _arm_privacy(self, turn, plan, bindings, *, sensitive=False):
        cloud = self.service.cloud_browser
        path, state = cloud.state(turn)
        _, entry = cloud.selected(turn, state)
        guard = {'origin': plan.origin, 'marker': plan.marker,
                 'selectors': [item['selector'] for item in bindings],
                 'sensitive': sensitive or any(item['field'] in {'password', 'code', 'totp', 'gender', 'api_key'}
                    or item['field'].startswith('code_digit_') for item in bindings)}
        guards = entry.setdefault('vault_controls', [])
        if guard not in guards:
            guards.append(guard)
        entry['vault_controls'] = guards[-32:]
        cloud.save(path, state)

    def refresh_privacy(self, turn):
        """Recover observation protection after restart without storing values."""
        from tools import browser_vault_tool as native
        from .browser_context import browser_task_id
        cloud = self.service.cloud_browser
        _, state = cloud.state(turn)
        _, entry = cloud.selected(turn, state)
        guards = entry.get('vault_controls', [])
        if not guards:
            key = (turn.source.scope_id, turn.source.user_id, str(turn.home.resolve()))
            self._split_redactions.pop(key, None)
            return False
        expression = '''(() => {
          const values=[], visible=[], split_values=[];
          for (const guard of __GUARDS__) {
            if (location.origin !== guard.origin || window.__hermesNativePageBinding !== guard.marker) continue;
            const elements=guard.selectors.flatMap(selector => Array.from(document.querySelectorAll(selector)));
            const split=guard.sensitive && elements.length === guard.selectors.length &&
              elements.length >= 4 && elements.length <= 8 && elements.every(el => el.maxLength === 1);
            const digits=[];
            for (const el of elements) {
              const value=String(el.value || '');
              if (split) { digits.push(value); if (value) split_values.push(value); }
              else if (value) values.push(value);
              if (value && el.getClientRects().length && el.type !== 'password') visible.push(guard.sensitive);
            }
            if (split && digits.every(value => /^[0-9]$/.test(value))) values.push(digits.join(''));
          }
          return JSON.stringify({values,visible,split_values});
        })()'''.replace('__GUARDS__', json.dumps(guards))
        result = native._eval_js_secret(browser_task_id(turn), expression)
        if result.get('success') is False and result.get('error_type') in {
                'active_page_changed', 'active_page_unbound'}:
            # Keep the old guard until owned, verified cleanup destroys its
            # browser. Rebinding here could authorize the wrong document, and
            # this refusal can occur after the requested action already ran.
            raise AccessError(
                'Private observation is blocked by a stale or unbound browser document. '
                'Call clanker_browser_stop for this authenticated task; only after it confirms stopped, '
                'use browser_navigate to reopen the intended page and inspect fresh state. '
                'The prior navigation or action may already have occurred. Do not replay login, codes, '
                'fills, submissions or other mutations; old page references are invalid.', 409)
        data = native._parse_json_result(result.get('result')) if result.get('success') else None
        if isinstance(data, str):
            data = native._parse_json_result(data)
        if not isinstance(data, dict) or not isinstance(data.get('values'), list) or not isinstance(data.get('visible'), list):
            raise AccessError('Private browser fields could not be protected for observation.', 409)
        split_values = data.get('split_values', [])
        if not isinstance(split_values, list) or any(not isinstance(value, str) for value in split_values):
            raise AccessError('Private browser fields could not be protected for observation.', 409)
        key = (turn.source.scope_id, turn.source.user_id, str(turn.home.resolve()))
        self._split_redactions[key] = tuple(value for value in split_values if value)
        self.remember_values(turn, data['values'])
        consent = self.service.personal.store(turn.source.scope_id, turn.source.user_id).model_access()
        return any(item is True for item in data['visible']) or bool(data['visible']) and not consent

    def protect_observation(self, turn, tool_name):
        if self.refresh_privacy(turn) and tool_name in {'browser_vision', 'browser_get_images'}:
            raise AccessError('Private fields are still visible. Use the redacted text snapshot until the website finishes verification.', 409)

    def scope(self, team, owner):
        return team, owner, self.service.private_home(team, owner)

    def ensure_vault(self, team, owner):
        scope = self.scope(team, owner)
        # Existing invitations can be resolved while another owner's task lock
        # is held. Reading immutable mappings avoids opposite lock ordering for
        # two members who have invited each other.
        mapping = self.metadata.vault(*scope)
        if mapping:
            return {'id': mapping['vault_id']}
        with self.service.lock_for(scope[2]):
            mapping = self.metadata.vault(*scope)
            if mapping:
                return {'id': mapping['vault_id']}
            name = 'clanker-' + hashlib.sha256(':'.join(map(str, scope)).encode()).hexdigest()[:40]
            # A name is deterministic. An unknown create is reconciled by GET
            # on the next invocation, never by blindly repeating the POST.
            remote = self.client.get_vault(name)
            if remote is None:
                remote = self.client.create_vault(name)
            self.metadata.bind_vault(*scope, remote['id'], name)
            return {'id': remote['id']}

    def browser_vault(self, turn):
        self.service.validate_member(turn.source.scope_id, turn.source.user_id)
        return self.ensure_vault(turn.source.scope_id, turn.source.user_id)

    def browser_vaults(self, turn, *, principal=None):
        """Attach this account and only independently authorized dedicated items."""
        team, requester = turn.source.scope_id, turn.source.user_id
        self.service.validate_member(team, requester)
        if principal is not None and principal['kind'] == 'shared':
            registry = self.service.cloud_browser.profiles
            registry.authorize(turn, principal)
            selected = registry.selection_handle(turn)
            handle = selected or (principal['account_handle'] if principal['owner'] == requester else None)
            if handle is None:
                raise AccessError('Select the shared credential before attaching its browser vault.', 403)
            access = self.service.delegations.resolve(turn, handle)
            registry.authorize(turn, principal, access)
            scope = self.scope(team, access.owner)
            record = self.metadata.item(*scope, access.meta.id)
            binding = self.metadata.credential_vault(*scope, access.meta.id)
            if record is None:
                managed = getattr(self.service, 'kernel_auth', None)
                account = managed.account(team, access.owner, access.meta.id) if managed else None
                if account and account['credential_name']:
                    return []  # Managed Auth owns this login; no personal vault attachment.
            if (not record or record['status'] != 'ready' or record['kind'] != 'login' or
                    not binding or binding['vault_id'] != record['vault_id']):
                raise AccessError('The shared login requires its dedicated credential vault.', 403)
            return [{'id': binding['vault_id']}]
        ids = {self.ensure_vault(team, requester)['id']}
        scope = self.scope(team, requester)
        for binding in self.metadata.list_credential_vaults(*scope):
            record = self.metadata.item(*scope, binding['handle'])
            if record and record['status'] in {'ready', 'pending'}:
                if record['vault_id'] != binding['vault_id'] or record['kind'] == 'personal':
                    raise AccessError('A dedicated credential vault binding is invalid.', 403)
                if principal is not None:
                    with self.service.store.connection() as db:
                        shared = db.execute('SELECT 1 FROM credential_grants WHERE team=? AND owner=? '
                            'AND handle=? AND revoked IS NULL LIMIT 1',
                            (team, requester, binding['handle'])).fetchone()
                        catalog = db.execute("SELECT 1 FROM browser_profile_principals WHERE team=? AND owner=? "
                            "AND account_handle=? AND kind='shared' LIMIT 1",
                            (team, requester, binding['handle'])).fetchone()
                    if shared or catalog:
                        continue
                ids.add(binding['vault_id'])
        if principal is not None:
            # Invited credentials require their selected shared principal;
            # never make them available in the requester's personal profile.
            return [{'id': value} for value in sorted(ids)]
        with self.metadata.requests.connection() as db:
            grants = [dict(row) for row in db.execute('SELECT id,owner,handle FROM credential_grants '
                'WHERE team=? AND recipient=? AND revoked IS NULL ORDER BY id', (team, requester))]
        for grant in grants:
            access = self.service.delegations.lookup(team, requester, grant['id'])
            if access.owner != grant['owner'] or access.meta.id != grant['handle'] or access.grant_id != grant['id']:
                raise AccessError('An invited credential binding changed.', 403)
            scope = self.scope(team, access.owner)
            record = self.metadata.item(*scope, access.meta.id)
            binding = self.metadata.credential_vault(*scope, access.meta.id)
            if (not record or record['status'] != 'ready' or record['kind'] not in {'login', 'api_key'} or
                    not binding or binding['vault_id'] != record['vault_id']):
                raise AccessError('This invited credential requires a dedicated Kernel vault before browser use.', 403)
            ids.add(binding['vault_id'])
        return [{'id': value} for value in sorted(ids)]

    def native_store(self, team, owner):
        return KernelAccountStore(self, team, owner)

    def record(self, team, owner, handle):
        scope = self.scope(team, owner)
        self.ensure_vault(team, owner)
        record = self.metadata.item(*scope, handle)
        if not record or record['status'] not in {'ready', 'pending'}:
            raise AccessError('This Kernel credential is unavailable to this Slack account.', 403)
        return record

    def api_key(self, turn, handle):
        """Read an explicitly backend-readable API key for trusted HTTP use only.

        This is not a tool or a general credential resolver. The authenticated
        handle selects an exact owner and immutable Kernel item; ordinary item
        reads still strip values. Password and TOTP fields remain write-only.
        """
        from .delegation import credential_binding
        from .kernel_store import _origin
        self.service.assert_private(turn)
        self.service.delegations.check_execution(turn)
        access = self.service.delegations.resolve(turn, handle)
        if access.meta.kind != 'api_key':
            raise AccessError('Select an owned or invited API-key handle.', 403)
        with self.service.lock_for(access.home):
            current = self.service.delegations.resolve(turn, handle)
            binding = (current.owner, current.home, current.meta.id, current.grant_id,
                       credential_binding(current.meta))
            if (current.owner, current.home, current.meta.id, current.grant_id,
                    credential_binding(current.meta)) != (access.owner, access.home,
                    access.meta.id, access.grant_id, credential_binding(access.meta)):
                raise AccessError('The API credential binding changed.', 403)
            record = self.record(turn.source.scope_id, current.owner, current.meta.id)
            if (record['kind'] != 'api_key' or record['status'] != 'ready' or
                    record['home'] != str(current.home.resolve()) or
                    record['origin'] != _origin(current.meta.origin) or
                    record['fields'] != ['api_key']):
                raise AccessError('This API credential is not ready for backend use.', 403)
            remote = self.client.get_credential(record['vault_id'], record['key'],
                                                include_public_values=True)
            if (not remote or remote['id'] != record['remote_id'] or
                    remote['key'] != record['key'] or remote['state']['status'] != 'ready'):
                raise AccessError('The Kernel API credential was removed or replaced.', 409)
            fields = remote['spec']['fields']
            if (len(fields) != 1 or fields[0]['name'] != 'api_key' or
                    fields[0]['type'] != 'text' or fields[0]['sensitive'] is not False or
                    fields[0]['required'] is not True):
                error = AccessError('This Kernel API key is write-only. Collect a new backend-readable API key.', 409)
                error.kernel_api_key_reason = 'write_only'
                raise error
            state = remote['state']['fields'].get('api_key', {})
            value = state.get('value')
            if (state.get('has_value') is not True or not isinstance(value, str) or
                    not value or len(value.encode('utf-8')) > 16384 or
                    any(ord(char) < 32 or ord(char) == 127 for char in value)):
                raise AccessError('The Kernel API key is unavailable for an HTTP header.', 409)
            # Revocation or item replacement during the provider read must deny
            # the subsequent secret-bearing request as well.
            self.service.delegations.check_execution(turn)
            latest = self.service.delegations.resolve(turn, handle)
            if ((latest.owner, latest.home, latest.meta.id, latest.grant_id,
                    credential_binding(latest.meta)) != binding or
                    self.record(turn.source.scope_id, latest.owner, latest.meta.id) != record):
                raise AccessError('The API credential changed before use.', 403)
            self.remember_values(turn, [value])
            return value

    def _remote_record(self, team, owner, home, handle, key, remote, *, kind, label,
                       origin, login_method='password', identifier=''):
        return self.metadata.put_item(team, owner, home, handle, key, remote['id'],
            kind, label[:120], origin, login_method=login_method, identifier=identifier,
            fields=[field['name'] for field in remote['spec']['fields']],
            status='ready' if remote['state']['status'] == 'ready' else 'pending',
            version=remote['version'])

    def inspect(self, turn, expected_origin=None):
        from tools import browser_vault_tool as native
        from agent.vault_login_classifier import LoginControl, build_inspection_js
        from .browser_context import authorize_supervisor, browser_task_id
        self.service.assert_private(turn)
        self.service.delegations.check_execution(turn)
        task_id = browser_task_id(turn)
        supervisor = native._ensure_supervisor(task_id)
        if supervisor is None:
            raise AccessError('Open this task\'s browser form before using Kernel vault.', 409)
        authorize_supervisor(turn, supervisor)
        bound = native._bind_active_page(task_id, expected_origin=expected_origin)
        binding = native._page_binding(supervisor)
        if (not bound.get('success') or not binding or bound.get('origin') != binding.get('origin') or
                expected_origin and bound['origin'] != expected_origin or
                not native._active_binding_matches(task_id, binding)):
            raise AccessError('The active browser page does not match the authorized account.', 403)
        origin = bound['origin']
        if urlsplit(origin).scheme != 'https':
            raise AccessError('Kernel credentials require an observed HTTPS form.', 403)
        nonce = secrets.token_hex(12)
        observed = native._eval_js(task_id, build_inspection_js(nonce).replace(
            'input, select', 'input, select, textarea'))
        controls = native._parse_json_result(observed.get('result')) if observed.get('success') else None
        if isinstance(controls, str):
            controls = native._parse_json_result(controls)
        url = native._eval_js(task_id, 'window.location.href')
        page_url = url.get('result') if url.get('success') else None
        if not isinstance(controls, list) or not isinstance(page_url, str):
            raise AccessError('The browser form could not be inspected.', 409)
        parts = urlsplit(page_url)
        if parts.username or parts.password or ('https://' + parts.netloc) != origin:
            raise AccessError('The browser form changed during inspection.', 403)
        cloud = self.service.cloud_browser
        _, state = cloud.state(turn)
        _, entry = cloud.selected(turn, state)
        if not entry or not entry.get('session_id'):
            raise AccessError('This task has no owned Kernel browser.', 403)
        from .personal import PHONE_CONTEXT_JS
        phone_context = native._eval_js(task_id, PHONE_CONTEXT_JS)
        return FormPlan(task_id, origin, page_url, binding['marker'], nonce,
            tuple(LoginControl.from_dict(item) for item in controls if isinstance(item, dict)),
            supervisor, entry['session_id'], phone_context.get('result') if phone_context.get('success') else None)

    @staticmethod
    def selector(plan, control):
        return '[data-hermes-vault-slot="' + plan.nonce + ':' + str(control.index) + '"]'

    @staticmethod
    def _best(candidates, description):
        if not candidates:
            raise AccessError('Open the ' + description + ' field before using Kernel fill.', 409)
        score = max(candidate.score for candidate in candidates)
        best = [candidate.control for candidate in candidates if candidate.score == score]
        if len(best) != 1:
            raise AccessError('The ' + description + ' field is ambiguous. Leave the intended form open.', 409)
        return best[0]

    def bindings(self, plan, record, *, code=False):
        from agent.vault_login_classifier import classify_login_control
        from .login import normalize_controls
        controls = normalize_controls(list(plan.controls))
        if code:
            from .kernel_otp import bindings
            return bindings(plan, record, selector=self.selector, best=self._best)
        classified = [item for item in (classify_login_control(control) for control in controls) if item]
        if record['login_method'] == 'sms':
            phone = self._best([item for item in classified if item.token == 'tel'], 'phone number')
            return [{'field': 'phone_number', 'selector': self.selector(plan, phone)}]
        targets = []
        identity_field = 'identifier' if 'identifier' in record['fields'] else 'username'
        for field, tokens in ((identity_field, {'email', 'username', 'tel'}),
                              ('password', {'current-password'})):
            matches = [item for item in classified if item.token in tokens]
            if matches and field in record['fields']:
                targets.append({'field': field, 'selector': self.selector(plan, self._best(matches, field))})
        if not targets:
            raise AccessError('Open the account login fields before using Kernel fill.', 409)
        return targets

    def _current(self, turn, plan):
        from tools import browser_vault_tool as native
        from .browser_context import authorize_supervisor, browser_task_id
        self.service.assert_private(turn)
        self.service.delegations.check_execution(turn)
        if browser_task_id(turn) != plan.task_id or native._ensure_supervisor(plan.task_id) is not plan.supervisor:
            raise AccessError('The browser binding changed before Kernel fill.', 403)
        authorize_supervisor(turn, plan.supervisor)
        if not native._active_binding_matches(plan.task_id, {'marker': plan.marker, 'origin': plan.origin}):
            raise AccessError('The browser page changed before Kernel fill.', 403)

    def _observe_fill(self, turn, plan, bindings, *, expected_phone=None):
        """Read only selected inputs privately to protect subsequent observations.

        Kernel does not return sensitive values. Any still-rendered value is
        registered solely with the backend redactor, never returned by a tool.
        This script performs no editing and cannot fall back to local filling.
        """
        from tools import browser_vault_tool as native
        from .browser_context import remember_redactions
        selectors = [field['selector'] for field in bindings]
        expression = ('(() => {const selectors = ' + json.dumps(selectors) +
            ';if(location.origin !== ' + json.dumps(plan.origin) +
            ' || window.__hermesNativePageBinding !== ' + json.dumps(plan.marker) +
            ')return JSON.stringify({binding_matches:false,targets:[]});'
            'return JSON.stringify({binding_matches:true,targets:selectors.map('
            's=>Array.from(document.querySelectorAll(s),e=>String(e.value||"")))});})()')
        observed = {'stage': 'unavailable', 'expected': len(bindings), 'matched': 0, 'nonempty': 0}
        try:
            result = native._eval_js_secret(plan.task_id, expression)
            data = native._parse_json_result(result.get('result')) if result.get('success') else None
            if isinstance(data, str):
                data = native._parse_json_result(data)
        except Exception:
            return observed
        if not isinstance(data, dict) or type(data.get('binding_matches')) is not bool:
            return observed
        if data['binding_matches'] is False:
            return observed | {'stage': 'binding_changed'}
        targets = data.get('targets')
        if (not isinstance(targets, list) or
                any(not isinstance(target, list) or any(not isinstance(value, str) for value in target)
                    for target in targets)):
            return observed
        # Values stay inside the trusted redactor. Only fixed stage/count
        # evidence may reach durable storage, logs or the model.
        from .kernel_otp import confirmed_digits, redactions, split_bindings
        values = [value for target in targets for value in target]
        try:
            remember_redactions(turn, redactions(values) if split_bindings(bindings) else
                                [value for value in values if value])
        except Exception:
            return observed
        if len(targets) != len(bindings):
            return observed | {'stage': 'target_missing'}
        observed['matched'] = sum(len(target) == 1 for target in targets)
        observed['nonempty'] = sum(len(target) == 1 and bool(target[0]) for target in targets)
        if any(len(target) > 1 for target in targets):
            return observed | {'stage': 'target_ambiguous'}
        if any(not target for target in targets):
            return observed | {'stage': 'target_missing'}
        if observed['nonempty'] != len(bindings):
            return observed | {'stage': 'empty'}
        if split_bindings(bindings) and not confirmed_digits(values, len(bindings)):
            return observed | {'stage': 'invalid_code'}
        if expected_phone is not None:
            from .login import normalize_phone
            try:
                matches = len(values) == 1 and normalize_phone(values[0]) == expected_phone
            except AccessError:
                matches = False
            if not matches:
                return observed | {'stage': 'value_mismatch'}
        return observed | {'stage': 'retained'}

    def _remember_filled(self, turn, plan, bindings):
        return self._observe_fill(turn, plan, bindings)['stage'] == 'retained'

    def _formatted_phone(self, turn, record, plan, bindings, access):
        """Adapt an owned ordinary phone field to an observed country selector.

        Passwords, OTPs and invited credentials stay opaque. The saved item is
        never rewritten, and the formatted value stays inside the backend.
        """
        if (not access or access.grant_id or access.owner != turn.source.user_id or
                record['kind'] != 'login' or record['login_method'] != 'sms' or
                len(bindings) != 1 or bindings[0]['field'] != 'phone_number'):
            return None
        remote = self.client.get_credential(record['vault_id'], record['key'], include_public_values=True)
        if (not remote or remote['id'] != record['remote_id'] or remote['key'] != record['key'] or
                str(remote['version']) != str(record['version']) or remote['state']['status'] != 'ready'):
            raise AccessError('The saved phone credential changed before filling.', 409)
        definition = next((field for field in remote['spec']['fields'] if field['name'] == 'phone_number'), None)
        field = remote['state']['fields'].get('phone_number', {})
        if not definition or definition['type'] != 'text' or definition['sensitive'] is not False:
            return None
        value = field.get('value')
        if value is None:
            return None  # Preserve the provider-only path for opaque legacy items.
        from .login import normalize_phone
        from .personal import personal_fills
        number = normalize_phone(value)
        fill = personal_fills(plan.controls, {'phone': {'phone_number': number}}, ['phone'],
                              phone_context=plan.phone_context)[0]
        target = next(control for control in plan.controls if control.index == fill['index'])
        if bindings[0]['selector'] != self.selector(plan, target):
            raise AccessError('The phone binding differs from the observed phone form.', 403)
        self._current(turn, plan)
        if self.record(turn.source.scope_id, access.owner, record['handle']) != record:
            raise AccessError('The saved phone credential changed before filling.', 409)
        self.remember_values(turn, [value, number, fill['value']])
        return fill['value'] if fill['value'] != value else None

    def _phone_control_unchanged(self, plan, bindings):
        """Read the original stamped control without tagging replacement nodes."""
        from tools import browser_vault_tool as native
        from agent.vault_login_classifier import LoginControl
        original = next(control for control in plan.controls
                        if self.selector(plan, control) == bindings[0]['selector'])
        expression = '''(() => {
          const forms = Array.from(document.forms);
          return JSON.stringify(Array.from(document.querySelectorAll(__SELECTOR__), element => {
            const labels = Array.from(element.labels || [], label => label.textContent || '');
            const ariaText = (element.getAttribute('aria-labelledby') || '').split(/\\s+/).filter(Boolean)
              .map(id => {const node = document.getElementById(id); return node ? node.textContent || '' : '';}).join(' ');
            const formIndex = element.form ? forms.indexOf(element.form) : -1;
            return {index: __INDEX__, autocomplete: element.autocomplete || '',
              formIndex: formIndex >= 0 ? formIndex : null,
              maxLength: element.maxLength > 0 ? element.maxLength : null,
              label: [...labels, element.getAttribute('aria-label') || '', ariaText,
                element.getAttribute('placeholder') || '', element.getAttribute('title') || ''].join(' '),
              name: [element.name, element.id].join(' '),
              type: element.tagName === 'SELECT' ? 'select' : element.type || ''};
          }));
        })()'''.replace('__SELECTOR__', json.dumps(bindings[0]['selector'])).replace('__INDEX__', str(original.index))
        result = native._eval_js(plan.task_id, expression)
        controls = native._parse_json_result(result.get('result')) if result.get('success') else None
        if isinstance(controls, str):
            controls = native._parse_json_result(controls)
        return (isinstance(controls, list) and len(controls) == 1 and isinstance(controls[0], dict)
                and LoginControl.from_dict(controls[0]) == original)

    def _dispatch_fill(self, turn, record, plan, bindings, attempt, phone, target_probe):
        if phone is None:
            return self.client.fill(record['vault_id'], record['key'], browser_id=plan.browser_id,
                page_url=plan.page_url, fields=bindings, timeout_ms=30000)
        # The original login's durable attempt has already been claimed. An
        # uncertain create or fill cannot cause a second submission on retry.
        key = 'phone-' + attempt['operation_id']
        temporary = None
        try:
            temporary = self.client.create_credential(record['vault_id'], key,
                [{'name': 'phone_number', 'type': 'text', 'required': True,
                  'sensitive': False, 'value': phone}], description='Formatted phone for one login attempt')
            if temporary['key'] != key or temporary['state']['status'] != 'ready':
                raise AccessError('The formatted phone was not ready for this attempt.', 409)
            self._current(turn, plan)
            if self.record(turn.source.scope_id, turn.source.user_id, record['handle']) != record:
                raise AccessError('The saved phone credential changed before filling.', 409)
            saved = self.client.get_credential(record['vault_id'], record['key'])
            if (not saved or saved['id'] != record['remote_id'] or
                    str(saved['version']) != str(record['version']) or saved['state']['status'] != 'ready'):
                raise AccessError('The saved phone credential changed before filling.', 409)
            from tools import browser_vault_tool as native
            from .personal import PHONE_CONTEXT_JS
            context = native._eval_js(plan.task_id, PHONE_CONTEXT_JS)
            targets = native._eval_js(plan.task_id, target_probe)
            if (not self._phone_control_unchanged(plan, bindings) or
                    not context.get('success') or context.get('result') != plan.phone_context or
                    not targets.get('success') or targets.get('result') is not True):
                raise AccessError('The phone form changed before filling.', 409)
            return self.client.fill(record['vault_id'], key, browser_id=plan.browser_id,
                page_url=plan.page_url, fields=bindings, timeout_ms=30000)
        finally:
            if temporary and temporary.get('key') == key:
                try:
                    current = self.client.get_credential(record['vault_id'], key)
                    if current and current['id'] == temporary['id']:
                        self.client.delete_credential(record['vault_id'], key)
                except Exception:
                    pass  # Cleanup never permits redispatch or changes the saved login.

    def assert_personal_browser(self, turn):
        cloud = self.service.cloud_browser
        selected = getattr(cloud, 'profile_principal', None)
        principal = selected(turn) if callable(selected) else None
        if principal and principal['kind'] == 'shared':
            raise AccessError('Personal details cannot be filled into a shared browser. Use your personal browser for those details.', 403)

    def _authorize_fill_profile(self, turn, access):
        cloud = self.service.cloud_browser
        selected = getattr(cloud, 'profile_principal', None)
        principal = selected(turn) if callable(selected) else None
        if principal is None:
            return
        if principal['kind'] == 'shared' and access is None:
            raise AccessError('Only the selected shared credential can fill this shared browser.', 403)
        cloud.profiles.authorize(turn, principal, access)

    def _fill(self, turn, record, plan, bindings, *, collection=None, operation_id=None, access=None):
        self._authorize_fill_profile(turn, access)
        self._current(turn, plan)
        scope = self.scope(turn.source.scope_id, turn.source.user_id)
        if access and access.grant_id:
            renewed = self.service.delegations.resolve(turn, access.handle)
            if renewed != access:
                raise AccessError('The shared credential permission changed before filling.', 403)
            self.service.delegations.record_browser_use(turn, access)
        current = self.record(scope[0], access.owner if access else scope[1], record['handle'])
        if collection:
            expected = (collection['vault_id'], collection['key'])
            if ((record['vault_id'], record['key']) != expected or
                    (collection['team'], collection['owner'], collection['home'], collection['task_id'],
                     collection['handle'], collection['origin']) !=
                    (scope[0], scope[1], str(scope[2]), turn.task_id, access.handle if access else record['handle'], plan.origin)):
                raise AccessError('The Kernel code item does not belong to this task.', 403)
        elif any(current.get(key) != record.get(key) for key in
                 ('vault_id', 'key', 'remote_id', 'version', 'kind', 'origin')):
            raise AccessError('The Kernel item changed before filling.', 403)
        if current['kind'] != 'personal' and current['origin'] != plan.origin:
            raise AccessError('The Kernel item belongs to another website.', 403)
        from tools import browser_vault_tool as native
        # Bindings are restricted to unique, editable controls in the observed
        # main document. Kernel's cross-frame selector search must not widen the
        # authorized account origin to an embedded third-party login.
        target_probe = '''(() => {
          if (location.origin !== __ORIGIN__ || window.__hermesNativePageBinding !== __MARKER__) return false;
          return __SELECTORS__.every(selector => {
            const targets = document.querySelectorAll(selector);
            if (targets.length !== 1) return false;
            const el = targets[0];
            return ['INPUT','TEXTAREA','SELECT'].includes(el.tagName) && el.isConnected &&
              !el.disabled && !el.readOnly && el.getClientRects().length > 0;
          });
        })()'''.replace('__ORIGIN__', json.dumps(plan.origin)).replace('__MARKER__', json.dumps(plan.marker)).replace(
            '__SELECTORS__', json.dumps([item['selector'] for item in bindings]))
        targets = native._eval_js(plan.task_id, target_probe)
        if not targets.get('success') or targets.get('result') is not True:
            raise AccessError('Kernel fill targets changed or are outside the observed form.', 403)
        phone = self._formatted_phone(turn, record, plan, bindings, access) if not collection else None
        if access:
            # Cookie access must stay tied to the credential even if the fill
            # response is lost or the website immediately submits the form.
            self.service.cloud_browser.bind_access(turn, access)
        self._arm_privacy(turn, plan, bindings, sensitive=bool(access and access.grant_id))
        digest = hashlib.sha256(json.dumps([plan.browser_id, plan.page_url, plan.marker, bindings], sort_keys=True).encode()).hexdigest()
        if collection:
            attempt = self.metadata.claim_fill(collection['request_id'], collection['version'],
                team=scope[0], owner=scope[1], home=scope[2], task_id=turn.task_id,
                handle=collection['handle'], origin=plan.origin, binding_digest=digest)
        else:
            identity = [
                turn.task_id, turn.message_id, access.handle if access else record['handle'], plan.origin,
                record['version']]
            if operation_id is None:
                previous_key = 'fill-' + hashlib.sha256(json.dumps(identity).encode()).hexdigest()
                with self.service.store.connection() as db:
                    if db.execute('SELECT 1 FROM kernel_fill_attempts WHERE operation_id=?', (previous_key,)).fetchone():
                        raise AccessError('A previous version already dispatched this fill. Inspect its outcome; it cannot be replayed.', 409)
                operation_id = 'fill-' + hashlib.sha256(json.dumps(
                    identity + [sorted({item['field'] for item in bindings})]).encode()).hexdigest()
            attempt = self.metadata.begin_attempt(operation_id, team=scope[0], owner=scope[1],
                home=scope[2], task_id=turn.task_id, handle=access.handle if access else record['handle'], origin=plan.origin,
                version=record['version'], binding_digest=digest,
                **({'grant_id': access.grant_id} if access and access.grant_id else {}))
        from .fill_outcome import validate_outcome
        success, failure = False, 'unknown'
        outcome = {'provider': None, 'readback': {'stage': 'unavailable',
                   'expected': len(bindings), 'matched': 0, 'nonempty': 0}}
        try:
            result = self._dispatch_fill(turn, record, plan, bindings, attempt, phone, target_probe)
            outcome = validate_outcome(outcome | {'provider':
                {'status': result.get('status'), 'fields': result.get('fields')}})
        except Exception:
            # A timeout may follow a write. The durable dispatch stays spent.
            failure = 'unknown'
        else:
            success = outcome['provider']['status'] == 'completed'
            failure = ('unknown' if outcome['provider']['status'] == 'unknown' else
                'partial' if any(field['status'] == 'filled' for field in outcome['provider']['fields'])
                else 'input_rejected')
        try:
            try:
                outcome['readback'] = self._observe_fill(turn, plan, bindings, expected_phone=phone)
            except Exception:
                # A private observation failure cannot erase a known provider
                # acknowledgement or expose its raw exception.
                pass
            # A provider acknowledgement can precede a controlled form reset.
            # Require nonempty bound controls before reporting a confirmed fill.
            # Navigation/auto-submit is left for a fresh website observation.
            if success and outcome['readback']['stage'] != 'retained':
                success = False
                failure = {'empty': 'value_not_retained', 'unavailable': 'readback_unavailable'}.get(
                    outcome['readback']['stage'], outcome['readback']['stage'])
        finally:
            self.metadata.finish_attempt(attempt['operation_id'], team=scope[0], owner=scope[1], home=scope[2],
                success=success, failure=None if success else failure, outcome=outcome)
        if not success:
            provider_status = outcome['provider']['status'] if outcome['provider'] else 'unconfirmed'
            error = AccessError('Kernel fill was not confirmed: provider=' + provider_status +
                '; readback=' + outcome['readback']['stage'] + '. Inspect the existing page. '
                'A missing or empty field does not prove the saved value is invalid. '
                'Do not repeat the fill or request another code automatically.', 409)
            error.kernel_fill_outcome = outcome
            raise error
        return {'success': True, 'provider': 'kernel', 'filled_fields': len(bindings),
                'fill_outcome': outcome,
                'next': 'Inspect the website to verify acceptance and continue the task. Kernel fill does not confirm login or submit an order.'}

    def fill_item(self, turn, record, bindings, origin, operation_id=None, *, plan=None):
        self.assert_personal_browser(turn)
        plan = plan or self.inspect(turn, origin)
        if plan.origin != origin:
            raise AccessError('The Kernel fill plan belongs to a different origin.', 403)
        if not isinstance(bindings, list) or not bindings or any(
                set(item) != {'field', 'selector'} or item['field'] not in record['fields']
                for item in bindings):
            raise AccessError('Use only declared Kernel fields and observed selectors.')
        return self._fill(turn, record, plan, bindings, operation_id=operation_id)

    def fill_values(self, turn, origin, fills, nonce, *, plan=None):
        """Format ordinary personal details, then let Kernel perform every write."""
        self.assert_personal_browser(turn)
        plan = plan or self.inspect(turn, origin)
        if plan.origin != origin or plan.nonce != nonce or not fills:
            raise AccessError('The personal form changed before Kernel fill.', 403)
        self._current(turn, plan)
        scope = self.scope(turn.source.scope_id, turn.source.user_id)
        purpose = sorted((item['index'], item['token']) for item in fills)
        operation_id = 'personal-' + hashlib.sha256(json.dumps([
            turn.task_id, turn.message_id, origin, purpose]).encode()).hexdigest()
        # Deterministic key permits reconciliation after unknown creation. A
        # previously dispatched fill is refused before any temporary item POST.
        if self.metadata.attempt(operation_id, team=scope[0], owner=scope[1], home=scope[2]):
            raise AccessError('This personal fill was already attempted. Inspect the existing form.', 409)
        vault = self.ensure_vault(*scope[:2])
        definitions = [{'name': 'field_' + str(index), 'type': 'text', 'required': True,
                        'sensitive': False, 'value': item['value']} for index, item in enumerate(fills)]
        key = operation_id
        remote = self.client.get_credential(vault['id'], key)
        if remote is None:
            remote = self.client.create_credential(vault['id'], key, definitions,
                description=urlsplit(origin).hostname)
        handle = key
        record = self._remote_record(*scope, handle, key, remote, kind='personal',
                                    label='Formatted personal details', origin=origin)
        bindings = [{'field': 'field_' + str(index), 'selector':
            '[data-hermes-vault-slot="' + nonce + ':' + str(item['index']) + '"]'}
            for index, item in enumerate(fills)]
        try:
            return self._fill(turn, record, plan, bindings, operation_id=operation_id)
        finally:
            if self.metadata.attempt(operation_id, team=scope[0], owner=scope[1], home=scope[2]):
                try:
                    self.client.delete_credential(vault['id'], key)
                    self.metadata.delete_item(*scope, handle)
                except Exception:
                    pass

    def fill_login(self, turn, access, *, fields=None):
        record = self.record(turn.source.scope_id, access.owner, access.meta.id)
        if record['kind'] != 'login' or record['status'] != 'ready':
            raise AccessError('Choose a ready Kernel login.', 409)
        plan = self.inspect(turn, record['origin'])
        bindings = fields if fields is not None else self.bindings(plan, record)
        if not isinstance(bindings, list) or not bindings or any(
                set(item) != {'field', 'selector'} or item['field'] not in record['fields'] for item in bindings):
            raise AccessError('Use only this login\'s declared fields and observed selectors.')
        return self._fill(turn, record, plan, bindings, access=access)

    def _waiting(self, turn, *, kind, origin, handle=None, login_method=None):
        scope = self.scope(turn.source.scope_id, turn.source.user_id)
        with self.service.store.connection() as db:
            row = db.execute("SELECT r.* FROM requests r JOIN kernel_collections k ON k.request_id=r.id WHERE r.team=? AND r.owner=? AND r.home=? AND r.task_id=? AND r.kind=? AND r.origin=? AND (? IS NULL OR r.handle=?) AND (? IS NULL OR r.login_method=?) AND r.status='waiting' AND r.expires>? AND k.state='pending' ORDER BY r.created DESC LIMIT 1",
                (*map(str, scope), turn.task_id, kind, origin, handle, handle,
                 login_method, login_method, self.service.store.clock())).fetchone()
            return dict(row) if row else None

    def _authorize_new_code(self, turn, access=None):
        """A model flag cannot turn an automatic resume into owner approval.

        The gateway owns Binding.message_id and message. Internal continuations
        use non-Slack event IDs; only an authenticated private owner message
        explicitly asking for another verification attempt, or the resume event
        of the owner's Retry button for these exact details, can pass this guard.
        """
        import re
        from gateway.config import Platform
        from .owner_approval import OwnerApprovalRequired, is_event
        self.service.assert_private(turn)
        self.service.delegations.check_execution(turn)
        event = turn.message_id
        if turn.source.platform != Platform.SLACK:
            raise AccessError('A fresh verification form requires an explicit new message from the owner.', 403)
        from .verification_retry import affirmative, answering_retry_prompt, retry_request
        rows = []
        if access is not None:
            scope = self.scope(turn.source.scope_id, turn.source.user_id)
            with self.service.store.connection() as db:
                rows = db.execute("SELECT id,status,expires,gateway_event_id FROM requests WHERE "
                    "team=? AND owner=? AND home=? AND task_id=? AND kind='code' AND handle=? "
                    "AND origin=? AND login_method=? AND grant_id IS ? AND approver IS ? "
                    "ORDER BY created DESC",
                    (*map(str, scope), turn.task_id, access.handle, access.meta.origin, access.meta.login_method,
                     access.grant_id, access.owner if access.grant_id else None)).fetchall()

        def details():
            # The previous request is the generation this approval retries.
            # Requests made by the current event do not change it.
            return {'handle': access.handle, 'origin': access.meta.origin,
                    'login_method': access.meta.login_method, 'grant_id': access.grant_id,
                    'approver': access.owner if access.grant_id else None,
                    'previous': next((row['id'] for row in rows if row['gateway_event_id'] != event), None)}

        def refused(message):
            if access is None:
                return AccessError(message, 403)
            return OwnerApprovalRequired('code_retry', details(), message)

        approval_event = is_event(event)
        if not approval_event and (not isinstance(event, str) or
                not re.fullmatch(r'[0-9]{10,}\.[0-9]{6}', event)):
            raise refused('A fresh verification form requires an explicit new message from the owner.')
        if access is not None:
            for row in rows:
                if row['gateway_event_id'] != event:
                    continue
                collection = self.metadata.collection(row['id'], team=scope[0], owner=scope[1], home=scope[2])
                if not (row['status'] == 'waiting' and row['expires'] > self.service.store.clock() and
                        collection is not None and collection['state'] == 'pending'):
                    raise AccessError('This message already authorized a verification attempt. Its code cannot be replayed or replaced automatically.', 403)
        refusal = ('A new verification attempt needs a direct owner retry request or an affirmative answer to this task\'s pending verification question. Ordinary wording is accepted; do not ask for an exact phrase.')
        if approval_event:
            if access is not None and self.service.approvals.consume(turn, 'code_retry', details()):
                return
            raise refused(refusal)
        message = turn.owner_message
        if retry_request(message):
            return
        prior = rows[0] if rows else None
        prior_event = prior['gateway_event_id'] if prior else None
        older = prior_event is not None and prior_event != event
        if older and re.fullmatch(r'[0-9]{10,}\.[0-9]{6}', prior_event):
            older = tuple(map(int, prior_event.split('.'))) < tuple(map(int, event.split('.')))
        if (affirmative(message) and answering_retry_prompt(turn.conversation) and prior and
                older and prior['status'] != 'cancelled'):
            return
        raise refused(refusal)

    async def _collect(self, turn, *, kind, label, origin, handle, fields, login_method='password', access=None):
        scope = self.scope(turn.source.scope_id, turn.source.user_id)
        self.ensure_vault(*scope[:2])
        row = self._waiting(turn, kind=kind, origin=origin, handle=handle, login_method=login_method)
        if row is None:
            with self.service.store.connection() as db:
                uncertain = db.execute("SELECT 1 FROM requests WHERE team=? AND owner=? AND home=? AND task_id=? AND kind=? AND origin=? AND login_method=? AND status IN ('kernel_creating','kernel_create_unknown') LIMIT 1",
                    (*map(str, scope), turn.task_id, kind, origin, login_method)).fetchone()
            if uncertain:
                raise AccessError('A previous Kernel collection creation is unconfirmed. Inspect that request before creating another form.', 409)
            row = self.service.store.create(team=scope[0], owner=scope[1], home=scope[2],
                task_id=turn.task_id, source=turn.source.to_dict(), task=self.service.channel_tasks.request_context(turn),
                kind=kind, label=label[:120], origin=origin, handle=handle, login_method=login_method,
                gateway_event_id=turn.message_id, grant_id=access.grant_id if access else None,
                approver=access.owner if access and access.grant_id else None)
            vault = self.ensure_vault(*scope[:2])
            key = 'request-' + row['id']
            with self.service.store.connection() as db:
                changed = db.execute("UPDATE requests SET status='kernel_creating' WHERE id=? AND status='waiting'", (row['id'],)).rowcount
            if changed != 1:
                raise AccessError('This Kernel collection is already being created.', 409)
            try:
                remote = await asyncio.to_thread(self.client.create_credential, vault['id'], key, fields,
                                                 description=urlsplit(origin).hostname)
            except (Exception, asyncio.CancelledError) as error:
                with self.service.store.connection() as db:
                    db.execute("UPDATE requests SET status='kernel_create_unknown' WHERE id=? AND status='kernel_creating'", (row['id'],))
                if isinstance(error, asyncio.CancelledError):
                    raise
                raise AccessError('Kernel collection creation could not be confirmed. It will not be repeated automatically.', 503) from None
            actual_handle = handle or 'kernel-' + row['id']
            if kind in {'login', 'api_key'}:
                self._remote_record(*scope, actual_handle, key, remote, kind=kind, label=label,
                                    origin=origin, login_method=login_method)
                with self.service.store.connection() as db:
                    db.execute('UPDATE requests SET handle=? WHERE id=?', (actual_handle, row['id']))
                row['handle'] = actual_handle
            with self.service.store.connection() as db:
                changed = db.execute("UPDATE requests SET status=? WHERE id=? AND status='kernel_creating'", (
                    'cancelled' if kind == 'login' and remote['state']['status'] == 'ready' else 'waiting', row['id']))
                if changed.rowcount != 1:
                    raise AccessError('This Kernel collection creation is no longer active. Its result cannot reopen the request.', 409)
            if kind == 'login' and remote['state']['status'] == 'ready':
                return {'status': 'access_ready', 'provider': 'kernel', 'handle': actual_handle,
                        'next': 'Use clanker_vault_fill for this saved login.'}
            self.metadata.put_collection(row['id'], *scope, turn.task_id, actual_handle,
                origin, vault['id'], key, remote['id'], remote['version'])
        if kind == 'code':
            from .kernel_otp import verify_schema
            collection = self.metadata.collection(row['id'], team=scope[0], owner=scope[1], home=scope[2])
            remote = self.client.get_credential(collection['vault_id'], collection['key'])
            if not remote or remote['id'] != collection['item_id']:
                raise AccessError('The Kernel verification item changed.', 409)
            verify_schema(remote, fields)
        delivery = await self.service.deliver_link(row)
        delivery_note = ('The private collection message was already sent; this call did not resend it.'
                         if delivery and delivery['status'] == 'already_sent' else 'Complete the private Kernel collection form.')
        return {'status': 'waiting_for_owner', 'provider': 'kernel', 'request_id': row['id'],
                'link_delivery': delivery,
                'next': delivery_note + ' Use link_delivery.message_url, when present, to point to the private Slack message. End this turn. Saving it resumes this task automatically.'}

    async def request_access(self, turn, *, label='', identifier='', kind='login', origin='', login_method='auto', use_primary=True):
        try:
            self.service.assert_private(turn)
        except AccessError:
            return await self.service.move_private(turn)
        if kind == 'api_key':
            from .kernel_store import _origin
            origin = _origin(origin)
            if not isinstance(label, str) or not label.strip() or identifier or login_method != 'auto':
                raise AccessError('Kernel API-key collection requires a service title and exact HTTPS origin.')
            return await self._collect(turn, kind='api_key', label=label.strip(), origin=origin,
                handle=None, fields=[{'name': 'api_key', 'label': 'API key', 'type': 'text',
                                     'required': True, 'sensitive': False}])
        if kind != 'login':
            raise AccessError('Kernel collection supports logins and API keys.', 409)
        if origin or login_method not in {'auto', 'password', 'sms'} or type(use_primary) is not bool:
            raise AccessError('Login collection must use the observed browser form.')
        plan = await asyncio.to_thread(self.inspect, turn)
        from agent.vault_login_classifier import classify_login_control
        classified = [item for item in (classify_login_control(control) for control in plan.controls) if item]
        if not classified:
            raise AccessError('Open the login form before collecting credentials.', 409)
        method = login_method
        if method == 'auto':
            method = 'sms' if any(item.token == 'tel' for item in classified) and not any(
                item.token == 'current-password' for item in classified) else 'password'
        saved = [item for item in self.native_store(turn.source.scope_id, turn.source.user_id).list_items()
                 if item.origin == plan.origin and item.login_method == method]
        if use_primary and len(saved) == 1:
            return {'status': 'access_ready', 'handle': saved[0].id, 'provider': 'kernel',
                    'next': 'Use clanker_vault_fill for this saved login.'}
        if use_primary and len(saved) > 1:
            return {'status': 'account_choice_required', 'handles': [item.id for item in saved],
                    'next': 'Ask which saved account to use; do not collect its details again.'}
        fields = ([{'name': 'phone_number', 'label': 'Phone number', 'type': 'text', 'required': True, 'sensitive': False}]
                  if method == 'sms' else
                  [{'name': 'identifier', 'label': 'Email or username', 'type': 'text', 'required': True, 'sensitive': False},
                   {'name': 'password', 'label': 'Password', 'type': 'password', 'required': True, 'sensitive': True}])
        if method == 'sms' and use_primary:
            primary = self.service.personal.store(*self.scope(turn.source.scope_id, turn.source.user_id)[:2]).values('phone')
            if primary:
                from .personal import personal_fills
                fills = personal_fills(list(plan.controls), {'phone': primary}, ['phone'], phone_context=plan.phone_context)
                fields[0]['value'] = fills[0]['value']
        return await self._collect(turn, kind='login', label=urlsplit(plan.origin).hostname,
            origin=plan.origin, handle=None, fields=fields, login_method=method)

    def _retire_expired_code_creations(self, turn, access, record, *, request_new):
        """A new owner attempt may retire expired, never-delivered creations.

        This changes only local lifecycle metadata. It never retries an old
        provider creation, collects a code, resends SMS or dispatches a fill.
        """
        scope = self.scope(turn.source.scope_id, turn.source.user_id)
        with self.service.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            rows = db.execute("SELECT id,expires,gateway_event_id FROM requests WHERE "
                "team=? AND owner=? AND home=? AND task_id=? AND kind='code' AND handle=? "
                "AND origin=? AND login_method=? AND grant_id IS ? AND approver IS ? "
                "AND status IN ('kernel_creating','kernel_create_unknown')",
                (*map(str, scope), turn.task_id, access.handle, record['origin'], record['login_method'],
                 access.grant_id, access.owner if access.grant_id else None)).fetchall()
            if not rows:
                return
            now = self.service.store.clock()
            if (not request_new or any(row['expires'] > now or row['gateway_event_id'] == turn.message_id
                                       for row in rows)):
                raise AccessError('The earlier verification form creation is unconfirmed. After it expires, a new owner verification request can open a fresh form; the old creation will not be replayed.', 409)
            for row in rows:
                db.execute("UPDATE requests SET status='kernel_create_expired' WHERE id=? "
                           "AND status IN ('kernel_creating','kernel_create_unknown')", (row['id'],))

    async def request_code(self, turn, access, *, request_new=False):
        if type(request_new) is not bool:
            raise AccessError('Choose whether this is an explicitly requested new verification attempt.')
        if request_new:
            self._authorize_new_code(turn, access)
        record = await asyncio.to_thread(self.record, turn.source.scope_id, access.owner, access.meta.id)
        plan = await asyncio.to_thread(self.inspect, turn, record['origin'])
        from .kernel_otp import collection_fields
        fields = collection_fields(self.bindings(plan, record | {'fields': ['code']}, code=True))
        self._retire_expired_code_creations(turn, access, record, request_new=request_new)
        scope = self.scope(turn.source.scope_id, turn.source.user_id)
        prior = [item for item in self.metadata.list_collections(*scope) if
                 item['task_id'] == turn.task_id and item['handle'] == access.handle and item['origin'] == record['origin']]
        if prior and not request_new and not self._waiting(turn, kind='code', origin=record['origin'], handle=access.handle):
            raise AccessError('A code was already collected for this verification. Inspect the page; request a fresh form only after an explicit new verification attempt.', 409)
        return await self._collect(turn, kind='code', label=urlsplit(record['origin']).hostname + ' verification',
            origin=record['origin'], handle=access.handle, login_method=record['login_method'],
            fields=fields, access=access)

    def enter_code(self, turn, access, *, request_new=False):
        home = self.service.private_home(turn.source.scope_id, turn.source.user_id)
        with self.service.lock_for(home):
            result = self._enter_code_locked(turn, access, request_new=request_new)
        if result is not None:
            return result
        # Never hold the threading.RLock while awaiting work on another
        # thread. request_code performs a fresh, separately locked inspection.
        return self.service.call(self.request_code(turn, access, request_new=request_new))

    def _enter_code_locked(self, turn, access, *, request_new=False):
        if type(request_new) is not bool:
            raise AccessError('Choose whether this is an explicitly requested new verification attempt.')
        if request_new:
            self._authorize_new_code(turn, access)
        record = self.record(turn.source.scope_id, access.owner, access.meta.id)
        plan = self.inspect(turn, record['origin'])
        bindings = self.bindings(plan, record, code=True)
        if 'totp' in record['fields']:
            return self._fill(turn, record, plan, bindings, access=access)
        scope = self.scope(turn.source.scope_id, turn.source.user_id)
        collections = [item for item in self.metadata.list_collections(*scope) if item['task_id'] == turn.task_id
            and item['handle'] == access.handle and item['origin'] == record['origin'] and item['state'] == 'ready']
        if not collections or request_new:
            return None
        collection = collections[-1]
        remote = self.client.get_credential(collection['vault_id'], collection['key'])
        if not remote or remote['id'] != collection['item_id'] or str(remote['version']) != collection['version']:
            raise AccessError('The Kernel verification item changed; this code cannot be replayed.', 409)
        from .kernel_otp import collection_fields, verify_schema
        verify_schema(remote, collection_fields(bindings))
        code_record = record | {'vault_id': collection['vault_id'], 'key': collection['key']}
        try:
            return self._fill(turn, code_record, plan, bindings, collection=collection, access=access)
        finally:
            # An OTP item is single-use even after an uncertain dispatch.
            operation_id = 'collection:' + collection['request_id'] + ':' + collection['version']
            if self.metadata.attempt(operation_id, team=scope[0], owner=scope[1], home=scope[2]):
                try:
                    self.client.delete_credential(collection['vault_id'], collection['key'])
                except Exception:
                    pass

    def collection_link(self, row):
        collection = self.metadata.collection(row['id'], team=row['team'], owner=row['owner'], home=row['home'])
        if not collection or collection['state'] != 'pending':
            raise AccessError('This Kernel collection link is no longer waiting.', 410)
        remote = self.client.collect(collection['vault_id'], collection['key'])
        action = remote.get('action', {})
        if action.get('name') != 'collect' or not action.get('url'):
            raise AccessError('Kernel did not return a private collection form.', 503)
        return action['url']

    def poll(self):
        with self.service.store.connection() as db:
            rows = [dict(row) for row in db.execute("SELECT r.* FROM requests r JOIN kernel_collections k ON k.request_id=r.id WHERE r.status='waiting' AND (k.state IN ('pending','ready') OR r.kind='code' AND k.state='expired')")]
        for row in rows:
            try:
                self.service.validate_member(row['team'], row['owner'])
                collection = self.metadata.collection(row['id'], team=row['team'], owner=row['owner'], home=row['home'])
                if collection['state'] == 'expired':
                    self.metadata.retire_expired_code_request(row['id'], team=row['team'], owner=row['owner'], home=row['home'])
                    continue
                if row['expires'] <= self.service.store.clock():
                    self.metadata.update_collection_state(row['id'], 'expired', team=row['team'], owner=row['owner'], home=row['home'])
                    self.metadata.retire_expired_code_request(row['id'], team=row['team'], owner=row['owner'], home=row['home'])
                    self.client.delete_credential(collection['vault_id'], collection['key'])
                    continue
                remote = self.client.get_credential(collection['vault_id'], collection['key'])
                if not remote or remote['id'] != collection['item_id'] or remote['state']['status'] != 'ready':
                    continue
                if row['kind'] in {'login', 'api_key'}:
                    self.metadata.update_item_status(row['team'], row['owner'], row['home'], row['handle'], 'ready', version=remote['version'])
                self.metadata.update_collection_ready(row['id'], team=row['team'], owner=row['owner'], home=row['home'], version=remote['version'])
            except Exception:
                # Read-only polling can retry. A fill is never dispatched here.
                continue
