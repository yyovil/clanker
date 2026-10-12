"""Pinned Kernel plugin with backend-scoped credentials and no shared profiles."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
from types import SimpleNamespace
from urllib.parse import quote
import uuid

import requests
from dotenv import dotenv_values

from vault.store import AccessError
from .kernel_diagnostics import current, operation
from .kernel_telemetry import validate_telemetry, telemetry_matches

COMMIT = '0f5a8e80707957a40b6a1e5512b2a391671e9317'
PROVIDER_SHA256 = '475e97022b4015beda641028cedccbfa0333d7dea09995a1a9f99edd903a8683'
API_URL = 'https://api.onkernel.com'


def validate_proxy_policy(value):
    if (not isinstance(value, dict) or set(value) != {'id', 'type', 'country'} or
            not isinstance(value.get('id'), str) or
            re.fullmatch(r'[A-Za-z0-9_-]{1,200}', value['id']) is None or
            value.get('type') != 'residential' or value.get('country') != 'IN'):
        raise AccessError('The protected Kernel proxy policy is unsupported.', 503)
    return dict(value)


def validate_vault_attachment(value):
    if (not isinstance(value, dict) or set(value) != {'id'} or
            not isinstance(value.get('id'), str) or
            re.fullmatch(r'[A-Za-z0-9_-]{1,200}', value['id']) is None):
        raise AccessError('The requester Kernel vault binding is unsupported.', 503)
    return dict(value)


def validate_vault_attachments(value):
    if not isinstance(value, list) or not value or len(value) > 100:
        raise AccessError('The requester Kernel vault bindings are unsupported.', 503)
    attachments = [validate_vault_attachment(item) for item in value]
    if len({item['id'] for item in attachments}) != len(attachments):
        raise AccessError('The requester Kernel vault bindings contain duplicates.', 503)
    return sorted(attachments, key=lambda item: item['id'])


def validate_profile_attachment(value):
    if (not isinstance(value, dict) or set(value) != {'name', 'save_changes'} or
            not isinstance(value.get('name'), str) or
            re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}', value['name']) is None or
            type(value.get('save_changes')) is not bool):
        raise AccessError('The authenticated Kernel profile binding is unsupported.', 503)
    return dict(value)


def validate_kernel_settings(settings):
    fields = {'enabled', 'provider', 'plugin_path', 'plugin_commit'}
    if (not isinstance(settings, dict) or set(settings) not in (fields, fields | {'proxy'}) or
            settings.get('enabled') is not True or settings.get('provider') != 'kernel'):
        raise AccessError('The Kernel browser configuration has unsupported fields.', 503)
    if 'proxy' in settings:
        validate_proxy_policy(settings['proxy'])
    return settings


def valid_session_record(created):
    return (isinstance(created, dict) and
        isinstance(created.get('bb_session_id'), str) and
        re.fullmatch(r'[A-Za-z0-9_-]{1,200}', created['bb_session_id']) is not None and
        isinstance(created.get('cdp_url'), str) and
        isinstance(created.get('session_name'), str) and
        isinstance(created.get('features'), dict))


class KernelClient:
    def __init__(self, home, settings):
        validate_kernel_settings(settings)
        self.home = Path(home).resolve(strict=True)
        self.proxy_policy = validate_proxy_policy(settings['proxy']) if 'proxy' in settings else None
        plugin = Path(settings['plugin_path']).resolve(strict=True)
        if settings.get('plugin_commit') != COMMIT or not plugin.is_relative_to(self.home / '.clanker-cloud'):
            raise AccessError('The reviewed Kernel plugin is not installed in the protected backend.', 503)
        source = plugin / 'provider.py'
        if hashlib.sha256(source.read_bytes()).hexdigest() != PROVIDER_SHA256:
            raise AccessError('Kernel plugin code changed; review it before activation.', 503)
        spec = importlib.util.spec_from_file_location('clanker_kernel_provider', source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # Adapt the upstream plugin's environment reader without changing the
        # gateway's process environment. Only the transport's service key is
        # available; profile persistence and API overrides stay absent. Proxy
        # selection is a protected fixed ID, never an environment/name lookup.
        client = self
        class Environment:
            def get(self, name, default=None):
                return client.key() if name == 'KERNEL_API_KEY' else default
        module.os = SimpleNamespace(environ=Environment())
        self.http = requests.Session()
        self.http.trust_env = False
        module.requests = SimpleNamespace(
            RequestException=requests.RequestException,
            get=lambda *a, **kw: self._request('GET', *a, allow_redirects=False, **kw),
            post=lambda *a, **kw: self._request('POST', *a, allow_redirects=False, **kw),
            delete=lambda *a, **kw: self._request('DELETE', *a, allow_redirects=False, **kw),
        )
        self.provider = module.KernelBrowserProvider()
        self.provider._resolve_proxy_id = lambda config: (
            self.proxy_policy['id'] if self.proxy_policy is not None else None)

    def key(self):
        key = dotenv_values(self.home / '.env', interpolate=False).get('KERNEL_API_KEY')
        if not key:
            raise AccessError('The protected Kernel service key is missing.', 503)
        diagnostic = current(self)
        if diagnostic is not None:
            diagnostic.remember_secret(key)
        return key

    def _request(self, method, url, *args, **kwargs):
        with operation(self, 'http_request') as diagnostic:
            return diagnostic.request(method, url, *args, **kwargs)

    def create_session(self, task_id, *, vault=None, profile=None, telemetry=None):
        with operation(self, 'create_session', task_id) as diagnostic:
            try:
                attachment = validate_vault_attachments([vault] if isinstance(vault, dict) else vault) if vault is not None else None
                profile = validate_profile_attachment(profile) if profile is not None else None
                telemetry = validate_telemetry(telemetry) if telemetry is not None else None
                if self.proxy_policy is not None:
                    self.verify_proxy(self.proxy_policy)
                created = (self._create_attached_session(task_id, attachment, profile=profile, telemetry=telemetry)
                    if attachment is not None or profile is not None or telemetry is not None
                    else self.provider.create_session(task_id))
                if not valid_session_record(created):
                    raise AccessError('Kernel did not confirm a browser session.', 502)
                return created
            except AccessError as error:
                diagnostic.failure(error, 'invalid_response' if error.status == 502 else 'configuration_error')
                result = error if getattr(error, 'diagnostic_ref', None) == diagnostic.reference else (
                    diagnostic.access_error(str(error), error.status))
            except Exception as error:
                diagnostic.failure(error)
                result = diagnostic.access_error('Kernel browser creation failed. No local fallback was attempted.', 503)
            result.browser_dispatch_attempted = any(request['method'] == 'POST' and request['route'] == '/browsers'
                for request in diagnostic.event['requests'])
            raise result from None

    def _create_attached_session(self, task_id, vault, *, profile=None, telemetry=None):
        # The hash-pinned upstream provider predates vault attachments. Keep its
        # browser defaults, but pass the authenticated owner's attachment in a
        # per-call request rather than mutable provider/environment state.
        name = 'hermes_' + task_id + '_' + uuid.uuid4().hex[:8]
        body = {'stealth': True, 'headless': False, 'name': name,
            'timeout_seconds': 600}
        if vault is not None:
            body['vaults'] = vault
        if profile is not None:
            body['profile'] = validate_profile_attachment(profile)
        if telemetry is not None:
            body['telemetry'] = validate_telemetry(telemetry)
        if self.proxy_policy is not None:
            body['proxy_id'] = self.proxy_policy['id']
        response = self._request('POST', API_URL + '/browsers',
            headers={'Authorization': 'Bearer ' + self.key(), 'Content-Type': 'application/json'},
            json=body, timeout=30, allow_redirects=False)
        if response.status_code not in (200, 201):
            raise AccessError('Kernel browser creation was not confirmed.', 503)
        try:
            remote = response.json()
        except ValueError:
            raise AccessError('Kernel returned an invalid browser record.', 502) from None
        if not isinstance(remote, dict):
            raise AccessError('Kernel returned an invalid browser record.', 502)
        if telemetry is not None and not telemetry_matches(remote.get('telemetry'), telemetry):
            raise AccessError('Kernel did not confirm the reviewed telemetry selection.', 502)
        return {'session_name': name, 'bb_session_id': remote.get('session_id'),
            'cdp_url': remote.get('cdp_ws_url'),
            'features': {'stealth': True, 'headless': False, 'proxies': self.proxy_policy is not None,
                'profile_persistence': bool(profile and profile['save_changes']),
                'live_view': bool(remote.get('browser_live_view_url')),
                **({'telemetry': telemetry} if telemetry is not None else {})}}

    def set_telemetry(self, session_id, telemetry):
        """Update only a verified task browser; authenticated callers own scope."""
        if not isinstance(session_id, str) or re.fullmatch(r'[A-Za-z0-9_-]{1,200}', session_id) is None:
            raise AccessError('The telemetry browser identifier is invalid.', 503)
        telemetry = validate_telemetry(telemetry)
        with operation(self, 'set_telemetry') as diagnostic:
            response = None
            try:
                response = self._request('PATCH', API_URL + '/browsers/' + quote(session_id, safe=''),
                    headers={'Authorization': 'Bearer ' + self.key(), 'Content-Type': 'application/json'},
                    json={'telemetry': telemetry}, timeout=30, allow_redirects=False)
                if response.status_code != 200:
                    raise AccessError('Kernel telemetry update was not confirmed.', 503)
                remote = response.json()
                if (not isinstance(remote, dict) or remote.get('session_id') != session_id or
                        not telemetry_matches(remote.get('telemetry'), telemetry)):
                    raise AccessError('Kernel did not confirm the reviewed telemetry selection.', 502)
                return telemetry
            except Exception as error:
                status = error.status if isinstance(error, AccessError) else 503
                diagnostic.failure(error, 'invalid_response' if status == 502 else None)
                raise diagnostic.access_error('Kernel telemetry update was not confirmed.', status) from None
            finally:
                if response is not None:
                    response.close()

    def _profile_request(self, method, name):
        validate_profile_attachment({'name': name, 'save_changes': True})
        route = '/profiles' if method == 'POST' else '/profiles/' + quote(name, safe='')
        with operation(self, 'profile_' + method.lower()) as diagnostic:
            kind = 'transport_error'
            try:
                response = self._request(method, API_URL + route,
                    headers={'Authorization': 'Bearer ' + self.key()},
                    **({'json': {'name': name}} if method == 'POST' else {}),
                    timeout=30, allow_redirects=False)
                if method in {'GET', 'DELETE'} and response.status_code == 404:
                    return None
                if method == 'DELETE' and response.status_code == 204:
                    return None
                kind = 'http_error' if response.status_code >= 300 else 'invalid_response'
                if method == 'DELETE' or response.status_code not in (200, 201):
                    raise ValueError
                result = response.json()
                if (not isinstance(result, dict) or result.get('name') != name or
                        not isinstance(result.get('id'), str) or
                        re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}', result['id']) is None):
                    raise ValueError
                return {'id': result['id'], 'name': name}
            except Exception as error:
                if isinstance(error, requests.Timeout):
                    kind = 'timeout'
                elif isinstance(error, requests.ConnectionError):
                    kind = 'connection_error'
                # Response bodies and exception text may contain opaque profile
                # data. Keep only request metadata and the bounded category.
                diagnostic.failure(kind=kind)
                raise diagnostic.access_error(
                    'Kernel browser profile operation could not be verified.', 503) from None

    def create_profile(self, name):
        return self._profile_request('POST', name)

    def get_profile(self, name):
        return self._profile_request('GET', name)

    def delete_profile(self, name):
        self._profile_request('DELETE', name)
        if self.get_profile(name) is not None:
            raise AccessError('Kernel browser profile deletion could not be verified.', 503)

    def get_proxy(self, proxy_id):
        with operation(self, 'get_proxy') as diagnostic:
            try:
                response = self._request('GET', API_URL + '/proxies/' + quote(proxy_id, safe=''),
                    headers={'Authorization': 'Bearer ' + self.key()}, timeout=15, allow_redirects=False)
                if response.status_code != 200:
                    raise AccessError('The configured Kernel proxy could not be checked.', 503)
                try:
                    result = response.json()
                except ValueError as error:
                    raise AccessError('Kernel returned an invalid proxy record.', 502) from error
                if not isinstance(result, dict):
                    raise AccessError('Kernel returned an invalid proxy record.', 502)
                return result
            except Exception as error:
                status = error.status if isinstance(error, AccessError) else 503
                diagnostic.failure(error, 'invalid_response' if status == 502 else None)
                message = str(error) if isinstance(error, AccessError) else 'The configured Kernel proxy could not be checked.'
                raise diagnostic.access_error(message, status) from None

    def verify_proxy(self, policy):
        policy = validate_proxy_policy(policy)
        remote = self.get_proxy(policy['id'])
        config = remote.get('config')
        country = config.get('country') if isinstance(config, dict) else None
        if (remote.get('id') != policy['id'] or remote.get('type') != policy['type'] or
                not isinstance(country, str) or country.upper() != policy['country'] or
                any(value for key, value in config.items() if key != 'country') or
                remote.get('bypass_hosts')):
            raise AccessError('Kernel proxy identity, location or routing could not be verified.', 403)
        if remote.get('status') != 'available':
            raise AccessError('The configured Kernel proxy is unavailable.', 503)
        return remote

    def get_session(self, session_id):
        with operation(self, 'get_session') as diagnostic:
            try:
                response = self._request('GET', API_URL + '/browsers/' + quote(session_id, safe=''),
                    headers={'Authorization': 'Bearer ' + self.key()}, timeout=15, allow_redirects=False)
                if response.status_code == 404:
                    return None
                if response.status_code != 200:
                    raise AccessError('Kernel browser ownership could not be checked.', 503)
                try:
                    result = response.json()
                except ValueError as error:
                    raise AccessError('Kernel returned an invalid browser record.', 502) from error
                if not isinstance(result, dict):
                    raise AccessError('Kernel returned an invalid browser record.', 502)
                return result
            except Exception as error:
                status = error.status if isinstance(error, AccessError) else 503
                diagnostic.failure(error, 'invalid_response' if status == 502 else None)
                message = str(error) if isinstance(error, AccessError) else 'Kernel browser ownership could not be checked.'
                raise diagnostic.access_error(message, status) from None

    def close_verified(self, session_id):
        with operation(self, 'close_verified') as diagnostic:
            try:
                response = self._request('DELETE', API_URL + '/browsers/' + quote(session_id, safe=''),
                    headers={'Authorization': 'Bearer ' + self.key()}, timeout=15, allow_redirects=False)
                if response.status_code not in (200, 201, 204, 404):
                    diagnostic.failure(kind='http_error')
                    return False
                if self.get_session(session_id) is not None:
                    diagnostic.failure(kind='cleanup_unconfirmed')
                    return False
                return True
            except Exception as error:
                diagnostic.failure(error)
                return False


def client_for(home):
    settings = json.loads((Path(home) / '.clanker-cloud/config.json').read_text())
    return KernelClient(home, settings)


def register_provider(ctx):
    from agent.browser_provider import BrowserProvider
    from hermes_constants import get_hermes_home
    from seatbelt.context import Context

    class ClankerKernelProvider(BrowserProvider):
        name = 'kernel'
        display_name = 'Kernel'

        def client(self):
            return client_for(Path(Context(get_hermes_home()).settings['transport_home']))

        def is_available(self):
            try:
                return bool(self.client().key())
            except (AccessError, OSError, ValueError):
                return False

        def create_session(self, task_id):
            # Native calls are prepared by the authenticated Clanker middleware.
            # A core renewal outside that boundary must fail closed.
            raise RuntimeError('Start or renew this Kernel browser through the authenticated Clanker task.')

        def close_session(self, session_id):
            from vault.store import RequestStore
            home = Path(Context(get_hermes_home()).settings['transport_home'])
            with RequestStore(home / '.clanker-vault').connection() as db:
                found = db.execute('SELECT team,requester,context FROM browser_session_owners WHERE provider=? AND session_id=?',
                    ('KernelBrowser', session_id)).fetchone()
            if not found:
                return False
            expected = hashlib.sha256(('v2:' + found['team'] + ':' + found['requester'] + ':' +
                str(Path(get_hermes_home()).resolve(strict=True))).encode()).hexdigest()
            return found['context'] == expected and self.client().close_verified(session_id)

        def emergency_cleanup(self, session_id):
            self.close_session(session_id)

    ctx.register_browser_provider(ClankerKernelProvider())
