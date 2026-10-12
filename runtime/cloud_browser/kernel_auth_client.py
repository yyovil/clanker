"""Backend-only Managed Auth transport with bounded, payload-silent requests.

Wire contracts: Kernel's /api-reference/managed-auth and /profiles docs.
The hosted login capability and post-login URL remain backend-only. Callers
must authorize the requester before accessing any connection or profile. This
client never returns secrets or retries mutations. Only the private owner web
form may forward a TOTP setup key directly to Kernel.
"""
from datetime import datetime
import ipaddress
import re
import time
from urllib.parse import quote, urlsplit

import requests
from requests.adapters import HTTPAdapter

from vault.store import AccessError
from .kernel_client import API_URL
from .kernel_diagnostics import operation

FLOW_STATUS = frozenset({'IN_PROGRESS', 'SUCCESS', 'FAILED', 'EXPIRED', 'CANCELED'})
FLOW_STEP = frozenset({'DISCOVERING', 'AWAITING_INPUT', 'AWAITING_EXTERNAL_ACTION',
                       'SUBMITTING', 'COMPLETED'})
FLOW_TYPE = frozenset({'LOGIN', 'REAUTH'})
AUTH_STATUS = frozenset({'AUTHENTICATED', 'NEEDS_AUTH'})
_REFERENCE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}\Z')
_HOSTED_HOSTS = frozenset({'auth.kernel.com', 'auth.kernel.sh', 'auth.onkernel.com',
                         'managed-auth.onkernel.com'})
_ERROR_CODES = frozenset({'credentials_invalid', 'totp_code_rejected', 'totp_required',
    'sms_code_required', 'email_code_required', 'external_action_required',
    'mfa_required', 'no_viable_plan', 'login_failed', 'timeout', 'internal_error',
    'awaiting_input_timeout', 'captcha_blocked', 'bot_detected', 'unsupported_auth_method',
    'domain_not_allowed', 'flow_failed'})
# Match Kernel's published SDK request budget for the two auth mutations;
# a locally shorter read timeout can leave a successfully-created connection
# unbound. Mutations still dispatch once and unknown outcomes need GET recovery.
_AUTH_MUTATION_TIMEOUT = 60
_CONNECTION_PAGE_SIZE = 100
_CONNECTION_MAX_PAGES = 5


class _ResponseError(Exception):
    pass


def _argument(condition):
    if not condition:
        raise AccessError('The Kernel authentication request has unsupported fields or values.', 400)


def _response(condition):
    if not condition:
        raise _ResponseError()


def _reference(value, *, response=False):
    (_response if response else _argument)(
        isinstance(value, str) and _REFERENCE.fullmatch(value) is not None)
    return quote(value, safe='')


def _domain(value, *, response=False):
    check = _response if response else _argument
    check(isinstance(value, str) and 1 <= len(value) <= 253 and value == value.lower())
    labels = value.split('.')
    check(len(labels) >= 2 and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',
                                              label) is not None for label in labels))
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        check(False)
    check(not value.endswith(('.localhost', '.local', '.internal')))
    return value


def _url(value, *, hosted=False, response=False):
    check = _response if response else _argument
    check(isinstance(value, str) and 1 <= len(value) <= 8192 and
          not any(ord(char) < 33 or ord(char) == 127 for char in value) and '\\' not in value)
    try:
        parsed = urlsplit(value)
        check(parsed.scheme == 'https' and parsed.username is None and parsed.password is None and
              parsed.port in (None, 443) and parsed.hostname is not None)
        _domain(parsed.hostname, response=response)
        if hosted:
            check(parsed.hostname in _HOSTED_HOSTS and parsed.path.startswith('/login/') and
                  len(parsed.path) > len('/login/') and not parsed.fragment)
    except (ValueError, UnicodeError):
        check(False)
    return value


def _timestamp(value):
    _response(isinstance(value, str) and len(value) <= 64)
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    _response(parsed.tzinfo is not None)
    return value


def _proxy(value):
    """Keep IDs/modes only; reject conflicting/ambiguous provider references."""
    _response(isinstance(value, dict))
    result = {}
    if value.get('id') is not None:
        _reference(value['id'], response=True)
        result['id'] = value['id']
    if value.get('mode') is not None:
        _response(value['mode'] in ('direct', 'default'))
        result['mode'] = value['mode']
    return result


def _connection(body):
    _response(isinstance(body, dict))
    for key in ('id', 'profile_name'):
        _reference(body.get(key), response=True)
    _domain(body.get('domain'), response=True)
    _response(body.get('status') in AUTH_STATUS)
    result = {key: body[key] for key in ('id', 'domain', 'profile_name', 'status')}
    for key in ('record_session', 'save_credentials'):
        _response(type(body.get(key)) is bool)
        result[key] = body[key]
    for key in ('auto_reauth', 'health_checks', 'can_reauth'):
        if key in body:
            _response(type(body[key]) is bool)
            result[key] = body[key]
    for key, choices in (('flow_status', FLOW_STATUS), ('flow_step', FLOW_STEP),
                         ('flow_type', FLOW_TYPE)):
        value = body.get(key)
        _response(value is None or isinstance(value, str) and value in choices)
        result[key] = value
    for key in ('flow_expires_at', 'last_auth_at', 'last_auth_check_at'):
        value = body.get(key)
        if value is not None:
            result[key] = _timestamp(value)
    for key in ('hosted_url', 'login_url', 'post_login_url'):
        value = body.get(key)
        if value is not None:
            result[key] = _url(value, hosted=key == 'hosted_url', response=True)
    if body.get('allowed_domains') is not None:
        domains = body['allowed_domains']
        _response(isinstance(domains, list) and len(domains) <= 32)
        result['allowed_domains'] = [_domain(value, response=True) for value in domains]
        _response(len(set(result['allowed_domains'])) == len(domains))
    if body.get('health_check_interval') is not None:
        interval = body['health_check_interval']
        _response(type(interval) is int and 300 <= interval <= 86400)
        result['health_check_interval'] = interval
    if body.get('health_check_unavailable_reason') is not None:
        _response(body['health_check_unavailable_reason'] == 'no_auth_check_url')
        result['health_check_unavailable_reason'] = 'no_auth_check_url'
    if body.get('credential') is not None:
        credential = body['credential']
        _response(isinstance(credential, dict))
        # Managed Auth credentials are a separate resource from Vault items.
        # External providers are not silently converted into Kernel names.
        if credential.get('name') is not None and not credential.get('provider'):
            _reference(credential['name'], response=True)
            result['credential'] = {'name': credential['name']}
        elif credential:
            result['external_credential'] = True
    if body.get('error_code') is not None:
        code = body['error_code']
        result['error_code'] = code if isinstance(code, str) and code in _ERROR_CODES else 'provider_failure'
    browser = body.get('browser')
    if browser is not None:
        _response(isinstance(browser, dict))
        clean = {}
        if browser.get('proxy') is not None:
            clean['proxy'] = _proxy(browser['proxy'])
        if 'stealth' in browser:
            _response(type(browser['stealth']) is bool)
            clean['stealth'] = browser['stealth']
        if browser.get('region') is not None:
            _response(browser['region'] in ('us-east', 'eu-west', 'ap-southeast'))
            clean['region'] = browser['region']
        if browser.get('telemetry') is not None:
            telemetry = browser['telemetry']
            _response(isinstance(telemetry, dict))
            if 'enabled' in telemetry:
                _response(type(telemetry['enabled']) is bool)
                clean['telemetry'] = {'enabled': telemetry['enabled']}
        result['browser'] = clean
    if body.get('proxy_id') is not None:
        _reference(body['proxy_id'], response=True)
        result['proxy_id'] = body['proxy_id']
        modern = result.get('browser', {}).get('proxy', {}).get('id')
        _response(modern is None or modern == body['proxy_id'])
    # No discovered fields, hints, chosen account labels, raw errors, selectors,
    # live-view URLs, handoff codes, or credential values leave this parser.
    return result


class KernelAuthClient:
    """Protected backend transport. Connection ownership is the caller's ACL."""
    def __init__(self, kernel_client, *, project=None):
        if project is not None:
            _reference(project)
        self.kernel = kernel_client
        self.project = project
        self.http = requests.Session()
        self.http.trust_env = False
        self.http.mount('https://', HTTPAdapter(max_retries=0))

    def _request(self, method, path, route, *, body=None, parser=None,
                 params=None, response_parser=None,
                 absent=False, timeout=15, expected=(200,)):
        attempted = False
        with operation(self.kernel, 'auth_' + method.lower()) as diagnostic:
            event = {'method': method, 'route': route, 'upstream_status': None,
                     'timeout_seconds': timeout}
            started = time.monotonic()
            try:
                key = self.kernel.key()
                if not isinstance(key, str) or not key:
                    raise AccessError('The protected Kernel service key is missing.', 503)
                headers = {'Authorization': 'Bearer ' + key, 'Accept': 'application/json'}
                if self.project is not None:
                    headers['X-Kernel-Project'] = self.project
                diagnostic.event['requests'].append(event)
                attempted = True
                options = {'headers': headers, 'json': body, 'timeout': timeout,
                           'allow_redirects': False}
                if params is not None:
                    options['params'] = params
                from .kernel_transport import request
                response = request(self.http, method, API_URL + path, event=event, **options)
                status = response.status_code
                if type(status) is not int or not 100 <= status <= 599:
                    raise _ResponseError()
                event['upstream_status'] = status
                if absent and status == 404:
                    return None
                if status not in expected:
                    code, exposed_status = {
                        400: ('invalid_request', 400), 401: ('authentication_failed', 503),
                        403: ('forbidden', 403), 404: ('not_found', 404),
                        409: ('conflict', 409), 422: ('invalid_request', 400),
                        429: ('rate_limited', 429),
                    }.get(status, ('upstream_error', 503))
                else:
                    if response_parser is not None:
                        return response_parser(response)
                    return parser(response.json()) if parser is not None else True
            except (ValueError, TypeError, KeyError, _ResponseError):
                code, exposed_status = 'invalid_response', 502
            except requests.Timeout:
                code, exposed_status = 'timeout', 503
            except requests.ConnectionError:
                code, exposed_status = 'connection_error', 503
            except Exception:
                code, exposed_status = 'transport_error', 503
            finally:
                event['elapsed_ms'] = round((time.monotonic() - started) * 1000, 2)
            # Never inspect response error bodies/headers, nor log exceptions.
            diagnostic.failure(kind=code)
            error = diagnostic.access_error('Kernel authentication request could not be confirmed.', exposed_status)
            error.kernel_auth_code = code
            error.mutation_attempted = attempted and method in ('POST', 'PATCH', 'DELETE')
            raise error from None

    @staticmethod
    def _path(connection_id):
        return '/auth/connections/' + _reference(connection_id)

    def create_connection(self, domain, profile_name, *, login_url=None, proxy_id=None,
                          credential_name=None, allowed_domains=None, health_checks=False,
                          auto_reauth=False, save_credentials=True):
        _domain(domain)
        _reference(profile_name)
        _argument(all(type(value) is bool for value in (health_checks, auto_reauth, save_credentials)))
        domains = [domain] if allowed_domains is None else allowed_domains
        _argument(isinstance(domains, list) and 1 <= len(domains) <= 32)
        domains = [_domain(value) for value in domains]
        _argument(domain in domains and len(set(domains)) == len(domains))
        body = {'domain': domain, 'profile_name': profile_name, 'allowed_domains': domains,
                'health_checks': health_checks, 'auto_reauth': auto_reauth,
                'save_credentials': save_credentials, 'record_session': False,
                'browser': {'stealth': True, 'telemetry': {'enabled': False}}}
        if login_url is not None:
            _url(login_url)
            host = urlsplit(login_url).hostname
            _argument(any(host == value or host.endswith('.' + value) for value in domains))
            body['login_url'] = login_url
        if proxy_id is not None:
            _reference(proxy_id)
            body['browser']['proxy'] = {'id': proxy_id}
        if credential_name is not None:
            _reference(credential_name)
            body['credential'] = {'name': credential_name}
        def parse(raw):
            result = _connection(raw)
            _response(result['domain'] == domain and result['profile_name'] == profile_name)
            return result
        return self._request('POST', '/auth/connections', '/auth/connections', body=body,
                             parser=parse, timeout=_AUTH_MUTATION_TIMEOUT,
                             expected=(200, 201))

    def find_connection(self, domain, profile_name):
        """Reconcile a lost create response without dispatching another mutation.

        Both exact filters are required. Return a unique sanitized match only
        after the provider explicitly confirms the final page. Missing, invalid,
        non-advancing, or excessive pagination never proves absence/uniqueness.
        This metadata read does not authorize using the recovered connection.
        """
        _domain(domain)
        _reference(profile_name)
        offset = 0
        found = []
        with operation(self.kernel, 'auth_find') as diagnostic:
            for _ in range(_CONNECTION_MAX_PAGES):
                def parse(response):
                    raw = response.json()
                    _response(isinstance(raw, list) and len(raw) <= _CONNECTION_PAGE_SIZE)
                    items = [_connection(item) for item in raw]
                    _response(all(item['domain'] == domain and
                                  item['profile_name'] == profile_name for item in items))
                    # Even repeated copies of one ID cannot establish a unique
                    # snapshot when a supposedly exact result set is malformed.
                    _response(len(found) + len(items) <= 1)
                    more = response.headers.get('X-Has-More')
                    following = response.headers.get('X-Next-Offset')
                    _response(more in ('true', 'false') and isinstance(following, str) and
                              re.fullmatch(r'0|[1-9][0-9]{0,8}', following) is not None)
                    following = int(following)
                    _response((more == 'false' and following == 0) or
                              (more == 'true' and following > offset))
                    return items, following

                items, following = self._request('GET', '/auth/connections',
                    '/auth/connections', params={'domain': domain,
                        'profile_name': profile_name, 'limit': _CONNECTION_PAGE_SIZE,
                        'offset': offset}, response_parser=parse)
                found.extend(items)
                if following == 0:
                    return found[0] if found else None
                offset = following
            diagnostic.failure(kind='pagination_incomplete')
            error = diagnostic.access_error(
                'Kernel authentication lookup could not be completed.', 502)
            error.kernel_auth_code = 'pagination_incomplete'
            error.mutation_attempted = False
            raise error from None

    def get_connection(self, connection_id):
        def parse(raw):
            result = _connection(raw)
            _response(result['id'] == connection_id)
            return result
        return self._request('GET', self._path(connection_id), '/auth/connections/{id}',
                             parser=parse, absent=True)

    def start_login(self, connection_id, *, proxy_id=None):
        body = {'record_session': False,
                'browser': {'stealth': True, 'telemetry': {'enabled': False}}}
        if proxy_id is not None:
            _reference(proxy_id)
            body['browser']['proxy'] = {'id': proxy_id}
        def parse(raw):
            _response(isinstance(raw, dict) and raw.get('id') == connection_id)
            _response(raw.get('flow_type') in FLOW_TYPE)
            return {'id': raw['id'], 'flow_type': raw['flow_type'],
                    'flow_expires_at': _timestamp(raw.get('flow_expires_at')),
                    'hosted_url': _url(raw.get('hosted_url'), hosted=True, response=True)}
        return self._request('POST', self._path(connection_id) + '/login',
                             '/auth/connections/{id}/login', body=body, parser=parse,
                             timeout=_AUTH_MUTATION_TIMEOUT)

    def delete_connection(self, connection_id):
        self._request('DELETE', self._path(connection_id), '/auth/connections/{id}',
                      absent=True, expected=(204,))
        if self.get_connection(connection_id) is not None:
            raise AccessError('Kernel authentication cleanup could not be confirmed.', 503)
        return True

    def get_profile(self, profile_name):
        _reference(profile_name)
        def parse(raw):
            _response(isinstance(raw, dict))
            _reference(raw.get('id'), response=True)
            name = raw.get('name')
            _response(profile_name in (raw['id'], name))
            if name is not None:
                _reference(name, response=True)
            return {'id': raw['id'], 'name': name}
        return self._request('GET', '/profiles/' + _reference(profile_name),
                             '/profiles/{id_or_name}', parser=parse, absent=True)

    def delete_profile(self, profile_name):
        self._request('DELETE', '/profiles/' + _reference(profile_name),
                      '/profiles/{id_or_name}', absent=True, expected=(204,))
        if self.get_profile(profile_name) is not None:
            raise AccessError('Kernel profile cleanup could not be confirmed.', 503)
        return True

    @staticmethod
    def _credential_metadata(raw):
        _response(isinstance(raw, dict))
        for key in ('id', 'name'):
            _reference(raw.get(key), response=True)
        _domain(raw.get('domain'), response=True)
        _response(type(raw.get('has_totp_secret')) is bool)
        _response(type(raw.get('has_values')) is bool)
        # Updates can return a current TOTP code. Never return it to callers.
        return {key: raw[key] for key in ('id', 'name', 'domain', 'has_totp_secret', 'has_values')}

    def credential_metadata(self, reference):
        return self._request('GET', '/credentials/' + _reference(reference),
            '/credentials/{id_or_name}', parser=self._credential_metadata)

    def set_totp(self, credential_id, secret):
        """Only the authenticated private web endpoint calls this value path."""
        _reference(credential_id)
        if not isinstance(secret, str) or not 16 <= len(secret) <= 2048:
            raise AccessError('Enter the authenticator setup key, not a one-time code.', 400)
        if not (re.fullmatch(r'[A-Z2-7]{16,128}={0,6}', secret, re.IGNORECASE) or
                secret.startswith('otpauth://totp/') and not any(ord(c) < 32 for c in secret)):
            raise AccessError('Enter a valid authenticator setup key or otpauth URI.', 400)
        return self._request('PATCH', '/credentials/' + _reference(credential_id),
            '/credentials/{id_or_name}', body={'totp_secret': secret}, parser=self._credential_metadata)

    def delete_credential(self, credential_name):
        """Retire an already-authorized Managed Auth credential, never read it.

        Official generated SDK credentials.retrieve/delete use this route;
        this is separate from Vault's /vaults/{id}/items/{key} resources.
        The verification GET deliberately does not parse a successful body.
        """
        path = '/credentials/' + _reference(credential_name)
        self._request('DELETE', path, '/credentials/{id_or_name}',
                      absent=True, expected=(204,))
        if self._request('GET', path, '/credentials/{id_or_name}', absent=True) is not None:
            raise AccessError('Kernel credential cleanup could not be confirmed.', 503)
        return True
