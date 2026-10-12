"""Backend-only Kernel credential transport; no secret readback or mutation retries.

Contract: https://kernel.sh/docs/vaults/credentials and /vaults/fill.
Collection actions are bearer capabilities: callers must keep returned URLs on
the authenticated private collection surface. This module never logs payloads.
"""
from datetime import datetime
import re
import time
from urllib.parse import quote, urlsplit

import requests
from requests.adapters import HTTPAdapter

from vault.store import AccessError
from .kernel_client import API_URL
from .kernel_diagnostics import operation

FIELD_TYPES = frozenset({'text', 'email', 'password', 'totp'})
FILL_ERROR_CODES = frozenset({'target_changed', 'element_not_found',
    'ambiguous_selector', 'element_not_editable', 'option_not_found',
    'timeout', 'execution_failed'})
_FIELD_NAME = re.compile(r'[A-Za-z][A-Za-z0-9_]{0,63}\Z')
_REFERENCE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}\Z')
_MAX_VALUE_BYTES = 16384


class _ResponseError(Exception):
    pass


def _argument(condition):
    if not condition:
        raise AccessError('The Kernel vault request has unsupported fields or values.', 400)


def _response(condition):
    if not condition:
        raise _ResponseError()


def _reference(value):
    _argument(isinstance(value, str) and _REFERENCE.fullmatch(value) is not None)
    return quote(value, safe='')


def _text(value, limit=_MAX_VALUE_BYTES, *, empty=False):
    try:
        return (isinstance(value, str) and (empty or bool(value)) and
                len(value.encode('utf-8')) <= limit)
    except UnicodeError:
        return False


def _field_name(value):
    return isinstance(value, str) and _FIELD_NAME.fullmatch(value) is not None


def _definitions(fields, *, incoming=False):
    check = _argument if incoming else _response
    check(isinstance(fields, list) and 1 <= len(fields) <= 32)
    result = []
    names = set()
    for field in fields:
        check(isinstance(field, dict))
        if incoming:
            check(set(field) <= {'name', 'label', 'type', 'required', 'sensitive', 'value'})
        name, kind = field.get('name'), field.get('type')
        required, sensitive = field.get('required', True), field.get('sensitive', True)
        check(_field_name(name) and name not in names and isinstance(kind, str) and kind in FIELD_TYPES)
        check(type(required) is bool and type(sensitive) is bool)
        # A missing sensitivity flag in a provider response never authorizes a
        # public value; require the complete immutable server definition.
        if not incoming:
            check('required' in field and 'sensitive' in field)
        check(kind not in ('password', 'totp') or sensitive is True)
        clean = {'name': name, 'type': kind, 'required': required, 'sensitive': sensitive}
        label = field.get('label')
        if label is not None:
            check(_text(label, 128) and label == label.strip() and
                  not any(ord(char) < 32 or ord(char) == 127 for char in label))
            clean['label'] = label
        if incoming and 'value' in field:
            check(_text(field['value']))
            clean['value'] = field['value']
        names.add(name)
        result.append(clean)
    return result


def _timestamp(value):
    _response(isinstance(value, str) and len(value) <= 64)
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    _response(parsed.tzinfo is not None)
    return value


def _vault(body):
    _response(isinstance(body, dict))
    _response(isinstance(body.get('id'), str) and _REFERENCE.fullmatch(body['id']) is not None)
    _response(isinstance(body.get('name'), str) and _REFERENCE.fullmatch(body['name']) is not None)
    result = {'id': body['id'], 'name': body['name']}
    for field in ('created_at', 'updated_at'):
        if field in body:
            result[field] = _timestamp(body[field])
    return result


def _item(body, *, key=None, include_public_values=False):
    _response(isinstance(body, dict) and body.get('type') == 'credential')
    _response(isinstance(body.get('id'), str) and _REFERENCE.fullmatch(body['id']) is not None)
    _response(isinstance(body.get('key'), str) and _REFERENCE.fullmatch(body['key']) is not None)
    _response(key is None or body['key'] == key)
    _response(type(body.get('version')) is int and body['version'] >= 1)
    spec, state = body.get('spec'), body.get('state')
    _response(isinstance(spec, dict) and spec.get('provider') == 'kernel')
    _response(isinstance(state, dict) and state.get('provider') == 'kernel')
    _response(state.get('status') in ('pending_collection', 'ready'))
    definitions = _definitions(spec.get('fields'))
    clean_spec = {'provider': 'kernel', 'fields': definitions}
    if spec.get('description') is not None:
        _response(_text(spec['description'], empty=True))
        clean_spec['description'] = spec['description']
    values = state.get('fields')
    _response(isinstance(values, dict) and set(values) == {field['name'] for field in definitions})
    clean_values = {}
    for definition in definitions:
        field = values[definition['name']]
        _response(isinstance(field, dict) and type(field.get('has_value')) is bool)
        clean = {'has_value': field['has_value']}
        if (include_public_values and definition['sensitive'] is False and
                definition['type'] in ('text', 'email') and field['has_value']):
            _response(_text(field.get('value')))
            clean['value'] = field['value']
        clean_values[definition['name']] = clean
    if state['status'] == 'ready':
        _response(all(not field['required'] or clean_values[field['name']]['has_value']
                      for field in definitions))
    operations = body.get('available_operations')
    _response(isinstance(operations, list))
    clean_operations = []
    for advertised in operations:
        _response(isinstance(advertised, dict))
        # Unknown provider operations are never exposed or invoked here.
        if advertised.get('type') in ('collect', 'fill'):
            _response(advertised['type'] not in {entry['type'] for entry in clean_operations})
            clean_operations.append({'type': advertised['type']})
    result = {'id': body['id'], 'key': body['key'], 'type': 'credential',
              'version': body['version'], 'spec': clean_spec,
              'state': {'provider': 'kernel', 'status': state['status'], 'fields': clean_values},
              'available_operations': clean_operations}
    action = body.get('action')
    if action is not None:
        _response(isinstance(action, dict) and action.get('name') == 'collect')
        _response(_text(action.get('url')) and
                  not any(ord(char) < 32 or ord(char) == 127 for char in action['url']))
        parsed = urlsplit(action['url'])
        _response(parsed.scheme == 'https' and parsed.hostname == 'vault.kernel.sh' and
                  parsed.username is None and parsed.password is None and parsed.port in (None, 443))
        result['action'] = {'name': 'collect', 'url': action['url'],
                            'expires_at': _timestamp(action.get('expires_at'))}
    for field in ('created_at', 'updated_at'):
        if field in body:
            result[field] = _timestamp(body[field])
    return result


def _fill_result(body, count):
    _response(isinstance(body, dict) and body.get('type') == 'fill')
    status, fields = body.get('status'), body.get('fields')
    _response(status in ('completed', 'failed', 'unknown'))
    _response(isinstance(fields, list) and len(fields) == count)
    result, stopped = [], False
    for index, field in enumerate(fields):
        _response(isinstance(field, dict) and type(field.get('index')) is int and field['index'] == index)
        outcome = field.get('status')
        _response(outcome in ('filled', 'failed', 'unknown', 'not_attempted'))
        _response(outcome == 'not_attempted' if stopped else outcome != 'not_attempted')
        clean = {'index': index, 'status': outcome}
        if field.get('error_code') is not None:
            _response(field['error_code'] in FILL_ERROR_CODES and outcome in ('failed', 'unknown'))
            clean['error_code'] = field['error_code']
        result.append(clean)
        stopped = stopped or outcome in ('failed', 'unknown')
    outcomes = {field['status'] for field in result}
    _response((status == 'completed' and outcomes == {'filled'}) or
              (status == 'failed' and 'failed' in outcomes and 'unknown' not in outcomes) or
              (status == 'unknown' and 'unknown' in outcomes))
    return {'type': 'fill', 'status': status, 'fields': result}


class KernelVaultClient:
    """Uses a protected KernelClient key; never exposes an API-key argument.

    All returned collection actions and opted-in public values are backend-only.
    Caller authorization must precede fill; exact page_url is selection, not ACL.
    """
    def __init__(self, kernel_client, *, project=None):
        if project is not None:
            _reference(project)
        self.kernel = kernel_client
        self.project = project
        # A separate non-environment session prevents cookies, custom retry
        # adapters or ambient proxies on another client from affecting secrets.
        self.http = requests.Session()
        self.http.trust_env = False
        self.http.mount('https://', HTTPAdapter(max_retries=0))

    def _request(self, method, path, route, *, body=None, params=None, parser=None,
                 absent=False, timeout=15, expected=(200,)):
        attempted = False
        with operation(self.kernel, 'vault_' + method.lower()) as diagnostic:
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
                from .kernel_transport import request
                response = request(self.http, method, API_URL + path, event=event, headers=headers,
                    json=body, params=params, timeout=timeout, allow_redirects=False)
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
                    # Do not inspect an error body, response headers, or URL.
                else:
                    return parser(response.json()) if parser is not None else True
            except (ValueError, TypeError, KeyError, _ResponseError):
                code, exposed_status = 'invalid_response', 502
            except requests.Timeout:
                code, exposed_status = 'timeout', 503
            except requests.ConnectionError:
                code, exposed_status = 'connection_error', 503
            except Exception:
                # Provider exceptions can include submitted secrets. Never pass
                # the object/string/traceback to the diagnostic logger.
                code, exposed_status = 'transport_error', 503
            finally:
                event['elapsed_ms'] = round((time.monotonic() - started) * 1000, 2)
            diagnostic.failure(kind=code)
            error = diagnostic.access_error('Kernel vault request could not be confirmed.', exposed_status)
            error.kernel_vault_code = code
            error.mutation_attempted = attempted and method in ('POST', 'PUT', 'PATCH', 'DELETE')
            raise error from None

    @staticmethod
    def _path(vault, key=None):
        path = '/vaults/' + _reference(vault)
        return path if key is None else path + '/items/' + _reference(key)

    def create_vault(self, name):
        _reference(name)
        def parse(body):
            result = _vault(body)
            _response(result['name'] == name)
            return result
        return self._request('POST', '/vaults', '/vaults', body={'name': name},
                             parser=parse, expected=(200, 201))

    def get_vault(self, vault):
        def parse(body):
            result = _vault(body)
            _response(vault in (result['id'], result['name']))
            return result
        return self._request('GET', self._path(vault), '/vaults/{vault}', parser=parse, absent=True)

    def delete_vault(self, vault):
        """Explicit lifecycle cleanup only; does not erase browser-filled values."""
        self._request('DELETE', self._path(vault), '/vaults/{vault}',
                      absent=True, expected=(200, 204))
        return True

    def create_credential(self, vault, key, fields, *, description=None):
        spec = {'provider': 'kernel', 'fields': _definitions(fields, incoming=True)}
        if description is not None:
            _argument(_text(description, empty=True))
            spec['description'] = description
        return self._request('PUT', self._path(vault, key), '/vaults/{vault}/items/{key}',
            body={'type': 'credential', 'spec': spec}, parser=lambda body: _item(body, key=key),
            expected=(200, 201))

    def get_credential(self, vault, key, *, wait=0, include_public_values=False):
        _argument(type(wait) is int and 0 <= wait <= 60 and type(include_public_values) is bool)
        return self._request('GET', self._path(vault, key), '/vaults/{vault}/items/{key}',
            params={'wait': wait} if wait else None, timeout=max(15, wait + 5), absent=True,
            parser=lambda body: _item(body, key=key, include_public_values=include_public_values))

    def list_credentials(self, vault):
        def parse(body):
            _response(isinstance(body, list))
            result = []
            for item in body:
                _response(isinstance(item, dict))
                if (item.get('type') == 'credential' and isinstance(item.get('spec'), dict) and
                        item['spec'].get('provider') == 'kernel'):
                    result.append(_item(item))
            return result
        return self._request('GET', self._path(vault) + '/items', '/vaults/{vault}/items', parser=parse)

    def update_credential(self, vault, key, *, version, fields=None, description=None, expected_item_id=None):
        _argument(type(version) is int and version >= 1)
        spec = {}
        if fields is not None:
            _argument(isinstance(fields, dict) and 1 <= len(fields) <= 32)
            clean = {}
            for name, field in fields.items():
                _argument(_field_name(name) and isinstance(field, dict) and set(field) == {'value'})
                _argument(field['value'] is None or _text(field['value'], empty=True))
                clean[name] = {'value': field['value']}
            spec['fields'] = clean
        if description is not None:
            _argument(_text(description, empty=True))
            spec['description'] = description
        _argument(bool(spec))
        body = {'type': 'credential', 'version': version, 'spec': spec}
        if expected_item_id is not None:
            _reference(expected_item_id)
            body['expected_item_id'] = expected_item_id
        def parse(result):
            result = _item(result, key=key)
            _response(expected_item_id is None or result['id'] == expected_item_id)
            _response(result['version'] > version)
            return result
        return self._request('PATCH', self._path(vault, key), '/vaults/{vault}/items/{key}',
                             body=body, parser=parse)

    def delete_credential(self, vault, key):
        self._request('DELETE', self._path(vault, key), '/vaults/{vault}/items/{key}',
                      absent=True, expected=(200, 204))
        return True

    def _available(self, vault, key, operation_type):
        item = self.get_credential(vault, key)
        if item is None:
            raise AccessError('The Kernel credential item is unavailable.', 404)
        if not any(operation['type'] == operation_type for operation in item['available_operations']):
            raise AccessError('The Kernel credential operation is unavailable.', 409)
        return item

    def collect(self, vault, key):
        item = self._available(vault, key, 'collect')
        def parse(body):
            result = _item(body, key=key)
            _response(result['id'] == item['id'] and 'action' in result)
            return result
        return self._request('POST', self._path(vault, key) + '/operations',
            '/vaults/{vault}/items/{key}/operations', body={'type': 'collect'}, parser=parse)

    def fill(self, vault, key, *, browser_id, page_url, fields, timeout_ms=10000):
        _reference(browser_id)
        _argument(_text(page_url))
        try:
            url = urlsplit(page_url)
            _argument(url.scheme == 'https' and bool(url.hostname) and url.username is None and
                      url.password is None and url.port in (None, 443) and
                      not any(ord(char) < 32 or ord(char) == 127 for char in page_url))
        except ValueError:
            raise AccessError('The Kernel fill destination is unsupported.', 400) from None
        _argument(type(timeout_ms) is int and 1 <= timeout_ms <= 30000)
        _argument(isinstance(fields, list) and 1 <= len(fields) <= 32)
        bindings = []
        for binding in fields:
            _argument(isinstance(binding, dict) and set(binding) == {'field', 'selector'})
            _argument(_field_name(binding['field']) and _text(binding['selector']))
            bindings.append(dict(binding))
        _argument(len({field['selector'] for field in bindings}) == len(bindings))
        item = self._available(vault, key, 'fill')
        _argument(all(field['field'] in item['state']['fields'] and
                      item['state']['fields'][field['field']]['has_value'] for field in bindings))
        body = {'type': 'fill', 'browser_id': browser_id, 'page_url': page_url,
                'fields': bindings, 'timeout_ms': timeout_ms}
        return self._request('POST', self._path(vault, key) + '/operations',
            '/vaults/{vault}/items/{key}/operations', body=body,
            timeout=max(15, timeout_ms / 1000 + 5), parser=lambda body: _fill_result(body, len(bindings)))
