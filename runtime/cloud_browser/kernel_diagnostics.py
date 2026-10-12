"""Sanitized operator diagnostics for the protected Kernel API boundary."""
from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import json
import logging
from pathlib import Path
import re
import time
import traceback
from urllib.parse import quote, quote_plus, urlsplit
import uuid

import requests

from vault.store import AccessError

logger = logging.getLogger(__name__)
_active = ContextVar('clanker_kernel_diagnostic', default=None)
_URL = re.compile(r'\b(?:https?|wss?)://[^\s<>\"\']+', re.IGNORECASE)
_BEARER = re.compile(r'\bBearer\s+[^\s\"\',;]+', re.IGNORECASE)


def _http_failed(request):
    status = request['upstream_status']
    return status is not None and status >= 300 and not (
        status == 404 and request['method'] in ('GET', 'DELETE'))


def current(client):
    diagnostic = _active.get()
    return diagnostic if diagnostic is not None and diagnostic.client is client else None


@contextmanager
def operation(client, name, task_id=None):
    # Deletion and its verification read form one operation, including its error
    # reference. ContextVars keep concurrent requester operations independent.
    existing = current(client)
    if existing is not None:
        yield existing
        return
    diagnostic = KernelDiagnostic(client, name, task_id)
    token = _active.set(diagnostic)
    try:
        yield diagnostic
    finally:
        _active.reset(token)


class KernelDiagnostic:
    def __init__(self, client, name, task_id):
        self.client = client
        self.reference = uuid.uuid4().hex
        self.secrets = set()
        self.logged = False
        self.event = {'event': 'kernel_upstream_failure', 'provider': 'kernel',
                      'operation': name, 'diagnostic_ref': self.reference, 'requests': []}
        if task_id is not None:
            self.event['task_ref'] = hashlib.sha256(str(task_id).encode()).hexdigest()[:24]

    def remember_secret(self, value):
        if isinstance(value, str) and value:
            self.secrets.update((value, quote(value, safe=''), quote_plus(value),
                                 json.dumps(value)[1:-1]))

    def text(self, value, limit=1000):
        # Sanitize BEFORE constructing a LogRecord: log formatters may run in a
        # different thread, and ordinary profile redaction can be switched off.
        try:
            from agent.redact import redact_sensitive_text
            text = str(value).replace('\\/', '/')
            for secret in sorted(self.secrets, key=len, reverse=True):
                text = text.replace(secret, '[REDACTED]')
            if len(text) > 8192:
                return '[oversized diagnostic text omitted]'
            text = _URL.sub('[REDACTED_URL]', text)
            text = _BEARER.sub('Bearer [REDACTED]', text)
            text = redact_sensitive_text(text, force=True, redact_url_credentials=True)
            return text[:limit]
        except Exception:
            return '[diagnostic text unavailable]'

    def error_fields(self, response):
        # Success records contain control capabilities; never inspect or log
        # them. Error bodies are untrusted: retain only scalar code/message.
        try:
            if len(response.content) > 8192:
                return {'format': 'oversized_body_omitted'}
            body = response.json()
        except Exception:
            return {'format': 'non_json'}
        if not isinstance(body, dict):
            return {'format': 'unsupported_json'}
        fields = {}
        for name in ('code', 'message', 'error'):
            value = body.get(name)
            if isinstance(value, (str, int)) and not isinstance(value, bool):
                fields[name] = self.text(value)
            elif name == 'error' and isinstance(value, dict):
                fields[name] = {key: self.text(value[key]) for key in ('code', 'message')
                               if isinstance(value.get(key), (str, int))}
        return fields

    def request(self, method, url, *args, **kwargs):
        authorization = kwargs.get('headers', {}).get('Authorization', '')
        if authorization.startswith('Bearer '):
            self.remember_secret(authorization[7:])
        path = urlsplit(url).path
        route = ('/browsers/{id}' if path.startswith('/browsers/') else
            '/proxies/{id}/check' if re.fullmatch(r'/proxies/[^/]+/check', path) else
            '/proxies/{id}' if re.fullmatch(r'/proxies/[^/]+', path) else
            '/profiles/{name}' if re.fullmatch(r'/profiles/[^/]+', path) else
            path if path in ('/browsers', '/proxies', '/profiles') else '[other]')
        event = {'method': method, 'route': route, 'upstream_status': None,
                 'timeout_seconds': kwargs.get('timeout')}
        self.event['requests'].append(event)
        start = time.monotonic()
        try:
            from .kernel_transport import request
            response = request(self.client.http, method, url, event=event, **kwargs)
            event['upstream_status'] = response.status_code
            for header in ('x-request-id', 'request-id'):
                value = response.headers.get(header)
                if isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', value):
                    event['provider_request_id'] = self.text(value, 128)
                    break
            expected_absence = response.status_code == 404 and method in ('GET', 'DELETE')
            if response.status_code >= 300 and not expected_absence and not route.startswith('/profiles'):
                event['upstream_error'] = self.error_fields(response)
            return response
        except Exception as error:
            event['exception_type'] = type(error).__module__ + '.' + type(error).__name__
            raise
        finally:
            event['elapsed_ms'] = round((time.monotonic() - start) * 1000, 2)

    def failure(self, error=None, kind=None):
        if self.logged:
            return
        chain = []
        seen = set()
        while error is not None and id(error) not in seen and len(chain) < 6:
            seen.add(id(error))
            if kind is None:
                if isinstance(error, requests.Timeout):
                    kind = 'timeout'
                elif isinstance(error, requests.ConnectionError):
                    kind = 'connection_error'
            # A provider HTTP exception can repeat its raw body. The selected
            # HTTP error fields above already preserve the useful detail.
            http_error = any(_http_failed(request) for request in self.event['requests'])
            chain.append({'type': type(error).__module__ + '.' + type(error).__name__,
                          'message': '[see upstream_error]' if http_error else self.text(error),
                          'frames': [{'file': Path(frame.filename).name,
                                      'function': frame.name, 'line': frame.lineno}
                                     for frame in traceback.extract_tb(error.__traceback__)[-8:]]})
            error = error.__cause__ or error.__context__
        if kind is None and any(_http_failed(request) for request in self.event['requests']):
            kind = 'http_error'
        self.event.update(failure_kind=kind or 'provider_exception', exception_chain=chain)
        self.logged = True
        # No exception objects, raw headers/bodies, locals or tracebacks enter
        # the logging queue. json.dumps escapes control characters in messages.
        try:
            logger.warning('Kernel upstream failure %s', json.dumps(self.event, sort_keys=True))
        except Exception:
            pass  # A broken operator log sink must not alter provider outcomes.

    def access_error(self, message, status):
        error = AccessError(message + ' Reference: ' + self.reference + '.', status)
        error.diagnostic_ref = self.reference
        return error
