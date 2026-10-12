"""Bounded recovery for read-only Kernel metadata requests.

A silent pooled connection must not force another user turn. Ordinary GETs
reserve part of their existing budget for one fresh connection. Provider writes
and intentional long polls retain their original one-dispatch behavior.
"""
import hashlib
import json
import logging
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Timeout

logger = logging.getLogger(__name__)


def _fresh_session():
    session = requests.Session()
    session.trust_env = False
    session.mount('https://', HTTPAdapter(max_retries=0))
    session.mount('http://', HTTPAdapter(max_retries=0))
    return session


def request(session, method, url, *, event=None, **options):
    """Retry only a transport-failed ordinary GET, once, in an isolated session.

    The monotonic budget bounds connection/header waits across attempts; like
    requests' existing timeout it is not a hard deadline for DNS or a trickling
    response body. No exception text, query, headers or response body is logged.
    """
    timeout = options.get('timeout')
    params = options.get('params') or {}
    ordinary_read = (method == 'GET' and type(timeout) in (int, float) and timeout > 0
                     and not params.get('wait') and options.get('stream') is not True)
    if event is not None:
        # References allow an operator to compare audit paths without recording
        # account/resource identifiers or URLs in agent-facing diagnostics.
        event['resource_ref'] = hashlib.sha256(urlsplit(url).path.encode()).hexdigest()
        event['started_at_utc'] = datetime.now(timezone.utc).isoformat()
        event['attempts'] = []
    started = time.monotonic()
    attempts = 2 if ordinary_read else 1
    retry_session = None
    try:
        for index in range(attempts):
            chosen = session if index == 0 else retry_session
            current = dict(options)
            remaining = max(0.001, timeout - (time.monotonic() - started)) if ordinary_read else None
            if ordinary_read:
                read_timeout = min(5.0, timeout / 2, remaining) if index == 0 else remaining
                connect_timeout = min(3.0, remaining) if index == 0 else remaining
                current['timeout'] = Timeout(total=remaining, connect=connect_timeout, read=read_timeout)
            attempt = {'attempt': index + 1,
                       'connection_mode': 'isolated_retry' if index > 0 else 'primary_pool',
                       'upstream_status': None}
            if ordinary_read:
                attempt.update(connect_timeout_seconds=connect_timeout,
                               read_timeout_seconds=read_timeout,
                               remaining_budget_seconds=round(remaining, 3))
            if event is not None:
                event['attempts'].append(attempt)
            before = time.monotonic()
            try:
                response = chosen.request(method, url, **current)
                attempt['upstream_status'] = response.status_code
                if index > 0 and event is not None:
                    event['recovered'] = True
                    # The eager response is already read; record only transport
                    # metadata, even for vault and managed-auth requests.
                    attempt['elapsed_ms'] = round((time.monotonic() - before) * 1000, 2)
                    try:
                        logger.info('Kernel read recovered %s', json.dumps({
                            'event': 'kernel_read_recovered', 'method': method,
                            'route': event.get('route', '[other]'), 'resource_ref': event['resource_ref'],
                            'started_at_utc': event['started_at_utc'], 'attempts': event['attempts'],
                            'upstream_status': response.status_code}, sort_keys=True))
                    except Exception:
                        pass  # Diagnostics cannot change the provider outcome.
                return response
            except (requests.Timeout, requests.ConnectionError) as error:
                attempt['exception_type'] = type(error).__module__ + '.' + type(error).__name__
                if (index + 1 == attempts or
                        isinstance(error, (requests.exceptions.SSLError, requests.exceptions.ProxyError)) or
                        time.monotonic() - started >= timeout):
                    raise
                retry_session = _fresh_session()
            finally:
                attempt['elapsed_ms'] = round((time.monotonic() - before) * 1000, 2)
    finally:
        if retry_session is not None:
            retry_session.close()
