"""Owner-requested exact-site reset followed by an atomic login writer handoff.

This broker is deliberately not a general cookie API. Cookie data remains in
memory on the trusted CDP channel; the durable ledger stores only identities
and phases. An uncertain mutation is never automatically repeated.
"""
from dataclasses import dataclass, field, replace
import hashlib
import json
import re
import time
from urllib.parse import urlsplit

from vault.delegation import credential_binding
from vault.store import AccessError

_PROOF = object()
_FIELDS = ('id', 'principal_key', 'remote_id', 'team', 'requester', 'home', 'thread')
_UNKNOWN = 'The site reset outcome requires reconciliation. It will not be repeated automatically.'


def reset_requested(auth, turn, origin):
    from vault.verification_retry import _text
    host = urlsplit(origin).hostname
    text = turn.owner_message
    if not host or not isinstance(text, str) or len(text) > 500:
        return False
    # Slack autolinks a bare hostname in the authenticated owner's request.
    # Accept only its exact host/label form, never a different target or URL
    # component. Remaining markup and all owner restrictions still fail closed.
    for scheme in ('http', 'https'):
        text = text.replace(f'<{scheme}://{host}|{host}>', host)
    text = _text(text)
    if not text or not host:
        return False
    clause = rf'(?:please )?clear cookies and site data for {re.escape(host)} in this browser only'
    sentences = [s for s in re.split(r'[.!?:;](?:\s+|$)', text) if s]
    matches = [i for i, sentence in enumerate(sentences) if re.fullmatch(clause, sentence)]
    if len(matches) != 1:
        return False
    remaining = '. '.join(s for i, s in enumerate(sentences) if i != matches[0])
    return auth._fresh_login_request(replace(turn, request_message=remaining))


def cookie_selectors(cookies, host):
    """Exact host/domain-cookie identities; never copy values or widen partitions."""
    if not isinstance(cookies, list):
        raise AccessError('The site cookie inventory could not be verified.', 409)
    selected = []
    for cookie in cookies:
        if not isinstance(cookie, dict):
            raise AccessError('The site cookie inventory could not be verified.', 409)
        if cookie.get('domain') not in {host, '.' + host}:
            continue
        if (not isinstance(cookie.get('name'), str) or not isinstance(cookie.get('path'), str) or
                not cookie['path'].startswith('/') or cookie.get('partitionKeyOpaque')):
            raise AccessError('This site cookie cannot be reset with an exact selector.', 409)
        item = {key: cookie[key] for key in ('name', 'domain', 'path')}
        if 'partitionKey' in cookie:
            partition = cookie['partitionKey']
            if (not isinstance(partition, dict) or set(partition) != {'topLevelSite', 'hasCrossSiteAncestor'} or
                    not isinstance(partition['topLevelSite'], str) or
                    urlsplit(partition['topLevelSite']).scheme not in {'https', 'http'} or
                    type(partition['hasCrossSiteAncestor']) is not bool):
                raise AccessError('This cookie partition is unsupported; no broader reset was attempted.', 409)
            item['partitionKey'] = dict(partition)
        selected.append(item)
    return selected


@dataclass(frozen=True)
class VerifiedBrowserClosure:
    lease_id: str
    principal_key: str
    remote_id: str
    team: str
    requester: str
    home: str
    thread: str
    _proof: object = field(default=None, repr=False, compare=False)

    def matches(self, lease, turn):
        return (self._proof is _PROOF and isinstance(lease, dict) and
            tuple(getattr(self, name) for name in ('lease_id', *_FIELDS[1:])) ==
            tuple(lease.get(name) for name in _FIELDS) and
            (self.team, self.requester, self.home, self.thread) ==
            (turn.source.scope_id, turn.source.user_id, str(turn.home.resolve()),
             turn.source.chat_id + ':' + str(turn.source.thread_id or '')))


def _close_verified(cloud, turn, lease):
    cloud.check_claim(turn, lease['remote_id'])
    if cloud.client.close_verified(lease['remote_id']) is not True:
        raise AccessError(_UNKNOWN, 409)
    return VerifiedBrowserClosure(*(lease[name] for name in _FIELDS), _proof=_PROOF)


async def _protocol(supervisor, origin, binding, session_id):
    """All operations use the verified active page's CDP browser context."""
    async def call(method, params=None, *, browser=False):
        response = await supervisor._cdp(method, params or {}, session_id=None if browser else session_id)
        if not isinstance(response, dict) or 'error' in response or not isinstance(response.get('result'), dict):
            raise AccessError(_UNKNOWN, 409)
        return response['result']

    current = await call('Target.getTargetInfo')
    info = current.get('targetInfo', {})
    parts = urlsplit(info.get('url', ''))
    if (info.get('type') != 'page' or not info.get('targetId') or
            f'{parts.scheme}://{parts.netloc}' != origin):
        raise AccessError('Navigate the current browser to the exact saved origin before reset.', 409)
    targets = (await call('Target.getTargets', browser=True)).get('targetInfos', [])
    context = info.get('browserContextId')
    pages = [target for target in targets if target.get('type') == 'page' and target.get('browserContextId') == context]
    if len(pages) != 1 or pages[0].get('targetId') != info['targetId']:
        raise AccessError('Site reset requires only this one page in the current browser context.', 409)
    probe = ('window.__hermesNativePageBinding === ' + json.dumps(binding['marker']) +
             ' && window.location.origin === ' + json.dumps(origin))
    result = await call('Runtime.evaluate', {'expression': probe, 'returnByValue': True})
    if result.get('exceptionDetails') or result.get('result', {}).get('value') is not True:
        raise AccessError('The active page changed before site reset.', 409)
    params = {'browserContextId': context} if context else {}
    host = parts.hostname
    # Preflight all partition selectors before the first site mutation.
    cookie_selectors((await call('Storage.getCookies', params, browser=True)).get('cookies'), host)
    await call('Emulation.setScriptExecutionDisabled', {'value': True})
    await call('Page.stopLoading')
    # DOMStorage resolves a live frame by origin; clear this namespace before
    # leaving its document, while page script execution is already disabled.
    await call('DOMStorage.clear', {'storageId': {'securityOrigin': origin, 'isLocalStorage': False}})
    # End the inspected document before clearing so its timers cannot immediately
    # replace the cleared state. This is an intentional part of the owner reset.
    await call('Page.navigate', {'url': 'about:blank'})
    # Navigation acknowledgment is not a committed-document observation. Poll
    # only metadata; do not evaluate script after disabling script execution.
    deadline = time.monotonic() + 5
    for _ in range(50):
        observed = (await call('Target.getTargetInfo')).get('targetInfo', {})
        if any(observed.get(k) != info.get(k) for k in ('targetId', 'browserContextId', 'type')):
            raise AccessError(_UNKNOWN, 409)
        if observed.get('url') == 'about:blank':
            break
        if observed.get('url') != info['url'] or time.monotonic() >= deadline:
            raise AccessError(_UNKNOWN, 409)
    else:
        raise AccessError(_UNKNOWN, 409)
    await call('Storage.clearDataForOrigin', {'origin': origin,
        'storageTypes': 'local_storage,indexeddb,cache_storage,service_workers'})
    cookies = (await call('Storage.getCookies', params, browser=True)).get('cookies')
    for selector in cookie_selectors(cookies, host):
        await call('Network.deleteCookies', selector)
    if cookie_selectors((await call('Storage.getCookies', params, browser=True)).get('cookies'), host):
        raise AccessError(_UNKNOWN, 409)


def _reset_protocol(supervisor, origin, binding):
    from tools.browser_supervisor import _schedule
    import asyncio
    with supervisor._state_lock:
        active, session_id = supervisor._active, supervisor._page_session_id
    if not active or not session_id or supervisor._loop is None:
        raise AccessError('The current browser control session is unavailable.', 409)
    _schedule(asyncio.wait_for(_protocol(supervisor, origin, binding, session_id), timeout=75),
              supervisor._loop, timeout=90)


def _ledger(store):
    with store.connection() as db:
        db.execute('CREATE TABLE IF NOT EXISTS browser_site_resets ('
            'key TEXT PRIMARY KEY, principal_key TEXT NOT NULL, identity TEXT NOT NULL, '
            'phase TEXT NOT NULL, browser_lease TEXT NOT NULL, auth_lease TEXT)')


def _phase(store, key, phase, lease=None):
    with store.connection() as db:
        db.execute('UPDATE browser_site_resets SET phase=?,auth_lease=? WHERE key=?',
            (phase, json.dumps(lease, sort_keys=True) if lease else None, key))


def _remove_browser(cloud, turn, old):
    path, state = cloud.state(turn)
    for name, entry in list(state['sessions'].items()):
        if ((entry.get('profile_lease') or {}).get('id') == old['id'] and
                entry.get('session_id') == old['remote_id']):
            cloud.detach(entry)
            state['sessions'].pop(name)
            state['threads'] = {k: v for k, v in state['threads'].items() if v != name}
    cloud.save(path, state)


def _unrelated_legacy_creation(db, request, principal, account_handle, now):
    """A narrow preserved unknown whose only possible writer names another profile.

    Expiry alone never resolves a provider outcome. This exception cannot admit
    a live human flow, a known connection/lease, or any ambiguous profile mapping.
    """
    if (request['kind'] != 'login' or request['status'] != 'waiting' or
            request['expires'] > now or request['purchase_unknown'] or
            not db.execute("SELECT 1 FROM sqlite_master WHERE name='kernel_auth_flows'").fetchone()):
        return False
    row = db.execute('SELECT * FROM kernel_auth_flows WHERE request_id=?', (request['id'],)).fetchone()
    if (not row or row['state'] != 'create_unknown' or row['connection_id'] is not None or
            row['principal_key'] is not None or row['auth_lease'] is not None or
            not re.fullmatch(r'[0-9a-f]{64}', row['key']) or
            row['profile_name'] != 'clanker-auth-' + row['key'][:40] or
            row['profile_name'] == principal['profile_name'] or row['account_handle'] == account_handle or
            (row['team'], row['requester'], row['account_owner'], row['home'], row['origin'], row['handle']) !=
            (request['team'], request['owner'], request['owner'], request['home'], request['origin'], request['handle']) or
            row['handle'] != row['account_handle']):
        return False
    try:
        source = json.loads(request['source'])
    except (ValueError, TypeError):
        return False
    return (isinstance(source, dict) and isinstance(source.get('chat_id'), str) and
        source.get('scope_id') == row['team'] and
        source.get('user_id') == row['requester'] and
        source.get('chat_id', '') + ':' + str(source.get('thread_id') or '') == row['thread'])


def _assert_no_pending_work(store, turn, principal, account_handle):
    from vault.kernel_store import expired_unfilled_code_request
    # A personal profile spans tasks and origins. Unmapped owner work is
    # ambiguous and blocks; only exact distinct legacy-profile provenance can
    # exclude a legacy unknown. Terminal unused code forms use the same proof
    # as normal polling, without changing their historical rows here.
    with store.connection() as db:
        db.execute('BEGIN')
        purchases = "EXISTS (SELECT 1 FROM kernel_purchases p WHERE p.request_id=r.id AND " \
            "p.state NOT IN ('completed','cancelled','review'))"
        requests = db.execute("SELECT r.*, " + purchases + " AS purchase_unknown FROM requests r "
            "WHERE r.team=? AND r.owner=? AND ("
            "r.status IN ('kernel_creating','kernel_create_unknown','waiting','saved') OR "
            "r.status='resumed' AND r.resume_delivered IS NULL OR " + purchases + ")",
            (turn.source.scope_id, turn.source.user_id)).fetchall()
        pending = any(not expired_unfilled_code_request(db, request, store.clock()) and
                      not _unrelated_legacy_creation(db, request, principal, account_handle, store.clock())
                      for request in requests)
        approval = db.execute("SELECT 1 FROM owner_approvals WHERE team=? AND user=? AND "
            "(state IN ('posting','pending') OR state='approved' AND resumed IS NULL) LIMIT 1",
            (turn.source.scope_id, turn.source.user_id)).fetchone()
    if pending or approval:
        raise AccessError('Resolve unfinished private work on this profile or reconcile its ownership before site reset.', 409)


def reset_for_auth(auth, turn, row, access):
    cloud, store = auth.service.cloud_browser, auth.service.store
    origin = access.meta.origin
    if (not reset_requested(auth, turn, origin) or access.grant_id or access.owner != turn.source.user_id or
            not row.get('connection_id') or row.get('account_owner') != access.owner or
            row.get('account_handle') != access.meta.id or row.get('origin') != origin or
            row.get('binding') != credential_binding(access.meta)):
        raise AccessError('Site reset requires a current explicit request for this owner\'s exact saved login.', 403)
    principal = cloud.profiles.selected(turn)
    cloud.profiles.authorize(turn, principal, access)
    if (principal['kind'] != 'personal' or principal['owner'] != turn.source.user_id or
            principal['key'] != row.get('principal_key') or
            cloud.profiles.selection_handle(turn) != access.handle):
        raise AccessError('Site reset requires the selected owner account in this personal browser.', 403)
    identity = json.dumps((turn.source.scope_id, turn.source.user_id, str(turn.home.resolve()),
        cloud.thread(turn), turn.message_id, principal['key'], row['key'], row['connection_id'],
        row['binding'], origin), separators=(',', ':'))
    key = hashlib.sha256(identity.encode()).hexdigest()
    _ledger(store)
    with auth.service.lock_for(turn.home):
        _assert_no_pending_work(store, turn, principal, access.meta.id)
        with store.connection() as db:
            prior = db.execute('SELECT * FROM browser_site_resets WHERE key=?', (key,)).fetchone()
            blocked = db.execute("SELECT 1 FROM browser_site_resets WHERE principal_key=? AND phase!='complete' AND key!=?",
                                 (principal['key'], key)).fetchone()
        if blocked:
            raise AccessError(_UNKNOWN, 409)
        if prior:
            if prior['identity'] != identity or prior['phase'] not in {'closed', 'complete'}:
                raise AccessError(_UNKNOWN, 409)
            old = json.loads(prior['browser_lease'])
            current = cloud.profiles.current_lease(principal['key'])
            # Handoff may have committed before the caller saved its receipt.
            # Only the exact intended auth writer/context can reconcile it.
            if (current and current['kind'] == 'auth' and current['writer_key'] == 'auth:' + row['key'] and
                    all(current[k] == old[k] for k in ('principal_key', 'team', 'requester', 'home', 'thread')) and
                    current['remote_id'] in (None, row['connection_id']) and
                    (prior['auth_lease'] is None or json.loads(prior['auth_lease'])['id'] == current['id'])):
                _remove_browser(cloud, turn, old)
                _phase(store, key, 'complete', current)
                return current
            # A confirmed-closed browser reservation survives a crash before
            # handoff. Reconfirm absence, never repeat the reset.
            if prior['phase'] == 'closed' and current == old:
                closure = _close_verified(cloud, turn, old)
                lease = cloud.profiles.handoff(old, turn, 'auth:' + row['key'], closure=closure)
                _remove_browser(cloud, turn, old)
                _phase(store, key, 'complete', lease)
                return lease
            raise AccessError(_UNKNOWN, 409)
        from tools import browser_vault_tool as native
        from tools.browser_supervisor import SUPERVISOR_REGISTRY
        task_id = cloud.native_task_id(turn)
        supervisor = cloud.assert_supervisor(turn, SUPERVISOR_REGISTRY.get(task_id))
        path, state = cloud.state(turn)
        _, entry = cloud.selected(turn, state)
        lease = entry.get('profile_lease') or {}
        if (entry.get('profile_principal') != principal['key'] or lease.get('state') != 'active' or
                lease.get('kind') != 'browser' or lease.get('remote_id') != entry.get('session_id')):
            raise AccessError('The current personal browser has no confirmed writer.', 409)
        if native._bind_active_page(task_id, expected_origin=origin).get('success') is not True:
            raise AccessError('Navigate the current browser to the exact saved origin before reset.', 409)
        binding = native._page_binding(supervisor)
        if not binding or not native._active_binding_matches(task_id, binding):
            raise AccessError('The current browser page could not be bound for reset.', 409)
        # Recheck authority immediately before persisting dispatch intent.
        cloud.assert_supervisor(turn, supervisor)
        cloud.profiles.authorize(turn, principal, access)
        _assert_no_pending_work(store, turn, principal, access.meta.id)
        with store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute("SELECT 1 FROM browser_site_resets WHERE principal_key=? AND phase!='complete'",
                          (principal['key'],)).fetchone():
                raise AccessError(_UNKNOWN, 409)
            db.execute('INSERT INTO browser_site_resets VALUES (?,?,?,?,?,NULL)',
                (key, principal['key'], identity, 'resetting', json.dumps(lease, sort_keys=True)))
        try:
            _reset_protocol(supervisor, origin, binding)
            closure = _close_verified(cloud, turn, lease)
        except Exception:
            _phase(store, key, 'unknown')
            raise AccessError(_UNKNOWN, 409) from None
        _phase(store, key, 'closed')
        _assert_no_pending_work(store, turn, principal, access.meta.id)
        replacement = cloud.profiles.handoff(lease, turn, 'auth:' + row['key'], closure=closure)
        _remove_browser(cloud, turn, lease)
        _phase(store, key, 'complete', replacement)
        return replacement
