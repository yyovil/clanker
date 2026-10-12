"""Opaque, requester-owned profile references; cookie data stays in Kernel."""
import hashlib
import json
from pathlib import Path
import secrets

from vault.store import AccessError


def claim(cloud, turn, profile_name):
    owner = (turn.source.scope_id, turn.source.user_id, cloud.context_key(turn))
    with cloud.vault.store.connection() as db:
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT team,requester,context FROM browser_session_owners '
            'WHERE provider=? AND session_id=?', ('KernelTaskProfile', profile_name)).fetchone()
        if row and tuple(row) != owner:
            raise AccessError('This saved browser profile belongs to another requester context.', 403)
        db.execute('INSERT OR IGNORE INTO browser_session_owners VALUES (?,?,?,?,?)',
            ('KernelTaskProfile', profile_name, *owner))


def _idle_private_writer(cloud, state, name):
    """Require trusted gateway idleness and no unfinished owner interaction."""
    from agent.gateway_context import current_gateway_turn, isolated_gateway_task
    from gateway.config import Platform
    from gateway.session import SessionSource

    current = current_gateway_turn()
    owner, entry = state['owner'], state['sessions'][name]
    if current is None or isolated_gateway_task(current.source):
        return False
    source = current.source
    if (source.platform != Platform.SLACK or source.chat_type != 'dm' or
            (source.scope_id, source.user_id) != (owner['team'], owner['requester'])):
        return False
    home = str(cloud.vault.private_home(owner['team'], owner['requester']).resolve())
    member = cloud.vault.validate_member(owner['team'], owner['requester'])
    if (str(Path(current.home).resolve()) != home or entry.get('home') != home or
            source.chat_id != member['dm_id'] or source.profile != member['profile']):
        return False
    runner = current.runner
    if not callable(getattr(runner, '_is_session_running', None)) or not callable(
            getattr(runner, '_session_key_for_source', None)):
        return False
    threads = [key for key, value in state['threads'].items() if value == name]
    if not threads:
        return False
    for thread in threads:
        chat, separator, root = thread.partition(':')
        if not separator or chat != member['dm_id']:
            return False
        previous = SessionSource(Platform.SLACK, chat, user_id=owner['requester'],
            scope_id=owner['team'], profile=member['profile'], thread_id=root or None)
        if runner._is_session_running(runner._session_key_for_source(previous)) is not False:
            return False
        with cloud.vault.store.connection() as db:
            # A queued resume or uncertain payment is unfinished even if the
            # gateway currently has no running model turn for this thread.
            requests = db.execute("SELECT r.source FROM requests r WHERE r.team=? AND r.owner=? AND r.home=? AND ("
                "r.status IN ('kernel_creating','kernel_create_unknown') OR "
                "r.status IN ('waiting','saved') AND r.expires>? OR "
                "r.status='resumed' AND r.resume_delivered IS NULL OR EXISTS ("
                "SELECT 1 FROM kernel_purchases p WHERE p.request_id=r.id AND "
                "p.state NOT IN ('completed','cancelled','review')))",
                (owner['team'], owner['requester'], home, cloud.vault.store.clock())).fetchall()
            for request in requests:
                try:
                    pending = json.loads(request['source'])
                except (ValueError, TypeError):
                    return False
                if pending.get('chat_id') == chat and (pending.get('thread_id') or '') == root:
                    return False
            if db.execute("SELECT 1 FROM owner_approvals WHERE team=? AND user=? AND home=? "
                "AND channel=? AND COALESCE(thread,'')=? AND expires>? AND "
                "(state IN ('posting','pending') OR state='approved' AND resumed IS NULL) LIMIT 1",
                (owner['team'], owner['requester'], home, chat, root, cloud.vault.store.clock())).fetchone():
                return False
    return True


def release_previous_writer(cloud, path, state, name):
    """Retire an expired browser or a verified idle owner's private writer."""
    entry = state['sessions'][name]
    if entry.get('dispatch_unknown'):
        return False
    session_id = entry.get('session_id')
    if not session_id:
        return True
    owner = state['owner']
    with cloud.vault.store.connection() as db:
        claim_row = db.execute('SELECT team,requester,context FROM browser_session_owners '
            'WHERE provider=? AND session_id=?', ('KernelBrowser', session_id)).fetchone()
    if not claim_row or tuple(claim_row) != (owner['team'], owner['requester'], path.stem):
        raise AccessError('The previous browser writer has no verified owner.', 403)
    if cloud.client.get_session(session_id) is not None:
        if not _idle_private_writer(cloud, state, name):
            return False
        cloud.check_remote(entry, vault=entry.get('vault_binding'), profile=entry.get('profile_binding'))
    cloud.close_entry(path, state, name, cleanup_auth=False)
    return True


def private_principal(cloud, turn):
    """Shared-channel discovery cannot load any member's saved browser state."""
    conversation = cloud.vault.policy.state.get('conversations', {}).get(turn.source.chat_id, {})
    if conversation.get('kind') != 'dm':
        return None
    return cloud.profiles.selected(turn)


def select(cloud, turn, path, state, name, auth, *, principal=None):
    if principal is None:
        return None
    cloud.profiles.authorize(turn, principal)
    if auth is not None and auth['profile_name'] != principal['profile_name']:
        raise AccessError('This legacy sign-in is not mapped to the selected persistent browser profile.', 409)
    remote = cloud.profiles.ensure_profile(principal, cloud.client)
    profile = {'name': principal['profile_name'], 'id': remote['id'],
               'principal_key': principal['key'], 'home': str(turn.home.resolve())}
    handle = cloud.profiles.selection_handle(turn)
    if handle:
        profile['access_handle'] = handle
    profiles = state.setdefault('task_profiles', {})
    previous = profiles.get(name)
    if previous and previous.get('name') != profile['name']:
        # Keep old snapshots quarantined. Never relabel or delete their cookies.
        state.setdefault('legacy_profiles', {})[previous['name']] = previous
    profiles[name] = profile
    cloud.save(path, state)
    return {'name': profile['name'], 'id': profile['id'], 'principal_key': principal['key']}


def select_account(cloud, turn, access):
    access = cloud.vault.delegations.resolve(turn, access.handle)
    if access.meta.kind != 'login':
        raise AccessError('Choose a saved login for this browser.', 403)
    principal = cloud.profiles.resolve(turn, access)
    with cloud.vault.lock_for(turn.home):
        path, state = cloud.state(turn)
        name = hashlib.sha256(cloud.thread(turn).encode()).hexdigest()[:24]
        current = state['sessions'].get(name, {})
        cloud.check_access(turn, current)
        if current.get('session_id') and current.get('profile_principal') != principal['key']:
            cloud.close_entry(path, state, name, cleanup_auth=False)
        cloud.profiles.select(turn, access)
        state.setdefault('account_selections', {})[name] = access.handle
        cloud.save(path, state)
        if state['sessions'].get(name, {}).get('session_id'):
            cloud.bind_access(turn, access)


def purge(cloud, path, state):
    # Task/grant cleanup closes requester sessions; it does not own persistent
    # principal deletion. Preserve legacy snapshots for explicit reconciliation.
    for profile in state.get('task_profiles', {}).values():
        if not profile.get('principal_key'):
            state.setdefault('legacy_profiles', {})[profile['name']] = profile
    state['task_profiles'] = {}
    cloud.save(path, state)


PROFILE_WAIT_SECONDS = 60.0
PROFILE_POLL_SECONDS = 0.25


def _idle_source(cloud, entry, lease, requesting_turn):
    from agent.gateway_context import current_gateway_turn
    from gateway.session import SessionSource
    current = current_gateway_turn()
    if (current is None or not entry.get('source') or
            current.source.scope_id != requesting_turn.source.scope_id or
            current.source.user_id != requesting_turn.source.user_id or
            str(Path(current.home).resolve()) != str(requesting_turn.home.resolve()) or
            cloud.thread(type('Turn', (), {'source': current.source})()) != cloud.thread(requesting_turn)):
        return False
    source = SessionSource.from_dict(entry['source'])
    if (source.scope_id != lease['team'] or source.user_id != lease['requester'] or
            cloud.thread(type('Turn', (), {'source': source})()) != lease['thread'] or
            str(Path(entry['home']).resolve()) != lease['home']):
        raise AccessError('The previous browser lease has inconsistent task ownership.', 403)
    runner = current.runner
    if not callable(getattr(runner, '_is_session_running', None)) or not callable(
            getattr(runner, '_session_key_for_source', None)):
        return False
    if runner._is_session_running(runner._session_key_for_source(source)) is not False:
        return False
    with cloud.vault.store.connection() as db:
        requests = db.execute("SELECT r.source FROM requests r WHERE r.team=? AND r.owner=? AND ("
            "r.status IN ('kernel_creating','kernel_create_unknown') OR "
            "r.status IN ('waiting','saved') AND r.expires>? OR "
            "r.status='resumed' AND r.resume_delivered IS NULL OR EXISTS ("
            "SELECT 1 FROM kernel_purchases p WHERE p.request_id=r.id AND "
            "p.state NOT IN ('completed','cancelled','review')))",
            (lease['team'], lease['requester'], cloud.vault.store.clock())).fetchall()
        for request in requests:
            try:
                pending = json.loads(request['source'])
            except (ValueError, TypeError):
                return False
            if all(pending.get(field) == getattr(source, field) for field in ('chat_id', 'thread_id', 'profile')):
                return False
        if db.execute("SELECT 1 FROM owner_approvals WHERE team=? AND user=? AND "
            "channel=? AND COALESCE(thread,'')=? AND expires>? AND "
            "(state IN ('posting','pending') OR state='approved' AND resumed IS NULL) LIMIT 1",
            (lease['team'], lease['requester'], source.chat_id, source.thread_id or '',
             cloud.vault.store.clock())).fetchone():
            return False
    return True


def reconcile_writer(cloud, lease, requesting_turn):
    """Only a confirmed expired or trusted idle browser can yield its profile."""
    import hashlib
    if lease['kind'] != 'browser' or lease.get('state') != 'active' or not lease.get('remote_id'):
        return False
    home = Path(lease['home']).resolve(strict=True)
    key = hashlib.sha256(('v2:' + lease['team'] + ':' + lease['requester'] + ':' + str(home)).encode()).hexdigest()
    path = cloud.directory / 'kernel' / 'contexts' / (key + '.json')
    with cloud.vault.lock_for(home):
        if not path.exists():
            return False
        state = json.loads(path.read_text())
        if state.get('owner') != {'team': lease['team'], 'requester': lease['requester']}:
            raise AccessError('The previous browser writer has no verified requester.', 403)
        for name, entry in state['sessions'].items():
            if (entry.get('profile_lease') or {}).get('id') != lease['id']:
                continue
            if entry.get('dispatch_unknown') or entry.get('session_id') != lease['remote_id']:
                return False
            with cloud.vault.store.connection() as db:
                claim_row = db.execute('SELECT team,requester,context FROM browser_session_owners '
                    'WHERE provider=? AND session_id=?', ('KernelBrowser', entry['session_id'])).fetchone()
            if not claim_row or tuple(claim_row) != (lease['team'], lease['requester'], key):
                raise AccessError('The previous browser writer has no verified owner.', 403)
            remote_absent = cloud.client.get_session(entry['session_id']) is None
            if not remote_absent:
                if not _idle_source(cloud, entry, lease, requesting_turn):
                    return False
                cloud.check_remote(entry, vault=entry.get('vault_binding'), profile=entry.get('profile_binding'))
            cloud.close_entry(path, state, name, cleanup_auth=False, remote_absent=remote_absent)
            return True
    return False


def acquire(cloud, turn, principal, writer_key, *, kind='browser'):
    import time
    from .profile_registry import ProfileBusy
    deadline = time.monotonic() + PROFILE_WAIT_SECONDS
    while True:
        cloud.profiles.authorize(turn, principal)
        try:
            return cloud.profiles.acquire(turn, principal, writer_key, kind=kind)
        except ProfileBusy as error:
            if reconcile_writer(cloud, error.lease, turn):
                continue
            if time.monotonic() >= deadline:
                raise
            time.sleep(min(PROFILE_POLL_SECONDS, max(0, deadline - time.monotonic())))
