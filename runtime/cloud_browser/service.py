"""Kernel backend selection and authenticated browser ownership helpers."""
import hashlib
import json

from vault.store import AccessError


def configured(vault_service):
    path = vault_service.policy.home / '.clanker-cloud' / 'config.json'
    if not path.exists():
        return None
    try:
        settings = json.loads(path.read_text())
    except (OSError, ValueError):
        raise AccessError('The Kernel browser configuration is invalid.', 503) from None
    if not isinstance(settings, dict):
        raise AccessError('The Kernel browser configuration is invalid.', 503)
    if settings.get('enabled') is False:
        return None
    from .kernel_client import KernelClient, validate_kernel_settings
    validate_kernel_settings(settings)
    from .kernel import KernelBrowser
    return KernelBrowser(vault_service, settings, KernelClient(vault_service.policy.home, settings))


class BrowserContext:
    def __init__(self, vault_service, settings, client):
        self.vault = vault_service
        self.settings = settings
        self.client = client
        self.directory = vault_service.policy.home / '.clanker-cloud'

    def context_key(self, turn):
        self.vault.validate_member(turn.source.scope_id, turn.source.user_id)
        if not self.vault.policy.authorize_source(turn.source):
            raise AccessError('This browser context is not authorized.', 403)
        return hashlib.sha256(('v2:' + turn.source.scope_id + ':' + turn.source.user_id + ':' + str(turn.home.resolve())).encode()).hexdigest()

    def owned_state(self, turn, path):
        owner = {'team': turn.source.scope_id, 'requester': turn.source.user_id}
        state = json.loads(path.read_text()) if path.exists() else {'owner': owner, 'sessions': {}, 'threads': {}}
        if state.get('owner') != owner:
            raise AccessError('The browser state has no verified requester ownership.', 403)
        return state

    def claim_session(self, turn, session_id):
        owner = (turn.source.scope_id, turn.source.user_id, self.context_key(turn))
        provider = type(self).__name__
        with self.vault.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT team,requester,context FROM browser_session_owners WHERE provider=? AND session_id=?',
                             (provider, session_id)).fetchone()
            if row and tuple(row) != owner:
                raise AccessError('The provider returned a browser assigned to another requester. This task is quarantined.', 403)
            db.execute('INSERT OR IGNORE INTO browser_session_owners VALUES (?,?,?,?,?)',
                       (provider, session_id, *owner))

    def check_access(self, turn, entry):
        if entry.get('cleanup_pending'):
            raise AccessError('Browser cookie cleanup has not been verified. This account context remains blocked.', 403)
        self.vault.delegations.check_execution(turn)
        if entry.get('access_handle'):
            self.vault.delegations.resolve(turn, entry['access_handle'])

    def bind_access(self, turn, access):
        self.vault.delegations.resolve(turn, access.handle)
        self.vault.delegations.check_execution(turn)
        path, state = self.state(turn)
        _, entry = self.selected(turn, state)
        if entry.get('access_handle') not in (None, access.handle):
            raise AccessError('This browser is bound to another credential. Stop it before opening a different account.', 403)
        entry['access_handle'] = access.handle
        self.save(path, state)
        self.vault.delegations.record_browser_use(turn, access)

    def save(self, path, state):
        from seatbelt.install import write
        write(path, json.dumps(state, indent=2) + '\n')

    def thread(self, turn):
        return turn.source.chat_id + ':' + str(turn.source.thread_id or '')

    def selected(self, turn, state):
        name = state['threads'].get(self.thread(turn))
        if not name or name not in state['sessions']:
            raise AccessError('Open this thread\'s Kernel browser before using saved access.', 409)
        return name, state['sessions'][name]
