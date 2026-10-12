"""Authenticated Slack turns -> private links -> durable save -> scoped resume.

The model never selects an owner, profile path, or link token. Only the live
gateway turn may bind a tool call to the already authenticated Slack source.
"""
import asyncio
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import threading
from urllib.parse import urlencode, urlsplit

from .store import AccessError, RequestStore

_lock = threading.RLock()


@dataclass
class Binding:
    service: object
    source: object
    task_id: str
    message: str
    home: Path
    message_id: str = None
    conversation: tuple[tuple[str, str], ...] = ()
    handoff_context: dict = field(default_factory=dict, repr=False)
    request_message: str = None

    @property
    def owner_message(self):
        # Gateway-added context is useful to the model, but it is not the
        # current owner's wording for retry authorization. Empty stays empty.
        return self.message if self.request_message is None else self.request_message


def binding(task_id):
    from hermes_constants import get_hermes_home
    from agent.gateway_context import current_gateway_turn
    from gateway.slack_workspace import workspace_policy
    current=current_gateway_turn()
    if current and current.task_id==str(task_id) and current.home==str(get_hermes_home()):
        policy=workspace_policy(current.runner,current.source)
        service=getattr(policy,'vault_service',None)
        if service:
            result=Binding(service,current.source,current.task_id,current.message,Path(current.home),
                           current.message_id,current.conversation,current.handoff_context,
                           current.request_message)
            service.validate_member(result.source.scope_id,result.source.user_id)
            if policy.authorize_source(result.source):return result
        raise AccessError('Secure access is unavailable in this session. The hosted vault must be connected by the operator.',503)
    raise AccessError('Secure access is unavailable in this session. The hosted vault must be connected by the operator.',503)


async def on_gateway_control(command, source, runner):
    if command not in ('stop','new','reset'):return None
    from gateway.slack_workspace import workspace_policy
    policy=workspace_policy(runner,source)
    service=getattr(policy,'vault_service',None)
    if service and policy.authorize_source(source):
        rows=service.store.channel_tasks_for_control(source.scope_id,source.user_id,source.to_dict())
        count=await asyncio.to_thread(service.store.cancel,team=source.scope_id,owner=source.user_id,source=source.to_dict())
        await asyncio.to_thread(service.approvals.cancel,source.scope_id,source.user_id)
        cleanup_pending=await service.channel_control.stop_sources(rows)
        conversation = policy.state['conversations'].get(source.chat_id,{})
        if (service.cloud_browser is not None and getattr(source,'isolated_task',None) is None and
                conversation.get('kind')=='dm'):
            home=policy.home if source.profile=='default' else policy.home/'profiles'/source.profile
            turn=Binding(service,source,'control','',home.resolve(strict=True))
            try:
                await asyncio.to_thread(service.cloud_browser.stop,turn)
            except Exception:
                cleanup_pending=True
        return {'cancelled_pending':count,'cleanup_pending':cleanup_pending}


class VaultService:
    def __init__(self, policy, config):
        self.policy, self.config = policy, config
        self.store = RequestStore(policy.home/'.clanker-vault')
        from .owner_approval import OwnerApprovals
        self.approvals = OwnerApprovals(self)
        from .delegation import Delegations
        self.delegations = Delegations(self)
        from .personal import PersonalInfo
        self.personal = PersonalInfo(self)
        from .card_payments import Payments
        self.payments = Payments(self)
        self.loop = None
        self.fill_locks = {}
        self.link_delivery_locks = {}
        self.resume_tasks = {}
        self.poll_tasks = {}
        self.poll_closing = False
        from .channel_tasks import ChannelTasks
        self.channel_tasks = ChannelTasks(self)
        from .channel_control import ChannelControl
        self.channel_control = ChannelControl(self)
        from cloud_browser.service import configured
        self.cloud_browser = configured(self)
        self.kernel_vault = None
        self.kernel_auth = None
        if config.get('provider') == 'kernel':
            if self.cloud_browser is None:
                raise AccessError('Kernel Vault requires the authenticated Kernel browser backend.', 503)
            from .kernel_service import KernelVaultService
            from .kernel_personal import KernelPersonalInfo
            self.kernel_vault = KernelVaultService(self)
            self.personal = KernelPersonalInfo(self, self.kernel_vault)
            from .managed_auth import ManagedAuth
            self.kernel_auth = ManagedAuth(self)
            from cloud_browser.profile_migration import apply_startup
            apply_startup(self)
            from cloud_browser.profile_provisioning import apply_startup as provision_profiles
            provision_profiles(self)
            from cloud_browser.profile_cleanup import apply_startup as cleanup_profiles
            cleanup_profiles(self)

    def credential_store(self, team, owner):
        if self.kernel_vault is None:
            raise AccessError('Kernel Vault is not activated. No local credential storage is available.', 503)
        return self.kernel_vault.native_store(team, owner)

    def validate_member(self, team, owner):
        member = self.policy.state['members'].get(owner,{})
        if team!=self.policy.team or member.get('status')!='ready':
            raise AccessError('This Slack account is not authorized for Clanker.',403)
        return member

    def private_home(self, team, owner):
        member = self.validate_member(team,owner)
        profile = member['profile']
        home = self.policy.home if profile=='default' else self.policy.home/'profiles'/profile
        home = home.resolve(strict=True)
        if home!=self.policy.home.resolve() and not home.is_relative_to((self.policy.home/'profiles').resolve()):
            raise AccessError('The private account context is unavailable.',403)
        return home

    def assert_private(self, turn):
        member = self.validate_member(turn.source.scope_id,turn.source.user_id)
        home = self.private_home(turn.source.scope_id,turn.source.user_id)
        conversation = self.policy.state['conversations'].get(turn.source.chat_id,{})
        profile = member['profile']
        if getattr(turn.source,'isolated_task',None) is not None:
            profile = self.channel_tasks.execution_route(turn.source)
            home = self.policy.home / 'profiles' / profile
        if (conversation.get('kind')!='dm' or home!=turn.home.resolve() or
                turn.source.chat_id!=member['dm_id'] or turn.source.profile!=profile or
                not self.policy.authorize_source(turn.source)):
            raise AccessError('Private accounts are available only in your DM with Clanker.',403)
        return home

    async def invitation_members(self, identity):
        self.validate_member(identity['team'], identity['owner'])
        members = []
        client = self.policy.client()
        for uid, member in self.policy.state['members'].items():
            if uid == identity['owner'] or member.get('status') != 'ready':
                continue
            label = member.get('name') or uid
            if hasattr(client, 'users_info'):
                try:
                    user = (await client.users_info(user=uid))['user']
                    label = user.get('profile', {}).get('display_name') or user.get('real_name') or user.get('name') or uid
                except Exception:
                    pass
            members.append({'id': uid, 'name': label})
        return members

    async def revoke_invitation(self, identity, grant_id):
        grant = self.delegations.revoke(identity, grant_id)
        with self.store.connection() as db:
            usages = [dict(row) for row in db.execute(
                'SELECT * FROM credential_grant_usage WHERE grant_id=? AND team=? AND recipient=?',
                (grant_id, grant['team'], grant['recipient']))]
        pending = False
        for usage in usages:
            try:
                await self.channel_control.stop_usage(usage)
            except Exception:
                # Each uncertain context retains its own usage marker. Continue
                # interrupting the other contexts that used this invitation.
                pending = True
        return {'revoked': True, 'cleanup_pending': pending}

    async def set_invitation_access(self, identity, recipient, handles):
        result = await asyncio.to_thread(self.delegations.set_access, identity, recipient, handles)
        pending = False
        # Every revoked grant can have distinct guest task cookie contexts.
        for grant_id in result['revoked']:
            with self.store.connection() as db:
                used = db.execute('SELECT 1 FROM credential_grant_usage WHERE grant_id=?', (grant_id,)).fetchone()
            if used:
                pending = (await self.revoke_invitation(identity, grant_id))['cleanup_pending'] or pending
        notification = 'not_needed'
        if result['added']:
            notification = await self.notify_invitation(identity, recipient, len(result['added']))
        return {'saved': True, 'recipient': recipient, 'cleanup_pending': pending,
                'notification': notification,
                'grants': [{'id': row['id'], 'handle': row['handle']} for row in result['grants']]}

    async def notify_invitation(self, identity, recipient, count):
        # Access is already committed. Slack failures must not look like a
        # failed grant, or encourage the owner to create duplicate invitations.
        try:
            self.validate_member(identity['team'], identity['owner'])
            member = self.validate_member(identity['team'], recipient)
            dm = member['dm_id']
            if not isinstance(dm, str) or not dm.startswith('D'):
                return 'failed'
            url = self.config['public_url'].rstrip('/') + '/vault'
            summary = (f"<@{identity['owner']}> shared {count} "
                       f"{'credential' if count == 1 else 'credentials'} with you in Clanker.")
            instruction = 'Find them under Shared with you in your vault. You can use them on the owner\'s behalf.'
            posted = await asyncio.wait_for(self.policy.client().chat_postMessage(
                channel=dm, unfurl_links=False, unfurl_media=False,
                text=summary + '\n' + instruction + '\nOpen vault: ' + url,
                blocks=[{'type': 'section', 'text': {'type': 'mrkdwn', 'text': summary + '\n' + instruction}},
                        {'type': 'actions', 'elements': [{'type': 'button',
                         'text': {'type': 'plain_text', 'text': 'Open vault'},
                         'url': url, 'action_id': 'clanker_vault_link'}]}]), timeout=10)
            return 'sent' if posted.get('ts') and posted.get('ok') is not False else 'failed'
        except Exception:
            # Provider errors may contain sensitive inputs. Report only the
            # delivery status to the owner; never echo or log the exception.
            return 'failed'

    def clear_invited_browsers(self, turn):
        home = self.channel_control.validate_cleanup(turn)
        with self.lock_for(home):
            errors = []
            if self.cloud_browser is not None:
                try:
                    self.cloud_browser.stop_by_home(home)
                except Exception as error:
                    errors.append(error)
            try:
                from seatbelt.retired_browsers import stop_owned_local_browsers
                stop_owned_local_browsers(home, purge=True)
            except Exception as error:
                errors.append(error)
            if errors:
                raise AccessError('Browser cleanup is still pending. This account context remains blocked.', 409)
            # Keep cleanup and its completion marker inside the guest lock.
            # A new fill must not race between cookie removal and this delete.
            with self.store.connection() as db:
                db.execute('DELETE FROM credential_grant_usage WHERE team=? AND recipient=? AND home=?',
                           (turn.source.scope_id, turn.source.user_id, str(home)))

    def call(self, coroutine, *, timeout=30):
        if self.loop is None or not self.loop.is_running():
            coroutine.close()
            raise AccessError('The hosted credential service is unavailable.',503)
        future = asyncio.run_coroutine_threadsafe(coroutine,self.loop)
        try:
            return future.result(timeout=timeout)
        except TimeoutError:
            future.cancel()
            raise AccessError('The access request is still pending. Please retry shortly.',503) from None

    def lock_for(self, home):
        with _lock:
            return self.fill_locks.setdefault(str(home),threading.RLock())

    async def move_private(self, turn):
        policy = self.policy
        if (policy.state['conversations'].get(turn.source.chat_id,{}).get('kind')!='shared' or
                not policy.authorize_source(turn.source)):
            raise AccessError('This account task is not authorized in this conversation.',403)
        original = turn.source.to_dict()
        if turn.message_id:original['message_id']=turn.message_id
        edits = getattr(policy.adapter, '_message_edits', None)
        revision = edits.lookup((turn.source.scope_id, turn.source.chat_id, turn.source.user_id,
                                 original.get('message_id'))) if edits else None
        if revision:
            original['slack_request_version'] = str(revision.version)
            original['slack_request_digest'] = revision.digest
        original['thread_id'] = turn.source.thread_id or turn.source.message_id or turn.message_id
        if not original['thread_id']:
            raise AccessError('The originating Slack message is unavailable.',409)
        home=self.private_home(turn.source.scope_id,turn.source.user_id)
        row=self.store.linked_channel_task(original,active_only=True)
        pending_access = row is not None and self.store.pending_channel_access(row)
        if row is not None and not pending_access:
            # A historical form is not a queued continuation. New shared
            # requests get fresh isolated work, only after the prior turn ends.
            busy = (row['status'] in ('waiting','saved') or row['task_state']=='result_pending' or
                    row['id'] in self.resume_tasks)
            if row['source']:
                from gateway.session import SessionSource
                from gateway.platforms.event import MessageEvent
                source = SessionSource.from_dict(json.loads(row['source']))
                self.channel_tasks.restore(source)
                policy.adapter._canonicalize(source)
                key = policy.adapter._event_session_key(MessageEvent('',source=source))
                task = policy.adapter._session_tasks.get(key)
                busy = busy or key in policy.adapter._active_sessions or (task is not None and not task.done())
            if busy:
                raise AccessError('The existing private worker or its result is still pending. '
                    'The latest shared request was not dispatched. Wait for that work to finish before retrying.',409)
            row=None
        if row is None:
            from .task_context import recalled_context, context_receipt
            recalled = recalled_context(turn)
            row=self.store.transfer(team=turn.source.scope_id,owner=turn.source.user_id,home=home,
                task_id=turn.task_id,source=original,
                task=self.channel_tasks.request_context(turn,recalled=recalled),reply_mode='channel',
                context_receipt=context_receipt(recalled))
        await self.deliver_transfer(row)
        await self.drain()
        with self.store.connection() as db:
            current = dict(db.execute('SELECT * FROM transfers WHERE id=?',(row['id'],)).fetchone())
        result = {'status':'moved_to_private','private_results':True,
                  'task_context_saved':not pending_access,
                  **json.loads(current.get('context_receipt') or '{"recalled_message_ids":[],"recalled_context_truncated":false}'),
                  'shared_updates':'clanker_task_update',
                  'reply_surface':'original_shared_channel',
                  'next':'The private task thread is ready and its worker continues automatically. Task context is saved; recalled_message_ids identifies the exact recalled source messages included. Claim recalled choices were carried over only when their source is listed; truncated context is incomplete. Your reply is still in the shared channel: say the DM is ready and share private_thread_url so the requester can reply there. Never call this channel private or ask for passenger/contact details here. Return private_thread_url as a task-thread link, not a vault link or credential-form link. Moving the task does not mean a credential form was sent; the worker sends a secure form only when access is needed. Do not ask the requester to wait for or save credentials unless a form has actually been sent. End this turn.'}
        if pending_access:
            result['new_request_dispatched'] = False
            result['next'] = ('The existing private task has pending access or access continuation. '
                'The latest shared request was not forwarded and no new worker was started. '
                'Only the previously saved task context and recalled_message_ids remain with that worker. '
                'Explain that status accurately; do not claim the latest changes are queued or being applied. '
                'The requester can send changes in the linked private task thread. '
                'This reply stays in the shared channel; never ask for credentials or private details here. End this turn.')
        get_link = getattr(self.policy.client(),'chat_getPermalink',None)
        if get_link is not None and current['source']:
            destination=json.loads(current['source'])
            try:
                link=await get_link(channel=destination['chat_id'],message_ts=destination['thread_id'])
                if link.get('permalink'):result['private_thread_url']=link['permalink']
            except Exception:
                result['private_thread_link_unavailable']=True
        return result

    async def deliver_transfer(self, row):
        from gateway.session import SessionSource
        from gateway.config import Platform
        if row.get('source') or row['status']!='waiting':return
        member = self.validate_member(row['team'],row.get('approver') or row['owner'])
        dm = member['dm_id']
        profile = member['profile']
        if row['reply_mode']=='channel':
            profile = await self.channel_tasks.prepare(row)
        message_id = 'clanker-private-'+row['id']
        from uuid import uuid5, NAMESPACE_URL
        client_id = str(uuid5(NAMESPACE_URL,message_id))
        history = await self.policy.client().conversations_history(channel=dm,limit=100)
        existing = next((m for m in history.get('messages',[]) if m.get('client_msg_id')==client_id),None)
        delivered = existing or await self.policy.client().chat_postMessage(channel=dm,
            text=("I'll continue your task here, with the original conversation's context. "
                  "If account access is needed, I'll send a secure form in this thread. "
                  "Private questions and details stay here. I'll share brief progress and the outcome in the original thread."
                  if row['reply_mode']=='channel' else "I'll handle your account access and results privately here."),client_msg_id=client_id)
        original=json.loads(row['original_source'])
        source = SessionSource(platform=Platform.SLACK,chat_id=dm,chat_type='dm',user_id=row['owner'],
                               user_name=original.get('user_name'),thread_id=delivered['ts'],scope_id=row['team'],
                               profile=profile)
        self.store.set_transfer_source(row['id'],source.to_dict())

    async def public_update(self, turn, kind, stage, text='', *, thread=None):
        return await self.channel_tasks.public_update(turn,kind,stage,text,thread=thread)

    async def request_access(self, turn, *, label='', identifier='', kind='login', origin='', login_method='auto', use_primary=True):
        if kind == 'login' and self.kernel_auth is not None:
            try:
                self.assert_private(turn)
            except AccessError:
                return await self.move_private(turn)
            return await self.kernel_auth.authenticate(turn, origin=origin or None)
        if self.kernel_vault is not None:
            return await self.kernel_vault.request_access(turn, label=label, identifier=identifier,
                kind=kind, origin=origin, login_method=login_method, use_primary=use_primary)
        raise AccessError('Kernel Vault is not activated. No local credential form is available.', 503)

    async def deliver_link(self, row, *, delivery_event_id=None):
        # A resend is a new Slack delivery, never a new provider login or code.
        # The event comes from the authenticated turn, not a model argument.
        if delivery_event_id is not None and (not isinstance(delivery_event_id, str) or
                not re.fullmatch(r'[0-9]{10,}\.[0-9]{6}', delivery_event_id)):
            raise AccessError('Resending a private link requires a current Slack request.', 409)
        lock = self.link_delivery_locks.setdefault(row['id'], asyncio.Lock())
        async with lock:
            return await self._deliver_link(row['id'], delivery_event_id)

    def private_link_response_owned(self, source, event_id):
        """A committed sign-in card answers only its own private request turn."""
        if (self.kernel_auth is None or not isinstance(event_id, str) or
                not re.fullmatch(r'[0-9]{10,}\.[0-9]{6}', event_id)):
            return False
        member = self.validate_member(source.scope_id, source.user_id)
        if (source.chat_type != 'dm' or source.chat_id != member['dm_id'] or
                source.profile != member['profile'] or not self.policy.authorize_source(source)):
            return False
        with self.store.connection() as db:
            rows = db.execute('''
                SELECT r.source FROM requests r
                JOIN kernel_auth_flows a ON a.request_id=r.id
                JOIN private_link_deliveries d ON d.request_id=r.id
                WHERE r.team=? AND r.owner=? AND r.approver IS NULL
                  AND a.state IN ('pending','authenticated')
                  AND (r.status IN ('saved','resumed') OR (r.status='waiting' AND r.expires>?))
                  AND d.message_ts<>''
                  AND (d.event_id=? OR (d.event_id='initial' AND r.gateway_event_id=?))
            ''', (source.scope_id, source.user_id, self.store.clock(), event_id, event_id)).fetchall()
        return any(self.store.same_task_source(json.loads(row['source']), source.to_dict()) for row in rows)

    async def _link_delivery_receipt(self, row, member, message_ts, status):
        source = json.loads(row['source'])
        receipt = {'status': status,
                   'recipient': 'account_owner' if row.get('approver') else 'requester',
                   'location': 'private_thread' if source.get('thread_id') and not row.get('approver') else 'private_dm'}
        # An invited account's owner receives the form in their own private DM.
        # Never return that DM's permalink to the requester.
        get_link = getattr(self.policy.client(), 'chat_getPermalink', None)
        if not row.get('approver') and get_link is not None:
            try:
                result = await get_link(channel=member['dm_id'], message_ts=message_ts)
                url = result.get('permalink')
                parts = urlsplit(url) if isinstance(url, str) else None
                expected_path = '/archives/' + member['dm_id'] + '/p' + message_ts.replace('.', '')
                if (result.get('ok') is not False and parts and parts.scheme == 'https' and parts.hostname and
                        parts.hostname.endswith('.slack.com') and not parts.username and
                        not parts.password and parts.port in (None, 443) and parts.path == expected_path):
                    # Thread permalinks include Slack routing query parameters.
                    # The canonical message URL needs only its verified path.
                    receipt['message_url'] = parts._replace(query='', fragment='').geturl()
            except Exception:
                pass  # Delivery is committed even if its permalink is unavailable.
        return receipt

    async def _deliver_link(self, request_id, delivery_event_id):
        def current_request():
            with self.store.connection() as db:
                current = db.execute('SELECT * FROM requests WHERE id=?', (request_id,)).fetchone()
            if not current or current['status'] != 'waiting' or current['expires'] <= self.store.clock():
                raise AccessError('This private access request expired or was cancelled.', 410)
            return dict(current)

        row = current_request()
        # The durable outbox can see the request while Kernel creation is still
        # running or its acknowledgement was lost. Publish only a verified,
        # current hosted login; otherwise a broken link escapes on drain().
        if self.kernel_auth is not None and self.kernel_auth.flow_for_request(row['id']):
            await asyncio.to_thread(self.kernel_auth.hosted_link, row)
        member = self.validate_member(row['team'],row.get('approver') or row['owner'])
        if delivery_event_id == row.get('gateway_event_id'):
            delivery_event_id = None
        event_id = delivery_event_id or 'initial'
        with self.store.connection() as db:
            delivered = db.execute('SELECT message_ts FROM private_link_deliveries WHERE request_id=? AND event_id=?',
                                   (row['id'], event_id)).fetchone()
        message_ts = (delivered['message_ts'] if delivered else None) if delivery_event_id else row.get('message_ts')
        if message_ts:
            return await self._link_delivery_receipt(row, member, message_ts, 'already_sent')

        from uuid import uuid5, NAMESPACE_URL
        key = 'clanker-access:' + row['id'] + (':retry:' + delivery_event_id if delivery_event_id else '')
        message_id = str(uuid5(NAMESPACE_URL, key))
        source = json.loads(row['source'])
        thread = (source.get('thread_id') or None) if not row.get('approver') else None
        client = self.policy.client()
        replies = getattr(client, 'conversations_replies', None) if thread else None
        cursor, posted = None, None
        while True:
            args = {'channel': member['dm_id'], 'limit': 100}
            if cursor:args['cursor'] = cursor
            if replies is not None:
                args['ts'] = thread
                history = await replies(**args)
            else:
                history = await client.conversations_history(**args)
            if history.get('ok') is False:
                raise AccessError('Private link delivery could not be confirmed. Please retry.', 503)
            posted = next((m for m in history.get('messages', []) if m.get('client_msg_id') == message_id), None)
            cursor = history.get('response_metadata', {}).get('next_cursor')
            if posted or not cursor:
                if not posted and history.get('has_more') and not cursor:
                    raise AccessError('Private link delivery could not be confirmed. Please retry.', 503)
                break
        recovered = posted is not None
        if not posted:
            row = current_request()
            self.validate_member(row['team'], row.get('approver') or row['owner'])
            url = self.config['public_url'].rstrip('/')+'/vault/fill#'+urlencode({'r':row['id'],'token':self.store.token(row['id'])})
            instructions={'code':("Enter your current verification code securely. I'll continue after you submit it.",'Enter verification code'),
                          'login':("Add your login securely. I'll continue after you save it.",'Add login to vault'),
                          'api_key':("Add your API key securely. I'll continue after you save it.",'Add API key to vault'),
                          'payment':("Enter your card privately to pay.", row['label'].split(' · ',1)[-1])}
            instruction,button=instructions[row['kind']]
            if self.kernel_auth is not None and self.kernel_auth.flow_for_request(row['id']):
                instruction,button=("Sign in to your account securely. I'll continue when you're signed in.", 'Continue sign-in')
            posted = await client.chat_postMessage(channel=member['dm_id'],
                thread_ts=thread,client_msg_id=message_id,unfurl_links=False,unfurl_media=False,
                text=urlsplit(row['origin']).hostname+': '+instruction,
                blocks=[{'type':'section','text':{'type':'plain_text','text':row['label']+'\n'+instruction}},
                        {'type':'actions','elements':[{'type':'button','text':{'type':'plain_text','text':button},'url':url,'action_id':'clanker_vault_link'}]}])
        if posted.get('ok') is False or not posted.get('ts'):
            raise AccessError('Private link delivery could not be confirmed. Please retry.', 503)
        with self.store.connection() as db:
            db.execute('INSERT OR IGNORE INTO private_link_deliveries VALUES (?,?,?)',
                       (row['id'], event_id, posted['ts']))
            db.execute('UPDATE requests SET message_ts=? WHERE id=?', (posted['ts'],row['id']))
        return await self._link_delivery_receipt(row, member, posted['ts'], 'already_sent' if recovered else 'sent')

    async def request_code(self, turn, meta, *, access=None):
        if self.kernel_vault is not None:
            return await self.kernel_vault.request_code(turn, access or self.delegations.resolve(turn, meta.id))
        raise AccessError('Kernel Vault is not activated. No local code form is available.', 503)

    def delivery_owned(self, key, event_id):
        """A native final-response obligation owns delivery across the outbox crash gap."""
        from gateway.delivery_ledger import _db_path, compute_obligation_id
        import sqlite3
        path=_db_path()
        if not path.exists():return False
        with sqlite3.connect('file:'+str(path)+'?mode=ro',uri=True) as db:
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='delivery_obligations'").fetchone():return False
            for oid,content in db.execute('SELECT obligation_id,content FROM delivery_obligations WHERE session_key=?',(key,)):
                if oid==compute_obligation_id(key,event_id,content):return True
        return False

    async def resume(self, row, *, transfer=False, recovery_event_id=None):
        from gateway.session import SessionSource
        from gateway.platforms.event import MessageEvent
        member = self.validate_member(row['team'],row['owner'])
        source = SessionSource.from_dict(json.loads(row['source']))
        channel_task = self.channel_tasks.restore(source)
        origin_context = ''
        finish=self.store.mark_transfer_resumed if transfer else self.store.mark_resumed
        if recovery_event_id:
            if not transfer:raise AccessError('Task recovery requires its original private handoff.',403)
            finish=lambda task_id:self.store.mark_task_recovered(task_id,recovery_event_id)
            if (row.get('recovery_profile')!=member['profile'] or
                    not self.store.is_pending_recovery(row['id'],recovery_event_id)):
                finish(row['id']);return
        if channel_task:
            if channel_task['task_state']=='result_pending' and channel_task['result_return_state']=='active':
                await self.channel_tasks.deliver(channel_task['id'])
                channel_task=self.store.channel_task(source.to_dict())
            if channel_task['task_state'] in ('completed','result_pending','cancelled'):
                finish(row['id'])
                return
            origin_context = await self.channel_tasks.origin_context(channel_task)
            await self.policy.serve_profile(source.profile)
            self.channel_tasks.execution_route(source)
        if not transfer:
            self.delegations.request_access(row)
        expected_profile = source.profile if channel_task else member['profile']
        if source.chat_id!=member['dm_id'] or source.profile!=expected_profile or self.private_home(row['team'],row['owner'])!=Path(row['home']):
            raise AccessError('The original private task is no longer authorized.',403)
        if not recovery_event_id and not self.store.is_pending(row['id'],transfer=transfer):return
        managed_prefix = (await asyncio.to_thread(self.kernel_auth.resume_prefix, row)
                          if not transfer and self.kernel_auth is not None else None)
        prefix=(("Continue the original channel task using only this requester's authorized account. "
                 "This is an isolated task: do not use unrelated private conversations or files. "
                 "Your ordinary replies, questions and private detail collection stay in this DM. "
                 "Use clanker_task_update for brief meaningful shared progress and the final public outcome. "
                 "Ordinary DM dialogue and private details are never mirrored to the shared thread. "
                 "Login and code forms are delivered privately. Do not include credentials or access links in the result."
                 if channel_task else "Continue the requester's private account task. Keep account observations and results in this DM.") if transfer else
                f"{'Verification code submitted; use clanker_vault_enter_code' if row['kind']=='code' else 'Access saved'} for {row['label']} ({row['origin']}). Credential handle: {row['handle']}. Authentication is only a step in the original task below. After checking it, continue the selected task from its stopping point. Preserve confirmed route, dates, passengers, selections and price decisions. Ask only for missing details; login success alone is not task completion.")
        if not transfer and row['kind']=='payment':
            prefix=f"Native Kernel purchase {row['id']} has a private payment update. Use clanker_payment_status before continuing. For ready, use clanker_payment_fill then clanker_payment_submit. For otp_ready, use clanker_payment_verify_code; never submit the purchase again. Continue the reviewed Pay by card checkout. Use the remembered card directly when ready. Never submit through ordinary browser tools or repeat an uncertain purchase. Observe the merchant result and use clanker_payment_complete for the new private-card flow; legacy purchases retain their existing reconciliation path."
        if managed_prefix:
            prefix = managed_prefix + '\nOriginal site: ' + row['origin'] + '. Account handle: ' + row['handle'] + '.'
        if recovery_event_id:
            prefix += ('\nThis task was stranded by an earlier DM routing error. Resume the original goal automatically '
                       'without asking the requester to say continue. Verification in another profile is not account '
                       'authorization for this worker. Check only this isolated task\'s own browser session; if verification '
                       'is still needed, request a fresh private code here. Do not replay old codes, copy cookies, or transfer '
                       'payment approval. Preserve confirmed choices and continue until the next real blocker or verified result.')
        if origin_context:
            prefix += '\n\n' + origin_context
        event_id=recovery_event_id or ('clanker-private-resume-' if transfer else 'clanker-access-resume-')+row['id']
        event = MessageEvent(source=source,user_id=source.user_id,user_name=source.user_name,
            text=prefix+'\n\nOriginal request: '+row['task'],message_id=event_id,
            allow_gateway_control=False,metadata={'clanker_private_resume' if transfer else 'clanker_access_resume':row['id']})
        # Use the native gateway turn/delivery path and await its completion. The
        # saved record stays retryable across shutdown, with no secret in events.
        adapter = self.policy.adapter
        adapter._canonicalize(source)
        key = adapter._event_session_key(event)
        if key in adapter._active_sessions:
            return
        if channel_task:
            if self.store.channel_task_requested_access(source.to_dict(),event_id):
                # This native turn durably handed off to a form. Its saved
                # request owns continuation even if the waiting reply was not
                # acknowledged before shutdown, or the form is already saved.
                finish(row['id'])
                return
            recovered = await asyncio.to_thread(self.channel_tasks.recover_response,channel_task,event_id)
            if recovered is not None:
                await self.channel_tasks.handle_response(event,recovered,getattr(adapter,'gateway_runner',None))
                finish(row['id'])
                return
        if await asyncio.to_thread(self.delivery_owned,key,event_id):
            finish(row['id']);return
        if channel_task and not self.store.begin_channel_reply(channel_task['id'],event_id,recovery=bool(recovery_event_id)):
            finish(row['id']);return
        if recovery_event_id:
            self.store.expire_recovery_form(row['id'],recovery_event_id)
        await adapter.handle_message(event)
        if not getattr(event,'_gateway_accepted',False):
            return
        task = adapter._session_tasks.get(key)
        if task is None:
            return
        await asyncio.shield(task)
        if channel_task and hasattr(event,'_isolated_response'):
            current = self.store.channel_task(source.to_dict())
            if (current['task_state']=='active' and current['result_event_id']!=event_id and
                    not self.store.channel_task_waiting(source.to_dict())):
                # Adopt the native completed reply before retrying any work.
                return
        finish(row['id'])

    @staticmethod
    async def _await_owned_task(task):
        # Cancelling an asyncio wrapper cannot stop its running thread. Keep
        # ownership until that worker ends, including during gateway shutdown.
        cancelled = False
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                cancelled = True
            except Exception:
                break
        if cancelled:
            if not task.cancelled():
                task.exception()  # retrieve a worker failure before propagating cancellation
            raise asyncio.CancelledError
        return task.result()

    def _schedule_poll(self, name, provider, *, deliver=None):
        if getattr(self, 'poll_closing', False):
            return
        tasks = getattr(self, 'poll_tasks', None)
        if tasks is None:
            self.poll_tasks = tasks = {}
        previous = tasks.get(name)
        if previous is not None and not previous.done():
            return

        async def poll():
            try:
                worker = asyncio.create_task(asyncio.to_thread(provider.poll))
                await self._await_owned_task(worker)
                if deliver is not None and not getattr(self, 'poll_closing', False):
                    await deliver()
            except Exception:
                # Individual transports log sanitized failures. A failed poll
                # can run on the next pass without blocking unrelated owners.
                pass
            finally:
                if tasks.get(name) is asyncio.current_task():
                    tasks.pop(name, None)

        tasks[name] = asyncio.create_task(poll())

    async def drain(self):
        if getattr(self, 'poll_closing', False):
            return
        if self.kernel_vault is not None:
            self._schedule_poll('payments', self.payments, deliver=self.payments.deliver_actions)
        if self.kernel_auth is not None:
            self._schedule_poll('auth', self.kernel_auth)
        if self.kernel_vault is not None:
            self._schedule_poll('vault', self.kernel_vault)
        await self.channel_tasks.drain()
        await self.approvals.drain()
        async def dispatch(row,transfer):
            try:
                recovery_event_id=row.get('recovery_event_id') if row.get('recovery_state')=='pending' else None
                if transfer and not recovery_event_id:
                    await self.deliver_transfer(row)
                    row=next((item for item in self.store.pending_transfers() if item['id']==row['id']),None)
                    if row is None:return
                if not transfer and row['status']=='waiting':await self.deliver_link(row)
                else:await self.resume(row,transfer=transfer,recovery_event_id=recovery_event_id)
            except Exception:
                # No raw exceptions or links in logs. Retry on the next pass.
                pass
        recoveries=await asyncio.to_thread(self.store.pending_task_recoveries)
        for transfer,rows in ((False,self.store.pending_links()+self.store.pending_resumes()),
                             (True,self.store.pending_transfers()+recoveries)):
            for row in rows:
                row_id=row['id']
                if row_id in self.resume_tasks:continue
                # Freeze the cleanup key per task; membership polling stays responsive.
                async def run(row=row,transfer=transfer,row_id=row_id):
                    try:await dispatch(row,transfer)
                    finally:self.resume_tasks.pop(row_id,None)
                self.resume_tasks[row_id]=asyncio.create_task(run())

    def save_login(self, request_id, token, identity, fields):
        raise AccessError('Credentials are collected directly by Kernel. Open your private Kernel form.', 410)

    def save_code(self, request_id, token, identity, fields):
        raise AccessError('Verification codes are collected directly by Kernel. Open your private Kernel form.', 410)

    def save_api_key(self, request_id, token, identity, fields):
        raise AccessError('API keys are collected directly by Kernel. Open your private Kernel form.', 410)

    def approve_payment(self, request_id, token, identity, fields):
        home=self.private_home(identity['team'],identity['owner'])
        with self.lock_for(home):
            row = self.store.get(request_id,token,identity=identity)
            self.delegations.request_access(row)
            return self.payments.approve(request_id,token,identity,fields)

    async def disconnect(self, team, owner, handle):
        home = self.private_home(team,owner)
        if self.credential_store(team,owner).get_meta(handle) is None:raise AccessError('This saved account was not found.',404)
        with self.store.connection() as db:
            grants = [row[0] for row in db.execute('SELECT id FROM credential_grants WHERE team=? AND owner=? AND handle=?',
                                                  (team, owner, handle))]
        cleanup_pending = False
        for grant_id in grants:
            try:
                cleanup_pending = (await self.revoke_invitation(
                    {'team':team,'owner':owner}, grant_id))['cleanup_pending'] or cleanup_pending
            except Exception:
                cleanup_pending = True
        self.store.cancel_owner(team,owner)
        try:
            cleanup_pending = await self.channel_control.stop_owner(team,owner) or cleanup_pending
        except Exception:
            cleanup_pending = True
        # Native interruption prevents a concurrent owner turn reopening a browser
        # while its profiles are being removed. Other owners keep running.
        runner=getattr(self.policy.adapter,'gateway_runner',None)
        from gateway.session import SessionSource
        from gateway.config import Platform
        member=self.validate_member(team,owner)
        source=SessionSource(Platform.SLACK,member['dm_id'],user_id=owner,scope_id=team,profile=member['profile'])
        interruption_pending = False
        if runner is not None:
            try:
                await self.channel_control.interrupt(source,home,whole_private_home=True)
            except Exception:
                interruption_pending = True
        def remove():
            with self.lock_for(home):
                store = self.credential_store(team,owner)
                meta=store.get_meta(handle)
                if meta is None:
                    raise AccessError('This saved account was not found.',404)
                owner_pending = False
                try:
                    # A remote failure must not skip local browser shutdown.
                    # The RLock also covers marker retention and final removal.
                    self.channel_control.clear_with_retention(
                        Binding(self,source,'disconnect','',home), retain_usage=interruption_pending)
                except Exception:
                    owner_pending = True
                if cleanup_pending or interruption_pending or owner_pending:
                    raise AccessError('Account tasks were cancelled, but browser cleanup is still pending. The saved account remains in your vault. Retry disconnect after cleanup.',409)
                store.remove_item(handle)
        await asyncio.to_thread(remove)

    async def start(self):
        from .web import VaultWeb
        self.loop = asyncio.get_running_loop()
        from agent.secret_scope import build_profile_secret_scope
        if not build_profile_secret_scope(self.policy.home).get('CLANKER_SLACK_CLIENT_SECRET'):
            raise AccessError('Slack sign-in has not been configured.',503)
        self.web = VaultWeb(self,self.config)
        await self.web.start()
        async def acknowledge(ack):
            await ack()
        self.policy.adapter._app.action('clanker_vault_link')(acknowledge)
        self.approvals.register(self.policy.adapter._app)

    async def close(self):
        self.poll_closing = True
        cancelled = False
        # Polls can own claimed payment/auth mutations. Let them finish before
        # shutting down the hosted vault; never cancel and forget a thread.
        polls = list(getattr(self, 'poll_tasks', {}).values())
        if polls:
            try:
                await self._await_owned_task(asyncio.gather(*polls, return_exceptions=True))
            except asyncio.CancelledError:
                cancelled = True
        for task in list(self.resume_tasks.values()):task.cancel()
        try:
            await self._await_owned_task(asyncio.gather(*list(self.resume_tasks.values()),return_exceptions=True))
        except asyncio.CancelledError:
            cancelled = True
        try:
            await self._await_owned_task(asyncio.create_task(self.web.close()))
        except asyncio.CancelledError:
            cancelled = True
        if cancelled:
            raise asyncio.CancelledError


def configured_service(policy):
    config = policy.home/'.clanker-vault'/'config.json'
    if not config.exists():
        return None
    settings = json.loads(config.read_text())
    if not settings.get('enabled'):
        return None
    if set(settings)-{'enabled','client_id','public_url','port','provider'}:
        raise AccessError('The hosted vault configuration has unsupported options.',503)
    if settings.get('provider') not in (None, 'kernel'):
        raise AccessError('Only Kernel credential storage is supported.',503)
    if not settings.get('client_id') or not settings.get('public_url'):
        raise AccessError('The hosted vault requires its public URL and Slack sign-in configuration.',503)
    return VaultService(policy,settings)
