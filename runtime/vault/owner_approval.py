"""Owner-only Slack buttons that approve one exact backend action.

The model can cause a prompt to be shown, never answer it. A click is checked
against the stored owner, DM and message, then resumes the task with a
gateway-owned event id. Only that event can spend the approval, and only for
the details that were shown on the card.
"""
import asyncio
import hashlib
import json
from pathlib import Path
import re
import secrets
from urllib.parse import urlsplit

from .store import AccessError

APPROVE = 'clanker_owner_approve'
DECLINE = 'clanker_owner_decline'
EVENT_PREFIX = 'clanker-approval-'
_EVENT = re.compile(re.escape(EVENT_PREFIX) + r'[A-Za-z0-9_-]{24}')
PROMPT_TTL = 30 * 60
APPROVED_TTL = 15 * 60
_LIVE = ('posting', 'pending', 'approved')


def _host(details):
    return urlsplit(details['origin']).hostname or 'this site'


# Card and resume wording come from bound details only, never model text.
KINDS = {
    'signin_retry': {
        'prompt': lambda d: (f"Sign-in to {_host(d)} didn't finish.\n"
                             'Retry with a fresh private sign-in link?'),
        'button': 'Retry sign-in',
        'resume': lambda d: (f'The owner tapped Retry for the {_host(d)} sign-in. This approves one fresh '
                             f"sign-in attempt for account handle {d['handle']}. Call clanker_authenticate with "
                             'that handle now, then continue the original task from its stopping point and keep '
                             'its confirmed choices. This approval covers sign-in only, not payments or other actions.'),
    },
    'code_retry': {
        'prompt': lambda d: (f"Verification for {_host(d)} didn't finish.\n"
                             'Request a fresh verification code form?'),
        'button': 'Retry verification',
        'resume': lambda d: (f'The owner tapped Retry for {_host(d)} verification. This approves one fresh '
                             f"verification form for account handle {d['handle']}. Call clanker_vault_enter_code "
                             'with that handle and request_new=true now, then continue the original task from its '
                             'stopping point. This approval covers verification only, not payments or other actions.'),
    },
}

_NEXT = {
    'sent': 'A private Retry button was sent to the owner in this DM. End this turn and do not ask for typed '
            'approval. If they tap Retry, the task resumes automatically with one fresh attempt. They may also '
            'reply in their own words.',
    'already_sent': 'A private Retry button is already waiting for the owner in this DM. End this turn without '
                    'posting another request.',
    'approved': 'The owner already approved this retry. The task resumes automatically; end this turn.',
    'declined': 'The owner chose not to retry this. Do not retry or ask again unless they bring it up.',
    'unavailable': 'The Retry button could not be delivered. Ask the owner in this DM whether to retry; '
                   'ordinary wording is accepted.',
}

_OUTCOMES = {
    'approved': 'Retry approved. Continuing the task…',
    'declined': 'Not retried. Reply here if you change your mind.',
    'inactive': 'This retry request is no longer active.',
}


class OwnerApprovalRequired(AccessError):
    """A refusal the owner can lift with one button press for these details."""

    def __init__(self, kind, details, message, status=403):
        super().__init__(message, status)
        if kind not in KINDS:
            raise ValueError('Unknown owner approval kind')
        self.kind, self.details = kind, dict(details)


def _digest(kind, details):
    return hashlib.sha256(json.dumps([kind, details], sort_keys=True).encode()).hexdigest()


def is_event(event_id):
    return isinstance(event_id, str) and _EVENT.fullmatch(event_id) is not None


class OwnerApprovals:
    def __init__(self, service):
        self.service = service
        self.store = service.store
        with self.store.connection() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS owner_approvals (
                id TEXT PRIMARY KEY, team TEXT NOT NULL, user TEXT NOT NULL, home TEXT NOT NULL,
                task_id TEXT NOT NULL, kind TEXT NOT NULL, digest TEXT NOT NULL, details TEXT NOT NULL,
                source TEXT NOT NULL, task TEXT NOT NULL, channel TEXT NOT NULL, thread TEXT,
                message_ts TEXT, state TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL,
                decided REAL, resumed REAL)''')

    def register(self, app):
        app.action(APPROVE)(self.on_action)
        app.action(DECLINE)(self.on_action)

    def _get(self, approval_id):
        with self.store.connection() as db:
            row = db.execute('SELECT * FROM owner_approvals WHERE id=?', (approval_id,)).fetchone()
        return dict(row) if row else None

    def _reply(self, status):
        return {'owner_approval': {'status': status}, 'next': _NEXT[status]}

    async def prompt(self, turn, error):
        self.service.assert_private(turn)
        kind, details = error.kind, error.details
        digest = _digest(kind, details)
        home = str(turn.home.resolve())
        now = self.store.clock()
        approval_id = secrets.token_urlsafe(18)
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            existing = db.execute(
                'SELECT state FROM owner_approvals WHERE team=? AND user=? AND home=? AND task_id=? '
                "AND kind=? AND digest=? AND state IN ('posting','pending','approved','declined') "
                'AND expires>? ORDER BY created DESC LIMIT 1',
                (turn.source.scope_id, turn.source.user_id, home, turn.task_id, kind, digest, now)).fetchone()
            if existing:
                state = existing['state']
                return self._reply('already_sent' if state in ('posting', 'pending') else state)
            db.execute('INSERT INTO owner_approvals VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (approval_id, turn.source.scope_id, turn.source.user_id, home, turn.task_id, kind, digest,
                 json.dumps(details), json.dumps(turn.source.to_dict()),
                 self.service.channel_tasks.request_context(turn), turn.source.chat_id,
                 turn.source.thread_id, None, 'posting', now, now + PROMPT_TTL, None, None))
        text = KINDS[kind]['prompt'](details)
        try:
            from uuid import NAMESPACE_URL, uuid5
            posted = await asyncio.wait_for(self.service.policy.client().chat_postMessage(
                channel=turn.source.chat_id, thread_ts=turn.source.thread_id or None,
                client_msg_id=str(uuid5(NAMESPACE_URL, EVENT_PREFIX + approval_id)),
                unfurl_links=False, unfurl_media=False, text=text,
                blocks=[{'type': 'section', 'text': {'type': 'plain_text', 'text': text}},
                        {'type': 'actions', 'elements': [
                            {'type': 'button', 'style': 'primary', 'action_id': APPROVE, 'value': approval_id,
                             'text': {'type': 'plain_text', 'text': KINDS[kind]['button']}},
                            {'type': 'button', 'action_id': DECLINE, 'value': approval_id,
                             'text': {'type': 'plain_text', 'text': 'Not now'}}]}]), timeout=10)
            if posted.get('ok') is False or not posted.get('ts'):
                raise AccessError('Retry button delivery failed.', 503)
        except Exception:
            # Slack errors can echo request content; report only the status.
            with self.store.connection() as db:
                db.execute("UPDATE owner_approvals SET state='failed' WHERE id=?", (approval_id,))
            return self._reply('unavailable')
        with self.store.connection() as db:
            db.execute("UPDATE owner_approvals SET state='pending',message_ts=? WHERE id=? AND state='posting'",
                       (posted['ts'], approval_id))
        return self._reply('sent')

    def consume(self, turn, kind, details):
        """Spend an approval once, only from its own resume event and details."""
        if not is_event(turn.message_id):
            return False
        approval_id = turn.message_id[len(EVENT_PREFIX):]
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM owner_approvals WHERE id=?', (approval_id,)).fetchone()
            if (not row or row['kind'] != kind or row['digest'] != _digest(kind, details) or
                    (row['team'], row['user'], row['home'], row['task_id']) !=
                    (turn.source.scope_id, turn.source.user_id, str(turn.home.resolve()), turn.task_id) or
                    not self.store.same_task_source(json.loads(row['source']), turn.source.to_dict())):
                return False
            if row['state'] == 'consumed':
                # The same resumed turn may call again; per-event request
                # guards decide whether that call can create anything new.
                return True
            if row['state'] != 'approved' or row['expires'] <= self.store.clock():
                return False
            db.execute("UPDATE owner_approvals SET state='consumed' WHERE id=?", (approval_id,))
        return True

    def cancel(self, team, user):
        with self.store.connection() as db:
            db.execute("UPDATE owner_approvals SET state='cancelled' WHERE team=? AND user=? AND state IN "
                       "('posting','pending','approved')", (team, user))

    async def on_action(self, ack, body, action):
        await ack()
        try:
            await self._decide(body, action)
        except Exception:
            pass  # Never echo Slack payloads or provider errors into logs.

    async def _decide(self, body, action):
        user = (body.get('user') or {}).get('id')
        team = (body.get('team') or {}).get('id') or (body.get('user') or {}).get('team_id')
        channel = (body.get('channel') or {}).get('id')
        message_ts = (body.get('container') or {}).get('message_ts') or (body.get('message') or {}).get('ts')
        row = self._get(action.get('value'))
        if (not row or not message_ts or
                (row['team'], row['user'], row['channel'], row['message_ts']) != (team, user, channel, message_ts)):
            return
        member = self.service.validate_member(team, user)
        if (member['dm_id'] != channel or
                self.service.policy.state['conversations'].get(channel, {}).get('kind') != 'dm'):
            return
        approve = action.get('action_id') == APPROVE
        now = self.store.clock()
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            current = db.execute('SELECT state,expires FROM owner_approvals WHERE id=?', (row['id'],)).fetchone()
            if current['state'] in ('approved', 'consumed', 'declined'):
                return
            if current['state'] != 'pending' or current['expires'] <= now:
                outcome = 'inactive'
                db.execute("UPDATE owner_approvals SET state='expired' WHERE id=? AND state='pending'", (row['id'],))
            elif approve:
                outcome = 'approved'
                db.execute("UPDATE owner_approvals SET state='approved',decided=?,expires=? WHERE id=?",
                           (now, now + APPROVED_TTL, row['id']))
            else:
                outcome = 'declined'
                db.execute("UPDATE owner_approvals SET state='declined',decided=? WHERE id=?", (now, row['id']))
        text = KINDS[row['kind']]['prompt'](json.loads(row['details']))
        try:
            await self.service.policy.client().chat_update(channel=channel, ts=message_ts,
                text=text + '\n' + _OUTCOMES[outcome],
                blocks=[{'type': 'section', 'text': {'type': 'plain_text', 'text': text}},
                        {'type': 'context', 'elements': [{'type': 'plain_text', 'text': _OUTCOMES[outcome]}]}])
        except Exception:
            pass  # The decision is committed; a stale card is refused on its next click.
        if outcome == 'approved':
            await self.drain()

    async def drain(self):
        now = self.store.clock()
        with self.store.connection() as db:
            db.execute("UPDATE owner_approvals SET state='expired' WHERE state IN ('posting','pending','approved') "
                       'AND expires<=?', (now,))
            rows = [dict(row) for row in db.execute(
                "SELECT * FROM owner_approvals WHERE state='approved' AND resumed IS NULL")]
        tasks = self.service.resume_tasks
        for row in rows:
            key = 'approval:' + row['id']
            if key in tasks:
                continue

            async def run(row=row, key=key):
                try:
                    await self._resume(row)
                except Exception:
                    pass  # Retried on the next drain until the approval expires.
                finally:
                    tasks.pop(key, None)
            tasks[key] = asyncio.create_task(run())

    def _mark_resumed(self, approval_id):
        with self.store.connection() as db:
            db.execute('UPDATE owner_approvals SET resumed=? WHERE id=?', (self.store.clock(), approval_id))

    async def _resume(self, row):
        from gateway.platforms.event import MessageEvent
        from gateway.session import SessionSource
        service = self.service
        member = service.validate_member(row['team'], row['user'])
        source = SessionSource.from_dict(json.loads(row['source']))
        channel_task = service.channel_tasks.restore(source)
        if channel_task:
            if channel_task['task_state'] != 'active':
                with self.store.connection() as db:
                    db.execute("UPDATE owner_approvals SET state='expired' WHERE id=?", (row['id'],))
                return
            await service.channel_tasks.validate_destination(channel_task)
            await service.policy.serve_profile(source.profile)
            expected_profile = service.channel_tasks.execution_route(source)
            expected_home = service.channel_tasks.home(channel_task)
        else:
            expected_profile = member['profile']
            expected_home = service.private_home(row['team'], row['user'])
        if (source.chat_id != member['dm_id'] or source.profile != expected_profile or
                source.scope_id != row['team'] or source.user_id != row['user'] or
                expected_home.resolve() != Path(row['home']).resolve()):
            raise AccessError('The original private task is no longer authorized.', 403)
        event_id = EVENT_PREFIX + row['id']
        event = MessageEvent(source=source, user_id=source.user_id, user_name=source.user_name,
            text=KINDS[row['kind']]['resume'](json.loads(row['details'])) + '\n\nOriginal request: ' + row['task'],
            message_id=event_id, allow_gateway_control=False, metadata={'clanker_owner_approval': row['id']})
        adapter = service.policy.adapter
        adapter._canonicalize(source)
        key = adapter._event_session_key(event)
        if key in adapter._active_sessions:
            return  # The owner is mid-turn; the next drain resumes afterwards.
        if await asyncio.to_thread(service.delivery_owned, key, event_id):
            self._mark_resumed(row['id'])
            return
        if channel_task and not service.store.begin_channel_reply(channel_task['id'], event_id):
            self._mark_resumed(row['id'])
            return
        await adapter.handle_message(event)
        if getattr(event, '_gateway_accepted', False):
            self._mark_resumed(row['id'])
