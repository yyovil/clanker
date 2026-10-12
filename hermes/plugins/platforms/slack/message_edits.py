"""Version Slack requests without treating unfurls as new user instructions."""

import asyncio
import hashlib
import json
import logging
import sqlite3
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation

from hermes_constants import get_hermes_home

logger = logging.getLogger(__name__)


def fingerprint(text):
    return hashlib.sha256(str(text or "").encode()).hexdigest()


def version(raw):
    edited = raw.get("edited") or {}
    try:
        value = Decimal(str(edited.get("ts") or raw.get("ts") or "0"))
        return value if value.is_finite() else Decimal(0)
    except (InvalidOperation, ValueError):
        return Decimal(0)


@dataclass
class Reply:
    ids: list = field(default_factory=list)
    obligations: dict = field(default_factory=dict)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


@dataclass
class Revision:
    key: tuple
    version: Decimal
    digest: str
    reply: Reply = field(default_factory=Reply)
    event: object = None


class MessageEdits:
    def __init__(self):
        self.path = get_hermes_home() / "slack-message-edits.sqlite"
        self.records = {}
        self.processing = {}
        self.locks = {}

    def key(self, adapter, raw, payload=None):
        return (adapter._event_team_id(raw, payload), str(raw.get("channel") or ""),
                str(raw.get("user") or ""), str(raw.get("ts") or ""))

    def lookup(self, key):
        if key in self.records:
            return self.records[key]
        if self.path.exists():
            with sqlite3.connect(self.path) as db:
                row = db.execute("SELECT version,digest,replies FROM message_versions WHERE identity=?",
                                 (json.dumps(key),)).fetchone()
            if row:
                saved = json.loads(row[2])
                reply = Reply(saved) if isinstance(saved, list) else Reply(saved['ids'], saved['obligations'])
                self.records[key] = Revision(key, Decimal(row[0]), row[1], reply)
                return self.records[key]

    def user_edit(self, adapter, envelope, payload=None):
        raw = dict(envelope.get("message") or {})
        for name in ("channel", "team", "team_id"):
            raw.setdefault(name, envelope.get(name))
        edited = raw.get("edited")
        if (not isinstance(edited, dict) or not raw.get("user")
                or edited.get("user") != raw.get("user") or not edited.get("ts")):
            return False
        known = self.lookup(self.key(adapter, raw, payload))
        if known:
            incoming = version(raw)
            if incoming <= known.version:
                return False
            if fingerprint(raw.get("text")) == known.digest:
                old_version = str(known.version)
                known.version = incoming
                for obligation, stored_version in known.reply.obligations.items():
                    if stored_version == old_version:
                        known.reply.obligations[obligation] = str(incoming)
                if self.path.exists():
                    with sqlite3.connect(self.path) as db:
                        db.execute("UPDATE message_versions SET version=?,replies=? WHERE identity=?",
                                   (str(incoming), json.dumps({'ids':known.reply.ids,
                                    'obligations':known.reply.obligations}), json.dumps(known.key)))
                return False
            return True
        previous = envelope.get("previous_message")
        if isinstance(previous, dict):
            return (previous.get("user") == raw.get("user") and previous.get("ts") == raw.get("ts")
                    and fingerprint(previous.get("text")) != fingerprint(raw.get("text")))
        return True  # e.g. a mention added to an ignored message

    def claim(self, adapter, raw, payload=None):
        key = self.key(adapter, raw, payload)
        previous = self.lookup(key)
        incoming = version(raw)
        if previous and incoming <= previous.version:
            return None
        record = Revision(key, incoming, fingerprint(raw.get("text")),
                          previous.reply if previous else Reply())
        self.records[key] = record
        # Disk retains completed mappings; bound the process-local intake cache.
        if len(self.records) > 4000:
            oldest = next(iter(self.records))
            if oldest != key:
                self.records.pop(oldest)
        return record

    def current(self, record):
        return self.records.get(record.key) is record

    def for_reply(self, event):
        inbound = str(event.ledger_message_id or event.message_id or "")
        bound = getattr(event, "_slack_revision", None)
        if bound and (inbound == bound.key[3] or inbound.startswith(bound.key[3] + ":edit:")):
            return bound
        if not inbound:
            return None
        source = event.source
        record = self.lookup((source.scope_id or "", source.chat_id, source.user_id or "", inbound))
        if record:
            return record
        # Native queued finals carry the terminal inbound ID on the opening event. Slack message
        # IDs are unique within a channel; a validated queued sender can differ from the opener.
        matches = [r for r in self.records.values()
                   if r.key[:2] == (source.scope_id or "", source.chat_id) and r.key[3] == inbound]
        return matches[0] if len(matches) == 1 else None

    def edited(self, record):
        return record.version > version({"ts": record.key[3]})

    def for_obligation(self, obligation, chat_id):
        records = list(self.records.values())
        if self.path.exists():
            with sqlite3.connect(self.path) as db:
                keys = [json.loads(row[0]) for row in db.execute('SELECT identity FROM message_versions')]
            records.extend(self.lookup(tuple(key)) for key in keys if key[1] == chat_id)
        for record in records:
            if record and record.key[1] == chat_id and obligation in record.reply.obligations:
                obsolete = record.reply.obligations[obligation] != str(record.version)
                return record, obsolete
        return None, False

    def envelope_raw(self, envelope):
        raw = dict(envelope.get("message") or {}) if envelope.get("subtype") == "message_changed" else dict(envelope)
        for name in ("channel", "team", "team_id"):
            if not raw.get(name):
                raw[name] = envelope.get(name)
        return raw

    def release_failed(self, key, raw, previous):
        current = self.records.get(key)
        if current is not previous and current and current.version == version(raw):
            if previous is None:
                self.records.pop(key, None)
            else:
                self.records[key] = previous

    @staticmethod
    def same_message(left, right):
        if left is None or right is None:
            return False
        return (str(left.message_id or "") == str(right.message_id or "")
                and all(getattr(left.source, name, None) == getattr(right.source, name, None)
                        for name in ("scope_id", "chat_id", "user_id")))

    async def dispatch(self, adapter, event, record, *, edited):
        if not self.current(record) or adapter._drop_unresolved(event):
            return
        runner = adapter.gateway_runner
        if runner and not runner._is_user_authorized_for_source(event.source):
            return
        key = adapter._event_session_key(event)
        lock = self.locks.setdefault(key, asyncio.Lock())
        async with lock:
            if not self.current(record):
                return
            record.event = event
            event._slack_revision = record
            if not edited:
                await adapter.handle_message(event)
                return
            edit_context = ('This Slack message was edited. The following request replaces its '
                            'previous wording. Work only on the updated request.')
            event.channel_context = '\n\n'.join(part for part in (event.channel_context, edit_context) if part)
            from gateway.delivery_ledger import supersede_obligation
            for obligation in tuple(record.reply.obligations):
                await asyncio.to_thread(supersede_obligation, obligation)
            # A pending edit updates its place in the queue; another active request keeps running.
            state = runner._peek_session_state(key) if runner else None
            pending = adapter._pending_messages.get(key)
            if self.same_message(pending, event):
                adapter._pending_messages[key] = event
                event._gateway_accepted = True
                return
            overflow = state.conversation.queued_events if state else []
            for index, queued in enumerate(overflow):
                if self.same_message(queued, event):
                    overflow[index] = event
                    event._gateway_accepted = True
                    return
            active = self.processing.get(key)
            if state and state.turn.ctx:
                ctx = state.turn.ctx
                active = type(event)(text="", source=ctx.source, message_id=ctx.inbound_message_id)
            elif state and state.turn.event:
                active = state.turn.event
            if self.same_message(active, event):
                generation = None
                if runner:
                    generation = runner._interrupt_running_turn(
                        key, interrupt_reason="Slack message edited", invalidation_reason="message_edited")
                guard = adapter._active_sessions.get(key)
                if guard:
                    guard.set()
                task = adapter._session_tasks.get(key)
                # Own the lane while the old finally unwinds. Its queued follow-ups stay parked.
                adapter._session_tasks[key] = asyncio.current_task()
                if task is not None and not task.done():
                    adapter._expected_cancelled_tasks.add(task)
                    task.cancel()
                    try:
                        await asyncio.wait_for(asyncio.shield(task), 5)
                    except asyncio.CancelledError:
                        if asyncio.current_task().cancelling():
                            raise
                    except asyncio.TimeoutError:
                        logger.warning("Edited Slack turn is still unwinding: %s", key)
                if runner:
                    runner._drop_turn_slot(key, run_generation=generation)
                adapter._release_session_guard(key)
                if adapter._session_tasks.get(key) is asyncio.current_task():
                    adapter._session_tasks.pop(key, None)
            policy = getattr(adapter, "_workspace_membership", None)
            service = getattr(policy, "vault_service", None)
            if service:
                await service.channel_control.stop_message(event.source, event.message_id)
            if self.current(record):
                await adapter.handle_message(event)

    async def save(self, record):
        # A send that was already accepted by Slack may complete after an edit arrived.
        # The shared reply IDs still belong to the latest version of that same request.
        latest = self.records.get(record.key, record)
        values = (json.dumps(record.key), str(latest.version), latest.digest, json.dumps({
            'ids':record.reply.ids, 'obligations':record.reply.obligations}))
        def write():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(self.path) as db:
                db.execute("CREATE TABLE IF NOT EXISTS message_versions "
                           "(identity TEXT PRIMARY KEY,version TEXT,digest TEXT,replies TEXT)")
                db.execute("INSERT INTO message_versions VALUES (?,?,?,?) ON CONFLICT(identity) "
                           "DO UPDATE SET version=excluded.version,digest=excluded.digest,replies=excluded.replies "
                           "WHERE CAST(excluded.version AS REAL)>=CAST(message_versions.version AS REAL)", values)
        await asyncio.to_thread(write)

    async def update_reply(self, adapter, record, content, metadata):
        from gateway.platforms.base import SendResult
        async with record.reply.lock:
            if not self.current(record):
                return SendResult(success=True)
            chunks = adapter.truncate_message(adapter.format_message(content), adapter.MAX_MESSAGE_LENGTH)
            client = adapter._client_for(record.key[1], metadata)
            for index, chunk in enumerate(chunks):
                if not self.current(record):
                    return SendResult(success=True)
                args = {"channel": record.key[1], "text": chunk, "blocks": []}
                if index < len(record.reply.ids):
                    args["ts"] = record.reply.ids[index]
                    await client.chat_update(**args)
                else:
                    args.pop("blocks")
                    args["thread_ts"] = adapter._resolve_thread_ts(record.key[3], metadata)
                    response = await client.chat_postMessage(**args)
                    record.reply.ids.append(response["ts"])
            while len(record.reply.ids) > len(chunks):
                await client.chat_delete(channel=record.key[1], ts=record.reply.ids[-1])
                record.reply.ids.pop()
            await self.save(record)
            await adapter._clear_thread_status_quietly(record.key[1], metadata)
            return SendResult(success=True, message_id=record.reply.ids[-1] if record.reply.ids else None)
