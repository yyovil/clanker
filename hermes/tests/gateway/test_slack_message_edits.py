"""Slack edits cancel obsolete work and retain one reply across completed revisions."""

import asyncio
import sqlite3
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from aiohttp import web
from slack_sdk.web.async_client import AsyncWebClient

from gateway.config import GatewayConfig, PlatformConfig
from gateway.run import GatewayRunner
from gateway import delivery_ledger
from gateway.platforms.event import MessageEvent
from gateway.session import SessionSource
from plugins.platforms.slack.adapter import SlackAdapter


def message(text, ts="100.001"):
    return {"type": "message", "user": "U1", "channel": "D1", "channel_type": "im",
            "team": "T1", "ts": ts, "thread_ts": "100.001", "text": text,
            "client_msg_id": "human-" + ts}


def edit(text, edited_ts, ts="100.001"):
    raw = message(text, ts)
    raw["edited"] = {"user": "U1", "ts": edited_ts}
    return {"type": "message", "subtype": "message_changed", "channel": "D1",
            "channel_type": "im", "team": "T1", "ts": edited_ts, "event_ts": edited_ts,
            "message": raw}


@pytest_asyncio.fixture
async def harness(monkeypatch):
    requests, replies, runs, stopped = [], {}, [], []
    gates = {}
    entered = asyncio.Queue()
    cancelling, release_cancel = asyncio.Event(), asyncio.Event()

    async def receive(request):
        body = await request.json() if request.content_type == "application/json" else dict(await request.post())
        body = {**dict(request.query), **body}
        method = request.match_info["method"]
        requests.append((method, body))
        if method == "chat.postMessage":
            ts = f"200.{len(requests):06d}"
            replies[ts] = body["text"]
        else:
            ts = body.get("ts", "0")
            if method == "chat.update":
                assert ts in replies
                replies[ts] = body["text"]
            elif method == "chat.delete":
                replies.pop(ts)
        return web.json_response({"ok": True, "ts": ts})

    app = web.Application()
    app.router.add_post("/api/{method}", receive)
    server = web.AppRunner(app)
    await server.setup()
    await web.TCPSite(server, "127.0.0.1", 0).start()
    url = f"http://127.0.0.1:{server.addresses[0][1]}/api/"
    adapters = []

    def make_adapter():
        adapter = SlackAdapter(PlatformConfig(enabled=True, token="xoxb-dummy", typing_indicator=False,
                                              extra={"reactions": False}))
        adapter._bot_user_id = "U_BOT"
        adapter._app = SimpleNamespace(client=AsyncWebClient(token="xoxb-dummy", base_url=url,
                                                            timeout=5, retry_handlers=[]))
        adapter._resolve_user_name = AsyncMock(return_value="Member")
        adapter._resolve_channel_name = AsyncMock(return_value="DM")
        adapter._hydrate_thread_context = AsyncMock(return_value=(None, [], []))
        adapter._set_assistant_thread_title = AsyncMock()
        adapter._clear_thread_status_quietly = AsyncMock()
        adapter._early_reject_unauthorized = lambda *_args: False
        adapter._media_delivery_scope = lambda *_args: nullcontext()
        native = object.__new__(GatewayRunner)
        native.config = GatewayConfig()
        native._sessions = {}
        native._persist_active_agents = lambda: None
        native._delivery_adapter_for = lambda source: adapter
        native._is_user_authorized_for_source = lambda source: source.user_id == "U1"
        native._profile_name_for_source = lambda source, **kwargs: None
        native._evict_cached_agent = lambda key: None
        adapter.gateway_runner = native

        async def run(event):
            key = adapter._event_session_key(event)
            generation = native._begin_session_run_generation(key)
            state = native._session_state(key)
            state.turn.event = event
            state.turn.agent = SimpleNamespace(hard_interrupt=stopped.append, session_id="fixture")
            state.turn.ctx = SimpleNamespace(source=event.source, inbound_message_id=event.message_id)
            runs.append(event.text)
            await entered.put(event.text)
            try:
                if event.text in gates:
                    await gates[event.text].wait()
                return event.text if native._is_session_run_current(key, generation) else None
            except asyncio.CancelledError:
                if event.text == "old":
                    cancelling.set()
                    await release_cancel.wait()
                raise
            finally:
                native._release_running_agent_state(key, run_generation=generation)

        adapter.set_message_handler(run)
        adapters.append(adapter)
        return adapter

    async def idle(adapter):
        while adapter._background_tasks:
            await asyncio.gather(*tuple(adapter._background_tasks), return_exceptions=True)

    try:
        yield SimpleNamespace(make=make_adapter, runs=runs, replies=replies, requests=requests,
                              stopped=stopped, gates=gates, entered=entered, cancelling=cancelling,
                              release_cancel=release_cancel, idle=idle)
    finally:
        release_cancel.set()
        for adapter in adapters:
            await adapter.cancel_background_tasks()
        await server.cleanup()


@pytest.mark.asyncio
async def test_only_latest_active_revision_runs_and_other_queued_messages_survive(harness):
    h = harness
    adapter = h.make()
    latest_claimed = asyncio.Event()
    claim = adapter._message_edits.claim
    def observe_claim(a, raw, payload=None):
        result = claim(a, raw, payload)
        if raw.get("text") == "latest":
            latest_claimed.set()
        return result
    adapter._message_edits.claim = observe_claim
    h.gates["old"] = asyncio.Event()
    await adapter._handle_slack_message(message("old"))
    assert await asyncio.wait_for(h.entered.get(), 5) == "old"
    await adapter._handle_slack_message(message("unrelated", "100.002"))
    await adapter._handle_slack_message(edit("unrelated edited", "100.005", "100.002"))
    assert h.stopped == []
    first_edit = asyncio.create_task(adapter._handle_slack_message(edit("intermediate", "101.001")))
    await asyncio.wait_for(h.cancelling.wait(), 5)
    latest_edit = asyncio.create_task(adapter._handle_slack_message(edit("latest", "102.001")))
    # Wait for the newer version's intake claim while cancellation is held open.
    await asyncio.wait_for(latest_claimed.wait(), 5)
    h.release_cancel.set()
    await asyncio.wait_for(asyncio.gather(first_edit, latest_edit), 5)
    await asyncio.wait_for(h.idle(adapter), 5)
    assert h.stopped == ["Slack message edited"]
    assert h.runs == ["old", "latest", "unrelated edited"]
    assert sorted(h.replies.values()) == ["latest", "unrelated edited"]
    await adapter._handle_slack_message(edit("stale", "101.002"))
    await adapter._handle_slack_message(edit("latest", "102.001"))
    await asyncio.wait_for(h.idle(adapter), 5)
    assert h.runs == ["old", "latest", "unrelated edited"]
    # An edit can also overtake the original while its sender enrichment is still awaiting I/O.
    enriching, release_enrichment = asyncio.Event(), asyncio.Event()
    first_lookup = True
    async def enrich(*args, **kwargs):
        nonlocal first_lookup
        if first_lookup:
            first_lookup = False
            enriching.set()
            await release_enrichment.wait()
        return "Member"
    adapter._resolve_user_name = enrich
    intake = asyncio.create_task(adapter._handle_slack_message(message("pending intake", "110.001")))
    await asyncio.wait_for(enriching.wait(), 5)
    await adapter._handle_slack_message(edit("edited during intake", "111.001", "110.001"))
    release_enrichment.set()
    await asyncio.wait_for(intake, 5)
    await asyncio.wait_for(h.idle(adapter), 5)
    assert h.runs[-1] == "edited during intake" and "pending intake" not in h.runs


@pytest.mark.asyncio
async def test_completed_revision_updates_existing_reply_and_mapping_survives_restart(harness):
    h = harness
    adapter = h.make()
    adapter.MAX_MESSAGE_LENGTH = 30
    await adapter._handle_slack_message(message("original answer " * 7))
    await asyncio.wait_for(h.idle(adapter), 5)
    original_ids = list(h.replies)
    original_revision = adapter._message_edits.lookup(("T1", "D1", "U1", "100.001"))
    original_obligation = next(iter(original_revision.reply.obligations))
    delivery_ledger.mark_failed(original_obligation, "fixture delivery failure")
    assert len(original_ids) > 1
    await adapter._handle_slack_message(edit("corrected", "101.001"))
    await asyncio.wait_for(h.idle(adapter), 5)
    assert h.replies == {original_ids[0]: "corrected"}
    assert len([method for method, body in h.requests if method == "chat.postMessage"]) == len(original_ids)
    with sqlite3.connect(delivery_ledger._db_path()) as db:
        assert db.execute('SELECT state FROM delivery_obligations WHERE obligation_id=?',
                          (original_obligation,)).fetchone()[0] == 'superseded'
    # A recovery already claimed before the edit must also suppress its obsolete text.
    native = adapter.gateway_runner
    native._obligation_adapter = AsyncMock(return_value=adapter)
    native._arm_flood_timers_for_waiting_rows = AsyncMock()
    await native._redeliver_claimed_obligations([{
        'obligation_id':original_obligation,'chat_id':'D1','thread_id':'100.001',
        'content':'obsolete recovered answer','platform':'slack','needs_marker':False}])
    assert h.replies == {original_ids[0]: "corrected"}
    # A metadata/unfurl change retaining the edit timestamp must not re-run.
    unfurl = edit("corrected", "101.001")
    unfurl["event_ts"] = "101.002"
    unfurl["message"]["attachments"] = [{"title": "preview"}]
    await adapter._handle_slack_message(unfurl)
    await adapter._handle_slack_message(edit("corrected", "101.004"))
    await adapter._handle_slack_message(edit("stale content", "101.003"))
    await asyncio.wait_for(h.idle(adapter), 5)
    # The native recursive queue uses a synthetic final event carrying its raw inbound ID.
    synthetic = MessageEvent(text="", ledger_message_id="100.001", source=SessionSource(
        adapter.platform, "D1", user_id="U1", scope_id="T1", thread_id="100.001"))
    result, _ = await adapter.send_final_ledgered(synthetic, "fixture", "queued final",
        {"slack_team_id": "T1", "thread_id": "100.001"}, reply_to="100.001")
    assert result.success and h.replies == {original_ids[0]: "queued final"}
    restarted = h.make()
    await restarted._handle_slack_message(edit("after restart", "102.001"))
    await asyncio.wait_for(h.idle(restarted), 5)
    assert h.runs == ["original answer " * 7, "corrected", "after restart"]
    assert h.replies == {original_ids[0]: "after restart"}
    revision = restarted._message_edits.lookup(("T1", "D1", "U1", "100.001"))
    current_obligation = next(key for key, value in revision.reply.obligations.items()
                              if value == str(revision.version))
    native = restarted.gateway_runner
    native._obligation_adapter = AsyncMock(return_value=restarted)
    native._arm_flood_timers_for_waiting_rows = AsyncMock()
    await native._redeliver_claimed_obligations([{
        'obligation_id':current_obligation,'chat_id':'D1','thread_id':'100.001',
        'content':'recovered latest answer','platform':'slack','needs_marker':False}])
    assert h.replies == {original_ids[0]: "recovered latest answer"}
