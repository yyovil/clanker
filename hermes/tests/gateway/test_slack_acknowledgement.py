"""Acknowledgements use model output under the sender's profile and outlive work.

The real auxiliary router and Slack SDK use loopback HTTP, including failures.
"""

import asyncio
from types import SimpleNamespace

import pytest
import pytest_asyncio
import yaml

pytest.importorskip("slack_bolt")
web = pytest.importorskip("aiohttp.web")
AsyncWebClient = pytest.importorskip("slack_sdk.web.async_client").AsyncWebClient

from gateway.config import Platform, PlatformConfig
from gateway.platforms.event import MessageEvent, ProcessingOutcome
from gateway.run import _async_profile_runtime_scope
from gateway.session import SessionSource
from plugins.platforms.slack import adapter as slack


@pytest_asyncio.fixture
async def transport():
    requests = []
    replies = {"A": "thumbsup", "B": "heart"}
    model_started = asyncio.Event()

    async def receive(request):
        body = (await request.json() if request.content_type == "application/json"
                else dict(await request.post()))
        body = {**dict(request.query), **body}
        method = request.match_info["method"]
        auth = request.headers.get("Authorization", "")
        requests.append((method, auth, body))
        if method == "chat/completions":
            model_started.set()
            reply = replies[auth.removeprefix("Bearer key-")]
            if reply == "failure":
                return web.json_response({"error": {"message": "unavailable"}}, status=503)
            if reply == "timeout":
                await asyncio.sleep(30)
            return web.json_response({
                "id": "ack", "object": "chat.completion", "created": 0,
                "model": body["model"], "choices": [{"index": 0,
                    "message": {"role": "assistant", "content": reply},
                    "finish_reason": "stop"}],
            })
        if method == "chat.postMessage" and body.get("text") == "broken interim":
            return web.json_response({"ok": False, "error": "not_in_channel"})
        return web.json_response({"ok": True, "ts": "171.999"})

    app = web.Application()
    app.router.add_post("/{kind}/{method:.*}", receive)
    runner = web.AppRunner(app, shutdown_timeout=0.1)
    await runner.setup()
    try:
        await web.TCPSite(runner, "127.0.0.1", 0).start()
        yield f"http://127.0.0.1:{runner.addresses[0][1]}", requests, replies, model_started
    finally:
        await runner.cleanup()


def make_adapter(tmp_path, url):
    homes = {}
    for profile in ("A", "B"):
        home = tmp_path / profile
        home.mkdir()
        (home / ".env").write_text(f"ACK_TEST_KEY=key-{profile}\n")
        (home / "config.yaml").write_text(yaml.safe_dump({"auxiliary": {
            "slack_acknowledgement": {"provider": "custom", "model": "fixture-ack",
                "base_url": f"{url}/v1", "key_env": "ACK_TEST_KEY",
                "api_mode": "chat_completions"},
        }}))
        homes[profile] = home
    a = slack.SlackAdapter(PlatformConfig(enabled=True, extra={
        "acknowledgement_reactions": True, "reactions": True,
    }))
    a._app = SimpleNamespace(client=AsyncWebClient(
        token="xoxb-A", base_url=f"{url}/api/", timeout=5, retry_handlers=[]))
    a._team_clients = {team: AsyncWebClient(
        token=f"xoxb-{team}", base_url=f"{url}/api/", timeout=5, retry_handlers=[])
        for team in ("A", "B")}
    a.gateway_runner = SimpleNamespace(
        _async_profile_scope_for_source=lambda source: _async_profile_runtime_scope(homes[source.profile]))
    return a


def make_event(a, profile, message_id="171.001"):
    event = MessageEvent(text="Please help me with this task.", message_id=message_id,
        source=SessionSource(platform=Platform.SLACK, chat_id="D_SHARED", chat_type="dm",
            user_id="U_SHARED", scope_id=profile, profile=profile, thread_id="171.000"))
    a._track_reacting_message(profile, message_id)
    return event


@pytest.mark.asyncio
async def test_model_acknowledgement_is_scoped_persistent_and_idempotent(transport, tmp_path):
    url, requests, _, _ = transport
    a = make_adapter(tmp_path, url)
    for index, profile in enumerate(("A", "B", "A")):
        event = make_event(a, profile, f"171.00{index + 1}")
        await a.on_processing_start(event)
        await a.on_processing_start(event)
        await a.on_processing_complete(event, ProcessingOutcome.SUCCESS)

    model = [(auth, body) for method, auth, body in requests if method == "chat/completions"]
    assert [auth for auth, _ in model] == ["Bearer key-A", "Bearer key-B", "Bearer key-A"]
    assert all(body["messages"][-1]["content"] == event.text for _, body in model)
    reactions = [(method, auth, body) for method, auth, body in requests if method.startswith("reactions.")]
    assert [(auth, body["name"]) for _, auth, body in reactions] == [
        ("Bearer xoxb-A", "thumbsup"), ("Bearer xoxb-B", "heart"), ("Bearer xoxb-A", "thumbsup")]
    assert all(method == "reactions.add" for method, _, _ in reactions)
    assert [body["timestamp"] for _, _, body in reactions] == ["171.001", "171.002", "171.003"]
    assert not a._reacting_message_ids


@pytest.mark.asyncio
@pytest.mark.parametrize("reply", ["thumbsup", "failure", "timeout", "white_check_mark", "bad output"])
async def test_working_status_survives_interim_and_ack_failure(transport, tmp_path, monkeypatch, reply):
    url, requests, replies, model_started = transport
    replies["A"] = reply
    a = make_adapter(tmp_path, url)
    a.gateway_runner = None  # standalone, already bound below
    monkeypatch.setattr(slack, "_AGENT_SESSIONS_SUPPORTED", True)
    event = make_event(a, "A")
    metadata = {"thread_id": event.source.thread_id, "scope_id": "A"}

    async with _async_profile_runtime_scope(tmp_path / "A"):
        await a.send_typing(event.source.chat_id, metadata)
        await a.on_processing_start(event)
        await a.send(event.source.chat_id, "Checking now", metadata={**metadata, "_interim_send": True})
        await a.send(event.source.chat_id, "", metadata={**metadata, "_interim_send": True})
        failed = await a.send(event.source.chat_id, "broken interim",
                              metadata={**metadata, "_interim_send": True})
        assert not failed.success
        statuses = [body["status"] for method, _, body in requests if method == "agents.sessions.setStatus"]
        assert statuses == ["processing"]
        await a.send_typing(event.source.chat_id, metadata)
        await a.send(event.source.chat_id, "Here is the result", metadata=metadata)
        await a.on_processing_complete(event, ProcessingOutcome.FAILURE)
    statuses = [body["status"] for method, _, body in requests if method == "agents.sessions.setStatus"]
    assert statuses == ["processing", "processing", "active"]
    assert model_started.is_set()
    reactions = [(method, body["name"]) for method, _, body in requests if method.startswith("reactions.")]
    assert reactions == [("reactions.add", "thumbsup" if reply == "thumbsup" else "eyes")]
    assert not a._active_status_threads and not a._reacting_message_ids
