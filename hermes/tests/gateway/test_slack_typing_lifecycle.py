"""Typing must use Slack's status contract and clear only the owning thread.

Exercise the installed SDK over loopback HTTP: AsyncMock status setters accept
free text even though agents.sessions.setStatus rejects it with invalid_status.
"""

from types import SimpleNamespace

import pytest
import pytest_asyncio

pytest.importorskip("slack_bolt")
web = pytest.importorskip("aiohttp.web")
AsyncWebClient = pytest.importorskip("slack_sdk.web.async_client").AsyncWebClient

from gateway.config import PlatformConfig
from plugins.platforms.slack import adapter as slack


@pytest_asyncio.fixture
async def status_transport():
    requests = []

    async def receive(request):
        body = await request.json()
        method = request.match_info["method"]
        accepted = method == "assistant.threads.setStatus" or (
            method == "agents.sessions.setStatus"
            and body["status"] in {"processing", "active", "suspended", "closed"}
        )
        requests.append((method, request.headers["Authorization"], body, accepted))
        return web.json_response({"ok": True} if accepted else {
            "ok": False, "error": "invalid_status",
        })

    app = web.Application()
    app.router.add_post("/api/{method}", receive)
    runner = web.AppRunner(app)
    await runner.setup()
    try:
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = runner.addresses[0][1]
        yield f"http://127.0.0.1:{port}/api/", requests
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
@pytest.mark.parametrize("modern,custom_text", [(True, None), (False, None), (True, "is typing...")],
                         ids=["agent-sessions", "legacy", "custom-text"])
async def test_typing_refresh_and_clear_follow_slack_contract(status_transport, monkeypatch, modern, custom_text):
    url, requests = status_transport
    monkeypatch.setattr(slack, "_AGENT_SESSIONS_SUPPORTED", modern)
    a = slack.SlackAdapter(PlatformConfig(enabled=True, typing_status_text=custom_text))
    if not custom_text:
        a.set_status_text("D_SHARED", "is working...")
    clients = {
        team: AsyncWebClient(token=f"xoxb-test-{team}", base_url=url, timeout=5, retry_handlers=[])
        for team in ("T_A", "T_B")
    }
    a._app = SimpleNamespace(client=clients["T_A"])
    a._team_clients = clients
    # Slack Connect may reuse channel/thread ids across workspaces.
    first = {"thread_id": "1717171717.123456", "scope_id": "T_A"}
    second = {**first, "scope_id": "T_B"}

    await a.send_typing("D_SHARED", metadata=first)
    await a.send_typing("D_SHARED", metadata=second)
    await a.stop_typing("D_SHARED", metadata=first)
    assert len(a._active_status_threads) == 1
    await a.send_typing("D_SHARED", metadata=second)
    await a.stop_typing("D_SHARED", metadata=second)

    assert len(requests) == 5
    assert all(accepted for _, _, _, accepted in requests), requests
    sessions = modern and not custom_text
    method = "agents.sessions.setStatus" if sessions else "assistant.threads.setStatus"
    assert all(actual == method for actual, _, _, _ in requests)
    assert [auth for _, auth, _, _ in requests] == [
        f"Bearer xoxb-test-{team}" for team in ("T_A", "T_B", "T_A", "T_B", "T_B")
    ]
    statuses = [body["status"] for _, _, body, _ in requests]
    label = custom_text or "is working..."
    assert statuses == (["processing", "processing", "active", "processing", "active"] if sessions else
                        [label, label, "", label, ""])
    assert all(body["thread_ts"] == first["thread_id"] and body["channel_id"] == "D_SHARED"
               for _, _, body, _ in requests)
    assert not a._active_status_threads
