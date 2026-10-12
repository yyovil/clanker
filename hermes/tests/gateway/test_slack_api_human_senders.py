"""Tests for the Slack ``api_human_users`` allowlist.

A message posted through the Web API with a *user* token (``xoxp-``) is
authored by a real person, but it arrives with the posting ``app_id`` and no
``client_msg_id`` — the #35777 app/bot signature — so
``_event_declares_bot_sender`` drops it. ``platforms.slack.extra.api_human_users``
allowlists those *users* (never apps: an app's own ``xoxb`` bot posts carry
the same user+app_id shape).
"""

import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest


# Mock slack-bolt / slack-sdk the same way test_slack_mention.py does.
def _ensure_slack_mock():
    if "slack_bolt" in sys.modules and hasattr(sys.modules["slack_bolt"], "__file__"):
        return
    slack_bolt = MagicMock()
    slack_bolt.async_app.AsyncApp = MagicMock
    slack_bolt.adapter.socket_mode.async_handler.AsyncSocketModeHandler = MagicMock
    slack_sdk = MagicMock()
    slack_sdk.web.async_client.AsyncWebClient = MagicMock
    for name, mod in [
        ("slack_bolt", slack_bolt),
        ("slack_bolt.async_app", slack_bolt.async_app),
        ("slack_bolt.adapter", slack_bolt.adapter),
        ("slack_bolt.adapter.socket_mode", slack_bolt.adapter.socket_mode),
        (
            "slack_bolt.adapter.socket_mode.async_handler",
            slack_bolt.adapter.socket_mode.async_handler,
        ),
        ("slack_sdk", slack_sdk),
        ("slack_sdk.web", slack_sdk.web),
        ("slack_sdk.web.async_client", slack_sdk.web.async_client),
    ]:
        sys.modules.setdefault(name, mod)
    sys.modules.setdefault("aiohttp", MagicMock())


_ensure_slack_mock()

import plugins.platforms.slack.adapter as _slack_mod  # noqa: E402

_slack_mod.SLACK_AVAILABLE = True

from plugins.platforms.slack.adapter import SlackAdapter  # noqa: E402

from gateway.config import Platform, PlatformConfig  # noqa: E402


HUMAN_ID = "U_human"


def _make_adapter(extra=None):
    adapter = object.__new__(SlackAdapter)
    adapter.platform = Platform.SLACK
    adapter.config = PlatformConfig(enabled=True, extra=dict(extra or {}))
    return adapter


def _api_post(**overrides):
    """A user-token chat.postMessage as delivered over Socket Mode:
    real ``user``, app_id stamp, no ``client_msg_id``."""
    event = {"type": "message", "user": HUMAN_ID, "app_id": "A_frontend", "text": "hi"}
    event.update(overrides)
    return event


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("SLACK_API_HUMAN_USERS", raising=False)


def test_api_post_is_bot_by_default():
    assert _make_adapter()._event_declares_bot_sender(_api_post()) is True


def test_allowlisted_user_api_post_is_human():
    adapter = _make_adapter({"api_human_users": ["U_other", HUMAN_ID]})
    assert adapter._event_declares_bot_sender(_api_post()) is False
    # Same predicate everywhere: no other user, and no user-less app post, rides it.
    assert adapter._event_declares_bot_sender(_api_post(user="U_stranger")) is True
    assert adapter._event_declares_bot_sender({"app_id": "A_frontend", "text": "hi"}) is True


def test_unverified_bot_markers_win_over_allowlist():
    """Raw bot stamps remain bot traffic until the inbound path verifies the author."""
    adapter = _make_adapter({"api_human_users": HUMAN_ID})
    assert adapter._event_declares_bot_sender(_api_post(subtype="bot_message")) is True
    assert adapter._event_declares_bot_sender(_api_post(bot_id="B_stamp")) is True


TEAM_ID = "T_human"
BOT_ID = "U_clanker"


def _receiving_adapter():
    adapter = SlackAdapter(PlatformConfig(enabled=True, extra={"api_human_users": [HUMAN_ID]}))
    client = SimpleNamespace(
        users_info=AsyncMock(return_value={"ok": True, "user": {
            "id": HUMAN_ID, "team_id": TEAM_ID, "is_bot": False,
            "profile": {"display_name": "Human"},
        }}),
        conversations_info=AsyncMock(return_value={"ok": True, "channel": {"is_im": True}}),
    )
    adapter._app = SimpleNamespace(client=client)
    adapter._team_clients = {TEAM_ID: client}
    adapter._bot_user_id = BOT_ID
    adapter._team_bot_user_ids = {TEAM_ID: BOT_ID}
    adapter.handle_message = AsyncMock()
    return adapter, client


def _stamped_post(**overrides):
    return _api_post(channel="D_human", channel_type="im", team=TEAM_ID,
                     ts="12345.000001", bot_id="B_user_token_stamp",
                     bot_profile={"id": "B_user_token_stamp", "app_id": "A_frontend"}, **overrides)


@pytest.mark.asyncio
async def test_verified_api_human_reaches_turn_with_human_source():
    """API stamps cannot change an allowlisted, verified human into a bot source."""
    adapter, client = _receiving_adapter()
    event = _stamped_post()
    await adapter._handle_slack_message(event, {"team_id": TEAM_ID})

    adapter.handle_message.assert_awaited_once()
    delivered = adapter.handle_message.await_args.args[0]
    assert delivered.source.user_id == event["user"]
    assert delivered.source.scope_id == event["team"]
    assert delivered.source.is_bot is False
    assert delivered.text == event["text"]
    assert adapter._workspace_message_marker(TEAM_ID, event["ts"]) in adapter._reacting_message_ids
    assert event["bot_id"] == "B_user_token_stamp"  # caller's transport evidence stays intact
    client.users_info.assert_any_await(user=HUMAN_ID)

    # The same ID in another workspace must not inherit the first workspace's human lookup.
    other_client = SimpleNamespace(users_info=AsyncMock(return_value={"ok": True, "user": {
        "id": HUMAN_ID, "team_id": "T_other", "is_bot": True,
    }}))
    adapter._team_clients["T_other"] = other_client
    await adapter._handle_slack_message(
        dict(event, team="T_other", channel="D_other", ts="12345.000002"), {"team_id": "T_other"})
    adapter.handle_message.assert_awaited_once()
    other_client.users_info.assert_awaited_once_with(user=HUMAN_ID)
    await adapter._handle_slack_message(dict(event, ts="12345.000003"), {"team_id": TEAM_ID})
    assert adapter.handle_message.await_count == 2
    assert all(call.args[0].source.scope_id == TEAM_ID and not call.args[0].source.is_bot
               for call in adapter.handle_message.await_args_list)
    assert client.users_info.await_count == 2  # each API event verifies independently


@pytest.mark.asyncio
@pytest.mark.parametrize("event_changes,user_changes,reply,allowlist", [
    pytest.param({}, {}, None, [], id="not_allowlisted"),
    pytest.param({"user": BOT_ID}, {"id": BOT_ID}, None, [BOT_ID], id="own_bot"),
    pytest.param({}, {"is_bot": True}, None, [HUMAN_ID], id="true_bot"),
    pytest.param({}, {"is_workflow_bot": True}, None, [HUMAN_ID], id="workflow_bot"),
    pytest.param({}, {"is_app_user": True}, None, [HUMAN_ID], id="app_user"),
    pytest.param({}, {"profile": {"bot_id": "B_actual_bot"}}, None, [HUMAN_ID], id="profile_bot"),
    pytest.param({}, {"deleted": True}, None, [HUMAN_ID], id="deleted"),
    pytest.param({}, {"id": "U_other"}, None, [HUMAN_ID], id="wrong_user"),
    pytest.param({}, {"team_id": "T_other"}, None, [HUMAN_ID], id="wrong_team"),
    pytest.param({"team": "T_unknown"}, {}, None, [HUMAN_ID], id="unknown_team"),
    pytest.param({}, {"is_bot": None}, None, [HUMAN_ID], id="missing_is_bot"),
    pytest.param({}, {}, {}, [HUMAN_ID], id="empty"),
    pytest.param({}, {}, {"ok": False}, [HUMAN_ID], id="api_error"),
    pytest.param({}, {}, RuntimeError("lookup unavailable"), [HUMAN_ID], id="exception"),
    pytest.param({"subtype": "bot_message"}, {}, None, [HUMAN_ID], id="bot_message"),
    pytest.param({"_slack_api_human_verified": True}, {}, {}, [HUMAN_ID], id="payload_human_marker"),
])
async def test_api_stamps_need_confirmed_human_identity(event_changes, user_changes, reply, allowlist):
    """Neither allowlisting nor an untrusted marker may grant bot traffic human access."""
    adapter, client = _receiving_adapter()
    event = dict(_stamped_post(), **event_changes)
    adapter.config.extra["api_human_users"] = allowlist
    user = client.users_info.return_value["user"]
    user.update(user_changes)
    if isinstance(reply, Exception):
        client.users_info.side_effect = reply
    elif reply is not None:
        client.users_info.return_value = reply

    # A failed legacy bot lookup can cache False; that is not evidence of a human.
    adapter._user_is_bot_cache[(TEAM_ID, event["user"])] = False
    await adapter._handle_slack_message(event, {"team_id": event["team"]})
    adapter.handle_message.assert_not_awaited()
