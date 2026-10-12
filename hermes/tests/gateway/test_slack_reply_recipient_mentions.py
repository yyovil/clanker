"""Shared Slack replies address the authenticated turn sender without a DM ping."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from gateway.config import PlatformConfig
from gateway.platforms.base import Platform
from gateway.run import GatewayRunner, _profile_runtime_scope
from gateway.session import SessionSource
from plugins.platforms.slack.adapter import SlackAdapter


def _adapter():
    adapter = SlackAdapter(PlatformConfig(enabled=True, extra={"mention_reply_user": True}))
    adapter._app = MagicMock()
    client = AsyncMock()
    client.chat_postMessage.return_value = {"ts": "123.456"}
    client.chat_startStream.return_value = {"ts": "123.457"}
    adapter._get_client = MagicMock(return_value=client)
    adapter.stop_typing = AsyncMock()
    return adapter, client


@pytest.mark.asyncio
async def test_shared_thread_uses_each_turn_sender_across_profiles_and_dm_has_no_ping(tmp_path):
    adapter, client = _adapter()
    runner = object.__new__(GatewayRunner)
    homes = [tmp_path / "alice", tmp_path / "bob"]
    for home in homes:
        home.mkdir()
    metadata = []
    for home, user in ((homes[0], "U123ABC"), (homes[1], "U456DEF"), (homes[0], "U123ABC")):
        with _profile_runtime_scope(home):
            source = SessionSource(platform=Platform.SLACK, chat_id="C123SHARED",
                                   chat_type="group", thread_id="123.000", user_id=user,
                                   scope_id="T123TEAM", message_id="123.100")
            metadata.append(runner._thread_metadata_for_source(source))
    # Build every turn's metadata before delivery: a later sender cannot overwrite an earlier one.
    for meta in metadata:
        result = await adapter.send("C123SHARED", "The form is in your DM.", metadata=meta)
        assert result.success
        assert client.chat_postMessage.await_args.kwargs["text"].startswith(f'<@{meta["user_id"]}> ')

    meta = metadata[0]
    content = "<@U123ABC> I checked with <@U456DEF>."
    await adapter.send("C123SHARED", content, metadata=meta)
    assert client.chat_postMessage.await_args.kwargs["text"] == content
    await adapter.edit_message("C123SHARED", "123.456", content, finalize=True, metadata=meta)
    assert client.chat_update.await_args.kwargs["text"] == content
    await adapter.send("C123SHARED", "I checked with <@U456DEF>.", metadata=meta)
    assert client.chat_postMessage.await_args.kwargs["text"] == "<@U123ABC> I checked with <@U456DEF>."
    adapter.config.extra["rich_blocks"] = True
    await adapter.send("C123SHARED", "Ready.", metadata=meta)
    payload = client.chat_postMessage.await_args.kwargs
    assert payload["text"] == "<@U123ABC> Ready."
    assert "<@U123ABC>" in str(payload["blocks"])
    adapter.config.extra["rich_blocks"] = False
    await adapter.send("D123PRIVATE", "Please share your details here.", metadata=meta)
    assert client.chat_postMessage.await_args.kwargs["text"] == "Please share your details here."
    await adapter.edit_message("D123PRIVATE", "123.456", "Received.", finalize=True, metadata=meta)
    assert client.chat_update.await_args.kwargs["text"] == "Received."
    for user in (None, "@alice", "U123> <!channel>"):
        await adapter.send("C123SHARED", "Ready.", metadata={"user_id": user})
        assert client.chat_postMessage.await_args.kwargs["text"] == "Ready."
    adapter.config.extra["mention_reply_user"] = False
    await adapter.send("C123SHARED", "Ready.", metadata=meta)
    assert client.chat_postMessage.await_args.kwargs["text"] == "Ready."


@pytest.mark.asyncio
async def test_native_stream_keeps_prefix_stable_then_addresses_final_by_edit():
    adapter, client = _adapter()
    meta = {"thread_id": "123.000", "user_id": "U123ABC"}
    await adapter.send_draft("C123SHARED", 1, "I checked", metadata=meta)
    await adapter.send_draft("C123SHARED", 1, "I checked the form.", metadata=meta)
    assert client.chat_startStream.await_args.kwargs["markdown_text"] == "I checked"
    assert client.chat_appendStream.await_args.kwargs["markdown_text"] == " the form."
    result = await adapter.send("C123SHARED", "I checked the form. It is ready.", metadata=meta)
    assert result.success and result.message_id == "123.457"
    assert client.chat_stopStream.await_args.kwargs["markdown_text"] == " It is ready."
    assert client.chat_update.await_args.kwargs["text"] == "<@U123ABC> I checked the form. It is ready."
    client.chat_postMessage.assert_not_awaited()
