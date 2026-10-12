"""Trusted isolated workers withhold private context and own final reply delivery."""

import asyncio
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

from agent.gateway_context import IsolatedGatewayTask, current_gateway_turn, gateway_turn_scope
from gateway.config import Platform
from gateway.platforms.event import MessageEvent
from gateway.run import GatewayRunner
from gateway.run_turn_runner import TurnRunner
from gateway.session import SessionSource
from gateway.turn_context import TurnContext


def test_native_turn_binds_conversation_for_task_handoff_without_mutating_history(tmp_path, monkeypatch):
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    source = SessionSource(Platform.SLACK, 'C1', user_id='U1', scope_id='T1', thread_id='100.1')
    history = [{'role': 'user', 'content': 'Find the earliest Mumbai flight on 9 October.'},
               {'role': 'assistant', 'content': [{'type': 'text', 'text': 'Where from?'}]},
               {'role': 'tool', 'content': 'PRIVATE_TOOL_CANARY'}]
    before = repr(history)
    captured = []

    class Agent:
        def run_conversation(self, message, **kwargs):
            captured.append(current_gateway_turn())
            assert kwargs['conversation_history'] is history
            return {'final_response': 'continued'}

    runner = SimpleNamespace(_consume_pending_native_image_paths=lambda key: [])
    ctx = TurnContext(source=source, session_id='flight-session', session_key='flight-lane',
                      message='NGP', inbound_message_id='100.2')
    result = TurnRunner(runner, ctx)._run_conversation_with_approval(Agent(), history, '', None, None)
    assert result['final_response'] == 'continued'
    assert captured[0].conversation == (
        ('user', history[0]['content']), ('assistant', 'Where from?'))
    assert captured[0].message == 'NGP' and captured[0].message_id == '100.2'
    assert repr(history) == before and current_gateway_turn() is None


def test_worker_capability_is_not_wire_data_and_owns_full_reply(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    captured = []

    async def respond(event, response, runner):
        captured.append((event, response, runner))

    source = SessionSource(Platform.SLACK, "D1", user_id="U1", scope_id="T1")
    source.isolated_task = IsolatedGatewayTask("task-1", respond)
    restored = SessionSource.from_dict({**source.to_dict(), "isolated_task": source.isolated_task})
    assert restored.isolated_task is None
    assert "isolated_task" not in source.to_dict()
    assert "respond" not in repr(source)
    with gateway_turn_scope("runner", source, "session-1", "request", message_id="resume-1"):
        assert current_gateway_turn().message_id == "resume-1"
    assert current_gateway_turn() is None

    runner = object.__new__(GatewayRunner)
    runner._delivery_adapter_for = MagicMock(side_effect=AssertionError("ordinary egress entered"))
    event = MessageEvent("continue", source=source)
    response = "complete result " * 100
    result = asyncio.run(runner._hmwa_deliver_turn_response(
        event, source, None, "worker", None, {"already_sent": True}, [], response, "footer", False,
    ))
    assert result is None
    assert captured == [(event, response, runner)]
    runner._delivery_adapter_for.assert_not_called()

    async def failed_publication(*_args):
        raise RuntimeError("publication unavailable")

    source.isolated_task = IsolatedGatewayTask("task-1", failed_publication)
    assert asyncio.run(runner._hmwa_deliver_turn_response(
        event, source, None, "worker", None, {}, [], response, None, False,
    )) is None
    runner._delivery_adapter_for.assert_not_called()


def test_worker_build_excludes_private_memory_and_ordinary_cache(monkeypatch, tmp_path):
    from agent.agent_init import _init_memory
    from gateway import run as gateway_run
    from model_tools import _select_tool_names

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    (tmp_path / "memories").mkdir()
    (tmp_path / "memories" / "MEMORY.md").write_text("unrelated private DM fact")
    (tmp_path / "memories" / "USER.md").write_text("unrelated private user profile")
    monkeypatch.setattr(gateway_run, "_checkpoint_agent_kwargs", lambda _cfg: {})

    class MemoryProbe:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.enabled_toolsets = kwargs["enabled_toolsets"]
            self.disabled_toolsets = kwargs["disabled_toolsets"]
            self.tools = []
            _init_memory(self, {}, kwargs["skip_memory"], "slack")

    async def respond(*_args):
        pass

    source = SessionSource(Platform.SLACK, "D1", user_id="U1", scope_id="T1")
    runner = MagicMock()
    runner._prefill_messages = [{"role": "user", "content": "private prefill"}]
    runner._session_db = None
    runner._agent_cache_lock = threading.RLock()
    runner._agent_cache = {}
    runner._agent_config_signature.return_value = "ordinary-signature"
    runner._extract_cache_busting_config.return_value = {}
    runner._refresh_fallback_model.return_value = None
    ctx = TurnContext(source=source, AIAgent=MemoryProbe, enabled_toolsets=["memory", "session_search"],
                      user_config={}, session_key="lane", session_id="session-1")
    turn = TurnRunner(runner, ctx)
    route = {"model": "test-model", "runtime": {}}
    ordinary = turn._build_fresh_agent(route, "slack", "", 5, None, {}, False)
    assert ordinary._memory_store is not None
    assert "unrelated private DM fact" in ordinary._memory_store.format_for_system_prompt("memory")
    runner._agent_cache[ctx.session_key] = (ordinary, "ordinary-signature", None, ctx.session_id)

    source.isolated_task = IsolatedGatewayTask("task-1", respond)
    worker, reused = turn._resolve_turn_agent(route, "slack", "", 5, None, {})
    assert not reused and worker is not ordinary
    assert worker._memory_store is None and worker._memory_manager is None
    assert worker.kwargs["skip_context_files"] and worker.kwargs["skip_background_review"]
    assert not worker.kwargs["load_soul_identity"] and worker.kwargs["prefill_messages"] is None
    assert not {"memory", "session_search"} & _select_tool_names(
        worker.enabled_toolsets, worker.disabled_toolsets, True,
    )
    assert turn._setup_stream_consumer("slack") == (None, None, None, False)

    from agent import secret_scope
    monkeypatch.setattr(secret_scope, "get_secret", lambda _key: None)
    monkeypatch.setattr(gateway_run, "_load_gateway_config", lambda: {
        "display": {"tool_progress": "all", "live_status": "full",
                    "interim_assistant_messages": True, "thinking_progress": True},
    })
    display_runner = object.__new__(GatewayRunner)
    display_runner._delivery_adapter_for = lambda _source: SimpleNamespace(
        supports_status_text=True, native_task_cards_enabled=lambda: True,
    )
    display_runner._resolve_turn_toolsets = lambda *_args: (["memory"], None)
    display = display_runner._run_agent_display_settings(source)
    assert not display.tool_progress_enabled and not display.needs_progress_queue
    assert not display.interim_assistant_messages_enabled and not display._thinking_enabled
    assert display._live_status_adapter is None and not display._native_slack_task_cards

    source.isolated_task = None
    ordinary_again, reused = turn._resolve_turn_agent(route, "slack", "", 5, None, {})
    assert not reused and ordinary_again._memory_store is not None
