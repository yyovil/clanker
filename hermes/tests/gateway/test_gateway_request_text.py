"""Authorization sees current event text while model prompts retain gateway context."""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from agent.gateway_context import current_gateway_turn, gateway_turn_scope
from gateway.config import GatewayConfig, Platform
from gateway.platforms.event import MessageEvent
from gateway.run import GatewayRunner
from gateway.run_turn_runner import TurnRunner
from gateway.session import SessionSource
from gateway.turn_context import TurnContext


EDIT_CONTEXT = ('This Slack message was edited. The following request replaces its '
                'previous wording. Work only on the updated request.')


def source():
    return SessionSource(Platform.SLACK, 'D1', user_id='U1', scope_id='T1',
                         thread_id='1790000000.000001', chat_type='dm')


def runner():
    result = object.__new__(GatewayRunner)
    result.config = GatewayConfig(group_sessions_per_user=False)
    result.adapters = {}
    return result


@pytest.mark.parametrize('raw,expected', [(None, 'wrapped prompt'), ('', ''), ('retry', 'retry')])
def test_gateway_scope_defaults_only_for_absent_request_text(tmp_path, monkeypatch, raw, expected):
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    with gateway_turn_scope('runner', source(), 'session', 'wrapped prompt',
                            request_message=raw):
        current = current_gateway_turn()
        assert current.message == 'wrapped prompt'
        assert current.request_message == expected
    assert current_gateway_turn() is None


def test_tool_context_receives_raw_request_without_changing_model_or_persisted_text(tmp_path, monkeypatch):
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    wrapped = EDIT_CONTEXT + '\n\n[New message]\nretry'
    captured = []

    class Agent:
        def run_conversation(self, message, **kwargs):
            captured.append(current_gateway_turn())
            assert message == wrapped
            assert kwargs['persist_user_message'] == wrapped
            return {'final_response': 'continued'}

    native = SimpleNamespace(_consume_pending_native_image_paths=lambda key: [])
    context = TurnContext(source=source(), session_id='session', session_key='lane',
                          message=wrapped, request_message='retry',
                          inbound_message_id='1790000000.000002')
    result = TurnRunner(native, context)._run_conversation_with_approval(
        Agent(), [], '', wrapped, None)
    assert result['final_response'] == 'continued'
    assert captured[0].request_message == 'retry'
    assert captured[0].message == wrapped
    assert captured[0].message_id == '1790000000.000002'
    assert current_gateway_turn() is None


@pytest.mark.asyncio
@pytest.mark.parametrize('raw', ['retry', '', EDIT_CONTEXT + '\n\n[New message]\nretry'])
async def test_initial_gateway_run_passes_event_text_without_parsing_wrappers(raw):
    native = runner()
    current_source = source()
    event = MessageEvent(raw, source=current_source, message_id='1790000000.000002',
                         channel_context=EDIT_CONTEXT, metadata={'request_message': 'retry'})
    wrapped = native._prefix_inbound_sender_context(event, current_source, raw)
    entry = SimpleNamespace(session_id='session')
    prepared = native._PreparedTurn([], '', wrapped, wrapped, None, None, 'session', 'owner')
    native._hmwa_resolve_session = AsyncMock(return_value=(current_source, entry, 'lane'))
    native._hmwa_prepare_turn = AsyncMock(return_value=(prepared, None))
    native.hooks = SimpleNamespace(emit=AsyncMock())
    native._clear_session_env = MagicMock()
    # Stop immediately after the production handoff to the agent, before reply delivery.
    native._run_agent = AsyncMock(side_effect=asyncio.CancelledError)
    with pytest.raises(asyncio.CancelledError):
        await native._handle_message_with_agent(event, current_source, 'lane', 1)
    parameters = native._run_agent.await_args.kwargs
    assert parameters['request_message'] == raw
    assert parameters['message'] == wrapped
    assert parameters['persist_user_message'] == wrapped
    assert parameters['inbound_message_id'] == event.message_id


@pytest.mark.asyncio
async def test_queued_followup_preserves_its_own_raw_request():
    native = runner()
    current_source = source()
    event = MessageEvent('retry', source=current_source, message_id='1790000000.000003',
                         channel_context=EDIT_CONTEXT)
    wrapped = native._prefix_inbound_sender_context(event, current_source, event.text)
    native._MAX_INTERRUPT_DEPTH = 8
    native._run_agent = AsyncMock(return_value={'final_response': 'done', 'messages': []})
    native._run_agent_deliver_first_response = AsyncMock()
    native._is_goal_continuation_event = MagicMock(return_value=False)
    native._session_key_for_source = MagicMock(return_value='lane')
    native._prepare_profile_scoped_inbound_message_text = AsyncMock(return_value=wrapped)
    native._reply_anchor_for_event = MagicMock(return_value=None)
    native._delivery_adapter_for = MagicMock(return_value=None)
    native._refresh_agent_cache_message_count = AsyncMock()
    context = TurnContext(source=current_source, session_id='session', session_key='lane',
                          run_generation=1, message='previous', request_message='previous', history=[])
    await native._run_agent_queued_followup(
        context, adapter=None, pending=event.text, pending_event=event,
        response='old response', result={'interrupted': True, 'messages': []}, stream_task=None)
    parameters = native._run_agent.await_args.kwargs
    assert parameters['request_message'] == 'retry'
    assert parameters['message'] == wrapped
    assert parameters['persist_user_message'] == wrapped
    assert parameters['inbound_message_id'] == event.message_id


@pytest.mark.asyncio
async def test_full_runner_binds_authored_text_for_initial_and_queued_turns(tmp_path, monkeypatch):
    from tests.gateway.test_queued_followup_processing_hooks import (
        HookRecordingAdapter, SESSION_KEY, _install_fake_agent, _make_runner, _source,
    )
    captured = []

    class Agent:
        def __init__(self, **kwargs):
            self.tools = []

        def run_conversation(self, message, **kwargs):
            turn = current_gateway_turn()
            captured.append((message, turn.message, turn.request_message, turn.message_id))
            return {'final_response': 'done', 'messages': [], 'api_calls': 1}

    _install_fake_agent(monkeypatch, tmp_path, Agent)
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    adapter = HookRecordingAdapter()
    native = _make_runner(adapter)
    adapter._pending_messages[SESSION_KEY] = MessageEvent(
        'retry', source=_source(), message_id='1790000000.000003', channel_context=EDIT_CONTEXT)
    initial = 'Observed history\n\n[New message]\nsign in'
    result = await native._run_agent(
        message=initial, request_message='sign in', inbound_message_id='1790000000.000002',
        context_prompt='', history=[], source=_source(), session_id='session', session_key=SESSION_KEY)
    queued = EDIT_CONTEXT + '\n\n[New message]\nretry'
    assert captured == [(initial, initial, 'sign in', '1790000000.000002'),
                        (queued, queued, 'retry', '1790000000.000003')]
    assert result['final_response'] == 'done'
    assert current_gateway_turn() is None
