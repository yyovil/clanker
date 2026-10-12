"""A pending plain-text stop gets truthful status without stale work heartbeats."""
import asyncio
import threading
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from gateway.platforms.base import Platform, build_session_key
from gateway.turn_context import TurnContext
from gateway.run_turn_runner import TurnRunner
from agent.interrupt_control import InterruptControlMixin
from tests.gateway.test_busy_session_ack import _make_event, _make_runner
from tests.gateway.test_run_cleanup_progress import CleanupCaptureAdapter


class HardStopAgent(InterruptControlMixin):
    def __init__(self):
        self._interrupt_requested = False
        self._interrupt_message = None
        self._hard_interrupt_requested = threading.Event()
        self._execution_thread_id = None
        self._active_children = []
        self._active_children_lock = threading.Lock()
        self.quiet_mode = True
        self._supports_active_turn_redirect = True
        self.redirect = MagicMock(return_value=True)
        self.get_activity_summary = MagicMock(return_value={})
        self.hard_interrupt = MagicMock(wraps=self.hard_interrupt)

    @property
    def is_interrupted(self):
        return self._interrupt_requested


def active_turn(monkeypatch, text):
    import gateway.run as gateway_run
    monkeypatch.setattr(gateway_run, '_load_gateway_config', lambda: {'onboarding': {'enabled': False}})
    monkeypatch.setattr('gateway.plugin_control.notify_gateway_control', AsyncMock(return_value=[]))
    monkeypatch.setattr('tools.async_delegation.interrupt_for_session', MagicMock(return_value=0))
    runner, _ = _make_runner()
    runner._busy_input_mode = 'interrupt'
    runner._restart_requested = False
    event = _make_event(text=text)
    event.source.platform = Platform.SLACK
    adapter = CleanupCaptureAdapter(Platform.SLACK)
    adapter._send_with_retry = AsyncMock()
    adapter.set_status_text = MagicMock(wraps=adapter.set_status_text)
    adapter._source_session_key = build_session_key
    adapter.send = AsyncMock(return_value=SimpleNamespace(success=True, message_id='heartbeat'))
    runner.adapters[event.source.platform] = adapter
    key = build_session_key(event.source)
    adapter._active_sessions[key] = asyncio.Event()
    agent = MagicMock()
    agent._supports_active_turn_redirect = True
    agent.redirect.return_value = True
    agent.is_interrupted = False
    agent.get_activity_summary.return_value = {}
    runner._running_agents[key] = agent
    ctx = TurnContext(source=event.source, session_key=key, agent_holder=[agent],
        _run_still_current=lambda: True, _live_status_adapter=adapter, _live_status_mode='full')
    runner._session_state(key).turn.ctx = ctx
    return runner, event, adapter, key, agent, ctx


@pytest.mark.asyncio
@pytest.mark.parametrize('text, stopping, mode, control', [
    ('Actually, stop. I’ll sort this out myself.', True, 'interrupt', 'redirect'),
    ('Please stop.', True, 'interrupt', 'redirect'),
    ('Stop the task now.', True, 'interrupt', 'redirect'),
    ('Cancel this request.', True, 'interrupt', 'redirect'),
    ('Never mind, I will handle it myself.', True, 'interrupt', 'redirect'),
    ('Please stop.', True, 'queue', 'redirect'),
    ('Please stop.', True, 'steer', 'redirect'),
    ('Actually, make it two packets.', False, 'interrupt', 'redirect'),
    ('Stop before payment.', False, 'interrupt', 'redirect'),
    ('Do not stop.', False, 'interrupt', 'redirect'),
    ("Don't stop.", False, 'interrupt', 'redirect'),
    ('Did you stop?', False, 'interrupt', 'redirect'),
    ('```text\nstop\n```', False, 'interrupt', 'redirect'),
    ('"stop"', False, 'interrupt', 'redirect'),
    ('Stop searching and compare the options.', False, 'interrupt', 'redirect'),
    ('The page says "stop". Please continue.', False, 'interrupt', 'redirect'),
    ('Please stop.', True, 'interrupt', 'subagents'),
    ('Please stop.', True, 'interrupt', 'compression'),
    ('Please stop.', True, 'interrupt', 'interrupt'),
    ('Please stop.', True, 'interrupt', 'interrupt_failed'),
    ('Please stop.', True, 'interrupt', 'no_interrupt'),
    ('Actually, make it two packets.', False, 'interrupt', 'subagents'),
    ('Actually, make it two packets.', False, 'interrupt', 'compression'),
])
async def test_stop_status_is_immediate_truthful_and_scoped_to_the_active_turn(monkeypatch, text, stopping, mode, control):
    runner, event, adapter, key, agent, ctx = active_turn(monkeypatch, text)
    runner._busy_input_mode = runner._busy_text_mode = mode
    real_hard_stop = stopping and control in {'subagents', 'compression'}
    if real_hard_stop:
        agent = HardStopAgent()
        runner._running_agents[key] = agent
        ctx.agent_holder[0] = agent
    if control == 'subagents':
        agent._active_children = [HardStopAgent() if real_hard_stop else MagicMock()]
    if control == 'compression':
        runner._session_has_compression_in_flight = AsyncMock(return_value=True)
    if control in {'interrupt', 'interrupt_failed', 'no_interrupt'}:
        agent.redirect.return_value = False
    if control == 'interrupt_failed':
        agent.interrupt.side_effect = RuntimeError('control unavailable')
    if control == 'no_interrupt':
        agent.interrupt = None
    accepted_stop = stopping and control not in {'interrupt_failed', 'no_interrupt'}
    old_followup = _make_event(text='Continue with another item')
    wake = _make_event(text='Background work completed')
    wake.internal = True
    if accepted_stop:
        adapter._pending_messages[key] = old_followup
        runner._session_state(key).conversation.queued_events = [old_followup, wake]
    if stopping:
        runner._session_state(key).turn.busy_ack_ts = time.time()  # cancellation must bypass ordinary debounce
    pending = asyncio.get_running_loop().create_future()
    adapter.set_status_text(event.source.chat_id, 'Searching the store')
    adapter.set_status_text.reset_mock()
    await runner._handle_active_session_busy_message(event, key)
    adapter._send_with_retry.assert_awaited_once()
    ack = adapter._send_with_retry.call_args.kwargs['content']
    assert ('Stopping' in ack) is accepted_stop
    assert 'Stopped' not in ack  # a pending operation is not a completed cancellation
    if stopping:
        agent.redirect.assert_not_called()
        if real_hard_stop:
            agent.hard_interrupt.assert_called_once_with(text)
            assert agent._hard_interrupt_requested.is_set()
            if control == 'subagents':
                assert agent._active_children[0]._hard_interrupt_requested.is_set()
        elif control != 'no_interrupt':
            agent.interrupt.assert_called_once_with(text)
    elif control in {'subagents', 'compression'}:
        agent.redirect.assert_not_called()
        agent.interrupt.assert_not_called()
    else:
        agent.redirect.assert_called_once()
        assert agent.redirect.call_args.args[0].endswith(text)
    if accepted_stop:
        assert adapter._pending_messages[key] is event
        assert runner._session_state(key).conversation.queued_events == [wake]
        import tools.async_delegation as delegation
        assert delegation.interrupt_for_session.call_args.kwargs['session_key'] == key
    if stopping and not accepted_stop:
        assert 'not stopped' in ack.lower()
        assert key not in adapter._pending_messages
    assert runner._should_emit_long_running_notification(key, agent, pending) is not accepted_stop
    progress = TurnRunner(runner, ctx)
    assert progress._agent_interrupted() is accepted_stop
    if accepted_stop:
        assert str(event.source.chat_id) not in adapter._status_text
    adapter.set_status_text.reset_mock()
    progress._progress_live_status('tool.started', 'browser_navigate', {})
    assert adapter.set_status_text.called is not accepted_stop
    assert not pending.done()
    runner._session_state(key).turn.clear()
    if real_hard_stop:
        agent.clear_interrupt(hard_cancel=True)
    runner._session_state(key).turn.agent = agent  # cached agent reused for a fresh turn
    assert runner._should_emit_long_running_notification(key, agent, pending) is True
    assert progress._agent_interrupted() is False
    pending.cancel()


@pytest.mark.asyncio
@pytest.mark.parametrize('lifecycle', ['heartbeat', 'typing', 'slow_ack', 'slow_cleanup', 'recursive',
                                     'exception_cleanup', 'handler_cancelled', 'repeat_stop'])
async def test_stop_lifecycle_waits_for_cleanup_and_preserves_later_work(monkeypatch, lifecycle):
    if lifecycle == 'typing':
        return await check_typing_after_stop(monkeypatch)
    if lifecycle != 'heartbeat':
        return await check_stop_drain_and_successor(monkeypatch, lifecycle)
    monkeypatch.setenv('HERMES_AGENT_NOTIFY_INTERVAL', '0.01')
    runner, event, adapter, key, agent, ctx = active_turn(monkeypatch, 'Actually, stop. I’ll sort this out myself.')
    runner._agent_activity_summary = lambda unused: None
    disp = MagicMock()
    disp.user_config = {}
    disp._display_surface_mode.return_value = 'generic'
    disp._generic_status_phrase.return_value = 'Still working on your request.'
    disp.resolve_display_setting.return_value = False
    pending = asyncio.get_running_loop().create_future()
    async def stop_during_edit(*args, **kwargs):
        await runner._handle_active_session_busy_message(event, key)
        return SimpleNamespace(success=False)
    adapter.edit_message = AsyncMock(side_effect=stop_during_edit)
    async def send(*args, **kwargs):
        # Bound the pre-fix reproducer without depending on a timeout.
        if adapter.send.await_count > 1:
            pending.set_result(None)
        return SimpleNamespace(success=True, message_id='heartbeat')
    adapter.send.side_effect = send
    await asyncio.wait_for(runner._run_agent_notify_long_running(disp, ctx, [pending]), 5)
    assert adapter.send.await_count == 1
    adapter.edit_message.assert_awaited_once()
    assert 'Stopping' in adapter._send_with_retry.call_args.kwargs['content']
    assert not pending.done()
    pending.cancel()


async def check_typing_after_stop(monkeypatch):
    runner, event, adapter, key, agent, ctx = active_turn(monkeypatch, 'Please stop.')
    other = _make_event(text='Unrelated work', chat_id=event.source.chat_id)
    other.source.platform = Platform.SLACK
    other.source.thread_id = 'other-thread'
    other_key = build_session_key(other.source)
    adapter._active_sessions[other_key] = asyncio.Event()
    first_tick, later_tick = asyncio.Event(), asyncio.Event()
    stopped = False
    stale_ticks = []
    async def typing(chat_id, metadata=None):
        if not metadata:
            if stopped:
                stale_ticks.append(adapter._status_text.get(str(chat_id), 'default working'))
            first_tick.set()
        elif stopped:
            later_tick.set()
    adapter.send_typing = typing
    adapter.set_status_text(event.source.chat_id, 'Searching the store')
    tasks = [adapter._start_typing_refresh(e, adapter._active_sessions[k],
                                          {'thread_id': e.source.thread_id} if e.source.thread_id else None)
             for e, k in ((event, key), (other, other_key))]
    try:
        await asyncio.wait_for(first_tick.wait(), 5)
        await runner._handle_active_session_busy_message(event, key)
        stopped = True
        await asyncio.wait_for(later_tick.wait(), 5)
        assert not stale_ticks
        assert str(event.source.chat_id) not in adapter._status_text
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def check_stop_drain_and_successor(monkeypatch, lifecycle):
    runner, event, adapter, key, agent, ctx = active_turn(monkeypatch, 'Please stop.')
    ack_entered, cleanup_entered = asyncio.Event(), asyncio.Event()
    ack_release, cleanup_release = asyncio.Event(), asyncio.Event()
    async def receipt(*args, **kwargs):
        ack_entered.set()
        await ack_release.wait()
    async def cleanup(*args, **kwargs):
        cleanup_entered.set()
        await cleanup_release.wait()
        return []
    adapter._send_with_retry.side_effect = receipt
    monkeypatch.setattr('gateway.plugin_control.notify_gateway_control', cleanup)
    stop = asyncio.create_task(runner._handle_active_session_busy_message(event, key))
    await asyncio.wait_for(ack_entered.wait(), 5)
    if lifecycle != 'slow_ack':
        ack_release.set()
        await asyncio.wait_for(cleanup_entered.wait(), 5)
    else:
        cleanup_release.set()
    result = {'interrupted': True, 'messages': [], 'final_response': 'interrupted'}
    drain_entered = asyncio.Event()
    async def drain():
        drain_entered.set()
        if lifecycle == 'exception_cleanup':
            tracking = asyncio.create_task(asyncio.Event().wait())
            return await runner._run_agent_cleanup_turn_tasks(
                ctx, progress_task=None, log_task=None, interrupt_monitor=None,
                _notify_task=None, tracking_task=tracking, stream_task=None,
            )
        return await runner._run_agent_drain_pending(result, adapter, event.source, key)
    drain_task = asyncio.create_task(drain())
    repeat = None
    try:
        await asyncio.wait_for(drain_entered.wait(), 5)
        assert not drain_task.done(), 'report drained before stop receipt/source cleanup finished'
        assert runner._session_state(key).turn.agent is agent
        if lifecycle == 'handler_cancelled':
            stop.cancel()
            await asyncio.gather(stop, return_exceptions=True)
            assert not drain_task.done()
        if lifecycle == 'repeat_stop':
            second = _make_event(text='Stop now.')
            second.source = event.source
            repeat = asyncio.create_task(runner._handle_active_session_busy_message(second, key))
    finally:
        ack_release.set()
        cleanup_release.set()
        await asyncio.wait_for(asyncio.gather(stop, return_exceptions=True), 5)
    if repeat:
        await asyncio.wait_for(repeat, 5)
        agent.interrupt.assert_called_once()
    drained = await asyncio.wait_for(drain_task, 5)
    if lifecycle == 'exception_cleanup':
        assert runner._session_state(key).turn.agent is None
        return
    pending_event, pending = drained
    assert pending_event is event
    if lifecycle != 'recursive':
        return
    # Exercise the actual recursive gateway handoff, with only the model/delivery
    # boundaries replaced. No manual TurnState.clear() between these turns.
    successor = _make_event(text='Start a different task')
    successor.source = event.source
    successor.message_id = 'successor'
    adapter._pending_messages[key] = successor
    runner._prepare_profile_scoped_inbound_message_text = AsyncMock(side_effect=lambda **kw: kw['event'].text)
    runner._refresh_agent_cache_message_count = AsyncMock()
    runner._intake_adapter_for = lambda source: None
    runner._session_key_for_source = lambda source: key
    runner._run_agent_deliver_first_response = AsyncMock()
    adapter.send_typing = AsyncMock()
    observed = []
    async def run(**kwargs):
        report = kwargs['request_message'] == event.text
        child = TurnContext(source=event.source, session_key=key, agent_holder=[agent],
                            _run_still_current=lambda: True)
        await runner._run_agent_track_agent(child)
        future = asyncio.get_running_loop().create_future()
        observed.append(runner._should_emit_long_running_notification(key, agent, future))
        future.cancel()
        answer = {'messages': [], 'final_response': 'stopped' if report else 'new work complete'}
        if report:
            next_event, next_text = await runner._run_agent_drain_pending(answer, adapter, event.source, key)
            return await runner._run_agent_queued_followup(child, adapter, next_text, next_event, answer, answer, None)
        return answer
    runner._run_agent = run
    await runner._run_agent_queued_followup(ctx, adapter, pending, pending_event, result, result, None)
    assert observed == [False, True]
    adapter.send_typing.assert_awaited_once()
