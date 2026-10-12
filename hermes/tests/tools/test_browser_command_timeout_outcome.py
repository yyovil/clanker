"""A dispatched timeout is uncertain, private, and must never be retried."""
import json
import logging
from pathlib import Path
import subprocess

import pytest

from tools import browser_tool as browser
from tools import browser_tool_session as session


@pytest.mark.parametrize('private', [False, True])
def test_cloud_timeout_discards_partial_output_and_never_falls_back(tmp_path, monkeypatch, caplog, private):
    task = 'uncertain-command'
    record = {'session_name': 'uncertain-client', 'cdp_url': 'wss://fixture.invalid/cdp',
              'bb_session_id': 'fixture-remote', 'features': {}}
    monkeypatch.setattr(browser, '_active_sessions', {task: record})
    monkeypatch.setattr(browser, '_last_active_session_key', {})
    monkeypatch.setattr(session, '_browser_command_preflight', lambda: {'browser_cmd': 'agent-browser'})
    monkeypatch.setattr(session, '_get_session_info', lambda _: browser._active_sessions[task])
    monkeypatch.setattr(session._cloud, '_get_browser_engine', lambda: 'lightpanda')
    monkeypatch.setattr(session._cdp, '_ensure_cdp_supervisor', lambda _: None)
    stopped = []
    monkeypatch.setattr(session._cdp, '_stop_cdp_supervisor', lambda value: stopped.append(value))
    monkeypatch.setattr(session, '_prepare_session_socket_dir', lambda _: str(tmp_path))
    monkeypatch.setattr(session, '_ensure_screen_for_headed_chromium', lambda: None)
    monkeypatch.setattr(session, '_agent_browser_command_env', lambda _: {})
    monkeypatch.setattr(session._lp, '_lightpanda_fallback_reason',
                        lambda *_: pytest.fail('A dispatched timeout must not replay through Chrome'))
    attempts = []
    partial = 'synthetic-private-partial-output-92814'

    class Process:
        def wait(self, timeout=None):
            if timeout is not None:
                raise subprocess.TimeoutExpired('agent-browser', timeout)
        def kill(self): pass

    def spawn(_argv, _env, directory, tag, _stdin=None):
        attempts.append(tag)  # Models the first external side effect before timeout.
        Path(directory, '_stdout_' + tag).write_text(partial)
        Path(directory, '_stderr_' + tag).write_text(partial)
        return Process()

    monkeypatch.setattr(session, '_popen_agent_browser', spawn)
    with caplog.at_level(logging.DEBUG):
        result = session._run_browser_command(task, 'type', ['@e1', 'hello'], timeout=3,
                                              _private_output=private)
    assert result['success'] is False
    assert result['code'] == 'browser_command_outcome_unknown'
    assert browser._active_sessions[task]['_command_timed_out'] is True
    assert browser._active_sessions[task]['bb_session_id'] == 'fixture-remote'
    assert attempts == ['type'] and stopped == [task]
    assert partial not in json.dumps(result) + caplog.text
    assert not list(tmp_path.glob('_std*'))


@pytest.mark.parametrize('requested', [None, 3, 120])
def test_character_dispatch_budget_preempts_upstream_socket_retry(monkeypatch, requested):
    budgets = []
    monkeypatch.setattr(browser, '_safe_command_timeout', lambda: 60)
    monkeypatch.setattr(session, '_browser_command_preflight', lambda: {'browser_cmd': 'agent-browser'})
    monkeypatch.setattr(session, '_get_session_info', lambda _: {'features': {}})
    def dispatch(_task, _record, _binary, command, args, budget, _engine, **kwargs):
        budgets.append((command, budget))
        return 'chrome', {'success': True}
    monkeypatch.setattr(session, '_dispatch_browser_command', dispatch)
    assert session._run_browser_command('fixture', 'type', ['@e1', 'short'], timeout=requested)['success']
    assert 0 < budgets[0][1] < 30  # The upstream client resends at its 30-second socket timeout.
    if requested == 3:
        assert budgets[0][1] == requested
    assert session._run_browser_command('fixture', 'fill', ['@e1', 'long' * 1000], timeout=requested)['success']
    assert budgets[1][1] == (60 if requested is None else requested)
