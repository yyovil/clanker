"""Internal clear readback stays private even when native output is unusable."""
import json
import logging
from pathlib import Path
import subprocess

import pytest

from tools import browser_tool as browser
from tools import browser_tool_session as session


READBACK = 'synthetic-preexisting-field-value-7391'


@pytest.fixture
def transport(tmp_path, monkeypatch):
    socket = tmp_path / 'native-socket'
    socket.mkdir()
    monkeypatch.setattr(browser, '_is_camofox_mode', lambda: False)
    monkeypatch.setattr(session, '_browser_command_preflight', lambda: {'browser_cmd': 'agent-browser'})
    monkeypatch.setattr(session, '_get_session_info', lambda *_args: {
        'session_name': 'private-fixture', 'cdp_url': None, 'features': {'local': False}})
    monkeypatch.setattr(session._cloud, '_get_browser_engine', lambda: 'chrome')
    monkeypatch.setattr(session._cloud, '_is_headed_mode', lambda: False)
    monkeypatch.setattr(session, '_prepare_session_socket_dir', lambda *_args: str(socket))
    monkeypatch.setattr(session, '_ensure_screen_for_headed_chromium', lambda: None)
    monkeypatch.setattr(session, '_agent_browser_command_env', lambda *_args: {})
    monkeypatch.setattr(session, '_apply_chromium_sandbox_args', lambda *_args: None)
    timeouts = []
    monkeypatch.setattr(session, '_handle_browser_command_timeout', lambda *_args: timeouts.append(True))

    def wire(stdout, stderr='', returncode=0, *, timeout=False):
        class Process:
            def __init__(self):self.returncode = returncode
            def wait(self, timeout=None):
                if timeout is not None and timed_out:
                    raise subprocess.TimeoutExpired('agent-browser', timeout, output=READBACK, stderr=READBACK)
                return self.returncode
            def kill(self):pass

        timed_out = timeout
        def spawn(_argv, _env, directory, tag, _stdin=None):
            Path(directory, '_stdout_' + tag).write_text(stdout)
            Path(directory, '_stderr_' + tag).write_text(stderr)
            return Process()
        monkeypatch.setattr(session, '_popen_agent_browser', spawn)
    return wire, timeouts


def read_private():
    return session._run_browser_command('private-fixture', 'get', ['value', '@e1'], timeout=3, _private_output=True)


@pytest.mark.parametrize('stdout,stderr,rc', [
    (READBACK, READBACK, 0),
    ('', READBACK, 1),
    (json.dumps({'success': False, 'error': READBACK}), READBACK, 0),
    (json.dumps({'success': True, 'data': {'value': ''}, 'extra': READBACK}), READBACK, 1),
    (json.dumps([READBACK]), READBACK, 0),
])
def test_failed_private_native_output_never_reaches_logs_or_response(transport, caplog, stdout, stderr, rc):
    wire, _ = transport
    wire(stdout, stderr, rc)
    with caplog.at_level(logging.DEBUG):result = read_private()
    assert result['success'] is False
    assert READBACK not in caplog.text + json.dumps(result)
    assert result['error'] == session._PRIVATE_OUTPUT_ERROR


def test_private_timeout_discards_both_partial_streams(transport, caplog):
    wire, timeouts = transport
    wire(READBACK, READBACK, timeout=True)
    with caplog.at_level(logging.DEBUG):result = read_private()
    assert result['success'] is False and timeouts == [True]
    assert READBACK not in caplog.text + json.dumps(result)


@pytest.mark.parametrize('where', ['spawn', 'session', 'preflight', 'dispatch'])
def test_private_exception_body_is_not_logged_or_returned(transport, monkeypatch, caplog, where):
    wire, _ = transport
    wire('')
    def fail(*_args, **_kwargs):raise RuntimeError(READBACK)
    target = {'spawn': '_popen_agent_browser', 'session': '_get_session_info',
              'preflight': '_browser_command_preflight', 'dispatch': '_dispatch_browser_command'}[where]
    monkeypatch.setattr(session, target, fail)
    with caplog.at_level(logging.DEBUG):result = read_private()
    assert result['success'] is False
    assert READBACK not in caplog.text + json.dumps(result)


def test_private_empty_value_stays_internal_and_exact(transport, caplog):
    wire, _ = transport
    wire(json.dumps({'success': True, 'data': {'value': ''}}), READBACK)
    with caplog.at_level(logging.DEBUG):result = read_private()
    assert result == {'success': True, 'data': {'value': ''}}
    assert READBACK not in caplog.text


def test_private_failure_preserves_only_typed_human_denial(transport, caplog):
    wire, _ = transport
    wire(json.dumps({'success': False, 'code': 'human_has_control', 'error': READBACK}))
    with caplog.at_level(logging.DEBUG):result = read_private()
    assert result['code'] == 'human_has_control'
    assert READBACK not in caplog.text + json.dumps(result)


def test_private_read_does_not_fallback_to_another_browser(transport, monkeypatch):
    wire, _ = transport
    wire(json.dumps({'success': False, 'error': READBACK}))
    monkeypatch.setattr(session._lp, '_lightpanda_fallback_reason', lambda *_args: pytest.fail('private read must not fallback'))
    assert read_private()['success'] is False


def test_default_output_handling_is_unchanged(transport, caplog):
    wire, _ = transport
    wire(READBACK)
    with caplog.at_level(logging.DEBUG):
        result = session._run_browser_command('private-fixture', 'get', ['value', '@e1'], timeout=3)
    assert result['success'] is False
    assert READBACK in result['error'] and READBACK in caplog.text
