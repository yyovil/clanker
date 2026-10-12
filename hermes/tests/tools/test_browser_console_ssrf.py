"""Tests that browser_console blocks console messages and errors from eval-navigated private pages.

browser_snapshot, browser_vision, _browser_eval, and browser_get_images all re-check
the page URL before returning content. browser_console (in console output mode) must
do the same to prevent leakage of console log messages and exception details.
"""

import json
import subprocess

import pytest

from tools import browser_tool
from tools import browser_tool_eval_policy as bt_eval_policy
from tools import browser_tool_session as bt_session

PRIVATE_URL = "http://127.0.0.1:8080/internal"


@pytest.fixture(autouse=True)
def _patches(monkeypatch):
    monkeypatch.setattr(browser_tool, "_is_camofox_mode", lambda: False)
    monkeypatch.setattr(browser_tool, "_last_session_key", lambda key: key)


def _mock_run_success(monkeypatch):
    def _run(task_id, command, args=None, **kwargs):
        if command == "console":
            return {
                "success": True,
                "data": {
                    "messages": [
                        {"type": "log", "text": "secret internal message"}
                    ]
                }
            }
        elif command == "errors":
            return {
                "success": True,
                "data": {
                    "errors": [
                        {"message": "internal exception info"}
                    ]
                }
            }
        return {"success": True, "data": {}}
    monkeypatch.setattr(bt_session, "_run_browser_command", _run)


def test_blocks_console_on_private_page(monkeypatch):
    _mock_run_success(monkeypatch)
    monkeypatch.setattr(bt_eval_policy, "_eval_ssrf_guard_active", lambda tid: True)
    monkeypatch.setattr(bt_eval_policy, "_current_page_private_url", lambda tid: PRIVATE_URL)

    result = json.loads(browser_tool.browser_console(task_id="test"))
    assert result["success"] is False
    assert "private or internal address" in result["error"]
    assert PRIVATE_URL in result["error"]


def test_allows_console_on_public_page(monkeypatch):
    _mock_run_success(monkeypatch)
    monkeypatch.setattr(bt_eval_policy, "_eval_ssrf_guard_active", lambda tid: True)
    monkeypatch.setattr(bt_eval_policy, "_current_page_private_url", lambda tid: None)

    result = json.loads(browser_tool.browser_console(task_id="test"))
    assert result["success"] is True
    assert result["total_messages"] == 1
    assert result["console_messages"][0]["text"] == "secret internal message"


def test_skips_guard_for_local_backend(monkeypatch):
    _mock_run_success(monkeypatch)
    monkeypatch.setattr(bt_eval_policy, "_eval_ssrf_guard_active", lambda tid: False)

    result = json.loads(browser_tool.browser_console(task_id="test"))
    assert result["success"] is True
    assert result["total_messages"] == 1


def test_skips_guard_when_private_urls_allowed(monkeypatch):
    _mock_run_success(monkeypatch)
    monkeypatch.setattr(bt_eval_policy, "_eval_ssrf_guard_active", lambda tid: False)

    result = json.loads(browser_tool.browser_console(task_id="test"))
    assert result["success"] is True
    assert result["total_messages"] == 1


def test_guard_does_not_block_on_failed_console_command(monkeypatch):
    """If the console command itself fails, browser_console returns the error naturally."""
    def _run(task_id, command, args=None, **kwargs):
        return {"success": False, "error": "console fetch failed"}
    monkeypatch.setattr(bt_session, "_run_browser_command", _run)
    monkeypatch.setattr(bt_eval_policy, "_eval_ssrf_guard_active", lambda tid: True)
    monkeypatch.setattr(bt_eval_policy, "_current_page_private_url", lambda tid: PRIVATE_URL)

    result = json.loads(browser_tool.browser_console(task_id="test"))
    # When the page is private, the guard checks _current_page_private_url first.
    # Because it checks _current_page_private_url BEFORE running the command, it should block it.
    assert result["success"] is False
    assert "private or internal address" in result["error"]


@pytest.mark.parametrize('configured_budget', [12, 37])
def test_slow_url_probe_uses_normal_deadline_and_keeps_cloud_binding(monkeypatch, tmp_path, configured_budget):
    """A URL guard that needs nine seconds must not discard the client's
    generation at an unrelated five-second diagnostic deadline."""
    task_id = 'slow-public-probe'
    session = {'session_name': 'fixture-client', 'bb_session_id': 'fixture-cloud',
               'cdp_url': 'ws://fixture.invalid/browser', 'session_key': task_id,
               'owner_task_id': task_id}
    monkeypatch.setattr(browser_tool, '_active_sessions', {task_id: session})
    monkeypatch.setattr(browser_tool, '_last_active_session_key', {task_id: task_id})
    monkeypatch.setattr(browser_tool, '_safe_command_timeout', lambda: configured_budget)
    monkeypatch.setattr(bt_session, '_browser_command_preflight', lambda: {'browser_cmd': 'fixture-driver'})
    monkeypatch.setattr(bt_session, '_get_session_info', lambda task: browser_tool._active_sessions[task])
    monkeypatch.setattr(bt_session._cdp, '_ensure_cdp_supervisor', lambda task: None)
    monkeypatch.setattr(bt_session, '_prepare_session_socket_dir', lambda name: str(tmp_path))
    monkeypatch.setattr(bt_session, '_agent_browser_command_env', lambda directory: {})
    monkeypatch.setattr(bt_session, '_ensure_screen_for_headed_chromium', lambda: None)
    monkeypatch.setattr(bt_session, '_apply_chromium_sandbox_args', lambda env: None)
    budgets = []

    class SlowProcess:
        returncode = 0

        def wait(self, timeout=None):
            budgets.append(timeout)
            if timeout is not None and timeout < 9:
                raise subprocess.TimeoutExpired('fixture-driver', timeout)
            (tmp_path / '_stdout_eval').write_text(json.dumps({
                'success': True, 'data': {'result': PRIVATE_URL}}))
            (tmp_path / '_stderr_eval').write_text('')
            return 0

        def kill(self):
            pytest.fail('A URL probe within the normal command budget must not kill its client')

    def spawn(argv, env, socket_dir, command, stdin_payload):
        assert argv[-2:] == ['eval', 'window.location.href']
        assert command == 'eval'
        return SlowProcess()

    monkeypatch.setattr(bt_session, '_popen_agent_browser', spawn)
    assert bt_eval_policy._current_page_private_url(task_id) == PRIVATE_URL
    assert budgets == [configured_budget]
    assert browser_tool._active_sessions[task_id] is session
    assert browser_tool._last_active_session_key[task_id] == task_id
