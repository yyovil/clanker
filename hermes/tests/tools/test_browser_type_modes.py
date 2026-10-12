"""Native replacement typing preserves dispatch, lease, and privacy boundaries."""

import json

import pytest

from tools import browser_tool as browser
from tools import browser_tool_session as session
from tools.bot_desktop import lease, runtime
from tools.registry import registry


@pytest.fixture(autouse=True)
def native_dispatch(monkeypatch):
    lease._reset_for_tests()
    monkeypatch.setattr(browser, "_is_camofox_mode", lambda: False)
    monkeypatch.setattr(browser, "_last_session_key", lambda task_id: task_id)
    monkeypatch.setattr(browser, "_blocked_private_page_action", lambda *_args: None)
    monkeypatch.setattr(browser, "routed_browser_handler", lambda _name, _args, *, fallback, **_kwargs: fallback())
    yield
    lease._reset_for_tests()


def dispatch(**args):
    return json.loads(registry.dispatch("browser_type", args, task_id="typing-fixture"))


def test_typing_schema_exposes_optional_replacement_modes():
    params = registry.get_schema("browser_type")["parameters"]
    assert params["properties"]["mode"]["enum"] == ["fill", "type"]
    assert params["properties"]["mode"]["default"] == "fill"
    assert "mode" not in params["required"]


@pytest.mark.parametrize("mode", [None, "fill"])
def test_default_and_explicit_fill_use_one_existing_native_action(monkeypatch, mode):
    calls = []
    monkeypatch.setattr(session, "_run_browser_command", lambda *args: calls.append(args) or {"success": True})
    args = {"ref": "e3", "text": "fixture text"}
    if mode is not None:
        args["mode"] = mode
    result = dispatch(**args)
    assert result["success"] is True
    assert calls == [("typing-fixture", "fill", ["@e3", "fixture text"])]


def test_character_mode_clears_before_typing_unchanged_text(monkeypatch):
    calls, private_flags = [], []
    def native(*args, **kwargs):
        calls.append(args)
        private_flags.append(kwargs.get('_private_output', False))
        return {"success": True, "data": {"value": ""}} if args[1] == "get" else {"success": True}
    monkeypatch.setattr(session, "_run_browser_command", native)
    text = "fixture + punctuation\nsecond line"
    result = dispatch(ref="@e3", text=text, mode="type")
    assert result["success"] is True
    assert calls == [("typing-fixture", "fill", ["@e3", ""]),
                     ("typing-fixture", "get", ["value", "@e3"]),
                     ("typing-fixture", "type", ["@e3", text])]
    assert private_flags == [False, True, False]


def test_long_character_input_refuses_before_clear_while_atomic_fill_remains_available(monkeypatch):
    calls = []
    def native(*args, **kwargs):
        calls.append(args)
        return {'success': True, 'data': {'value': ''}}
    monkeypatch.setattr(session, '_run_browser_command', native)
    text = 'document paragraph\n' * 100
    result = dispatch(ref='e3', text=text, mode='type')
    assert result['success'] is False and result['code'] == 'character_typing_too_long'
    assert 'not cleared' in result['error'] and "mode='fill'" in result['error']
    assert calls == []
    assert dispatch(ref='e3', text=text, mode='fill')['success'] is True
    assert calls == [('typing-fixture', 'fill', ['@e3', text])]


@pytest.mark.parametrize("mode", ["append", "", None, [], {}, 0])
def test_invalid_mode_refuses_before_browser_transport(monkeypatch, mode):
    def unexpected(*_args):
        raise AssertionError("invalid mode must not reach the browser")

    monkeypatch.setattr(session, "_run_browser_command", unexpected)
    result = dispatch(ref="@e3", text="fixture text", mode=mode)
    assert result["success"] is False
    assert result["error"] == "Invalid typing mode. Use 'fill' or 'type'."


def test_failed_clear_does_not_type_and_preserves_typed_denial(monkeypatch):
    calls = []

    def clear_denied(*args):
        calls.append(args)
        return {"success": False, "code": "human_has_control", "error": "Human has control."}

    monkeypatch.setattr(session, "_run_browser_command", clear_denied)
    result = dispatch(ref="@e3", text="fixture text", mode="type")
    assert result["success"] is False
    assert result["code"] == "human_has_control"
    assert calls == [("typing-fixture", "fill", ["@e3", ""])]


def test_private_page_guard_repeats_after_clear_before_typing(monkeypatch):
    checks, calls = [], []

    def guard(*args):
        checks.append(args)
        if len(checks) == 2:
            return json.dumps({"success": False, "error": "Page changed to a private address."})

    monkeypatch.setattr(browser, "_blocked_private_page_action", guard)
    monkeypatch.setattr(session, "_run_browser_command", lambda *args: calls.append(args) or {"success": True})
    result = dispatch(ref="@e3", text="fixture text", mode="type")
    assert result["success"] is False
    assert len(checks) == 2
    assert calls == [("typing-fixture", "fill", ["@e3", ""])]


def test_type_failure_redacts_native_error_and_fallback_echo(monkeypatch):
    secret = "sk-proj-ABCD1234567890EFGH"
    results = iter([{"success": True}, {"success": True, "data": {"value": ""}}, {"success": False, "error": "Refused " + secret,
                                       "fallback_warning": "Echo " + secret}])
    monkeypatch.setattr(session, "_run_browser_command", lambda *_args, **_kwargs: next(results))
    result = dispatch(ref="@e3", text=secret, mode="type")
    assert result["success"] is False
    assert secret not in json.dumps(result)


def wire_fenced_transport(monkeypatch, spawn):
    monkeypatch.delenv("AGENT_BROWSER_PROFILE", raising=False)
    monkeypatch.setattr(runtime, "published_env", lambda: {"DISPLAY": ":37"})
    monkeypatch.setattr(session, "_browser_command_preflight", lambda: {"browser_cmd": "agent-browser"})
    monkeypatch.setattr(session, "_get_session_info", lambda *_args: {
        "session_name": "typing-fixture", "cdp_url": None, "features": {"local": True}})
    monkeypatch.setattr(session._cloud, "_get_browser_engine", lambda: "chrome")
    monkeypatch.setattr(session._cloud, "_is_headed_mode", lambda: True)
    monkeypatch.setattr(session, "_bot_desktop_attach_port", lambda *_args: None)
    monkeypatch.setattr(session, "_spawn_and_collect", spawn)


def test_human_control_before_clear_blocks_both_native_commands(monkeypatch):
    calls = []
    wire_fenced_transport(monkeypatch, lambda *args: calls.append(args[3]) or {"success": True})
    lease.acquire("human-fixture")
    result = dispatch(ref="@e3", text="fixture text", mode="type")
    assert result.get("code") == "human_has_control"
    assert calls == []


def test_takeover_during_clear_discards_result_and_never_types(monkeypatch):
    calls = []

    def clear_then_takeover(*args):
        calls.append(args[3])
        lease.acquire("human-fixture")
        lease.release("human-fixture")
        return {"success": True}

    wire_fenced_transport(monkeypatch, clear_then_takeover)
    result = dispatch(ref="@e3", text="fixture text", mode="type")
    assert result.get("code") == "human_has_control"
    assert calls == ["fill"]


def test_lease_is_readmitted_between_clear_and_character_typing(monkeypatch):
    calls = []
    wire_fenced_transport(monkeypatch, lambda *args, **kwargs: calls.append(args[3]) or {"success": True})
    run_command = session._run_browser_command

    def take_control_after_clear(*args, **kwargs):
        result = run_command(*args, **kwargs)
        if args[1] == "fill":
            lease.acquire("human-fixture")
        return result

    monkeypatch.setattr(session, "_run_browser_command", take_control_after_clear)
    result = dispatch(ref="@e3", text="fixture text", mode="type")
    assert result.get("code") == "human_has_control"
    assert calls == ["fill"]


def test_session_is_resolved_again_before_character_typing(monkeypatch):
    calls = []
    wire_fenced_transport(monkeypatch, lambda *args, **kwargs: calls.append(args[3]) or {"success": True})
    checks = []

    def resolve_session(task_id):
        checks.append(task_id)
        if len(checks) > 1:
            raise RuntimeError("The browser no longer belongs to this task.")
        return {"session_name": "typing-fixture", "cdp_url": None, "features": {"local": True}}

    monkeypatch.setattr(session, "_get_session_info", resolve_session)
    result = dispatch(ref="@e3", text="fixture text", mode="type")
    assert result["success"] is False
    assert checks == ["typing-fixture", "typing-fixture"]
    assert calls == ["fill"]


@pytest.mark.parametrize('reply,code', [
    ({'success': True, 'data': {'value': 'unapproved existing value'}}, 'field_not_empty'),
    ({'success': True, 'data': {'value': None}}, 'clear_unconfirmed'),
    ({'success': True, 'data': {'value': False}}, 'clear_unconfirmed'),
    ({'success': True, 'data': {}}, 'clear_unconfirmed'),
    ({'success': True, 'data': []}, 'clear_unconfirmed'),
    ({'success': False, 'error': 'unapproved existing value'}, 'clear_unconfirmed'),
    ({'success': False, 'code': 'human_has_control', 'error': 'unapproved existing value'}, 'human_has_control'),
])
def test_unconfirmed_clear_never_types_or_exposes_readback(monkeypatch, reply, code):
    calls = []
    def native(*args, **kwargs):
        calls.append(args[1])
        return reply if args[1] == 'get' else {'success': True}
    monkeypatch.setattr(session, '_run_browser_command', native)
    result = dispatch(ref='@e3', text='fixture text', mode='type')
    assert result['success'] is False and result['code'] == code
    assert 'unapproved existing value' not in json.dumps(result)
    assert calls == ['fill', 'get']


def test_private_page_guard_repeats_after_empty_readback(monkeypatch):
    checks, calls = [], []
    def guard(*args):
        checks.append(args)
        if len(checks) == 3:
            return json.dumps({'success': False, 'error': 'Page changed before typing.'})
    def native(*args, **kwargs):
        calls.append(args[1])
        return {'success': True, 'data': {'value': ''}}
    monkeypatch.setattr(browser, '_blocked_private_page_action', guard)
    monkeypatch.setattr(session, '_run_browser_command', native)
    result = dispatch(ref='@e3', text='fixture text', mode='type')
    assert result['success'] is False
    assert len(checks) == 3 and calls == ['fill', 'get']


def test_human_taking_control_after_empty_readback_prevents_typing(monkeypatch):
    calls = []
    def spawn(*args, **kwargs):
        calls.append(args[3])
        return {'success': True, 'data': {'value': ''}}
    wire_fenced_transport(monkeypatch, spawn)
    run = session._run_browser_command
    def native(*args, **kwargs):
        result = run(*args, **kwargs)
        if args[1] == 'get':lease.acquire('human-fixture')
        return result
    monkeypatch.setattr(session, '_run_browser_command', native)
    result = dispatch(ref='@e3', text='fixture text', mode='type')
    assert result.get('code') == 'human_has_control'
    assert calls == ['fill', 'get']


def test_session_is_resolved_before_clear_readback_and_typing(monkeypatch):
    calls, checks = [], []
    def spawn(*args, **kwargs):
        calls.append(args[3])
        return {'success': True, 'data': {'value': ''}}
    wire_fenced_transport(monkeypatch, spawn)
    def resolve(task_id):
        checks.append(task_id)
        if len(checks) == 3:raise RuntimeError('Owner changed before typing.')
        return {'session_name': 'typing-fixture', 'cdp_url': None, 'features': {'local': True}}
    monkeypatch.setattr(session, '_get_session_info', resolve)
    result = dispatch(ref='@e3', text='fixture text', mode='type')
    assert result['success'] is False
    assert checks == ['typing-fixture'] * 3 and calls == ['fill', 'get']


def test_character_mode_is_not_silently_ignored_by_camofox(monkeypatch):
    monkeypatch.setattr(browser, "_is_camofox_mode", lambda: True)
    monkeypatch.setattr(browser, "_camofox", lambda *_args: pytest.fail("unsupported mode must not fill"))
    result = dispatch(ref="@e3", text="fixture text", mode="type")
    assert result["success"] is False
    assert "unavailable" in result["error"]
