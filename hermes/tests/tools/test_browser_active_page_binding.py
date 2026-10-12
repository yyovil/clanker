"""Native active-page/CDP handoff: two same-origin tabs must never be interchangeable."""
import asyncio
import json
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from tools import browser_supervisor, browser_tool, browser_tool_session, browser_vault_tool as vault


@pytest.fixture
def pages(monkeypatch):
    node = shutil.which('node')
    if not node:
        pytest.skip('Node.js is required to execute the actual page-binding guards')
    state = SimpleNamespace(
        active='checkout', windows={
            'account': {'location': {'origin': 'https://shop.example'}, 'label': 'account'},
            'checkout': {'location': {'origin': 'https://shop.example'}, 'label': 'checkout'},
        }, argv=[], cdp_expressions=[], detached=[], fault=None,
    )
    runner = """const fs=require('fs'),vm=require('vm');
const data=JSON.parse(fs.readFileSync(0,'utf8'));
const context={window:data.window};
const result=vm.runInNewContext(data.expression,context);
process.stdout.write(JSON.stringify({result:result===undefined?null:result,
 window:{...context.window,__hermesNativePageBinding:context.window.__hermesNativePageBinding}}));"""

    def evaluate(target, expression):
        proc = subprocess.run([node, '-e', runner], input=json.dumps({
            'window': state.windows[target], 'expression': expression,
        }), text=True, capture_output=True, check=True, timeout=10)
        data = json.loads(proc.stdout)
        state.windows[target] = data['window']
        return data['result']

    supervisor = browser_supervisor.CDPSupervisor('owner-task', 'ws://fixture.invalid')
    supervisor._loop = SimpleNamespace(is_running=lambda: True)
    supervisor._active = True
    supervisor._page_session_id = 'account'
    monkeypatch.setattr(browser_supervisor, '_schedule', lambda coro, loop, timeout=10: asyncio.run(coro))

    async def no_op(*args, **kwargs):
        return None

    async def cdp(method, params=None, *, session_id=None, **kwargs):
        if method == 'Target.getTargets':
            if state.fault == 'duplicate':
                state.windows['account']['__hermesNativePageBinding'] = state.windows['checkout'].get('__hermesNativePageBinding')
            if state.fault == 'lost_marker':
                state.windows['checkout'].pop('__hermesNativePageBinding', None)
            return {'result': {'targetInfos': [
                {'type': 'page', 'targetId': target, 'url': window['location']['origin'] + '/' + target}
                for target, window in state.windows.items()
            ]}}
        if method == 'Target.attachToTarget':
            return {'result': {'sessionId': params['targetId']}}
        if method == 'Target.detachFromTarget':
            state.detached.append(params['sessionId'])
            return {'result': {}}
        assert method == 'Runtime.evaluate'
        state.cdp_expressions.append(params['expression'])
        if state.fault == 'cdp_failure':
            raise RuntimeError('fixture evaluation unavailable')
        if state.fault == 'replace_at_write' and 'SYNTHETIC-SECRET' in params['expression']:
            state.windows[session_id].pop('__hermesNativePageBinding', None)
        result = evaluate(session_id, params['expression'])
        return {'result': {'result': {'type': 'boolean' if isinstance(result, bool) else 'string', 'value': result}}}

    supervisor._cdp = cdp
    supervisor._enable_page_domains = no_op
    supervisor._install_dialog_bridge = no_op
    monkeypatch.setattr(browser_supervisor.SUPERVISOR_REGISTRY, 'get', lambda task: supervisor)
    monkeypatch.setattr(browser_tool, '_last_session_key', lambda task: task)
    monkeypatch.setattr(vault, '_bot_desktop_browser_session', lambda task: False)

    def native(task, command, args):
        assert task == 'owner-task' and command == 'eval'
        state.argv.append(args[0])
        if state.fault == 'native_failure':
            return {'success': False, 'error': 'untrusted private-looking fixture output'}
        return {'success': True, 'data': {'result': evaluate(state.active, args[0])}}

    monkeypatch.setattr(browser_tool_session, '_run_browser_command', native)
    state.supervisor = supervisor
    return state


SECRET_WRITE = "(() => {window.privateWrite='SYNTHETIC-SECRET';return JSON.stringify({filled:1});})()"


def test_native_active_second_same_origin_tab_is_the_only_inspection_and_write_target(pages):
    assert vault._bind_active_page('owner-task', expected_origin='https://shop.example') == {
        'success': True, 'origin': 'https://shop.example'}
    assert pages.supervisor._page_session_id == 'checkout'
    assert vault._eval_js('owner-task', 'window.label')['result'] == 'checkout'
    result = vault._eval_js_secret('owner-task', SECRET_WRITE)
    assert json.loads(result['result']) == {'filled': 1}
    assert pages.windows['checkout']['privateWrite'] == 'SYNTHETIC-SECRET'
    assert 'privateWrite' not in pages.windows['account']
    assert all('SYNTHETIC-SECRET' not in expression for expression in pages.argv)


@pytest.mark.parametrize('fault', ['native_failure', 'duplicate', 'lost_marker'])
def test_failed_handoff_cannot_reuse_previous_binding_or_write_to_any_page(pages, fault):
    assert vault._bind_active_page('owner-task')['success']
    pages.fault = fault
    assert vault._bind_active_page('owner-task').get('success') is False
    assert pages.supervisor._vault_page_binding is None
    assert vault._eval_js_secret('owner-task', SECRET_WRITE)['error_type'] == 'active_page_unbound'
    assert all('privateWrite' not in window for window in pages.windows.values())
    assert all('SYNTHETIC-SECRET' not in expression for expression in pages.argv)
    if fault == 'duplicate':
        assert pages.detached[-2:] == ['account', 'checkout']


def test_wrong_origin_handoff_never_writes_or_selects_a_different_allowed_tab(pages):
    pages.windows['checkout']['location']['origin'] = 'https://other.example'
    assert vault._bind_active_page('owner-task', 'https://shop.example') == {
        'success': False, 'error_type': 'active_page_mismatch'}
    assert pages.supervisor._vault_page_binding is None
    assert vault._eval_js_secret('owner-task', SECRET_WRITE)['error_type'] == 'active_page_unbound'
    assert pages.cdp_expressions == []


def test_native_tab_switch_during_otp_wait_refuses_even_when_old_document_survives(pages):
    assert vault._bind_active_page('owner-task')['success']
    pages.active = 'account'
    result = vault._eval_js_secret('owner-task', SECRET_WRITE)
    assert result['error_type'] == 'active_page_changed'
    assert all('privateWrite' not in window for window in pages.windows.values())
    assert all('SYNTHETIC-SECRET' not in expression for expression in pages.argv)
    assert not any('SYNTHETIC-SECRET' in expression for expression in pages.cdp_expressions)


def test_document_replacement_after_active_recheck_is_caught_in_secret_socket(pages):
    assert vault._bind_active_page('owner-task')['success']
    pages.fault = 'replace_at_write'
    result = vault._eval_js_secret('owner-task', SECRET_WRITE)
    assert json.loads(result['result']) == {'refused': 'active_page_changed', 'filled': 0}
    assert all('privateWrite' not in window for window in pages.windows.values())
    assert all('SYNTHETIC-SECRET' not in expression for expression in pages.argv)


def test_bound_inspection_failure_cannot_fall_back_to_another_native_page(pages):
    assert vault._bind_active_page('owner-task')['success']
    pages.fault = 'cdp_failure'
    before = len(pages.argv)
    assert vault._eval_js('owner-task', 'window.label')['success'] is False
    assert len(pages.argv) == before + 1  # Only the nonsecret binding check, never the expression.
    assert 'window.label' not in pages.argv[-1]


def test_unbound_secret_evaluation_never_reaches_cli_or_cdp(pages):
    assert vault._eval_js_secret('owner-task', SECRET_WRITE)['error_type'] == 'active_page_unbound'
    assert pages.argv == pages.cdp_expressions == []


@pytest.mark.parametrize('operation', ['password', 'otp', 'save_login'])
def test_vault_handlers_stop_before_inspection_secret_resolution_or_prompt_on_failed_handoff(pages, monkeypatch, operation):
    pages.fault = 'native_failure'

    def forbidden(*args, **kwargs):
        pytest.fail('A failed native page handoff must stop before fallback, inspection, or secret access')

    backend = SimpleNamespace(needs_unlock=False, get_meta=lambda handle: SimpleNamespace(
        kind='login', origin='https://shop.example', allowed_origins=('https://shop.example',)),
        resolve_password=forbidden, resolve_otp=forbidden)
    monkeypatch.setattr('agent.vault_backends.backend_for_handle', lambda handle: backend)
    monkeypatch.setattr(vault, '_eval_js', forbidden)
    monkeypatch.setattr(vault, '_eval_js_secret', forbidden)
    monkeypatch.setattr(vault, '_current_page_origin', forbidden)
    monkeypatch.setattr('agent.vault_backends.unlock.get_code_prompt_callback', forbidden)
    monkeypatch.setattr('agent.vault_backends.unlock.get_save_login_prompt_callback', forbidden)
    if operation == 'password':
        result = vault.browser_vault_fill('fixture', task_id='owner-task')
    elif operation == 'otp':
        result = vault.browser_vault_enter_code('fixture', task_id='owner-task')
    else:
        result = vault.browser_vault_save_login(task_id='owner-task')
    assert json.loads(result)['success'] is False
    assert pages.cdp_expressions == []


def test_origin_and_public_eval_follow_native_active_tab_even_when_supervisor_is_stale(pages, monkeypatch):
    pages.windows['checkout']['location']['origin'] = 'https://checkout.example'
    assert vault._current_page_origin('owner-task') == 'https://checkout.example'
    monkeypatch.setattr(browser_tool, '_is_camofox_mode', lambda: False)
    monkeypatch.setattr(browser_tool._eval_policy, '_eval_ssrf_guard_active', lambda task: False)
    monkeypatch.setattr(browser_tool, '_blocked_private_page_content', lambda task: None)
    result = json.loads(browser_tool._browser_eval('window.label', task_id='owner-task'))
    assert result['success'] is True and result['result'] == 'checkout'
    assert pages.supervisor._page_session_id == 'account'
    assert pages.cdp_expressions == []
