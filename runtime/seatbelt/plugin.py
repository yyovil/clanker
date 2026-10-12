"""Hermes plugin using the native terminal provider ABC and toolset resolver."""
import json
import logging
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from seatbelt.context import Context
from agent.terminal_env_provider import TerminalEnvironmentProvider
from hermes_constants import get_hermes_home
from tools.environments.local import LocalEnvironment

logger = logging.getLogger(__name__)

NATIVE_BROWSER_TOOLS = [
    'browser_navigate', 'browser_snapshot', 'browser_click', 'browser_type',
    'browser_scroll', 'browser_back', 'browser_press', 'browser_get_images',
    'browser_vision', 'browser_console',
]

DISABLED_BROWSER_TOOLS = frozenset({
    'browser_exec', 'clanker_browser_run', 'clanker_browser_status',
    'clanker_web_search', 'clanker_web_fetch',
})


def cloud_settings():
    context = Context(get_hermes_home())
    config = Path(context.settings['transport_home']) / '.clanker-cloud/config.json'
    try:
        settings = json.loads(config.read_text()) if config.exists() else {}
    except (OSError, ValueError):
        return {}
    return settings if isinstance(settings, dict) else {}


def kernel_enabled():
    settings = cloud_settings()
    return settings.get('enabled') is True and settings.get('provider') == 'kernel'


def browser_tools():
    if not kernel_enabled():
        return []
    from tools.vision_tools import check_vision_requirements
    selected = [name for name in NATIVE_BROWSER_TOOLS
                if name != 'browser_vision' or check_vision_requirements()]
    return [*selected, 'clanker_browser_stop']


def discovery_tools():
    # Legacy public discovery shared the removed Composio browser connection.
    return []


def recall_tools():
    from slack_recall import TOOLS
    return list(TOOLS)


class SeatbeltEnvironment(LocalEnvironment):
    _sudo_nopasswd_probe_supported = False

    def __init__(self, *, cwd, timeout):
        self.execution = Context(get_hermes_home())
        base = self.execution.home / "workspace"
        path = Path(cwd).resolve() if cwd else base
        if not any(path.is_relative_to(root) for root in (base, self.execution.home / "artifacts")):
            raise RuntimeError("Terminal cwd is outside this context")
        super().__init__(cwd=str(path), timeout=timeout,
                         env={"TERMINAL_TEMP_DIR": str(self.execution.terminal)})

    def get_temp_dir(self):
        return str(self.execution.terminal)

    def _run_bash(self, cmd_string, *, login=False, timeout=120, stdin_data=None):
        context = Context(self.execution.home)
        env = context.safe_env()
        env["TERMINAL_TEMP_DIR"] = str(context.terminal)
        proc = subprocess.Popen(context.command(["/bin/bash", "-c", cmd_string]),
                                env=env, cwd=self.cwd, text=True, encoding="utf-8", errors="replace",
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
                                start_new_session=True, close_fds=True)
        if stdin_data is not None:
            from tools.environments.base_output import _pipe_stdin
            _pipe_stdin(proc, stdin_data)
        return proc


class SeatbeltProvider(TerminalEnvironmentProvider):
    name = "clanker_seatbelt"
    display_name = "Clanker macOS Seatbelt"
    is_remote = False
    is_container = False

    def is_available(self):
        try:
            Context(get_hermes_home())
            return True
        except Exception:
            return False

    def create_environment(self, *, cwd, timeout, **kwargs):
        return SeatbeltEnvironment(cwd=cwd, timeout=timeout)


def gate(tool_name, args, next_call, **kwargs):
    kernel_call = False
    try:
        if tool_name in DISABLED_BROWSER_TOOLS:
            return json.dumps({'success': False, 'error':
                'This browser tool has been removed. Use the authenticated task\'s native Kernel browser tools.',
                'status': 403})
        context = Context(get_hermes_home())
        from vault.tools import TOOLS as vault_tools
        kernel_call = tool_name in NATIVE_BROWSER_TOOLS
        if kernel_call:
            if not kernel_enabled():
                raise RuntimeError('The Kernel browser connection is unavailable')
            if not context.settings.get('activated'):
                raise RuntimeError('Execution unavailable: operator acceptance is pending')
            from vault.service import binding
            turn = binding(kwargs.get('task_id'))
            if kwargs.get('task_id') != turn.task_id or turn.home.resolve() != context.home:
                raise RuntimeError('The browser call is not bound to this authenticated task')
            cloud = turn.service.cloud_browser
            if cloud is None or cloud.settings.get('provider') != 'kernel':
                raise RuntimeError('The Kernel browser connection is unavailable')
            from tools.browser_tool import _BROWSER_SCHEMA_MAP
            permitted = set(_BROWSER_SCHEMA_MAP[tool_name]['parameters'].get('properties', {}))
            if not isinstance(args, dict) or set(args) - permitted:
                raise RuntimeError('Browser credentials and session identifiers are backend-owned')
            timings, started = {}, time.monotonic()
            def timed(phase, call, *call_args):
                phase_started = time.monotonic()
                try:
                    return call(*call_args)
                finally:
                    timings[phase] = round((time.monotonic() - phase_started) * 1000)
            try:
                timed('prepare', cloud.prepare, turn)
                kernel = getattr(turn.service, 'kernel_vault', None)
                if kernel is not None:
                    timed('payments', turn.service.payments.protect_browser, turn, tool_name)
                    timed('privacy', kernel.protect_observation, turn, tool_name)
                from cloud_browser.kernel_replay import ReplayCapture
                result = timed('action', ReplayCapture(cloud).around, turn, tool_name, args, next_call)
                return timed('finish', cloud.finish, turn, result)
            finally:
                timings['total'] = round((time.monotonic() - started) * 1000)
                logger.info('Kernel browser timing %s', json.dumps({'tool': tool_name, 'ms': timings}, sort_keys=True))
        if tool_name in vault_tools or tool_name in recall_tools() or tool_name in browser_tools():
            if tool_name in vault_tools and kernel_enabled():
                from vault.service import binding
                turn = binding(kwargs.get('task_id'))
                if kwargs.get('task_id') != turn.task_id or turn.home.resolve() != context.home:
                    raise RuntimeError('The private call is not bound to this authenticated task')
                cloud = turn.service.cloud_browser
                if cloud is not None and cloud.settings.get('provider') == 'kernel':
                    from cloud_browser.kernel_replay import ReplayCapture
                    ReplayCapture(cloud).suspend(turn, tool=tool_name)
            return next_call(args)
        if tool_name != 'terminal':
            return json.dumps({"success": False, "error": "Tool is outside this context's browser policy"})
        allowed = {'command', 'timeout', 'background', 'workdir', 'pty', 'notify_on_complete', 'watch_patterns', 'heartbeat'}
        if not isinstance(args, dict) or set(args) - allowed:
            return json.dumps({'success': False, 'error': 'Unsupported execution arguments'})
        if not context.settings.get('activated'):
            return json.dumps({'success': False, 'error': 'Execution unavailable: operator acceptance is pending'})
        from agent.gateway_context import current_gateway_turn
        current = current_gateway_turn()
        if current is not None:
            from vault.service import binding
            turn = binding(current.task_id)
            turn.service.delegations.check_execution(turn)
        if tool_name == "terminal" and args.get("background"):
            return json.dumps({"success": False, "error": "Use foreground terminal calls in the current browser POC"})
        if tool_name == 'terminal' and args.get('pty'):
            return json.dumps({'success': False, 'error': 'PTY execution is unavailable in the current browser POC'})
        return next_call(args)
    except Exception as error:
        if kernel_call:
            from vault.store import AccessError
            return json.dumps({'success': False,
                'error': str(error) if isinstance(error, AccessError) else 'The Kernel browser call could not complete in this authorized task.',
                'status': getattr(error, 'status', 503)})
        return json.dumps({"success": False, "error": "Execution unavailable: " + str(error)})


def register(ctx):
    from toolsets import create_custom_toolset
    from vault.tools import register_tools, TOOLS as vault_tools
    ctx.register_terminal_environment_provider(SeatbeltProvider())
    from vault.service import on_gateway_control
    ctx.register_hook('on_gateway_control', on_gateway_control)
    register_tools(ctx)
    from slack_recall import register_tools as register_recall
    register_recall(ctx)
    kernel = kernel_enabled()
    if kernel:
        from cloud_browser.kernel import register_provider
        from seatbelt.native_browser import register_tools as register_native_browser
        register_provider(ctx)
        register_native_browser(ctx)
        from cloud_browser.tools import register_tools as register_cloud
        register_cloud(ctx)
    selected = browser_tools()
    discovery = discovery_tools()
    create_custom_toolset("clanker_browser", "Kernel browser, recall and private access", tools=[*selected, *discovery, *recall_tools(), "terminal", *vault_tools])
    from slack_recall import RECALL_POLICY
    ctx.register_system_prompt_section('clanker.recall', RECALL_POLICY)
    ctx.register_system_prompt_section('clanker.task_handoff',
        'For shared-channel private continuation, call clanker_vault_list, link private_thread_url and end; this reply is still public. '
        'Carry task context into DM; keep questions and private details there. Never mirror DM replies. '
        'Use clanker_task_update for meaningful progress and the verified final public outcome, without private values.')
    ctx.register_middleware("tool_execution", gate)
    from clanker_policy import EXECUTION_POLICY
    ctx.register_system_prompt_section('clanker.execution', EXECUTION_POLICY)
    ctx.register_system_prompt_section('clanker.browser_handoff',
        ('Use the native browser tools directly. Preserve the goal, constraints, selected option, URL and stopping point across website actions. '
         'Try distinct permitted alternatives, record observed outcomes and reconcile uncertain side effects before another attempt.')
        if kernel else 'The Kernel browser connection is unavailable. Report the blocker; no other browser backend is permitted.')
    payment_policy = (
        'Use the private card flow through native Kernel enrollment and fill. Select Pay by card / Add New Card. '
        'Call clanker_request_payment only after the owner instructs payment in this task; proceed to payment is sufficient. '
        'Supply the amount in paise from your observed checkout and the final button. Do not collect cart summaries or total selectors. '
        'Remember my card grants reuse on subsequent owner payment instructions; use ready directly without asking approval again. '
        'If no remembered card exists, show the private Pay ₹X card with card entry and an optional remember choice each time. '
        'Never collect card values or OTPs in chat, files, environment or ordinary browser tool arguments. '
        'Use clanker_payment_fill then clanker_payment_submit. Never click Pay through ordinary browser tools. '
        'End on waiting_for_owner, preserving the browser and cart. Bank verification can still require private input. '
        'Never retry uncertain fill or submission, including through a new purchase. '
        'Observe merchant success or definite failure with clanker_payment_status, then clanker_payment_complete. '
        'Kernel requires Visa passkey approval even for remembered cards; Mastercard needs no hosted spend approval. Maximum ₹500. No receipt wording belongs on the payment page. clanker_payment_receipt is only for preexisting legacy native purchases.')
    ctx.register_system_prompt_section('clanker.payments', payment_policy)
    ctx.register_system_prompt_section('clanker.api_keys',
        'Collect API keys privately in Kernel Vault: clanker_request_access kind api_key, exact HTTPS API origin and service label. '
        'Use opaque handles with clanker_api_request for JSON requests, job submission and polling; only the backend injects keys at that origin. '
        'Terminal may run task code and download returned public/signed artifacts, never receive keys or recover them from files, browser text or environment. '
        'Reconcile uncertain side effects before retrying. Write-only keys require new private collection; verify API acceptance after saving.')
    personal_policy = (
        'Before login/delivery blockers or personal questions, call clanker_vault_list and check this task context. '
        'Kernel Vault stores, privately collects and fills credentials. Prefer clanker_personal_fill for saved name/address/phone/email/dob/gender. '
        'Use clanker_personal_read only for required ordinary details when explicit owner consent is present; gender/passwords/tokens/codes stay opaque. '
        'Inspect the form, map declared fields to observed selectors if needed, and verify acceptance. No secrets in browser arguments. '
        'Ask only for missing required details or account ambiguity. New details go through the private Kernel form, never Slack or local files. '
        'A failed or unknown fill is unfinished: keep the browser open and inspect it. Never automatically replay a fill or create another code form. '
        'Reopen/redeliver the same pending form with its handle and request_new=false without additional permission. '
        'Do not replace an unconfirmed creation, resend SMS or replay a code. '
        'Fresh verification needs a new owner retry request, a contextual affirmative to the pending question, or the private Retry button; never demand an exact sentence. '
        'On owner_approval refusal, the backend sent that button: end the turn, without asking for typed approval. '
        'A code-resume event never authorizes request_new or another verification loop. '
        'No personal values in public updates; no other-owner defaults. Filling grants no purchase, signup, message or account-change approval. Payment instructions stay owner-only; use the private card workflow afterward.')
    ctx.register_system_prompt_section('clanker.personal_info', personal_policy)
    if kernel:
        ctx.register_system_prompt_section('clanker.browser',
            'Use native browser tools; backend binds requester/task. Never choose sessions, endpoints or requesters. No local fallback. '
            'Verify website results. Keep session/cart open while waiting for owner login, an OTP/private credential form, or owner payment approval. '
            'End waiting turns without stopping. '
            'After OTP entry fails, inspect the live page before retry. Claim rejection only with a merchant error; never restart SMS for entry failure. '
            'Use clanker_browser_stop only after verified completion or explicit owner cancellation; keep unfinished login errors/blockers open. '
            'Exception: obey backend stop/reopen instructions only for a stale/unbound private-observation binding. '
            'Verify stop; inspect fresh state, never replay actions or reuse old references. '
            'Cookies do not authorize accounts. Use clanker_vault_list and clanker_authenticate for owned/invited accounts. '
            'Keep credentials/passwords/tokens/cards/OTPs out of tool arguments. On saved_login_available, use clanker_vault_fill; submit once, then clanker_vault_enter_code for private verification. '
            'Otherwise reuse Kernel Managed Auth for passwords/fresh SMS/email codes; never auto-resend SMS. Successful sign-in resumes the task. '
            'Shared tasks stay requester-owned; private dialogue stays in DM. Use clanker_task_update for public outcomes; end on waiting_for_owner/moved_to_private. '
            'Only clanker_payment_submit may make owner-authorized card payments. No card/CVV in browser tools. '
            'Foreground terminal is local/sandboxed and cannot launch/control browsers.')
        return
    ctx.register_system_prompt_section('clanker.browser',
        'The authenticated Kernel browser is unavailable. Report that blocker honestly; no local or alternate browser is permitted. '
        'Foreground terminal remains available for sandboxed Python and shell work, without launching or controlling a browser. '
        'Retain task context and saved access handles while the operator restores Kernel.')
