#!/usr/bin/env python3
"""Vault-backed model-blind browser autofill tools.

Two model-facing tools, gated on the local vault having at least one item
(zero schema cost otherwise, same ``check_fn`` pattern as the Home Assistant
tools):

- ``browser_vault_list``  → handles + metadata (for logins this includes the
  identifier — it is NOT a secret; the agent types it itself). Passwords are
  never returned.
- ``browser_vault_fill``  → server-side fill of the CURRENT page from a vault
  handle: the password field for logins, card fields for payment items (after
  the user confirms), address fields for address items. The secret is
  resolved locally, the page origin must EXACTLY match the item's bound
  origin (pre-checked AND re-asserted synchronously inside the fill script),
  the field is chosen by the ported login-control classifier, injection runs
  exclusively over the supervisor CDP WebSocket (never argv), and the tool
  result reports only ``{filled_fields, kind, origin, success}`` — the
  password never appears in tool results, logs, or the session DB, and its
  exact bytes are registered with the browser-result redaction boundary so
  no later browser tool call can echo them back to the model.

Ported design from Merit-Systems/OpenInstinct (MIT): opaque-handle vault
autofill (kernel-login-autofill.ts / fill_from_vault.ts).
"""

from __future__ import annotations

import json
import re
import secrets
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Availability check
# ---------------------------------------------------------------------------

def _check_vault_available() -> bool:
    """Schema-gate: the vault tools ride with the browser. An empty vault still needs
    browser_vault_save_login so the agent can offer to remember a login the first time it meets a
    form; hiding the tools until an item exists meant nobody ever discovered the feature."""
    from tools.browser_tool_install import check_browser_requirements
    from tools.browser_use_cli import is_browser_use_cli_mode
    # check_browser_requirements() is False by design in Browser Use mode (browser_exec replaces the
    # built-in surface); the vault serves both stacks.
    return bool(is_browser_use_cli_mode() or check_browser_requirements())


# ---------------------------------------------------------------------------
# JS evaluation plumbing (server-side; results never carry secret values)
# ---------------------------------------------------------------------------

def _native_page_eval(task_id: str, expression: str) -> Dict[str, Any]:
    """NON-SECRET eval on the native driver's active page, never the supervisor's guess."""
    from tools.browser_tool import _last_session_key
    from tools.browser_tool_session import _run_browser_command

    result = _run_browser_command(_last_session_key(task_id), "eval", [expression])
    if not result.get("success"):
        return {"success": False, "error": "The native active page could not be inspected."}
    return {"success": True, "result": result.get("data", {}).get("result")}


def _page_binding(supervisor):
    binding = getattr(supervisor, "_vault_page_binding", None)
    if (not isinstance(binding, dict) or set(binding) != {"marker", "origin"} or
            not isinstance(binding["marker"], str) or not re.fullmatch(r"[0-9a-f]{32}", binding["marker"]) or
            not isinstance(binding["origin"], str) or not binding["origin"]):
        return None
    return binding


def _bound_expression(expression: str, binding: Dict[str, str]) -> str:
    """Pin inspection and secret writes to the document selected by the native driver."""
    return ("(() => { if (window.__hermesNativePageBinding !== " + json.dumps(binding["marker"]) +
            " || window.location.origin !== " + json.dumps(binding["origin"]) +
            ") return JSON.stringify({refused:'active_page_changed',filled:0}); return (" + expression + "); })()")


def _active_binding_matches(task_id: str, binding: Dict[str, str]) -> bool:
    # This probe never contains the expression/values destined for the secret socket.
    probe = ("window.__hermesNativePageBinding === " + json.dumps(binding["marker"]) +
             " && window.location.origin === " + json.dumps(binding["origin"]))
    try:
        result = _native_page_eval(task_id, probe)
        return result.get("success") is True and _parse_json_result(result.get("result")) is True
    except Exception:
        return False


def _bind_active_page(task_id: str, expected_origin: str = "") -> Dict[str, Any]:
    """Hand off the native active document to the secret socket using a nonsecret marker.

    The native CLI sees only a fresh random marker and the public origin. A unique
    matching CDP page must acknowledge that marker before inspection or secret writes.
    No same-origin/form-based fallback is allowed when the handoff fails.
    """
    from agent.vault_store import normalize_origin

    try:
        supervisor = _ensure_supervisor(task_id)
    except Exception:
        supervisor = None
    if supervisor is None:
        return {"success": False, "error_type": "supervisor_required"}
    supervisor._vault_page_binding = None
    marker = secrets.token_hex(16)
    probe = ("(() => { const expected = " + json.dumps(expected_origin) +
             "; const origin = window.location.origin; if (expected && origin !== expected) return null; "
             "Object.defineProperty(window, '__hermesNativePageBinding', {value:" + json.dumps(marker) +
             ", configurable:true}); return origin; })()")
    try:
        native = _native_page_eval(task_id, probe)
        origin = _parse_json_result(native.get("result")) if native.get("success") else None
        if not isinstance(origin, str) or normalize_origin(origin) != origin or (expected_origin and origin != expected_origin):
            return {"success": False, "error_type": "active_page_mismatch"}
        accept = "window.__hermesNativePageBinding === " + json.dumps(marker)
        if not supervisor.focus_page(origin, accept=accept, require_unique=True).get("ok"):
            return {"success": False, "error_type": "active_page_unavailable"}
        binding = {"marker": marker, "origin": origin}
        check = supervisor.evaluate_runtime("window.location.origin === " + json.dumps(origin) + " && (" + accept + ")")
        if not check.get("ok") or check.get("result") is not True:
            return {"success": False, "error_type": "active_page_changed"}
        supervisor._vault_page_binding = binding
        return {"success": True, "origin": origin}
    except Exception:
        # Do not echo CLI output, page exceptions, URLs, or any capability.
        return {"success": False, "error_type": "active_page_unavailable"}


def _eval_js(task_id: str, expression: str) -> Dict[str, Any]:
    """Evaluate NON-SECRET JS on the current page (inspection, origin reads).

    Bound inspection uses the supervisor's persistent CDP WebSocket. Unbound
    public reads use the native driver's active page. Never use this for expressions that
    embed secret values — the fallback places the expression in subprocess
    argv. Use :func:`_eval_js_secret` for secret-bearing expressions.
    """
    try:
        from tools.browser_supervisor import SUPERVISOR_REGISTRY

        supervisor = SUPERVISOR_REGISTRY.get(task_id)
        binding = _page_binding(supervisor) if supervisor is not None else None
        if binding is not None:
            if not _active_binding_matches(task_id, binding):
                return {"success": False, "error": "The native active page changed after binding."}
            sup = supervisor.evaluate_runtime(_bound_expression(expression, binding))
            if sup.get("ok"):
                return {"success": True, "result": sup.get("result")}
            return {"success": False, "error": "The bound active page could not be inspected."}
    except ImportError:
        pass
    except Exception as exc:  # pragma: no cover — defensive
        logger.debug("vault fill: supervisor eval unavailable (%s)", exc)

        # A failed bound read cannot be retried on a different native page.
        return {"success": False, "error": "The bound active page could not be inspected."}
    return _native_page_eval(task_id, expression)


def _ensure_supervisor(task_id: str):
    """The supervisor for ``task_id``, attaching one on demand for a LOCAL built-in browser session.

    Cloud/CDP-override sessions and browser_exec attach their supervisor when the session is created;
    a local agent-browser ``--session`` has no ``cdp_url`` of its own, so nothing did. Ask the daemon
    for the packaged Chromium's endpoint (``get cdp-url``: same daemon, same reaper) and attach.
    Returns None when no endpoint is reachable; the fill then refuses rather than touching argv."""
    from tools.browser_supervisor import SUPERVISOR_REGISTRY

    supervisor = SUPERVISOR_REGISTRY.get(task_id)
    if supervisor is not None:
        return supervisor
    from tools.browser_tool import _last_session_key
    from tools.browser_tool_cdp import _get_dialog_policy_config, _resolve_cdp_override
    from tools.browser_tool_session import _run_browser_command

    res = _run_browser_command(_last_session_key(task_id), "get", ["cdp-url"])
    cdp_url = str(((res or {}).get("data") or {}).get("cdpUrl") or "") if (res or {}).get("success") else ""
    if not cdp_url:
        return None
    policy, timeout_s = _get_dialog_policy_config()
    try:
        return SUPERVISOR_REGISTRY.get_or_start(task_id=task_id, cdp_url=_resolve_cdp_override(cdp_url),
                                                dialog_policy=policy, dialog_timeout_s=timeout_s)
    except Exception as exc:
        logger.debug("vault fill: supervisor attach to local session failed (%s)", exc)
        return None


def _eval_js_secret(task_id: str, expression: str) -> Dict[str, Any]:
    """Evaluate a SECRET-BEARING JS expression. Supervisor CDP-WS only.

    Fails closed: there is deliberately NO fallback to the agent-browser CLI
    ``eval`` path, because that places the expression — and therefore the
    credential bytes — in subprocess argv, visible to any process listing.
    When no supervisor session is available the caller gets a typed refusal
    (``error_type='supervisor_required'``) and nothing is written.
    """
    try:
        supervisor = _ensure_supervisor(task_id)
    except Exception as exc:
        logger.debug("vault fill: supervisor unavailable (%s)", exc)
        supervisor = None

    if supervisor is None:
        return {
            "success": False,
            "error_type": "supervisor_required",
            "error": (
                "Vault fill requires the supervised browser session (direct "
                "CDP WebSocket). The fallback eval path would place the "
                "credential in subprocess argv, so it is never used for "
                "secrets. Start the browser through the Hermes-managed "
                "session and retry."
            ),
        }

    binding = _page_binding(supervisor)
    if binding is None:
        return {"success": False, "error_type": "active_page_unbound",
                "error": "Bind the native active page before filling saved details."}

    # Re-admit at the WRITE. The handler-level fence (_fenced_page_op) admitted before a possibly
    # human-length prompt (enter_code waits for the user's code); a takeover during that wait must
    # refuse here, before the credential lands in a page the human is now typing into. The outer
    # epoch check only discards the result, and a fill is a side effect, not a result.
    if _bot_desktop_browser_session(task_id):
        from tools.bot_desktop import lease as _bd_lease
        try:
            _bd_lease.assert_agent_may_act()
        except _bd_lease.HumanHasControl as exc:
            return {"success": False, "error_type": "human_has_control", "error": str(exc)}

    if not _active_binding_matches(task_id, binding):
        return {"success": False, "error_type": "active_page_changed",
                "error": "The native active page changed before saved details could be filled."}
    sup = supervisor.evaluate_runtime(_bound_expression(expression, binding))
    if sup.get("ok"):
        return {"success": True, "result": sup.get("result")}
    return {
        "success": False,
        "error_type": "supervisor_required"
        if "supervisor" in str(sup.get("error") or "").lower()
        else "eval_failed",
        "error": str(sup.get("error") or "eval failed"),
    }


def _parse_json_result(raw: Any) -> Any:
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return raw
    return raw


def _current_page_origin(task_id: str) -> Optional[str]:
    res = _native_page_eval(task_id, "window.location.origin")
    if not res.get("success"):
        return None
    href = str(res.get("result") or "").strip().strip('"').strip("'")
    if not href or href == "about:blank":
        return None
    try:
        from agent.vault_store import normalize_origin

        return normalize_origin(href)
    except Exception:
        return None


def _focus_bound_origin(task_id: str, origin: str, kind: str) -> Optional[str]:
    """Bind only the native driver's active document; never search other tabs for a form."""
    bound = _bind_active_page(task_id, expected_origin=origin)
    return bound.get("origin") if bound.get("success") else None


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def browser_vault_list() -> str:
    """List login handles + metadata across every enabled backend. Passwords are never included.

    A locked external manager contributes no items; instead it is reported under ``locked`` so the
    agent knows to call browser_vault_fill (which prompts the user to unlock) or tell the user.
    """
    from agent.vault_backends import enabled_backends
    from agent.vault_backends.unlock import can_prompt_here

    items, locked, errors = [], [], []
    for backend in enabled_backends():
        if backend.needs_unlock and not backend.is_unlocked():
            locked.append({"backend": backend.name, "display_name": backend.display_name,
                           "unlock": "browser_vault_unlock" if can_prompt_here() else "unavailable_in_this_session"})
            continue
        try:
            metas = backend.list_items()
        except Exception as exc:
            errors.append({"backend": backend.name, "error": str(exc)[:200]})
            continue
        for meta in metas:
            entry = {"handle": meta.id, "backend": backend.name, "label": meta.label, "kind": meta.kind,
                     "origin": meta.origin, "available": meta.kind == "login" or bool(meta.origin)}
            if len(meta.allowed_origins) > 1:
                entry["allowed_origins"] = list(meta.allowed_origins)
            if meta.has_otp or backend.needs_unlock:
                entry["two_factor"] = "automatic" if meta.has_otp else "automatic if the manager stores a TOTP seed, else the user is asked"
            if meta.identifier:
                entry["identifier"] = meta.identifier
                entry["identifier_type"] = meta.identifier_type
            items.append(entry)
    out: Dict[str, Any] = {"success": True, "items": items}
    if not items:
        out["hint"] = ("No saved logins. Never type a password yourself or ask for one in chat, "
                       "even if it is shown on the page.")
    if locked:
        out["locked"] = locked
    if errors:
        out["errors"] = errors
    return json.dumps(out, ensure_ascii=False)


def browser_vault_unlock(backend_name: str) -> str:
    """Ask the user (via the surface's masked prompt) to unlock an external manager for this session."""
    from agent.vault_backends import enabled_backends
    from agent.vault_backends.unlock import can_prompt_here, get_unlock_prompt_callback

    backend = next((b for b in enabled_backends() if b.name == backend_name and b.needs_unlock), None)
    if backend is None:
        return json.dumps({"success": False, "error": f"No unlockable vault backend named {backend_name!r}."})
    if backend.is_unlocked():
        return json.dumps({"success": True, "backend": backend.name, "already_unlocked": True})
    if not can_prompt_here():
        return json.dumps({"success": False, "error_type": "unlock_unavailable",
                           "error": (f"{backend.display_name} is locked and this session cannot prompt for the "
                                     "master password (headless/cron/API). Unlock it from an interactive Hermes "
                                     "session or the Desktop app first.")})
    prompt = get_unlock_prompt_callback()
    master = prompt(backend.name, backend.display_name) if prompt else ""
    if not master:
        return json.dumps({"success": False, "error_type": "unlock_cancelled",
                           "error": f"The user declined to unlock {backend.display_name}."})
    try:
        backend.unlock(master)  # type: ignore[attr-defined]
    except Exception as exc:
        return json.dumps({"success": False, "error_type": "unlock_failed", "error": str(exc)[:300]})
    finally:
        del master
    return json.dumps({"success": True, "backend": backend.name})


def browser_vault_save_login(label: str = "", task_id: Optional[str] = None) -> str:
    """Refuse removed local collection before prompting or accessing a browser."""
    return json.dumps({"success": False, "error_type": "local_vault_removed",
                       "error": "Local credential storage has been removed. Request a private Kernel Vault form through Clanker."})


def browser_vault_enter_code(handle: str = "", task_id: Optional[str] = None, *,
                             expected_origin: Optional[str] = None, provided_code: Optional[str] = None) -> str:
    """Second factor: fill the one-time code the CURRENT page asks for. If the saved login (``handle``) has an
    authenticator seed, the code is minted server-side and nobody is asked; otherwise the user is prompted on
    their surface for the code their phone/email/app shows. The code goes into the page over the supervisor
    socket and never enters the conversation."""
    from agent.redact import register_vault_redaction_value
    from agent.vault_backends import backend_for_handle
    from agent.vault_backends.unlock import can_prompt_here, get_code_prompt_callback
    from agent.vault_login_classifier import LoginControl, build_fill_js, build_inspection_js, build_otp_fills, classify_otp_controls

    effective_task_id = task_id or "default"
    origin = _focus_bound_origin(effective_task_id, expected_origin or "", "otp")
    if expected_origin and origin != expected_origin:
        return json.dumps({'success': False, 'error_type': 'origin_mismatch',
                           'error': 'The code page does not match this saved account.'})
    if not origin:
        return json.dumps({"success": False, "error": "No page with a code field is open."})
    site = origin.split("://", 1)[-1]

    nonce = secrets.token_hex(8)
    inspect = _eval_js(effective_task_id, build_inspection_js(nonce))
    raw_controls = _parse_json_result(inspect.get("result")) if inspect.get("success") else None
    if isinstance(raw_controls, str):
        raw_controls = _parse_json_result(raw_controls)
    otp_controls = classify_otp_controls([LoginControl.from_dict(r) for r in (raw_controls or []) if isinstance(r, dict)])
    if not otp_controls:
        return json.dumps({"success": False, "error_type": "no_code_field",
                           "error": ("No one-time-code field on the current page. If the site wants a passkey, hardware key or "
                                     "an approval tap in an app, tell the user to complete it on their device and wait for the page to move on.")})

    code: Optional[str] = provided_code
    source = "user"
    backend = backend_for_handle(handle) if handle else None
    if backend is not None and not code:
        try:
            code = backend.resolve_otp(handle)
        except Exception:
            code = None
        if code:
            source = backend.name
    if not code:
        prompt = get_code_prompt_callback()
        if prompt is None or not can_prompt_here():
            return json.dumps({"success": False, "error_type": "prompt_unavailable",
                               "error": (f"{site} asks for a one-time code and this session cannot ask the user (headless/cron/API). "
                                         "Save an authenticator key for this login so codes can be generated automatically.")})
        code = (prompt(site, "") or "").strip().replace(" ", "").replace("-", "")
        if not code:
            return json.dumps({"success": False, "error_type": "code_declined",
                               "error": "The user did not enter a code. Do not ask again this turn."})

    register_vault_redaction_value(code)
    fills = build_otp_fills(otp_controls, code)
    result = _eval_js_secret(effective_task_id, build_fill_js(fills, expected_origin=origin, nonce=nonce))
    del code
    if not result.get("success"):
        return json.dumps({"success": False, "error": str(result.get("error") or "fill failed")[:200]})
    parsed = _parse_json_result(result.get("result"))
    if isinstance(parsed, str):
        parsed = _parse_json_result(parsed)
    if isinstance(parsed, dict) and parsed.get("refused") == "origin_changed":
        return json.dumps({"success": False, "error_type": "origin_changed", "error": "The page navigated before the code could be entered. Nothing was written."})
    filled = int(parsed.get("filled", 0)) if isinstance(parsed, dict) else 0
    return json.dumps({"success": bool(filled), "filled_fields": filled, "origin": origin, "source": source,
                       "next": "Submit the form (many sites auto-submit when the last digit lands)."})


def browser_vault_fill(handle: str, task_id: Optional[str] = None) -> str:
    """Fill the current page's password field from a vault handle.

    Password-only: the identifier is agent-visible metadata (see
    browser_vault_list) and is typed by the agent via normal input tools.
    The password is resolved server-side and injected via in-page JS over
    the supervisor CDP WebSocket; the result reports only counts/metadata.
    """
    from agent.redact import register_vault_redaction_value
    from agent.vault_login_classifier import (
        ClassifiedLoginControl,
        LoginControl,
        build_fill_js,
        build_inspection_js,
        classify_checkout_control,
        classify_login_control,
        select_checkout_fills,
        select_password_fill,
    )
    from agent.vault_backends import UnlockRequired, backend_for_handle
    from agent.vault_store import ADDRESS_FIELDS, PAYMENT_FIELDS, scrub_secret_from_text

    effective_task_id = task_id or "default"
    backend = backend_for_handle(handle)
    if backend is not None and backend.needs_unlock and not backend.is_unlocked():
        unlocked = json.loads(browser_vault_unlock(backend.name))
        if not unlocked.get("success"):
            return json.dumps(unlocked)

    try:
        meta = backend.get_meta(handle) if backend is not None else None
    except UnlockRequired:
        return json.dumps({"success": False, "error_type": "unlock_required",
                           "error": f"{backend.display_name} locked again; call browser_vault_unlock."})
    if meta is None:
        return json.dumps(
            {
                "success": False,
                "error": f"No vault item with handle {handle!r}. Use browser_vault_list.",
            }
        )
    if meta.kind != "login" and not meta.origin:
        return json.dumps({"success": False, "error_type": "no_origin",
                           "error": f"Vault item {handle!r} has no bound origin; {meta.kind} items are filled only on the site they were saved for."})
    if meta.kind == "payment" and not _confirm_payment_fill(meta.label, str(meta.origin)):
        return json.dumps({"success": False, "error_type": "payment_declined",
                           "error": "The user did not confirm filling this payment card. Do not retry; ask them instead."})

    # ── Origin binding pre-check (cheap early exit; the authoritative check
    # runs synchronously inside the fill script itself) ──────────────────────
    # Manager items can bind several websites (e.g. amazon.co.uk + www.amazon.co.uk);
    # every saved origin is a valid fill target. Matching stays exact-origin —
    # nothing wildcard/parent-domain is ever inferred.
    allowed = list(meta.allowed_origins) or ([str(meta.origin)] if meta.origin else [])
    # Bind the driver's current page once, then check its exact origin against
    # the saved item. Never search through allowed origins for another tab.
    page_origin = _focus_bound_origin(effective_task_id, "", meta.kind)
    if not page_origin:
        return json.dumps(
            {"success": False, "error": "Could not determine the current page origin. Navigate to the login page first."}
        )
    if page_origin not in allowed:
        return json.dumps(
            {
                "success": False,
                "error_type": "origin_mismatch",
                "error": (
                    f"Refused: current page origin ({page_origin}) does not match "
                    f"the vault item's bound origin(s) ({', '.join(allowed)}). Vault fills "
                    "only run on the exact origin(s) the credential was saved for."
                ),
            }
        )

    # ── Inspect + classify page controls ────────────────────────────────────
    nonce = secrets.token_hex(8)  # binds this fill to THIS inspection's stamps
    inspect = _eval_js(effective_task_id, build_inspection_js(nonce))
    if not inspect.get("success"):
        return json.dumps(
            {"success": False, "error": f"Could not inspect page inputs: {inspect.get('error', 'eval failed')}"}
        )
    raw_controls = _parse_json_result(inspect.get("result"))
    if isinstance(raw_controls, str):
        raw_controls = _parse_json_result(raw_controls)
    if not isinstance(raw_controls, list):
        return json.dumps({"success": False, "error": "Page input inspection returned no usable controls."})

    classify = classify_login_control if meta.kind == "login" else classify_checkout_control
    classified: list[ClassifiedLoginControl] = []
    for raw in raw_controls:
        if not isinstance(raw, dict):
            continue
        result = classify(LoginControl.from_dict(raw))
        if result is not None:
            classified.append(result)
    if not classified:
        return json.dumps({"success": False, "error": f"No {meta.kind} form fields were found on the current page."})

    # ── Resolve secret and fill (secret never enters any logged string) ─────
    try:
        if meta.kind == "login":
            secret = {"password": backend.resolve_password(handle)}
            fills = select_password_fill(classified, secret["password"])
        else:
            secret = backend.resolve_secret(handle)
            fills = select_checkout_fills(classified, secret, PAYMENT_FIELDS if meta.kind == "payment" else ADDRESS_FIELDS)
    except UnlockRequired:
        return json.dumps({"success": False, "error_type": "unlock_required",
                           "error": f"{backend.display_name} locked again; call browser_vault_unlock."})
    if not fills:
        return json.dumps(
            {"success": False, "error": f"No fillable {meta.kind} field matched the saved item on this page."}
        )

    # Register the secret bytes with the model-egress redaction boundary
    # BEFORE they touch the page: any later browser_* result (including
    # browser_cdp Runtime.evaluate reads) that echoes them is scrubbed.
    # Address values are not secrets but the card fields are: register every payment value.
    for value in (secret.values() if meta.kind == "payment" else [secret.get("password", "")]):
        register_vault_redaction_value(value)

    try:
        fill_result = _eval_js_secret(
            effective_task_id, build_fill_js(fills, expected_origin=page_origin, nonce=nonce)
        )
    except Exception as exc:
        # Strip any secret material from exception text before surfacing.
        return json.dumps(
            {"success": False, "error": scrub_secret_from_text(str(exc), secret)}
        )
    if not fill_result.get("success"):
        err = scrub_secret_from_text(str(fill_result.get("error") or "fill failed"), secret)
        out = {"success": False, "error": err}
        if fill_result.get("error_type"):
            out["error_type"] = fill_result["error_type"]
        return json.dumps(out)

    parsed = _parse_json_result(fill_result.get("result"))
    if isinstance(parsed, str):
        parsed = _parse_json_result(parsed)
    if isinstance(parsed, dict) and parsed.get("refused") == "origin_changed":
        return json.dumps(
            {
                "success": False,
                "error_type": "origin_changed",
                "error": (
                    "Refused: the page navigated away from the bound origin "
                    f"({page_origin}) before the fill could run "
                    f"(now on {parsed.get('found') or 'unknown'}). "
                    "Nothing was written."
                ),
            }
        )
    filled = parsed.get("filled", 0) if isinstance(parsed, dict) else 0

    out = {"success": bool(filled), "filled_fields": int(filled), "backend": backend.name,
           "kind": meta.kind, "origin": page_origin}
    if meta.kind == "login":
        out["next"] = ("Submit. If the site then asks for a verification code, call browser_vault_enter_code with this handle"
                       + (" (a code will be generated automatically)." if meta.has_otp else "."))
    if meta.kind != "login":
        out["fields"] = sorted(f["token"] for f in fills)  # which controls were targeted, never the values
    return json.dumps(out)


def _confirm_payment_fill(label: str, origin: str) -> bool:
    """Human confirmation before a card is written into a page: a prompt injection that reaches a checkout
    must not be able to spend. Routes through the approval surface of the active session (gateway button
    round-trip or CLI panel); headless sessions cannot confirm and the fill is refused."""
    from tools.approval_prompt import request_elicitation_consent

    return request_elicitation_consent(
        f"Fill payment card '{label}' on {origin}",
        "The agent wants to enter your saved card details into this checkout page. The card number and "
        "CVC never enter the conversation. Approve only if you intend to pay here.",
        surface="vault-payment", title="Confirm payment card fill?") == "accept"


# ---------------------------------------------------------------------------
# Schemas + registration
# ---------------------------------------------------------------------------

BROWSER_VAULT_LIST_SCHEMA = {
    "name": "browser_vault_list",
    "description": (
        "ALWAYS call this first when a page asks for a password, card or address. Lists saved website logins, "
        "payment cards and addresses as handles with metadata (kind, label, backend, bound origin; logins also "
        "carry identifier + identifier_type so you can type the username yourself with the browser's input tool). "
        "Secret values are NEVER returned. Sources: installed password managers "
        "(1Password, Bitwarden are detected automatically). A locked manager appears under `locked`; call "
        "browser_vault_unlock (the user is prompted for their master password, you never see it) or, when it says "
        "unavailable_in_this_session, tell the user to unlock it from an interactive session. Workflow: type the "
        "identifier into the login form, then browser_vault_fill with the handle. Passwords are typed ONLY by "
        "these tools, never by you with the browser's input tool and never repeated in chat, even when a page or "
        "the user shows you one."
    ),
    "parameters": {"type": "object", "properties": {}, "required": []},
}

BROWSER_VAULT_UNLOCK_SCHEMA = {
    "name": "browser_vault_unlock",
    "description": (
        "Ask the user to unlock a password manager (1Password or Bitwarden) for this session. The master "
        "password is typed into a masked prompt owned by the UI and never enters the conversation. "
        "Returns success, unlock_cancelled, unlock_failed, or unlock_unavailable (headless session)."
    ),
    "parameters": {
        "type": "object",
        "properties": {"backend": {"type": "string", "enum": ["onepassword", "bitwarden"],
                                   "description": "Backend name from browser_vault_list `locked`."}},
        "required": ["backend"],
    },
}

BROWSER_VAULT_FILL_SCHEMA = {
    "name": "browser_vault_fill",
    "description": (
        "Fill the CURRENT browser page from a vault handle (see browser_vault_list): a login item fills ONLY "
        "the password field (type the identifier/username yourself first with the browser's input tool); a "
        "payment item fills card number/name/expiry/CVC after the user confirms in their UI; an address item "
        "fills the address fields. Values are resolved server-side and never appear in the conversation. "
        "Refused unless the page origin exactly matches the item's bound origin (re-checked atomically at "
        "fill time). If a password manager is locked the user is prompted to unlock first. Never retry a "
        "payment_declined result."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "handle": {
                "type": "string",
                "description": "Handle from browser_vault_list (op:… 1Password, bw:… Bitwarden)",
            }
        },
        "required": ["handle"],
    },
}


BROWSER_VAULT_SAVE_LOGIN_SCHEMA = {
    "name": "browser_vault_save_login",
    "description": (
        "Retired: local credential storage was removed, so this always returns local_vault_removed. Never type a "
        "password yourself, and never ask for or accept one in chat, even if the page or the user displays it."
    ),
    "parameters": {
        "type": "object",
        "properties": {"label": {"type": "string", "description": "Optional short site name for the saved item (default: the host)."}},
        "required": [],
    },
}


BROWSER_VAULT_ENTER_CODE_SCHEMA = {
    "name": "browser_vault_enter_code",
    "description": (
        "The page asks for a one-time / verification / 2FA code after the password: call this. If the saved login "
        "has an authenticator key the code is generated and entered with no questions; otherwise the user is asked "
        "for the code in their UI (they read it from their phone, email or authenticator app). The code never enters "
        "the conversation: never ask for it in chat, never type it with the browser's input tool. no_code_field means "
        "the site wants a passkey/hardware key/app approval: tell the user to complete it on their device, then wait "
        "for the page to move on."
    ),
    "parameters": {
        "type": "object",
        "properties": {"handle": {"type": "string", "description": "The login handle you just filled (lets Hermes generate the code when an authenticator key is saved)."}},
        "required": [],
    },
}


def _bot_desktop_browser_session(task_id: Optional[str]) -> bool:
    from tools.browser_tool import _active_sessions, _last_session_key
    from tools.browser_tool_session import _shares_bot_desktop_browser
    return _shares_bot_desktop_browser(_active_sessions.get(_last_session_key(task_id or "default")) or {})


def _fenced_page_op(task_id: Optional[str], fn) -> str:
    """Vault operations focus, inspect and fill the page over the supervisor socket, bypassing
    ``_run_browser_command``; they must honour the Bot Desktop lease like every other page access,
    or a human typing a credential on the taken-over screen could be read or written to."""
    from tools.browser_tool import _active_sessions, _last_session_key
    from tools.browser_tool_session import run_fenced

    session = _active_sessions.get(_last_session_key(task_id or "default")) or {}
    res = run_fenced(session, lambda: {"raw": fn()})
    return res["raw"] if "raw" in res else json.dumps(res)


def _handle_vault_enter_code(args: Dict[str, Any], **kwargs) -> str:
    tid = kwargs.get("task_id")
    return _fenced_page_op(tid, lambda: browser_vault_enter_code(handle=str(args.get("handle") or ""), task_id=tid))


def _handle_vault_save_login(args: Dict[str, Any], **kwargs) -> str:
    tid = kwargs.get("task_id")
    return _fenced_page_op(tid, lambda: browser_vault_save_login(label=str(args.get("label") or ""), task_id=tid))


def _handle_vault_list(args: Dict[str, Any], **kwargs) -> str:
    return browser_vault_list()


def _handle_vault_unlock(args: Dict[str, Any], **kwargs) -> str:
    return browser_vault_unlock(str(args.get("backend") or ""))


def _handle_vault_fill(args: Dict[str, Any], **kwargs) -> str:
    tid = kwargs.get("task_id")
    return _fenced_page_op(tid, lambda: browser_vault_fill(handle=str(args.get("handle") or ""), task_id=tid))


from tools.registry import no_cache_check_fn, registry  # noqa: E402

_check_vault_available = no_cache_check_fn(_check_vault_available)

registry.register(
    name="browser_vault_list",
    toolset="browser",
    schema=BROWSER_VAULT_LIST_SCHEMA,
    handler=_handle_vault_list,
    check_fn=_check_vault_available,
    emoji="🔐",
)

registry.register(
    name="browser_vault_unlock",
    toolset="browser",
    schema=BROWSER_VAULT_UNLOCK_SCHEMA,
    handler=_handle_vault_unlock,
    check_fn=_check_vault_available,
    emoji="🔐",
)

registry.register(
    name="browser_vault_save_login",
    toolset="browser",
    schema=BROWSER_VAULT_SAVE_LOGIN_SCHEMA,
    handler=_handle_vault_save_login,
    check_fn=_check_vault_available,
    emoji="🔐",
)

registry.register(
    name="browser_vault_enter_code",
    toolset="browser",
    schema=BROWSER_VAULT_ENTER_CODE_SCHEMA,
    handler=_handle_vault_enter_code,
    check_fn=_check_vault_available,
    emoji="🔐",
)

registry.register(
    name="browser_vault_fill",
    toolset="browser",
    schema=BROWSER_VAULT_FILL_SCHEMA,
    handler=_handle_vault_fill,
    check_fn=_check_vault_available,
    emoji="🔐",
)
