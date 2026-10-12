"""Tests for the vault-backed password-blind browser autofill feature.

Covers:
- Shared credential helpers and external manager behavior
  (login secret payload is password-only)
- login-control classifier: scoring + new-password/one-time-code exclusion,
  password-only fill selection
- origin-binding refusal (pre-check + in-script TOCTOU assert)
- fail-closed secret eval (no argv fallback)
- vault-value redaction registry (browser_cdp read-back regression)
- tool gating: check_fn False when the vault is empty
"""

from __future__ import annotations

import json
import re
import os
import stat
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from agent.vault_login_classifier import (  # noqa: E402
    ClassifiedLoginControl,
    LoginControl,
    build_fill_js,
    classify_login_control,
    select_password_fill,
)
from agent.vault_store import (  # noqa: E402
    VaultError,
    normalize_origin,
    scrub_secret_from_text,
)




@pytest.fixture(autouse=True)
def handler_page_fixture(monkeypatch):
    """These handler tests inject page descriptors; the real marker/CDP protocol
    is exercised separately by test_browser_active_page_binding.py."""
    from tools import browser_vault_tool

    def current_origin(task_id):
        result = browser_vault_tool._eval_js(task_id, "window.location.href")
        try:
            return normalize_origin(result["result"]) if result.get("success") else None
        except (ValueError, TypeError, KeyError):
            return None

    monkeypatch.setattr(browser_vault_tool, "_current_page_origin", current_origin)
    monkeypatch.setattr(browser_vault_tool, "_focus_bound_origin",
                        lambda task, origin, kind: browser_vault_tool._current_page_origin(task))


def _add_login(store, origin="https://example.com", password="s3cret-pw"):
    return store.add_item(
        kind="login",
        label="Example login",
        origin=origin,
        secret={
            "identifier_type": "email",
            "identifier": "user@example.com",
            "password": password,
            "origin": origin,
        },
    )


# ---------------------------------------------------------------------------
# VaultStore
# ---------------------------------------------------------------------------

class TestCredentialHelpers:










    def test_normalize_origin(self):
        assert normalize_origin("https://Example.com:443/login?x=1") == "https://example.com"
        assert normalize_origin("http://localhost:8931/") == "http://localhost:8931"
        assert normalize_origin("http://site.test:80") == "http://site.test"
        with pytest.raises(VaultError):
            normalize_origin("example.com")

    def test_scrub_secret_from_text(self):
        secret = {"password": "hunter22x", "identifier": "me@x.io"}
        out = scrub_secret_from_text("boom hunter22x at me@x.io", secret)
        assert "hunter22x" not in out
        assert "me@x.io" not in out


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

_CARD = {"card_number": "4111111111111111", "cardholder_name": "A User", "exp_month": "7", "exp_year": "2029",
         "cvc": "123", "billing_postal_code": "94110"}
_ADDRESS = {"address_line1": "1 Main St", "city": "Springfield", "postal_code": "12345", "country": "US"}


def _ctrl(**kw):
    base = dict(autocomplete="", form_index=0, index=0, label="", name="", type="text")
    base.update(kw)
    return LoginControl(**base)


class TestClassifier:
    def test_autocomplete_exact_match_maps_token(self):
        for token in ("username", "email", "tel", "current-password"):
            res = classify_login_control(_ctrl(autocomplete=token))
            assert res is not None and res.token == token

    def test_new_password_autocomplete_excluded(self):
        assert classify_login_control(
            _ctrl(autocomplete="new-password", type="password")
        ) is None

    def test_one_time_code_excluded(self):
        assert classify_login_control(_ctrl(autocomplete="one-time-code")) is None

    def test_label_new_password_excluded(self):
        for label in ("New password", "Confirm Password", "create-password", "Repeat  password"):
            assert classify_login_control(_ctrl(type="password", label=label)) is None, label

    def test_password_type_maps_current_password(self):
        res = classify_login_control(_ctrl(type="password"))
        assert res.token == "current-password"

    def test_email_tel_types_map_tokens(self):
        assert classify_login_control(_ctrl(type="email")).token == "email"
        res = classify_login_control(_ctrl(type="tel"))
        assert res.token == "tel"

    def test_label_heuristics(self):
        assert classify_login_control(_ctrl(label="E-mail address")).token == "email"
        assert classify_login_control(_ctrl(name="mobile_number")).token == "tel"
        res = classify_login_control(_ctrl(label="Username or account"))
        assert res.token == "username"

    def test_unmatched_returns_none(self):
        assert classify_login_control(_ctrl(label="Search the docs")) is None

    def test_select_password_fill_picks_best_password(self):
        user = ClassifiedLoginControl(_ctrl(index=0, form_index=0, autocomplete="username"), 100, "username")
        pw_heur = ClassifiedLoginControl(_ctrl(index=1, form_index=0, type="password"), 90, "current-password")
        pw_exact = ClassifiedLoginControl(_ctrl(index=3, form_index=0, autocomplete="current-password"), 100, "current-password")
        fills = select_password_fill([user, pw_heur, pw_exact], "p")
        # Password only — the identifier field is never filled by the vault.
        assert [(f["index"], f["token"]) for f in fills] == [(3, "current-password")]

    def test_select_password_fill_requires_password_field(self):
        user = ClassifiedLoginControl(_ctrl(index=0, autocomplete="username"), 100, "username")
        assert select_password_fill([user], "p") == []

    def test_select_password_fill_single_field_only(self):
        pw1 = ClassifiedLoginControl(_ctrl(index=1, type="password"), 90, "current-password")
        pw2 = ClassifiedLoginControl(_ctrl(index=2, type="password"), 90, "current-password")
        fills = select_password_fill([pw1, pw2], "p")
        assert len(fills) == 1 and fills[0]["index"] == 1


    def test_build_fill_js_leaves_no_dom_marker_and_binds_target_to_inspection(self):
        # P1-1: no persistent selector for filled controls. The fill targets the input by the
        # <nonce>:<index> stamp ITS OWN inspection wrote (a bare index is re-resolved by position,
        # and a second inspection in between would re-stamp — either way the password could land in
        # another field); stamps carry no secret and the fill script strips every one before returning.
        js = build_fill_js(
            [{"index": 0, "token": "current-password", "value": "x"}],
            expected_origin="https://example.com",
        )
        assert "vaultSecret" not in js
        assert "data-vault-secret" not in js
        assert "elements[f.index]" not in js
        assert "[data-hermes-vault-slot=" in js and "nonce + ':' + f.index" in js
        assert 'f.token === "current-password" && el.type !== "password"' in js  # a password fill never lands in a text box
        assert js.index('removeAttribute("data-hermes-vault-slot")') > js.index("setter.set.call")

    def test_build_fill_js_asserts_origin_before_any_write(self):
        # P1-2: the origin assert must run inside the SAME script, before
        # any element write.
        js = build_fill_js(
            [{"index": 0, "token": "current-password", "value": "x"}],
            expected_origin="https://example.com",
        )
        assert '"https://example.com"' in js
        assert "window.location.origin" in js
        assert "origin_changed" in js
        assert js.index("origin_changed") < js.index("querySelectorAll")


# ---------------------------------------------------------------------------
# Browser tool: origin binding + gating
# ---------------------------------------------------------------------------

class TestBrowserVaultTools:



    @staticmethod
    def _manager_meta():
        from agent.vault_store import VaultItemMeta

        return VaultItemMeta(
            id="op:multi", kind="login", label="Amazon", origin="https://amazon.co.uk",
            created_at="2026-01-01T00:00:00Z", identifier_type="username", identifier="jane@example.com",
            allowed_origins=("https://amazon.co.uk", "https://www.amazon.co.uk",
                             "https://eu.account.amazon.com"))

    def test_fill_allowed_on_every_saved_origin_of_a_multi_website_item(self):
        """A manager item with several saved websites fills on each of them
        (exact match only), and the in-page origin assert pins the origin
        actually being filled — not just the first saved one."""
        from tools import browser_vault_tool

        meta = self._manager_meta()

        class _ManagerBackend:
            name, display_name, needs_unlock = "onepassword", "1Password", False

            def is_unlocked(self):
                return True

            def get_meta(self, handle):
                return meta if handle == meta.id else None

            def resolve_password(self, handle):
                return "s3cret-pw"

        controls = [
            {"autocomplete": "email", "formIndex": 0, "index": 0, "label": "", "name": "email", "type": "email"},
            {"autocomplete": "current-password", "formIndex": 0, "index": 1, "label": "", "name": "pw", "type": "password"},
        ]
        secret_exprs = []

        def fake_eval(task_id, expression):
            return {"success": True, "result": json.dumps(controls)}

        def fake_eval_secret(task_id, expression):
            secret_exprs.append(expression)
            return {"success": True, "result": json.dumps({"filled": 1})}

        with patch("agent.vault_backends.backend_for_handle", return_value=_ManagerBackend()), \
             patch.object(browser_vault_tool, "_current_page_origin", return_value="https://www.amazon.co.uk"), \
             patch.object(browser_vault_tool, "_eval_js", side_effect=fake_eval), \
             patch.object(browser_vault_tool, "_eval_js_secret", side_effect=fake_eval_secret):
            raw = browser_vault_tool.browser_vault_fill("op:multi")
        out = json.loads(raw)
        assert out["success"] is True
        assert out["origin"] == "https://www.amazon.co.uk"
        # the synchronous in-page check is bound to the origin actually matched
        assert "https://www.amazon.co.uk" in secret_exprs[0]
        assert "s3cret-pw" not in raw
        assert out["filled_fields"] == 1

    def test_fill_still_refused_on_origin_not_saved_on_the_item(self):
        """Multi-website items widen nothing: an unsaved origin — even a sibling
        subdomain — is still refused (fail-closed regression)."""
        from tools import browser_vault_tool

        meta = self._manager_meta()

        class _ManagerBackend:
            name, display_name, needs_unlock = "onepassword", "1Password", False

            def is_unlocked(self):
                return True

            def get_meta(self, handle):
                return meta if handle == meta.id else None

            def resolve_password(self, handle):
                return "s3cret-pw"

        with patch("agent.vault_backends.backend_for_handle", return_value=_ManagerBackend()), \
             patch.object(browser_vault_tool, "_current_page_origin", return_value="https://payments.amazon.co.uk"):
            out = json.loads(browser_vault_tool.browser_vault_fill("op:multi"))
        assert out["success"] is False
        assert out["error_type"] == "origin_mismatch"
        assert "s3cret-pw" not in json.dumps(out)









class TestVaultHardening:
    """Read-deny, backup perms-tightening, canonical dir securing.

    Mirrors the browser-profile snapshot hardening (f1d05c): the vault dir
    holds key + ciphertext side by side, so it gets the same treatment.
    """

    def test_read_block_vault_dir_and_contents(self, tmp_path, monkeypatch):
        import agent.file_safety as fs

        home = tmp_path / "hermes_home"
        vault = home / "vault"
        vault.mkdir(parents=True)
        (vault / "vault.key").write_text("k", encoding="utf-8")
        (vault / "vault.json.enc").write_text("blob", encoding="utf-8")
        monkeypatch.setattr(fs, "_hermes_home_path", lambda: home)

        for target in (vault, vault / "vault.key", vault / "vault.json.enc"):
            err = fs.get_read_block_error(str(target))
            assert err is not None, f"expected read deny for {target}"

    def test_read_block_leaves_sibling_dirs_alone(self, tmp_path, monkeypatch):
        import agent.file_safety as fs

        home = tmp_path / "hermes_home"
        other = home / "vaults-notes"
        other.mkdir(parents=True)
        f = other / "notes.txt"
        f.write_text("hi", encoding="utf-8")
        monkeypatch.setattr(fs, "_hermes_home_path", lambda: home)
        assert fs.get_read_block_error(str(f)) is None

    def test_backup_secret_names_include_vault_files(self):
        from hermes_cli.backup import _SECRET_FILE_NAMES

        assert "vault.key" in _SECRET_FILE_NAMES
        assert "vault.json.enc" in _SECRET_FILE_NAMES





def test_every_registered_tool_schema_declares_openai_style_parameters():
    """The registry emits ``parameters`` (OpenAI function shape) and every provider adapter converts from
    it; a schema that spells it ``input_schema`` (Anthropic shape) ships with NO parameters, so the model is
    told the tool takes nothing and calls browser_vault_fill without a handle."""
    import model_tools  # noqa: F401 — triggers discovery
    from tools.registry import registry

    missing = [entry.name for entry in registry.get_all_entries()
               if "parameters" not in entry.schema or "input_schema" in entry.schema]
    assert not missing, missing






class TestManagerAutoDetection:
    def test_installed_manager_is_a_source_without_config_and_config_can_opt_out(self):
        from agent.vault_backends import base

        with patch.object(base, "is_installed", return_value=True):
            with patch.object(base, "_cfg", return_value={}):
                assert {b.name for b in base.enabled_backends()} == {"onepassword", "bitwarden"}
            with patch.object(base, "_cfg", return_value={"bitwarden": {"enabled": False}}):
                assert {b.name for b in base.enabled_backends()} == {"onepassword"}
        with patch.object(base, "is_installed", return_value=False), patch.object(base, "_cfg", return_value={}):
            assert [b.name for b in base.enabled_backends()] == []


def test_every_vault_tool_is_in_the_browser_toolset():
    """toolsets.py is a hand-maintained list; a tool registered here but missing there is invisible to the model
    (live: browser_vault_save_login was registered, tested, and never offered)."""
    import toolsets
    from tools import browser_vault_tool  # noqa: F401  (registers)
    from tools.registry import registry

    registered = {e.name for e in registry.get_all_entries() if e.name.startswith("browser_vault_")}
    assert registered <= set(toolsets.TOOLSETS["browser"]["tools"]), registered - set(toolsets.TOOLSETS["browser"]["tools"])


class TestTwoFactor:
    def test_totp_matches_rfc6238_vector_and_seed_normalisation(self):
        from agent.vault_store import VaultError, normalize_otp_secret, totp_now

        seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # "12345678901234567890"
        assert totp_now(seed, digits=8, at=59) == "94287082"
        assert totp_now(seed, at=1111111109) == "081804"
        assert normalize_otp_secret("otpauth://totp/GitHub:tek?secret=jbsw y3dp ehpk3pxp&issuer=GitHub") == "JBSWY3DPEHPK3PXP"
        with pytest.raises(VaultError):
            normalize_otp_secret("not base32!")
        # Non-default otpauth parameters are kept and honoured (RFC 6238 SHA-256 / 8-digit vector at T=59).
        stored = normalize_otp_secret(f"otpauth://totp/x?secret={'GEZDGNBVGY3TQOJQ' * 2}&digits=8&period=30&algorithm=SHA256")
        assert stored.endswith("|8|30|SHA256")
        sha256_seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA"  # "1234567890" * 3.2 -> RFC 32-byte seed
        assert totp_now(sha256_seed + "|8|30|SHA256", at=59) == "46119246"
        assert totp_now("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ|6|60|SHA1", at=119) == totp_now("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", period=60, at=119)
        with pytest.raises(VaultError):
            normalize_otp_secret("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1")


    def test_without_a_key_the_user_is_asked_and_split_boxes_get_one_digit_each(self):
        from agent.vault_backends import unlock as unlock_mod
        from tools import browser_vault_tool

        unlock_mod.set_code_prompt_callback(lambda site, hint: "246 810")
        boxes = [{"index": i, "type": "tel", "name": f"digit{i}", "label": "", "autocomplete": "one-time-code",
                  "formIndex": 0, "maxLength": 1} for i in range(6)]
        seen = {}
        fake_eval = lambda t, e: {"success": True, "result": json.dumps(boxes) if "querySelectorAll" in e else "https://acme.test/2fa"}

        def fake_secret(t, e):
            seen["expr"] = e
            return {"success": True, "result": json.dumps({"filled": 6})}

        with patch("agent.vault_backends.unlock.can_prompt_here", return_value=True), \
             patch.object(browser_vault_tool, "_focus_bound_origin", lambda *a, **k: "https://acme.test"), \
             patch.object(browser_vault_tool, "_eval_js", side_effect=fake_eval), \
             patch.object(browser_vault_tool, "_eval_js_secret", side_effect=fake_secret):
            out = json.loads(browser_vault_tool.browser_vault_enter_code(task_id="t"))
            unlock_mod.set_code_prompt_callback(lambda site, hint: "")
            declined = json.loads(browser_vault_tool.browser_vault_enter_code(task_id="t"))
        unlock_mod.set_code_prompt_callback(None)
        assert out["success"] and out["source"] == "user" and out["filled_fields"] == 6
        assert re.findall(r'"value": "(\d)"', seen["expr"]) == list("246810")
        assert declined["error_type"] == "code_declined"

    def test_several_code_like_inputs_that_are_not_a_digit_widget_get_one_field(self):
        """Reviewer case: a page with 4+ code-ish inputs (promo code, zip code, a real OTP box...) must never
        get a digit sprayed across them. Only an unmistakable maxlength=1 same-form adjacent group splits."""
        from agent.vault_login_classifier import ClassifiedLoginControl, LoginControl, build_otp_fills

        def ctl(i, form=0, maxlen=None, score=70):
            return ClassifiedLoginControl(LoginControl("", form, i, "", f"code{i}", "text", maxlen), score, "one-time-code")

        scattered = [ctl(0), ctl(3), ctl(7), ctl(9, form=1), ctl(12, score=100)]
        assert build_otp_fills(scattered, "246810") == [{"index": 12, "token": "one-time-code", "value": "246810"}]
        # maxlength=1 but different forms / non-adjacent: still one field
        assert len(build_otp_fills([ctl(i, form=i % 2, maxlen=1) for i in range(6)], "246810")) == 1
        assert len(build_otp_fills([ctl(i * 2, maxlen=1) for i in range(6)], "246810")) == 1
        # five boxes for a six-digit code: one field
        assert len(build_otp_fills([ctl(i, maxlen=1) for i in range(5)], "246810")) == 1
        # the real widget
        assert [f["value"] for f in build_otp_fills([ctl(i + 4, maxlen=1) for i in range(6)], "246810")] == list("246810")

    def test_no_code_field_points_at_passkey_or_device_approval(self):
        from tools import browser_vault_tool

        fake_eval = lambda t, e: {"success": True, "result": json.dumps([{"index": 0, "type": "text", "name": "q", "label": "Search", "autocomplete": ""}]) if "querySelectorAll" in e else "https://acme.test/approve"}
        with patch.object(browser_vault_tool, "_focus_bound_origin", lambda *a, **k: "https://acme.test"), \
             patch.object(browser_vault_tool, "_eval_js", side_effect=fake_eval):
            out = json.loads(browser_vault_tool.browser_vault_enter_code(task_id="t"))
        assert out["error_type"] == "no_code_field"
