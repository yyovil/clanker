"""External manager RPCs and refusals for removed local credential routes."""

from __future__ import annotations

import json

import pytest

import tui_gateway.server as srv


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / ".hermes"
    h.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(h))
    return h


def _result(envelope):
    assert "error" not in envelope, envelope
    return envelope["result"]


def _error(envelope):
    assert "error" in envelope, envelope
    return envelope["error"]


_LOGIN_PARAMS = {
    "kind": "login",
    "label": "Example login",
    "origin": "https://example.com",
    "secret": {
        "identifier_type": "email",
        "identifier": "user@example.com",
        "password": "s3cret-pw-9000",
    },
}


def test_removed_local_collection_refuses_without_echoing_secrets_or_writing(home):
    out = srv._methods['vault.add'](1, dict(_LOGIN_PARAMS))
    assert _error(out)['code'] == 5095
    assert 'removed' in _error(out)['message']
    assert 's3cret-pw-9000' not in json.dumps(out)
    assert _result(srv._methods['vault.list'](2, {}))['items'] == []
    assert not (home / 'vault').exists()


def test_add_validation_errors_are_clean(home):
    err = _error(
        srv._methods["vault.add"](
            1,
            {
                "kind": "login",
                "label": "no origin",
                "secret": {
                    "identifier_type": "email",
                    "identifier": "user@example.com",
                    "password": "s3cret-pw-9000",
                },
            },
        )
    )
    assert err["code"] == 5095
    assert "s3cret-pw-9000" not in json.dumps(err)

    err = _error(srv._methods["vault.add"](2, {"kind": "login", "label": "x"}))
    assert err["code"] == 5095

    err = _error(
        srv._methods["vault.add"](
            3, {"kind": "wat", "label": "x", "secret": {"password": "s3cret-pw-9000"}}
        )
    )
    assert err["code"] == 5095
    assert "s3cret-pw-9000" not in json.dumps(err)


def _sources_rows(home):
    out = _result(srv._methods["vault.sources"](90, {}))
    rows = {row["name"]: row for row in out["sources"]}
    assert "local" not in rows
    return rows


def test_enabling_a_detected_manager_reports_it_enabled(home, monkeypatch):
    """The Settings toggle and `hermes vault sources --enable` both clear the opt-out override;
    the shipped default must then agree with `is_enabled()`'s zero-config contract — an installed
    manager becomes a login source instead of silently staying off (#109546)."""
    monkeypatch.setattr(
        "agent.vault_backends.base.is_installed", lambda name: name == "bitwarden"
    )
    _result(
        srv._methods["vault.source.set"](80, {"name": "bitwarden", "enabled": True})
    )
    rows = _sources_rows(home)
    assert rows["bitwarden"]["installed"] is True
    assert rows["bitwarden"]["enabled"] is True


def test_disabling_a_manager_persists_the_opt_out(home, monkeypatch):
    monkeypatch.setattr(
        "agent.vault_backends.base.is_installed", lambda name: name == "bitwarden"
    )
    _result(
        srv._methods["vault.source.set"](81, {"name": "bitwarden", "enabled": False})
    )
    rows = _sources_rows(home)
    assert rows["bitwarden"]["installed"] is True
    assert rows["bitwarden"]["enabled"] is False


def test_undetected_manager_stays_off(home, monkeypatch):
    monkeypatch.setattr("agent.vault_backends.base.is_installed", lambda name: False)
    rows = _sources_rows(home)
    assert rows["bitwarden"]["installed"] is False


def test_source_set_tolerates_scalar_vault_section(home, monkeypatch):
    """A hand-edited ``vault: true`` in config.yaml must not crash the Desktop
    Credential Vault source toggle: the malformed section is coerced to a dict
    before the opt-out is written (same YAML-shape hazard class _voice_cfg_dict
    documents for voice.*, #19835)."""
    monkeypatch.setattr(
        "agent.vault_backends.base.is_installed", lambda name: name == "bitwarden"
    )
    (home / "config.yaml").write_text("vault: true\n")
    _result(
        srv._methods["vault.source.set"](82, {"name": "bitwarden", "enabled": False})
    )
    rows = _sources_rows(home)
    assert rows["bitwarden"]["enabled"] is False


def test_removed_local_deletion_refuses_without_opening_old_files(home):
    legacy = home / 'vault'
    legacy.mkdir()
    key = legacy / 'vault.key'
    key.write_bytes(b'opaque-existing-fixture')
    for index in (2, 3):
        out = srv._methods['vault.remove'](index, {'id': 'vault_stale'})
        assert _error(out)['code'] == 5095
        assert 'removed' in _error(out)['message']
    assert key.read_bytes() == b'opaque-existing-fixture'


def test_remove_requires_id(home):
    err = _error(srv._methods["vault.remove"](1, {}))
    assert err["code"] == 5095


def test_launch_profile_vault_rpcs_stay_scoped_once_the_process_multiplexes(home, monkeypatch):
    """Once a second profile has been served, ``get_secret`` fails closed for unscoped reads. The
    launch profile's vault.* calls (Desktop sends no ``profile`` for it) must still bind the launch
    secret scope — otherwise every enabled manager's token read raises UnscopedSecretError and the
    Passwords & Logins panel shows "Could not load vault items" until the gateway restarts."""
    from agent.secret_scope import set_multiplex_active

    monkeypatch.setattr("agent.vault_backends.base.is_installed", lambda name: name == "onepassword")
    set_multiplex_active(True)  # conftest resets the latch per test
    assert _sources_rows(home)["onepassword"]["enabled"] is True
