"""Tests for cloud browser provider runtime fallback to local Chromium.

Covers the fallback logic in _get_session_info() when a cloud provider
is configured but fails at runtime (issue #10883).
"""
import logging
from unittest.mock import Mock

import pytest

import tools.browser_tool as browser_tool
from tools import browser_tool_session as bt_session
from tools import browser_tool_cloud as bt_cloud


def _reset_session_state(monkeypatch):
    """Clear caches so each test starts fresh."""
    monkeypatch.setattr(browser_tool, "_active_sessions", {})
    monkeypatch.setattr(browser_tool, "_cached_cloud_provider", None)
    monkeypatch.setattr(browser_tool, "_cloud_provider_resolved", False)
    monkeypatch.setattr("tools.browser_tool_lifecycle._start_browser_cleanup_thread", lambda: None)
    monkeypatch.setattr("tools.browser_tool_lifecycle._update_session_activity", lambda t: None)


class TestCloudProviderRuntimeFallback:
    """Tests for _get_session_info cloud → local fallback."""

    def test_cloud_failure_falls_back_to_local(self, monkeypatch):
        """When cloud provider.create_session raises, fall back to local."""
        _reset_session_state(monkeypatch)

        provider = Mock()
        provider.create_session.side_effect = RuntimeError("401 Unauthorized")
        monkeypatch.setattr(bt_cloud, "_get_cloud_provider", lambda: provider)
        monkeypatch.setattr("tools.browser_tool_cdp._get_cdp_override", lambda: None)

        session = bt_session._get_session_info("task-1")

        assert session["fallback_from_cloud"] is True
        assert "401 Unauthorized" in session["fallback_reason"]
        assert session["fallback_provider"] == "Mock"
        assert session["features"]["local"] is True
        assert session["cdp_url"] is None


    def test_no_provider_uses_local_directly(self, monkeypatch):
        """When no cloud provider is configured, local mode is used with no fallback markers."""
        _reset_session_state(monkeypatch)

        monkeypatch.setattr(bt_cloud, "_get_cloud_provider", lambda: None)
        monkeypatch.setattr("tools.browser_tool_cdp._get_cdp_override", lambda: None)

        session = bt_session._get_session_info("task-4")

        assert session["features"]["local"] is True
        assert "fallback_from_cloud" not in session


    def test_cloud_returns_invalid_session_triggers_fallback(self, monkeypatch):
        """Cloud provider returning None or empty dict triggers fallback."""
        _reset_session_state(monkeypatch)

        provider = Mock()
        provider.create_session.return_value = None
        monkeypatch.setattr(bt_cloud, "_get_cloud_provider", lambda: provider)
        monkeypatch.setattr("tools.browser_tool_cdp._get_cdp_override", lambda: None)

        session = bt_session._get_session_info("task-7")

        assert session["fallback_from_cloud"] is True
        assert "invalid session" in session["fallback_reason"]

    @pytest.mark.parametrize("allow_fallback", [False, True])
    @pytest.mark.parametrize("failure", ["create", "invalid", "cdp"])
    def test_profile_policy_controls_creation_and_cdp_failure(
        self, tmp_path, monkeypatch, allow_fallback, failure
    ):
        """A cloud failure obeys the profile's policy before creating any local browser."""
        _reset_session_state(monkeypatch)
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        (tmp_path / "config.yaml").write_text(
            f"browser:\n  allow_local_fallback: {str(allow_fallback).lower()}\n",
            encoding="utf-8",
        )
        provider = Mock()
        if failure == "create":
            provider.create_session.side_effect = RuntimeError("provider unavailable")
        elif failure == "invalid":
            provider.create_session.return_value = None
        else:
            provider.create_session.return_value = {"cdp_url": "https://cloud.example.test/cdp"}
            monkeypatch.setattr(
                "tools.browser_tool_cdp._resolve_cdp_override",
                Mock(side_effect=RuntimeError("CDP discovery unavailable")),
            )
        monkeypatch.setattr(bt_cloud, "_get_cloud_provider", lambda: provider)
        monkeypatch.setattr("tools.browser_tool_cdp._get_cdp_override", lambda: None)
        local = Mock(return_value={"features": {"local": True}, "cdp_url": None})
        monkeypatch.setattr(bt_session, "_create_local_session", local)

        if allow_fallback:
            result = bt_session._get_session_info("policy-task")
            local.assert_called_once_with("policy-task")
            assert result["fallback_from_cloud"] is True
            assert result["fallback_provider"] == type(provider).__name__
            assert result["features"]["local"] is True
        else:
            with pytest.raises(RuntimeError, match="local fallback is disabled"):
                bt_session._get_session_info("policy-task")
            local.assert_not_called()
            assert "policy-task" not in browser_tool._active_sessions

    @pytest.mark.parametrize("allow_fallback", [False, True])
    def test_profile_policy_controls_explicit_provider_resolution_failure(
        self, tmp_path, monkeypatch, allow_fallback
    ):
        """A failed registered provider factory cannot silently select local when disabled."""
        _reset_session_state(monkeypatch)
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        (tmp_path / "config.yaml").write_text(
            "browser:\n  cloud_provider: test-cloud\n"
            f"  allow_local_fallback: {str(allow_fallback).lower()}\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(bt_cloud, "_ensure_browser_plugins_loaded", lambda: None)
        factory = Mock(side_effect=RuntimeError("provider factory unavailable"))
        monkeypatch.setattr(bt_cloud, "_registry_get_browser_provider", factory)
        monkeypatch.setattr("tools.browser_tool_cdp._get_cdp_override", lambda: None)
        local = Mock(return_value={"features": {"local": True}, "cdp_url": None})
        monkeypatch.setattr(bt_session, "_create_local_session", local)

        if allow_fallback:
            result = bt_session._get_session_info("resolution-task")
            local.assert_called_once_with("resolution-task")
            assert result["features"]["local"] is True
        else:
            with pytest.raises(RuntimeError, match="local fallback is disabled"):
                bt_session._get_session_info("resolution-task")
            local.assert_not_called()
            assert "resolution-task" not in browser_tool._active_sessions
        factory.assert_called_once_with("test-cloud")
