"""The observed Sol 6.1 route must never receive its rejected disabled effort."""

import pytest

from agent.transports.codex import ResponsesApiTransport
from tests.agent.test_auxiliary_client import TestCodexAdapterReasoningTranslation as _AdapterHarness


@pytest.mark.parametrize("model", ["gpt-6.1-sol", "openai/gpt-6.1-sol"])
@pytest.mark.parametrize("config", [{"enabled": False}, {"effort": "none"}, {"effort": "max"}])
def test_auxiliary_sol_reasoning_uses_supported_floor_and_preserves_max(model, config):
    adapter, captured = _AdapterHarness._build_adapter()
    adapter._client.base_url = "https://chatgpt.com/backend-api/codex"
    adapter._model = model
    adapter.create(model=model, messages=[{"role": "user", "content": "Name this task"}],
                   extra_body={"reasoning": config})
    expected = "max" if config.get("effort") == "max" else "low"
    assert captured["reasoning"]["effort"] == expected


@pytest.mark.parametrize("effort", ["none", "minimal", "max"])
def test_main_sol_reasoning_uses_the_same_supported_vocabulary(effort):
    request = ResponsesApiTransport().build_kwargs(
        model="gpt-6.1-sol", messages=[{"role": "user", "content": "Hi"}], tools=[],
        provider="openai-codex", base_url="https://chatgpt.com/backend-api/codex",
        is_codex_backend=True, reasoning_config={"enabled": True, "effort": effort},
    )
    assert request["reasoning"]["effort"] == ("max" if effort == "max" else "low")
