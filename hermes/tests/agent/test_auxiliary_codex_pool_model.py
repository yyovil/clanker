"""A cooldown for one Codex model must not disable another auxiliary model."""

import json
import time

import pytest

from agent.auxiliary_client import _build_codex_client
from gateway.run import _profile_runtime_scope


@pytest.mark.parametrize("requested,available", [("allowed-model", True), ("limited-model", False)])
def test_codex_aux_pool_uses_the_requested_model(tmp_path, requested, available):
    (tmp_path / "auth.json").write_text(json.dumps({"version": 1, "providers": {},
        "credential_pool": {"openai-codex": [{
            "id": "test-oauth", "provider": "openai-codex", "label": "fixture",
            "auth_type": "oauth", "source": "manual:device_code", "priority": 0,
            "access_token": "fixture-token", "base_url": "http://127.0.0.1:1",
            "model_cooldowns": {"limited-model": time.time() + 600},
        }]}}))
    with _profile_runtime_scope(tmp_path):
        client, model = _build_codex_client(requested)
        assert (client is not None) is available
        if client is not None:
            assert model == requested and client.api_key == "fixture-token"
            client.close()
