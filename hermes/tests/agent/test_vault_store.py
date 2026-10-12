"""Removed local credential storage refuses before touching profile files."""
import pytest
from agent.vault_store import VaultError, VaultStore, get_vault_store


def test_local_store_refuses_for_each_profile_without_creating_files(tmp_path, monkeypatch):
    for owner in ('a', 'b', 'a'):
        home = tmp_path / owner
        monkeypatch.setenv('HERMES_HOME', str(home))
        with pytest.raises(VaultError, match='removed'):
            VaultStore(home / 'vault')
        with pytest.raises(VaultError, match='removed'):
            get_vault_store()
        assert not home.exists()
