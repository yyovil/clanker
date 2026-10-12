"""`hermes vault sources --disable` must not crash on a hand-edited non-dict
``vault:`` section in config.yaml (the same YAML-shape hazard class
``_voice_cfg_dict`` guards for voice.*, #19835): the malformed section is
coerced to a dict before the opt-out is written."""

from types import SimpleNamespace

import yaml
import pytest

from hermes_cli.vault import _cmd_sources, vault_command




def test_sources_disable_tolerates_scalar_vault_section(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    (home / "config.yaml").write_text("vault: true\n")

    _cmd_sources(SimpleNamespace(enable=None, disable="bitwarden"))

    saved = yaml.safe_load((home / "config.yaml").read_text())
    assert saved["vault"]["bitwarden"]["enabled"] is False


def test_vault_command_refuses_local_collection_before_prompt(tmp_path, monkeypatch, capsys):
    from hermes_cli.vault import _cmd_add
    home = tmp_path / '.hermes'
    monkeypatch.setenv('HERMES_HOME', str(home))
    monkeypatch.setattr('builtins.input', lambda *args: pytest.fail('Local credential prompt'))
    vault_command(SimpleNamespace(_vault_handler=_cmd_add))
    out = capsys.readouterr().out
    assert 'removed' in out and 'Kernel' in out
    assert not home.exists()
