"""Update only discovery settings in this workspace's existing profiles."""
import json
from pathlib import Path

import yaml


def profile_configs(home):
    home = Path(home).resolve(strict=True)
    membership = json.loads((home / 'slack_membership.json').read_text())
    team = membership['workspace_id']
    bound_profiles = {member.get('profile') for member in membership.get('members', {}).values()
                      if member.get('status') == 'ready'}
    targets = [('default', home / 'config.yaml')]
    profiles = home / 'profiles'
    for target in sorted(profiles.iterdir() if profiles.exists() else []):
        marker, config = target / 'slack_identity.json', target / 'config.yaml'
        if (target.is_symlink() or marker.is_symlink() or config.is_symlink() or
                not target.is_dir() or not config.is_file()):
            continue
        if marker.is_file():
            owned = json.loads(marker.read_text()).get('workspace_id') == team
        else:
            owned = target.name in bound_profiles
        if owned:
            targets.append((target.name, config))
    return targets


def rollout(home, *, apply=False):
    from utils import atomic_roundtrip_yaml_update
    observations = []
    for name, path in profile_configs(home):
        config = yaml.safe_load(path.read_text()) or {}
        changed = config.get('clanker', {}).get('public_web', {}).get('enabled') is not True
        if apply and changed:
            atomic_roundtrip_yaml_update(path, 'clanker.public_web.enabled', True)
        observations.append({'profile': name, 'changed': changed, 'applied': apply and changed})
    return observations
