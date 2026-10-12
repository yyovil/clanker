"""Operator-only installation of protected launchers and context manifests."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

import yaml

from .context import HERE, Context, atomic_json


def write(path, content, mode=0o600):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name('.' + path.name + '.' + uuid.uuid4().hex)
    temporary.write_text(content)
    temporary.chmod(mode)
    os.replace(temporary, path)


def install_context(home, fleet, *, verify=True):
    home = Path(home).resolve(strict=True)
    fleet = Path(fleet).resolve(strict=True)
    settings = json.loads((fleet / 'fleet.json').read_text())
    atomic_json(home / '.clanker-execution' / 'context.json',
                {'home': str(home), 'fleet': str(fleet), 'enabled': True})
    # Old generated-code drivers must not survive rediscovery or installation.
    for relative in ('bin/browser-use', 'node/bin/agent-browser'):
        (home / relative).unlink(missing_ok=True)
    plugin = home / 'plugins' / 'clanker-seatbelt'
    write(plugin / 'plugin.yaml', (HERE / 'plugin.yaml').read_text())
    write(plugin / '__init__.py', f"import sys\nsys.path.insert(0, {str(HERE.parent)!r})\nfrom seatbelt.plugin import register\n")
    context = Context(home)
    if verify:
        context.verify()
    return context


def activate_context(home, fleet):
    """Provision sandboxed terminal execution and authenticated Kernel tools."""
    from cloud_browser.kernel_client import validate_kernel_settings
    fleet_settings = json.loads((Path(fleet) / 'fleet.json').read_text())
    cloud_path = Path(fleet_settings['transport_home']) / '.clanker-cloud/config.json'
    cloud = json.loads(cloud_path.read_text()) if cloud_path.exists() else {}
    validate_kernel_settings(cloud)
    context = install_context(home, fleet)
    if not context.settings.get('activated'):
        raise RuntimeError('The operator has not accepted browser execution')
    path = context.home / 'config.yaml'
    before = path.read_text()
    config = yaml.safe_load(before) or {}
    config.setdefault('platform_toolsets', {})['slack'] = ['clanker_browser']
    config['terminal'] = {'backend':'clanker_seatbelt', 'cwd':str(context.home/'workspace'),
                          'auto_source_bashrc':False, 'shell_init_files':[]}
    # Seatbelt is the command boundary; members are never asked to approve commands.
    # Hardline blocks and Clanker's owner approvals still apply.
    config.setdefault('approvals', {})['mode'] = 'off'
    config.setdefault('tools', {})['tool_search'] = {'enabled':'off'}
    config.setdefault('security', {})['allow_lazy_installs'] = False
    # Never auto-discover the operator's password managers in member contexts.
    config['vault'] = {'onepassword':{'enabled':False},'bitwarden':{'enabled':False}}
    config.setdefault('plugins', {})['enabled'] = ['clanker-seatbelt']
    slack_display = config.setdefault('display', {}).setdefault('platforms', {}).setdefault('slack', {})
    slack_display['long_running_notifications'] = 'generic'
    slack_display['status_phrases'] = {'mode': 'replace', 'status': ['Still working on your request.']}
    config.setdefault('agent', {})['gateway_notify_interval'] = 60
    kernel = cloud.get('enabled') is True and cloud.get('provider') == 'kernel'
    if kernel:
        # The protected adapter loads the pinned provider itself; no raw global-env
        # Kernel plugin is enabled in the multiplexed requester profiles.
        config['plugins'].setdefault('entries', {}).setdefault('clanker-seatbelt', {})['allow_tool_override'] = True
        config['browser'] = {'cloud_provider':'kernel', 'backend':'agent-browser',
            'use_real_profile':False, 'headed':False, 'auto_local_for_private_urls':False,
            'allow_private_urls':False, 'allow_local_fallback':False, 'record_sessions':False,
            'restrict_evaluate':True, 'allow_unsafe_evaluate':False,
            'extension_control':{'enabled':False}, 'inactivity_timeout':600}
    else:
        raise RuntimeError('Configure Kernel before enabling Clanker browser tools. No other browser provider is supported.')
    after = yaml.safe_dump(config, sort_keys=False)
    if before != after:
        write(path, after)
    return context


def prepare_fleet(home, receipt):
    home = Path(home).resolve(strict=True)
    fleet = home / '.clanker-execution'
    fleet.mkdir(mode=0o700, exist_ok=True)
    installed = receipt['installed_executables']
    agent_package = Path(installed['agent_browser_package']).resolve(strict=True) if 'agent_browser_package' in installed else Path('/Users/tanishqpalandurkar/.pnpm-global/5/.pnpm/agent-browser@0.31.1/node_modules/agent-browser').resolve(strict=True)
    node = Path(installed['node']).resolve(strict=True)
    settings = {
        'python': str(Path(sys.base_prefix).resolve()), 'python_executable': sys.executable,
        'hermes_venv': str(Path(sys.prefix).resolve()),
        'node_runtime': str(node.parent.parent), 'agent_browser_package': str(agent_package),
        'agent_browser_executable': str(agent_package / 'bin/agent-browser-darwin-arm64'),
        'transport_home': str(home), 'policy_sha256': hashlib.sha256((HERE / 'common.sb').read_bytes()).hexdigest(),
    }
    for key in ['python_executable', 'agent_browser_executable']:
        if not os.access(settings[key], os.X_OK):
            raise RuntimeError('Installed executable is unavailable: ' + key)
    previous = json.loads((fleet / 'fleet.json').read_text()) if (fleet / 'fleet.json').exists() else {}
    settings['activated'] = previous.get('activated', False) and previous.get('policy_sha256') == settings['policy_sha256']
    atomic_json(fleet / 'fleet.json', settings)
    ensure_broker(fleet)
    return fleet


def ensure_broker(fleet):
    state = fleet / 'proxy.json'
    import fcntl
    with (fleet/'proxy-start.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        _ensure_broker_locked(fleet,state)


def _ensure_broker_locked(fleet,state):
    healthy = False
    if state.exists():
        import urllib.request
        proxy = json.loads(state.read_text())
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(f"http://127.0.0.1:{proxy['port']}/__clanker_health", timeout=2) as response:
                healthy = json.load(response) == {'pid': proxy['pid'], 'generation': proxy['generation']}
        except OSError:
            pass
    if not healthy:
        if state.exists():
            state.unlink()
        with (fleet / 'proxy.log').open('ab') as log:
            process = subprocess.Popen([sys.executable, str(HERE / 'web_proxy.py'), '--state', str(state),
                                        '--generation', uuid.uuid4().hex],
                                       stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                       close_fds=True, start_new_session=True,
                                       env={'PATH': '/usr/bin:/bin', 'LANG': 'en_US.UTF-8'})
        for _ in range(50):
            if process.poll() is not None:
                raise RuntimeError('Web egress broker failed to start')
            if state.exists():
                break
            time.sleep(0.1)
        else:
            raise RuntimeError('Web egress broker readiness timed out')
