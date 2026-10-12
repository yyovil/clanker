"""Stop verified legacy Clanker browsers during migration or credential revocation.

This module cannot start a browser. Existing profile data is retained unless
credential revocation explicitly requires cookie cleanup.
"""
import hashlib
import json
from pathlib import Path
import shutil

from vault.store import AccessError


def stop_owned_local_browsers(home, *, purge=False):
    import psutil
    home = Path(home).resolve(strict=True)
    stopped = 0
    for path in (home / '.clanker-execution').glob('chrome-*.json'):
        if path.is_symlink():
            raise AccessError('Legacy browser state was replaced.', 409)
        value = json.loads(path.read_text())
        name = value.get('name')
        if not isinstance(name, str):
            raise AccessError('Legacy browser ownership could not be verified.', 409)
        tag = hashlib.sha256(name.encode()).hexdigest()[:16]
        profile = home / 'browser/sandbox/chromium' / tag
        if path.name != 'chrome-' + tag + '.json' or profile.resolve() != profile:
            raise AccessError('Legacy browser ownership could not be verified.', 409)
        try:
            process = psutil.Process(value['pid'])
            if process.create_time() != value['start_time']:
                raise AccessError('Legacy browser process identity changed.', 409)
            manifest = json.loads((home / '.clanker-execution/context.json').read_text())
            fleet = json.loads((Path(manifest['fleet']) / 'fleet.json').read_text())
            executable = fleet.get('chromium_executable')
            if manifest.get('home') != str(home) or not executable or process.exe() != executable:
                raise AccessError('Legacy browser executable identity changed.', 409)
            argv = process.cmdline()
            if (f'--user-data-dir={profile}' not in argv or
                    f"--remote-debugging-port={value['port']}" not in argv):
                raise AccessError('Legacy browser process ownership changed.', 409)
            process.terminate()
            try:
                process.wait(timeout=5)
            except psutil.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            stopped += 1
        except psutil.NoSuchProcess:
            pass
        path.unlink()
    if purge:
        directory = home / 'browser/sandbox/chromium'
        if directory.is_symlink():
            raise AccessError('Legacy browser profile root was replaced.', 409)
        if directory.exists():
            shutil.rmtree(directory)
    return stopped
