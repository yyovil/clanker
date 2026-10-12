"""Trusted gateway startup: recover web egress without changing accepted policy."""
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from seatbelt.context import HERE
from seatbelt.install import ensure_broker

fleet = Path(sys.argv[1]) / '.clanker-execution'
settings = json.loads((fleet/'fleet.json').read_text())
if not settings.get('activated'):
    raise RuntimeError('Execution acceptance is pending')
for key, filename in [('policy_sha256','common.sb')]:
    if settings[key] != hashlib.sha256((HERE/filename).read_bytes()).hexdigest():
        raise RuntimeError('An execution policy changed; operator verification is required')
ensure_broker(fleet)
print('Clanker web egress broker is ready')
