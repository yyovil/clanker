"""Trusted context policy construction, environment and port allocation."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import urllib.request


HERE = Path(__file__).resolve().parent


def atomic_json(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.chmod(0o600)
    os.replace(temporary, path)


class Context:
    def __init__(self, home):
        self.home = Path(home).resolve(strict=True)
        self.manifest = self.home / ".clanker-execution" / "context.json"
        self.config = json.loads(self.manifest.read_text())
        if self.config["home"] != str(self.home) or not self.config.get("enabled"):
            raise RuntimeError("No execution grant for this context")
        self.fleet = Path(self.config["fleet"])
        self.settings = json.loads((self.fleet / "fleet.json").read_text())
        if hashlib.sha256((HERE / "common.sb").read_bytes()).hexdigest() != self.settings["policy_sha256"]:
            raise RuntimeError("Execution policy changed; operator verification is required")
        self.proxy = json.loads((self.fleet / "proxy.json").read_text())
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(f"http://127.0.0.1:{self.proxy['port']}/__clanker_health", timeout=2) as response:
            health = json.load(response)
        if health != {"pid": self.proxy["pid"], "generation": self.proxy["generation"]}:
            raise RuntimeError("Web egress broker is unavailable")
        self.key = hashlib.sha256(str(self.home).encode()).hexdigest()[:16]
        self.temp = Path("/private/tmp") / ("csx-" + self.key)
        self.browser = self.home / "browser" / "sandbox"
        self.bu_work = self.home / "cache" / "browser-use" / "workspace"
        self.terminal = self.home / "cache" / "terminal"
        for path in (self.temp, self.browser, self.bu_work, self.terminal,
                     self.home / "workspace", self.home / "artifacts", self.browser / "home"):
            if path.is_symlink() or path.resolve() != path:
                raise RuntimeError("Execution resource root was replaced")
            path.mkdir(mode=0o700, parents=True, exist_ok=True)

    def lease(self, name):
        # Leases are never handed to another context during this broker generation.
        with (self.fleet / "leases.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            path = self.fleet / "leases.json"
            leases = json.loads(path.read_text()) if path.exists() else {}
            key = str(self.home) + "\0" + name
            if key not in leases:
                used = {item["port"] for item in leases.values()} | {self.proxy["port"]}
                for port in range(46000, 59000):
                    if port in used:
                        continue
                    test = socket.socket()
                    try:
                        test.bind(("127.0.0.1", port))
                    except OSError:
                        test.close()
                        continue
                    test.close()
                    leases[key] = {"port": port, "home": str(self.home)}
                    atomic_json(path, leases)
                    break
                else:
                    raise RuntimeError("No browser-control ports are available")
            return leases[key]["port"]

    def owned_cdp(self, value):
        raise RuntimeError('Local browser execution has been removed; use the authenticated Kernel browser.')

    def safe_env(self, *, name="default", cdp_url=None):
        env = {"HOME": str(self.browser / "home"), "HERMES_HOME": str(self.home),
               "PATH": f"{self.settings['hermes_venv']}/bin:/usr/bin:/bin:/usr/sbin:/sbin",
               "LANG": "en_US.UTF-8", "TMPDIR": str(self.temp), "TMP": str(self.temp),
               "MAC_CHROMIUM_TMPDIR": str(self.temp),
               "TEMP": str(self.temp), "PYTHONDONTWRITEBYTECODE": "1",
               "ANONYMIZED_TELEMETRY": "false", "DO_NOT_TRACK": "1"}
        env.update(BH_TAB_MARKER='0', AGENT_BROWSER_IDLE_TIMEOUT_MS='120000')
        proxy = f"http://127.0.0.1:{self.proxy['port']}"
        env.update(HTTP_PROXY=proxy, HTTPS_PROXY=proxy, ALL_PROXY=proxy,
                   http_proxy=proxy, https_proxy=proxy, NO_PROXY="localhost,127.0.0.1,::1")
        if cdp_url:
            self.owned_cdp(cdp_url)
        return env

    def command(self, argv, *, cdp_port=None, chromium=False):
        if cdp_port is not None or chromium:
            raise RuntimeError('Local browser execution has been removed.')
        if not Path("/usr/bin/sandbox-exec").is_file():
            raise RuntimeError("sandbox-exec is unavailable; execution is disabled")
        runtime = self.settings
        params = {
            "PYTHON": runtime["python"], "HERMES_VENV": runtime["hermes_venv"],
            "WORK": str(self.home / "workspace"), "ARTIFACTS": str(self.home / "artifacts"),
            "BROWSER": str(self.browser), "BU_WORK": str(self.bu_work),
            "TERMINAL": str(self.terminal), "TEMP": str(self.temp),
            "PROXY": f"localhost:{self.proxy['port']}",
            "CDP": f"localhost:{self.proxy['port']}",
        }
        command = ["/usr/bin/sandbox-exec", "-f", str(HERE / "common.sb")]
        for name, value in params.items():
            command.extend(["-D", name + "=" + value])
        return command + list(argv)

    def verify(self):
        protected = str(Path(self.settings["transport_home"]) / ".env")
        code = (
            "from pathlib import Path; import subprocess, sys, os\n"
            "p=Path('clanker-boundary-ready.tmp'); p.write_text('ready'); assert p.read_text()=='ready'; p.unlink()\n"
            f"try:\n Path({protected!r}).read_bytes()\nexcept PermissionError:\n pass\nelse:\n raise RuntimeError('protected read unexpectedly succeeded')\n"
            "assert not any(k in os.environ for k in ['SLACK_BOT_TOKEN','OPENAI_API_KEY','HERMES_API_KEY'])\n"
            "print('SEATBELT_READY')\n"
        )
        result = subprocess.run(self.command([self.settings["python_executable"], "-c", code]),
                                env=self.safe_env(), cwd=self.home / "workspace", close_fds=True,
                                capture_output=True, text=True, timeout=15)
        if result.returncode or result.stdout.strip() != "SEATBELT_READY":
            raise RuntimeError("Execution readiness failed: " + result.stderr[-1000:])
        return True
