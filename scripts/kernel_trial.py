"""Private key entry and actual Hermes browser-provider checks for the Kernel trial."""
import getpass
import json
import sys
import uuid

from dotenv import load_dotenv, set_key
from hermes_constants import get_hermes_home


def main():
    home = get_hermes_home()
    env_file = home / ".env"
    action = sys.argv[1]
    if action == "key":
        if not sys.stdin.isatty():
            raise SystemExit("Run this command in your terminal for hidden key entry.")
        key = getpass.getpass("Kernel API key (hidden): ").strip()
        if not key:
            raise SystemExit("No key saved.")
        set_key(str(env_file), "KERNEL_API_KEY", key)
        env_file.chmod(0o600)
        print("Kernel key saved to the isolated trial. No browser started.")
        return

    load_dotenv(env_file, override=True)
    from hermes_cli.plugins import discover_plugins
    from tools.browser_tool_cloud import _get_cloud_provider
    from tools.browser_tool_install import _find_agent_browser

    discover_plugins()
    provider = _get_cloud_provider()
    if provider is None or provider.name != "kernel":
        raise SystemExit("Kernel is not the resolved browser provider.")
    check = {
        "home": str(home),
        "provider": provider.name,
        "provider_class": type(provider).__name__,
        "key_present": provider.is_available(),
        "agent_browser": _find_agent_browser(),
    }
    if action == "check":
        print(json.dumps(check, indent=2))
        return
    if not check["key_present"]:
        raise SystemExit("Kernel key is missing. Run scripts/kernel-hermes-trial key first.")

    import os
    import requests

    # Observe the real Hermes session as well as the page result: local fallback
    # must never make a Kernel smoke test pass.
    from tools import browser_tool
    from tools.browser_tool_lifecycle import cleanup_browser
    from tools.browser_tool_session import _get_session_info

    task_id = "kernel-trial-" + uuid.uuid4().hex[:12]
    session_id = None
    try:
        navigate = json.loads(browser_tool.browser_navigate("https://example.com", task_id=task_id))
        session = _get_session_info(task_id)
        session_id = session.get("bb_session_id")
        kernel_browser_confirmed = False
        if session_id and not session.get("fallback_from_cloud"):
            response = requests.get(
                "https://api.onkernel.com/browsers/" + str(session_id),
                headers={"Authorization": "Bearer " + os.environ["KERNEL_API_KEY"]},
                timeout=15,
            )
            if response.status_code == 200:
                remote = response.json()
                kernel_browser_confirmed = (
                    remote.get("session_id") == session_id and remote.get("stealth") is True
                )
        snapshot = json.loads(browser_tool.browser_snapshot(task_id=task_id))
        passed = (
            navigate.get("success") is True
            and navigate.get("title") == "Example Domain"
            and "stealth" in navigate.get("stealth_features", [])
            and not navigate.get("fallback_warning")
            and not session.get("fallback_from_cloud")
            and bool(session_id)
            and kernel_browser_confirmed
            and snapshot.get("success") is True
        )
        report = {
            "passed": passed,
            "provider": provider.name,
            "kernel_session_id": session_id,
            "kernel_browser_confirmed": kernel_browser_confirmed,
            "title": navigate.get("title"),
            "stealth_features": navigate.get("stealth_features", []),
            "fallback": bool(session.get("fallback_from_cloud") or navigate.get("fallback_warning")),
            "snapshot_success": snapshot.get("success") is True,
        }
    finally:
        cleanup_browser(task_id)

    # Confirm deletion with Kernel; do not print CDP URLs or response bodies.
    if session_id:
        response = requests.get(
            "https://api.onkernel.com/browsers/" + str(session_id),
            headers={"Authorization": "Bearer " + os.environ["KERNEL_API_KEY"]},
            timeout=15,
        )
        report["cleanup_confirmed"] = response.status_code == 404
        report["passed"] = report["passed"] and report["cleanup_confirmed"]
    else:
        report["cleanup_confirmed"] = False
    receipt = home.parent / "smoke-result.json"
    receipt.write_text(json.dumps(report, indent=2) + "\n")
    receipt.chmod(0o600)
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
