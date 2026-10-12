# Kernel browser trial

> Historical trial record from October 8, 2026. For the current live Clanker
> integration, see [Kernel browser](KERNEL_BROWSER.md) and
> [access management](ACCESS_MANAGEMENT.md).

Status on October 8, 2026: Kernel 0.3.0 installed and enabled in the isolated
trial. Hermes resolves `KernelBrowserProvider`, and `agent-browser` is available.
Install scanning is restored. The user saved the API key privately, and the
live native Hermes browser test passed.
The active Clanker Slack gateway remains on its existing configuration.

Verified through the real `browser_navigate` and `browser_snapshot` functions:

- `https://example.com` returned the title `Example Domain`.
- A matching browser was retrieved from Kernel's API with stealth enabled.
- The tool result reported stealth and live view; no local fallback occurred.
- The browser snapshot succeeded.
- Hermes cleaned up the browser; Kernel returned 404 for the deleted session.

The redacted receipt is `.local/kernel-hermes-trial/smoke-result.json`.
This validates the native browser plugin; it does not test an LLM-driven chat,
Slack routing, vault login, or authenticated websites.

The trial uses the project Hermes source and existing Python environment at
`/Users/tanishqpalandurkar/Projects/yyot`, with separate state under
this checkout's `.local/kernel-hermes-trial/home`. It does not copy Slack,
Composio, vault, browser profile, or inference credentials.

## Reviewed installation exception

Reviewed upstream: <https://github.com/kernel/hermes-browser-plugin>
at commit `0f5a8e80707957a40b6a1e5512b2a391671e9317`, plugin version 0.3.0.

Installed:

```sh
scripts/kernel-hermes-trial plugins install kernel/hermes-browser-plugin \
  --ref 0f5a8e80707957a40b6a1e5512b2a391671e9317 --no-deps --enable
```

Hermes's scan reported a critical hardcoded secret in
`scripts/check-hermes-integration.sh:35`. Inspection shows the literal
`integration-test-key`, used for an offline registration test. The other five
findings concern `uv run` examples in documentation and development scripts.
The runtime consists of `__init__.py` and `provider.py`; it registers a browser
provider and sends authenticated requests to Kernel for browser creation,
proxy lookup, and deletion. Optional settings can override the API URL and
save browser state to a named Kernel profile. The trial's clean environment
does not supply those optional settings.

The user approved the exception: `plugins.scan_on_install` was disabled only in
the isolated trial for this pinned installation, with dependency installation
disabled. Scanning was restored immediately in a `finally` block and verified
as enabled afterward. The existing environment has `requests` 2.33.0.
The installed commit was verified, and the secret file has mode 0600.

## Private key and verification

1. Create a key in <https://dashboard.onkernel.com/api-keys> if needed.
2. Run `scripts/kernel-hermes-trial key` in your terminal. Input is hidden and
   saved only to the trial's `.env`, mode 0600.
3. Run `scripts/kernel-hermes-trial check`, then
   `scripts/kernel-hermes-trial smoke`.

The smoke command opens only `https://example.com` through the actual Hermes
`browser_navigate` and `browser_snapshot` functions. It requires the title
`Example Domain`, stealth enabled, no cloud fallback, and a matching browser
returned by Kernel's API. It cleans up through Hermes and verifies Kernel
returns 404 for that session afterward. It saves a redacted receipt to
`.local/kernel-hermes-trial/smoke-result.json`; CDP and live-view URLs are excluded.
This live test creates a cloud browser and may use Kernel credits.

For interactive agent use, configure inference in the isolated trial first,
then run `scripts/kernel-hermes-trial chat --verbose --toolsets browser`.
No inference credentials have been copied into the trial.

## Clanker integration

The existing Composio implementation is a separate browser tool/service path
with vault and requester routing. Selecting Kernel for native Hermes tools does
not port those behaviors. A Slack cutover needs the vault bridge and routing
adapted and tested against Kernel, including private credential entry,
requester-specific session state, and session cleanup.

The plugin reads credentials from process environment and supports a single
default `KERNEL_PROFILE_NAME`. Do not assume that this provides multi-user
account isolation in a shared gateway. This trial leaves profile persistence
unset and does not exercise authenticated websites.

Reference: <https://www.kernel.sh/docs/integrations/hermes-agent>
