# Agent setup prompt

Exact Slack app configuration: [slack-app-manifest.json](../config/slack-app-manifest.json).

Paste this into your coding agent with the already-cloned repository open:

```text
First check this system for Git, uv, and Python 3.13. Detect the OS, architecture,
and shell. Verify versions against the repository's baseline, install anything
missing or incompatible, and install the locked Python dependencies into the
project's dedicated virtual environment. The current execution boundary uses
macOS Seatbelt; report incompatible platforms before claiming full support.

Import config/slack-app-manifest.json as the Slack app configuration,
preserving its declared scopes, events, interactivity, and Socket Mode settings.
Replace deployment-specific URLs/hostnames as needed, then install the app in
the operator's workspace. Configure the bot token, app-level token with
connections:write, workspace/operator IDs, and app client ID/secret. Register
the vault's HTTPS /auth/callback URL, update the preview domain for this
deployment if enabled, and invite the bot to the test channel. Reinstall the
app after scope changes.

Then set up Kernel Vault and the Kernel browser connection. Have
the operator use their own Kernel account and enter KERNEL_API_KEY privately in
the protected gateway home's mode-600 .env. Use the reviewed pinned Kernel plugin
and scripts/configure-clanker-kernel-browser. Install Node and the agent-browser
driver package on the trusted host, prepare the execution fleet with
scripts/prepare-clanker-execution, and accept the current policy through
scripts/enable-clanker-browser while the gateway is fully stopped. Inspect each
command's --help first. Browser Use, local Chromium and Composio browser setup
are not part of the current flow; do not introduce a fallback.

Read AGENTS.md, docs/SETUP.md, docs/INSTALL.md, config/hermes-baseline.json, and the relevant
scripts. Use the bundled, already-patched hermes/ source as shipped, with pinned
dependencies and existing integrations. Keep setup to dependency installation,
account/integration configuration, startup, and verification. Hermes patching
and rebasing are maintainer work; report code or platform blockers to the maintainer.
Preserve unrelated changes and existing credentials. Check --help or the man
page before using unfamiliar CLI options.

Ask only for required sign-ins, missing account details, or paid actions. Enter
operator integration secrets through hidden input into protected ignored local
configuration. Collect end-user credentials through Kernel's authenticated private
collection flow; do not create local credential stores or key files.

For API integrations, Kernel API-key fields use type text with sensitive:false
under the approved backend-readable policy. This is authenticated Kernel storage,
not public access. clanker_api_request takes an opaque saved handle and a JSON
request; only the trusted backend reads the key and injects authentication after
checking access and the exact HTTPS API origin. Never give the key to the model,
generated scripts, shell environments or logs. Passwords and TOTP seeds remain
sensitive and opaque. Existing sensitive API-key items cannot be exported or
retyped; use a replacement item and private recollection when needed. Do not
recollect when no saved API-key item exists. Verify tool registration and refusal
of unauthorized origins before claiming API execution ready; report live provider
acceptance separately from local checks.

Start the gateway and vault, verify service health, and test a fresh public-page
Slack task through Kernel. Check the actual page and reply destination, plus
private context handoff without copying DM dialogue to the shared channel.
Verify native payment tool discovery and private owner-approval guidance for
INR card purchases up to ₹500; never submit an order as a setup check. Optional residential proxies
require the Kernel entitlement and their explicit operator configuration.
Keep services running and report access URLs, passed checks, start/stop commands,
and concrete blockers. Execute through to a working instance; do not stop at a
plan or claim unverified platform support or retailer checkout success.
```
