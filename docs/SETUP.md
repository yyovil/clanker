# Clanker operator setup

For agent-guided setup, paste the [setup prompt](SETUP_PROMPT.md) into your coding
agent with this repository open. This guide describes the current local POC.
Complete browser activation on a clean machine still needs verification.

## Runtime and model

Install the pinned environment using the [installation guide](INSTALL.md). The launcher creates
`.local/hermes-lab/home/config.yaml` from the initial baseline only if it does not
already exist. It also creates a mode-600 `.env`. Configure inference interactively
with `scripts/hermes-lab model`, preserving `auth.adopt_external_logins: false`.

Current development uses `gpt-6.1-sol` through `openai-codex`. A new operator must
authorize their own eligible account or choose another Hermes-supported provider.
Do not copy development authentication into a submission or another installation.

## Slack app and membership

Create the app from the [manifest](../config/slack-app-manifest.json),
enable Socket Mode, create an app-level token with `connections:write`, and
install the bot in the intended workspace. Record the workspace ID and operator
member ID from Slack. Put the real tokens only in the local `.env`:

```dotenv
SLACK_BOT_TOKEN=REPLACE_LOCALLY_WITH_BOT_TOKEN
SLACK_APP_TOKEN=REPLACE_LOCALLY_WITH_SOCKET_MODE_TOKEN
```

Merge this configuration into `.local/hermes-lab/home/config.yaml`, replacing
both ID placeholders. Preserve the model and baseline security/display settings:

```yaml
gateway:
  multiplex_profiles: true
  platforms:
    slack:
      skip_context_files: true

slack:
  require_mention: true
  unauthorized_dm_behavior: ignore

platforms:
  slack:
    enabled: true
    gateway_restart_notification: false
    typing_indicator: true
    extra:
      allow_admin_from:
        - OPERATOR_MEMBER_ID
      group_allow_admin_from:
        - OPERATOR_MEMBER_ID
      user_allowed_commands:
        - status
        - stop
      group_user_allowed_commands:
        - status
        - stop
      reactions: true
      acknowledgement_reactions: true
      workspace_membership:
        enabled: true
        workspace_id: WORKSPACE_TEAM_ID

platform_toolsets:
  cli: []
  slack: []
```

Starting with empty toolsets keeps chat available while execution is being
prepared. The verified execution plugin supplies `clanker_browser` only after
activation; adding that name by itself does not install or verify a browser.

For a fresh installation, the controller provisions eligible current workspace
members into new profiles. Existing installations may use an explicit
`workspace_membership.existing_profiles` mapping, but must verify those profiles'
ownership before reusing them. The configured workspace and current channel/bot
membership govern admission; an old owner-only `SLACK_ALLOWED_USERS` or channel
allowlist can prevent the intended member experience. Review existing restrictions
deliberately rather than blindly replacing a production configuration.

The manifest subscribes to `team_join`, `user_change`, `member_joined_channel` and
`member_left_channel`, which the membership controller handles. Slack documents
the [member-join](https://docs.slack.dev/reference/events/team_join/),
[member-change](https://docs.slack.dev/reference/events/user_change/),
[channel-join](https://docs.slack.dev/reference/events/member_joined_channel/) and
[channel-leave](https://docs.slack.dev/reference/events/member_left_channel/) events.
Their required scopes are already in the manifest. A local manifest edit does
not update an installed Slack app.

Invite the app to the intended demo channels. Workspace identity is the admission
boundary: this configuration enables eligible members of that workspace, not just
the operator. Use a dedicated demo workspace.

## Kernel driver and terminal sandbox

The current execution boundary uses macOS Seatbelt. Install Node and the
`agent-browser` package on the trusted host. Kernel hosts Chromium; Browser Use,
local Chromium and requester browser wrappers are not required or permitted.
Python and shell work retain their foreground terminal sandbox.

Inspect the operator commands before preparing the fleet:

```sh
.local/hermes-lab/venv/bin/python scripts/prepare-clanker-execution --help
scripts/enable-clanker-browser --help
```

Prepare with the absolute gateway home, Node executable and installed
agent-browser package directory:

```sh
.local/hermes-lab/venv/bin/python scripts/prepare-clanker-execution \
  --home /ABSOLUTE/GATEWAY/HOME \
  --node /ABSOLUTE/PATH/TO/node \
  --agent-browser-package /ABSOLUTE/PATH/TO/agent-browser
```

Preparation installs protected contexts and verifies the primitive terminal
boundary. It does not grant Slack tools. Configure Kernel below, then run
`scripts/enable-clanker-browser --home /ABSOLUTE/GATEWAY/HOME` while the gateway
is fully stopped with zero active agents. Acceptance verifies the current policy,
removes old profile browser wrappers, stops owned legacy local browser processes
and activates Kernel-only tools. It never restarts the gateway.

The launcher restores the public-web terminal egress broker when the fleet
exists. Missing or unaccepted policy must leave browser execution unavailable.
The [earlier execution decision](decisions/2026-10-05-local-execution-boundary.md)
is historical evidence; its local-browser flow is no longer supported.

## Hosted vault

After the gateway has created `slack_membership.json`, expose its loopback vault
service through HTTPS. Register `https://YOUR_VAULT_HOST/auth/callback` in the
Slack app's Sign in with Slack redirect configuration, then run interactively:

```sh
scripts/configure-clanker-vault \
  --public-url https://YOUR_VAULT_HOST \
  --client-id YOUR_SLACK_APP_CLIENT_ID
```

Use the app's numeric client ID. The script prompts privately for the client
secret if it is absent. It writes configuration for loopback port `8767` by
default; it does not deploy the HTTPS proxy or restart the gateway. Run the proxy
and gateway, then verify the public `/health` endpoint, Slack OIDC callback and an
owner-bound access request.

A temporary tunnel's hostname can change. Keep the registered callback and local
vault origin synchronized; links already sent to Slack retain their old URLs.

## Kernel browser

Use the operator's Kernel account. Enter `KERNEL_API_KEY` privately into a mode-600
local `.env`; never paste it in Slack or commit it. Obtain and review the pinned
plugin source documented in [Kernel integration](KERNEL_BROWSER.md). Clanker
loads that provider from protected backend storage, without enabling a raw
Kernel plugin in member profiles or copying its key there.

With Slack membership, hosted vault and the prepared fleet present, preview:

```sh
scripts/configure-clanker-kernel-browser \
  --home /ABSOLUTE/GATEWAY/HOME \
  --plugin-source /ABSOLUTE/REVIEWED/KERNEL/PLUGIN \
  --key-env /ABSOLUTE/PRIVATE/KEY/.env
```

After reviewing the preview, stop the gateway completely and repeat with
`--apply`. Accept the current execution fleet using `enable-clanker-browser`
before starting the gateway. Configuration snapshots contain private data and
must remain in protected ignored storage.

Optional India residential routing uses
`scripts/configure-kernel-residential-proxy --home /ABSOLUTE/GATEWAY/HOME`.
It previews first; `--apply` requires the managed-proxy entitlement and stopped
gateway. Existing browsers with a different routing policy are blocked from
control and private fills. Stop and reopen them within the same task to use the
current policy; a fresh Slack thread is not required. A healthy proxy does not
prove a retailer allows checkout.

Kernel receives website content and entered login secrets. See
[access management](ACCESS_MANAGEMENT.md) for requester binding, deletion checks
and provider trust limits. All shopping, login, personal-detail and payment forms
stay in the same Kernel browser. Card payment covers INR purchases up to ₹500;
see [Kernel integration](KERNEL_BROWSER.md) for the approval and remembered-card
flow, and never submit an order as a setup check. There is no local or alternate
browser fallback.

## Start and check

```sh
scripts/hermes-lab gateway run -v
```

Keep that foreground process open. In a second terminal:

```sh
scripts/hermes-lab gateway status
```

Check member provisioning, a DM browser task and a channel mention using public
pages. Inspect the actual page and reply destination. For an intentional restart,
account for active work first, then use `scripts/hermes-lab gateway run -v --replace`.
No system service is required for this local POC.
