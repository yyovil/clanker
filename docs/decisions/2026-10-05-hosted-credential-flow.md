# Clanker hosted credential flow

Status: the live local POC passed two end-to-end Slack runs with dummy credentials
on a controlled HTTP website. The local gateway and HTTPS form are active through
a temporary tunnel. Real Slack OIDC verified workspace `T0C6J1XCDE0` and owner
`U0C684PHZ5H`. A DM request completed hosted password save, automatic resume,
native browser login, hosted current-code submission, a second automatic resume,
and the correct authenticated private inbox answer. A shared-channel request
moved into the owner's DM, reused the saved login in a fresh browser, completed
code verification and kept the inbox answer out of the shared channel.

The live receipt is `verification/evidence/2026-10-05-hosted-vault-e2e.json`.
Google/Discord login, provider CAPTCHA/device approval and a second owner's live
OIDC flow remain unverified. This is a local POC acceptance, not production
deployment or a production tenant-isolation claim.

The current activation receipt is
`verification/evidence/2026-10-05-hosted-vault-activation.json`. The temporary
hostname is valid only while its tunnel process runs; a replacement hostname
requires updating the Slack redirect allowlist and protected gateway settings.

## Intended interaction

The [2026-10-06 channel detour decision](2026-10-06-channel-login-detour.md)
supersedes the shared-channel result behavior below for new channel tasks.
Login collection stays private; the requested final result returns to the
original thread. Its local verification and live activation status are recorded
separately. Existing private handoffs retain the behavior accepted here.

A user asks Clanker to check a private website account. If the request starts in
a shared Slack channel, Clanker moves the account operation and its results to
that requester's DM. The original goal survives the move.

Clanker opens the login page, checks the requester's existing vault, and fills
saved access when available. If a login is missing or its password is rejected,
the trusted handler sends a private **Add login to vault** link. The hosted page
checks Slack identity, shows the actual login hostname, and accepts email or
username, password and an optional authenticator setup key. Saving resumes the
original private task automatically. The user need not find the headless browser
or tell Clanker “done.” Expired cookies trigger a login using saved access first.

After a successful login save, the page shows a centered key/checkmark, **Vault
updated**, and “Your login is saved. Clanker will continue your task
automatically.” **Return to Slack** opens the authenticated owner's private
conversation with Clanker using Slack's [conversation redirect](https://docs.slack.dev/interactivity/deep-linking/).
**Open vault** opens account management. Verification-code submission uses the
same layout with **Verification submitted**. The confirmation appears only after
the durable save succeeds; a failed submission keeps the form available to retry.
Existing gateway processes serve the updated assets immediately. Until the next
gateway restart loads the new response handler, **Return to Slack** uses Slack's
native app opener; afterwards it targets the owner's private DM.

The 5 October confirmation update passed all 21 HTTP/storage tests and browser
checks against the isolated dummy-data fixture: desktop/mobile login completion,
mobile code completion, failed-save retry, keyboard focus, clearing submitted
values/link tokens, the vault-management link, and compatibility with an older
save response. The generated private-DM destination was checked for both owners;
launching a real Slack client was not part of this UI check. The running gateway
was checked to serve the updated HTML, JavaScript and CSS without restarting it.
[Desktop preview](../../output/playwright/clanker-vault-updated-desktop.png),
[mobile preview](../../output/playwright/clanker-vault-updated-mobile.png),
[code confirmation](../../output/playwright/clanker-verification-submitted-mobile.png).

An authenticator key lets the native browser tool generate later codes. Without
a key, a code challenge sends a separate hosted **Enter verification code** link.
The current code is encrypted, expires at most 90 seconds after submission, and
is consumed once. Device approval prompts still require the owner to approve
them on their device. No password, setup key or current code belongs in Slack.

## API-key collection template

The hosted page now has a separate `api_key` form with one masked **API key**
field, a reveal toggle and **Save to vault**. Its heading comes from the access
request's `label`; no provider name is built into the template. Login and current
verification-code forms keep their own fields. Successful API-key saves use the
same **Vault updated** confirmation and private **Return to Slack** destination.

`clanker_request_access` accepts `kind: api_key`, a request-defined title and the
exact HTTPS API origin. It does not require a browser login page. Shared-channel
requests move into the owner's DM. The existing Slack identity, CSRF, one-use
link, encrypted native storage and durable resume checks also cover API keys.
Only a handle and safe metadata reach the resumed agent; submitted values clear
after a successful save and remain available after a failed save for retry.
The management page lists API-key metadata and supports removal.

This checkpoint implemented collection and storage only. Authenticated HTTP calls using a
saved API-key handle remained unimplemented at this checkpoint, so this did not yet complete the
original API task. Agent guidance stated that limit and prohibited asking Slack
users for local key files or environment variables. The running gateway needs
its next restart and a new task to load the new request schema and prompt;
local HTTP/browser verification does not establish live Slack activation.

The [2026-10-06 invitation implementation](2026-10-06-vault-invitations.md) adds
origin-bound API execution for owned and invited handles. Its verification and
activation limits are recorded separately.

## Ownership and storage

The gateway binds a generic `GatewayTurn` after authenticated source routing.
The Clanker tools derive the owner, workspace, private home and task from that
context. A model supplies only a display label, visible identifier or opaque
vault handle. It cannot choose a user, profile path, origin, access token or
resume destination. Ordinary CLI/cron calls have no ambient vault authority.

Slack OIDC uses browser-bound, one-use state and nonce, an RS256 signature from
Slack's published keys, the exact client audience, issuer and expiry. The saved
Slack team/user must match the access request and current membership registry.
A copied link does not grant another Slack user access. The page uses secure,
HttpOnly, SameSite cookies and origin plus CSRF checks for mutations. Link
tokens live in URL fragments, are removed from the address bar, and are never
sent as HTTP query strings or returned to the agent. Responses disable caching
and referrers. Request bodies and access links have no server access log.

Passwords and authenticator keys use Hermes's native encrypted `VaultStore`
under the owner's private `<profile>/vault`. Task metadata and encrypted
temporary codes live in the protected gateway `.clanker-vault` directory. Keys
and credential files are outside generated browser/terminal code's Seatbelt
allowlist. This retains the existing local Mac operator trust boundary; it is
not a separate secret-management service or production tenant-security claim.

Filling uses a verified owner-local CDP endpoint and checks the exact saved
origin before inspection and again during the write. Secret-bearing JavaScript
travels over the native supervisor WebSocket, never subprocess arguments. Native
redaction registers the exact secret before filling and scrubs browser and
terminal outputs. This is an output guard, not a guarantee against arbitrary
malicious transformations of a value by code that can control its authorized
browser. The model receives handles, metadata and fill counts.

## Recovery, reuse and removal

Requests and private handoffs are durable SQLite outboxes. The native encrypted
save fsyncs before the request becomes ready. An idempotency key makes the
crash gap recoverable without creating duplicate vault entries. Saving a replacement
removes older entries only for the same origin and identifier. Private handoffs
deduplicate pending copies of the same goal; later goals and repeats after
completion can proceed in the same Slack session. Saved requests
resume through the existing gateway message, agent, transcript and delivery
path. Membership polling does not wait for the resumed agent. A matching native
delivery obligation prevents a completed resume from being re-executed after
the outbox acknowledgement gap. An interrupted unfinished task may run again;
this is not an exactly-once guarantee for arbitrary website side effects.

Managed browser contexts opt into stable names for local sessions. Their names
include the private home, so explicitly named website sessions can reuse their
own profile after Chromium or gateway restart. Real-profile/cloud modes and
private-network sidecars keep their previous behavior. This was needed because
stock local sessions use random daemon names, producing new on-disk profiles
after cleanup. The prompt recommends consistent website session names.

`/stop`, `/new` and `/reset` cancel pending access and private-handoff requests.
Old forms then fail instead of restarting the task. `/vault` lets an
authenticated owner manage saved logins even without a pending access request.
Disconnect removes the selected credential, cancels outstanding account work,
interrupts the owner's running DM tasks, stops recorded owner browser processes,
and removes all of that owner's Chromium profiles. Clearing all owner sessions
also removes cookies established by federated login on another website.

## Native integration

- `runtime/vault`: form, Slack OIDC, encrypted-code/request outboxes and scoped tools.
- `runtime/seatbelt`: plugin discovery, prompt and sandboxed execution surface.
- `runtime/slack_workspace.py`: gateway service startup and membership polling.
- `hermes/agent/gateway_context.py`: generic context available to native plugins.
- `hermes/gateway/plugin_control.py`: generic profile-scoped control notification.
- `patches/hermes/hosted-vault.patch`: additive generic Hermes changes, audited-pin only.

The six advertised tools are `browser_exec`, `terminal`,
`clanker_request_access`, `clanker_vault_list`, `clanker_vault_fill`, and
`clanker_vault_enter_code`. External password-manager auto-discovery is disabled
in managed contexts. The vault is unavailable until its hosted service is
configured; that failure must be stated instead of requesting sign-in to an
inaccessible browser.

## Activation

1. Choose the HTTPS origin. Run a reverse proxy/tunnel to `127.0.0.1:8767` on the
   same Mac as the gateway. Keep the vault service itself loopback-only.
2. Configure the Slack app's Sign in with Slack/OpenID scopes (`openid`,
   `profile`) and exact redirect URL `https://<chosen-host>/auth/callback`.
   These are separate from the existing bot token scopes.
3. Run `scripts/configure-clanker-vault --public-url https://<chosen-host>
   --client-id <Slack-client-id>` in an interactive terminal. It prompts for the
   app client secret without echo, stores it in the protected gateway `.env`,
   and writes `.clanker-vault/config.json`. It does not deploy or restart.
4. After the HTTPS/OIDC configuration is ready, restart with
   `scripts/hermes-lab gateway run -v --replace`. Start a new Slack task so the
   new tool definitions and prompt are loaded. Then accept a real owner's
   hosted sign-in/save/resume flow before calling the live issue fixed.

Use [Slack's OIDC documentation](https://docs.slack.dev/authentication/sign-in-with-slack/)
for app configuration. A temporary tunnel URL must be updated in both the Slack
redirect allowlist and Clanker configuration whenever it changes.

The loopback UI demo (`verification/probes/clanker_vault_ui_demo.py`) is an
isolated dummy-data fixture with a fixture-only entry route. It has no Slack
connection or resume agent and is not a deployable credential endpoint.
