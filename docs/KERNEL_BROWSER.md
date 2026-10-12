# Kernel browser integration

Clanker uses the pinned [Kernel Hermes plugin](https://www.kernel.sh/docs/integrations/hermes-agent) through its authenticated native browser tools. Website browsing, shopping, login and personal-detail forms use Kernel exclusively. Foreground Python and shell work retain the separate macOS Seatbelt terminal sandbox. There is no local Chromium or Composio browser fallback.

The adapter loads the reviewed upstream `provider.py` at commit `0f5a8e80707957a40b6a1e5512b2a391671e9317` from the protected backend. It checks SHA-256 `475e97022b4015beda641028cedccbfa0333d7dea09995a1a9f99edd903a8683` before loading. The raw Kernel plugin is not separately enabled in member profiles. Its service key comes from the protected backend `.env` without changing process environment or copying the key to requester profiles.

## Browser and vault behavior

- Each workspace, requester and execution home has protected browser state; each conversation thread has its own remote browser. Native task keys also include the authenticated requester, so a common Slack task ID cannot attach two people to one browser.
- Kernel Managed Auth saves a successful login profile. The owner can select that verified account in another thread in their canonical DM; each thread launches a separate browser with the same read-only snapshot (`save_changes: false`). Invited accounts and isolated task workers remain task scoped. Session and underlying CDP resource claims prevent reuse across requesters. Native calls verify the live Kernel API record, remote session ID, name, stealth setting, exact profile binding and stable browser routing identity before control. Kernel returns refreshed JWT capabilities; their full string is not a stable browser identifier.
- Kernel hosts website sign-in, passwords and fresh verification codes. The trusted supervisor handles ordinary personal details on the verified browser. Values stay out of model arguments; explicitly consented personal reads use their separate policy.
- Shared-channel private handoffs retain the originating conversation internally. Private questions, details and ordinary replies stay in the owner DM. The original channel receives separate brief milestones and a public outcome through `clanker_task_update`, without copied DM dialogue.
- Discovery checks the protected Kernel configuration, reviewed provider hash, service key and accepted host driver. It does not depend on a requester-accessible CLI wrapper or installed local Chromium. Vision is available only when its model requirements are satisfied.
- Legacy `browser_exec` and Composio browser calls are rejected before execution. Native cloud errors cannot start local Chromium. Private URL sidecars, extensions, local fallback and real desktop profiles are disabled.
- Native card payment covers INR purchases in India up to ₹500. Select Pay by card / Add New Card, then call `clanker_request_payment` with the merchant, the observed amount in paise and the final Pay button; the purchase is bound to that browser, page and button. Without a remembered card, the owner approves a private Pay ₹X request, can choose to remember the card, and enrolls it in Kernel's hosted form. With a remembered card, the owner's instruction to pay is enough and the request continues without another Clanker approval; Kernel still requires a Visa passkey approval. `clanker_payment_fill` and then `clanker_payment_submit` fill through Kernel and click the bound button once. Ordinary browser Pay clicks remain prohibited and uncertain payments are never retried. After observing an explicit merchant success or definite failure, report it with `clanker_payment_complete`; `clanker_payment_receipt` is only for older purchases. Local fixtures do not establish live merchant acceptance; reload the gateway and verify its actual tools and prompt before reporting activation.
- `clanker_browser_stop` selects the authenticated thread itself. Normal stop deletes the task browser and releases its account selection while retaining a verified successful owned login in the canonical DM. Explicit purge, account deletion and privileged home cleanup remove saved auth profiles too. Deletion requires a successful delete and subsequent Kernel API 404. Uncertain creation or cleanup remains recorded and blocks reuse. Revoking invited access closes the recipient's affected browsers before cleanup is confirmed.

## Prepare and activate

The operator command previews by default and never restarts the gateway. It requires the reviewed Git checkout, private key file, configured Slack membership/vault and a prepared execution fleet. It snapshots affected configs and `.env` with mode 0600. Read its `--help` and the [operator setup](SETUP.md) before applying to a running installation.

```sh
scripts/configure-clanker-kernel-browser \
  --plugin-source /path/to/reviewed/hermes-browser-plugin \
  --key-env /path/to/private/trial/.env
```

After approval to change the live gateway, stop it with zero active agents and repeat with `--apply`. Accept the current Kernel-only execution policy using `scripts/enable-clanker-browser --home /absolute/gateway/home`, then start the gateway. Acceptance verifies the terminal boundary, removes old profile browser wrappers and stops only owned legacy local browser processes. New execution profiles use the protected Kernel provider automatically.

Use the returned rollback snapshot with `--restore-backup /absolute/snapshot/path` to preview restoration; add `--apply` only for a reviewed compatible Kernel configuration. Historical Composio records and backups are retained as evidence, not an active browser option. Removing the integration does not prove deletion of old remote Composio resources.

## India residential proxy

`scripts/configure-kernel-residential-proxy` previews with authenticated reads only. It checks the organization's managed-proxy entitlement and the complete proxy list. It adopts the configured proxy ID or the unique name `clanker-india-residential`; the accepted policy is residential egress in India, without extra location selectors or bypass hosts. Credentials remain in the protected backend `.env`.

```sh
scripts/configure-kernel-residential-proxy --home /absolute/gateway/home
```

For `--apply`, first stop the owning gateway completely with zero active agents. Apply creates the named proxy only if absent, checks its health, verifies the exact available remote resource, and atomically adds `proxy: {id, type: "residential", country: "IN"}` to the protected Kernel config. It snapshots the previous config with mode 0600 and preserves the other settings. It never restarts the gateway, deletes a proxy/browser or sends Slack messages. `--proxy-id ID` selects an existing India residential proxy explicitly.

If a create request loses its acknowledgement, a protected dispatch marker blocks another creation. Rerunning can recover only the exact unique named proxy and then pins its ID; if it is absent or ambiguous, investigate the marker instead of repeating creation. Use the returned `--restore-backup /absolute/snapshot/path` to preview a SHA-checked config rollback; add `--apply` while the gateway is stopped to restore it. Restoration leaves the remote proxy intact.

Restart through the existing gateway procedure after applying. Every browser must match the current protected routing policy before control or private fill; an old default-egress browser is blocked when residential routing is configured. Stop and reopen an incompatible browser in the same task to apply the current policy. A confirmed expired remote browser can be recreated there automatically. Changing Slack threads is not required, and changing the backend setting does not silently move an existing remote browser. Runtime checks also require the residential proxy's exact ID, India routing and availability. Proxy health alone does not prove that a retailer permits the session or that ordering succeeds.

## Verification

`scripts/kernel-clanker-smoke --help` describes the explicit live check. It stages a fresh isolated backend, reads the existing private trial key, and opens public Example Domain browsers for two synthetic owners through the real model-tool dispatcher. It checks owner separation and A → B → A reattachment, fills a synthetic password in a DOM-only fixture without submitting anything, verifies redaction, and confirms deletion. It never sends a Slack message or uses an actual website account.

Fixtures cover vault storage and handlers for password/SMS/TOTP/personal/invited fills, revocation, cleanup failures, endpoint collisions, metadata tampering, native schemas and restart redaction. `verification/probes/test_kernel_only_routing.py` checks discovery, stale-tool denial, protected driver readiness, terminal availability and private owner-approved payment guidance. `verification/probes/clanker_kernel_discovery_profile_probe.py` checks real A → B → A plugin discovery and fixture dispatch without provider requests or browser launches.

Earlier integration evidence is recorded in `verification/evidence/2026-10-08-kernel-integration.md`; historical local-checkout checks do not describe the current browser flow. Retailer login, Add to Bag and ordering need fresh website-specific evidence. Public/synthetic probes and proxy health do not establish that Apple, Blinkit or Instamart checkout succeeds.
