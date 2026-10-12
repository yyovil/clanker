# Slack message edits

Status: implemented and verified locally on 6 October 2026 (Asia/Kolkata), then activated by the owner's approved gateway restart at 21:58 IST. Slack reconnected and the local and public vault endpoints passed their after-restart checks. Live edited-message visual acceptance remains pending.

A human text edit replaces the request represented by that Slack message. During active work, Clanker hard-interrupts the old agent, invalidates its delivery generation and runs the latest version. After completion, Clanker runs the edited task and updates its existing response. If the response spans several Slack messages, the retained messages are updated, additional chunks are appended when needed, and surplus response chunks are removed.

Edits are ordered by Slack's `edited.ts` and scoped to workspace, channel, author and original message timestamp. Replays, older revisions, unchanged text, bot edits and link-preview changes do not start another task. A queued request is replaced in its queue position. Unrelated queued requests survive an active-request cancellation. An edit arriving during sender or media enrichment prevents the older version from being dispatched. Existing membership, authorization and channel admission checks still apply.

The agent receives a per-turn note identifying the latest request as a replacement. Earlier conversation history is retained; the change does not rewrite the cached system prompt. Native cancellation uses Hermes's hard-interrupt and generation checks, with a bounded wait for the old adapter task to unwind. It cannot undo actions completed before the edit arrived.

The adapter persists text hashes, message identities, response message IDs and delivery-obligation versions in `slack-message-edits.sqlite` under its owning Hermes home. Raw request text and credentials are not added to that mapping. Completed-response reconciliation survives a gateway restart. Obsolete delivery obligations are withdrawn, and recovery carries their identity so a retry already claimed before an edit cannot replay the old answer. Recovery of the current version updates the same retained response.

For channel tasks with a private login detour, an edit revokes the matching message's forms and worker before starting its replacement. Another request from the same member in the same thread retains its worker. Channel-result publication checks the originating request version and updates a previously tracked response when present. Cleanup failures block replacement rather than allowing the old worker to continue alongside it.

Mappings begin with requests processed by this implementation. Replies sent before activation have no saved mapping and cannot yet be updated automatically. The verified scope is Clanker's current text-reply configuration, which has token streaming disabled. Native token-stream replacement, attachment retraction and exactly-once delivery after an unknown Slack acknowledgement remain outside this acceptance.

## Verification

Two behavior tests exercise the real Slack adapter, Slack SDK over loopback HTTP, native run generations and hard interruption, SQLite persistence, queued-final delivery and the real recovery send path. They cover active and queued edits, rapid supersession, edits during intake, stale/replayed/no-op edits, link previews, completion updates, response chunk removal, restart recovery, obsolete retries and current-version recovery.

A coordinator test uses real provisioning, SQLite and native interruption to verify that editing one request cancels its private worker and forms while another request by the same owner in the same thread remains active. Existing Slack acknowledgement, native streaming, delivery-ledger and channel-control tests are included in the affected checks.

The canonical `hermes/scripts/run_tests.sh` run passed 337 tests across 11 affected files with zero failures. All 13 installed patches reverse and reapply in a scratch checkout, and the 37 resulting files match their original bytes. The implementation patch excludes the concurrent SMS login changes.

The same two response contracts fail against the saved pre-change adapter: the active edit never interrupts the original, and the completed edit leaves the original response unchanged. The ignored local receipt directory is `.local/slack-edits-20261006/`. The incremental implementation patch is `patches/hermes/slack-message-edits.patch`.

Local verification used no Slack test messages, app permission changes or gateway restart. The owner subsequently approved activation. The idle gateway was replaced, changing its PID from 19540 to 36945; the separate Cloudflare tunnel process (PID 90242) and its public origin stayed unchanged. The activation receipt is `verification/evidence/2026-10-06-slack-edits-gateway-restart.md`.
