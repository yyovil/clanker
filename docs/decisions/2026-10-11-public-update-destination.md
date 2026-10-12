# Deliver private-task readiness to the recalled planning thread

## Finding

The travel task posted readiness to the new handoff request thread rather than the earlier planning thread requested by the user.

Evidence: [original Slack task](https://clanker-global.slack.com/archives/C0C6J277ZNG/p1791658782452879); QA run `r20261011-002942-sort-out-travel-67e0`; Hermes session `20261011_002958_8ddb8a32`. The original benchmark ran late 10 October through early 11 October 2026 IST. Time-only Kernel correlations are intentionally excluded pending exact-thread recollection.

## Change

Allow an optional public thread timestamp only if same-turn trusted recall evidence identifies it in the originating channel. Persist that destination in the private update envelope, revalidate its live root and ownership before sending, and include it in delivery and deduplication identity. The model cannot override the channel or owner.

## Validation and limits

Five new destination tests passed in the 41-test recall/handoff batch, including unobserved and cross-channel rejection. No production messages have been moved or posted by this code change; the live scenario remains required.

Status: activated through the QA restart workflow on 11 October 2026 at 02:44 IST (gateway PID 58797; Slack connected). Real-site verification is in progress; no new benchmark pass is claimed.

## Round 6 recurrence and deterministic guard

Run `r20261011-162819-sort-out-travel-67e0` recovered the correct planning root `1791715417.473369` through authorized recall, but both model-issued final updates omitted `thread`. The backend consequently used the new [handoff request root](https://clanker-global.slack.com/archives/C0C6J277ZNG/p1791716299112579). The final update was meant for the [planning thread](https://clanker-global.slack.com/archives/C0C6J277ZNG/p1791715417473369). Exact private continuation root: `1791716309.788959`; the relevant tool calls occurred at 16:35 and 16:38 IST on 11 October. The existing description already instructed the model to supply a recalled target, so further wording alone would not prevent this omission.

The registered model tool now calls the owning public-update method with destination selection required for final updates. An omitted target returns `destination_required` before any outbox entry or Slack post. Its `handoff_thread` is explicitly identified as the request that opened the DM, not necessarily the intended planning thread. The model must choose the intended root. The bound source root is authorized directly; any alternative still requires trusted recall in the current turn and validation in the same originating channel. A recalled thread is never selected automatically.

Model progress keeps its bound default. Internal service/recovery finalization retains its existing default and does not pass this model-only requirement. No service or store changes were made for this followup.

The four new registered-tool destination cases failed before the change; the six existing/default-preservation cases passed. All ten destination cases now pass. The final canonical focused run passed 49 checks across destination, continuation, fresh-auth routing, recalled handoff and isolated shared recall, with zero retries. Broader legacy channel/public-update suites had 31 failures and 13 passes: the exact failure IDs match the existing retired-local-Vault baseline, with no new IDs. All 15 legacy channel failures were additionally reproduced using an isolated copy of this change's own pre-edit source. These legacy failures remain visible in `round6-validation.json`; they are not described as a green full suite.

Snapshots and logs are in `.local/clanker-qa/findings/handoff-update-wrong-planning-thread/`. The original deployment's finding metadata and snapshots were archived before resetting the active rollback baseline to the four current owned files: channel tasks, tool routing, destination tests, and this document. The pre-edit tool snapshot includes the separately prepared fresh-auth fix; original capture timestamps are retained. Stale service/store paths from the first deployment are excluded from this followup's active rollback set.

This followup is locally verified and awaits coordinator-controlled idle activation and live benchmark verification. No Slack message, provider mutation, restart, or historical verdict promotion was performed during the repair.
