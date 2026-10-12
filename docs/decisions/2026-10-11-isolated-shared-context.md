# Recover an earlier shared plan inside its private worker

## Finding

The linked private travel worker could not recover the existing offsite plan because shared recall assumed an ordinary owner DM home. The task therefore re-asked for details already available in the originating channel.

Evidence: [original Slack task](https://clanker-global.slack.com/archives/C0C6J277ZNG/p1791658782452879); QA run `r20261011-002942-sort-out-travel-67e0`; Hermes session `20261011_002958_8ddb8a32`. The original benchmark ran late 10 October through early 11 October 2026 IST. Time-only Kernel correlations are intentionally excluded pending exact-thread recollection.

## Change

Resolve the isolated task from the durable routing record and allow recall only from its originating served shared channel. Verify transport identity, eligible requester and current channel membership before disclosure. Published bot replies are assistant evidence; API-posted human messages remain human. Resolve #channel-name only among already authorized channels.

## Validation and limits

The latest recall/handoff batch passed 41 tests, with two additional recalled-handoff tests passing in the auth batch. Private histories remain unavailable in shared channels or other owners DMs. Live offsite recovery is unverified.

Status: activated through the QA restart workflow on 11 October 2026 at 02:44 IST (gateway PID 58797; Slack connected). Real-site verification is in progress; no new benchmark pass is claimed.

## Follow-up: implicit search selected its own handoff

A fixture audit on 11 October found another concrete gap: when a newer handoff request repeats “Goa offsite,” both the saved-history search and the live-history fallback choose that request instead of the earlier plan. The worker already receives this handoff context, so the result can conceal the shared itinerary and participants' earlier preferences. The original implicit-recall test did not include a current matching handoff in either history source.

Implicit search in an isolated worker now excludes only the exact originating public thread from its durable, validated task route. It still searches only the authorized origin channel. An explicit thread timestamp can read the handoff's own public clarifications, and ordinary owner-DM/shared-channel recall retains its behavior. If the current handoff is the only match, the tool returns no prior thread rather than relabeling the request as recovered context.

Before the change, the two history-path regressions and the no-prior-match regression failed; the explicit-current-thread control passed (3 failed, 7 passed). Review additionally caught a changed ordinary-lookup fallback when the newest matching history record has a null or empty thread ID. Both regression cases failed before the exclusion predicate was made explicitly optional. The final canonical runner passed 47 tests across isolated shared recall, ordinary recall, recalled handoff, public destination, and isolated owner retry. Existing owner, channel, membership-revocation and explicit lookup coverage passed. No Slack API or browser was used by these fixture tests.

Current follow-up status: **deployed, live acceptance pending**. The idle QA restart activated the follow-up at 15:09 IST on 11 October (PID 98832; `clanker-qa-restart-20261011T093904Z.log`) and Slack reconnected. Google Docs authentication remains a separate prerequisite; this change does not create or update a Doc, verify participant-specific travel changes, or establish a new benchmark success. A current-source snapshot is retained under `.local/clanker-qa/findings/handoff-prior-plan-unavailable/before-current-repair/`, in addition to the finding's original snapshot.
