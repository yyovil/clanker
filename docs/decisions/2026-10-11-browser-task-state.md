# Persist task browser state without concurrent profile writers

## Finding

The verified Apple bag was empty after the task browser was stopped and reopened. Anonymous browsers had no persisted profile. Authenticated automation browsers also loaded profiles without saving changed cart state.

Evidence: [original Slack task](https://clanker-global.slack.com/archives/D0C6F49F2KD/p1791658186913709); QA run `r20261011-001947-add-13-inch-3755`; Hermes session `20261011_001950_ba8abced`. The original benchmark ran late 10 October through early 11 October 2026 IST. Time-only Kernel correlations are intentionally excluded pending exact-thread recollection.

## Change

Create opaque requester-owned task profiles and save changes on verified browser close. Preserve those profiles for reopening, bind saved Vault login profiles to their access handle, and reuse the same owned account profile across later DM threads. Recheck access before loading cookies. A profile may have only one live or unacknowledged writer; failed deletion keeps it blocked. Reauthentication drains only its own task. Explicit owner cleanup also removes retained guest profiles.

## Validation and limits

The final browser/Vault run passed 284 tests in eight files. Its client suite then passed 66 tests after two fixture updates, including new profile API contract checks; combined, 350 tests passed across nine files. Nine lifecycle tests cover profile continuity, ownership, single writers, cleanup and uncertain creation. Eight tests that still require the removed local secret store are explicitly strict expected failures and are not counted as passes. This does not prove Apple cart persistence or site login validity until the live rerun.

Status: activated through the QA restart workflow on 11 October 2026 at 02:44 IST (gateway PID 58797; Slack connected). Real-site verification is in progress; no new benchmark pass is claimed.

## Live Apple continuity acceptance

Independent review of `r20261011-035107-add-13-inch-3755`, Hermes session `20261011_035112_d983f9f3`, verified the bag at 04:01:33 IST and an explicit browser stop at 04:01:47 with `profile_retained=true`. A fresh browser showed the same requested quantity-one configuration at INR149900 at 04:05:53 without re-adding it. The initial reopened page required a reload before the retained bag rendered; this recovery is retained in the evidence.

The old browser `huxgbe2bsyuqp0wlfh13zfwj` and new browser `n669rf7izdwo3wcvrha3c9aq` used the exact owned profile `xtfcppj6jla98v8rvf4o50qd`, with `save_changes=true`; the old browser was deleted before the new one was created. Finding `apple-bag-continuity` is therefore **verified**. This proof is specific to the observed bag persistence and does not establish fresh authentication, every site's storage behavior, or server-side payment-stage submission. No order or payment was made.
