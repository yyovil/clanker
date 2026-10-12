# Correlate benchmark evidence by task rather than time

## Finding

The collector included unrelated parallel tasks in the same owner DM when their timestamps fell within a run window. Old evidence explicitly contains both time-match and thread-match sessions.

Evidence: [original Slack task](https://clanker-global.slack.com/archives/D0C6F49F2KD/p1791658186913709); QA run `r20261011-001947-add-13-inch-3755`; Hermes session `20261011_001950_ba8abced`. The original benchmark ran late 10 October through early 11 October 2026 IST. Time-only Kernel correlations are intentionally excluded pending exact-thread recollection.

## Change

Restrict Slack roots, Hermes sessions and Kernel contexts to the run exact threads plus durable handoffs with the same workspace and tester owner. Remove the time-only fallback. Restore overlapping pending fixes once from their earliest snapshot during automatic rollback, and refuse files changed after mark-fixed. Driver files live in the QA skill; pre-edit copies are in .local/clanker-qa/driver-backup-2026-10-11.

## Validation and limits

59 driver tests passed, including parallel DM exclusion, owner-bound handoff correlation, overlapping rollback and preservation of concurrent edits. Latency now uses the original delivery timestamp, not a later progress edit, and duplicate text is assessed within each tester turn. Original per-scenario Slack outcomes remain the historical score; contaminated diagnostic evidence is not used to claim extra successes.

Status: activated through the QA restart workflow on 11 October 2026 at 02:44 IST (gateway PID 58797; Slack connected). Real-site verification is in progress; no new benchmark pass is claimed.

## Follow-up: organization-wide Kernel audit attribution

The exact-thread repair runs for [Apple](https://clanker-global.slack.com/archives/D0C6F49F2KD/p1791670866984139) (`r20261011-035107-add-13-inch-3755`, Hermes `20261011_035112_d983f9f3`) and the [GitHub issue](https://clanker-global.slack.com/archives/D0C6F49F2KD/p1791670868375349) (`r20261011-035108-add-issue-called-c181`, Hermes `20261011_035111_d4eaedac`) contained three and two Kernel audit problems respectively, all marked `run_session: false`. The automatic check nevertheless flagged them against those runs. Organization-wide audit searches cannot establish ownership of a Vault operation or browser deletion without a matching browser resource. Unattributed does not mean proven unrelated.

The driver now matches the exact browser ID in the request path's `/browsers/<id>` resource, excluding substring collisions and query mentions. It separates run-bound audit problems from explicitly unattributed context before applying each list's existing 80-record cap. The per-run check and evidence rendering also filter legacy mixed evidence: only `run_session: true` can produce a run failure flag. Both old and new evidence retain the unattributed records and display their count with ownership unknown.

The regression was red with eight failures and three passes. The full driver suite then passed **70 tests**, with zero retries, through `hermes/scripts/run_tests.sh --file-retries 0 /Users/tanishqpalandurkar/.codex/skills/clanker-qa/scripts/test_clanker_qa.py`. Coverage includes exact browser identity, retained unbound context, preservation of attributed errors after many unbound calls, and legacy evidence checks/rendering. Offline re-adjudication of the preserved Apple and issue artifacts now gives zero attributed problems and three/two unattributed context records. Input hashes confirm their evidence and historical `pass` verdicts were not rewritten; no new task success is claimed.

Current pre-edit copies of the external driver, its tests and this document are preserved under `.local/clanker-qa/findings/benchmark-evidence-attribution/before-audit-attribution-repair/`, with source paths and hashes in `manifest.json`. The QA snapshot command rejects external skill paths, so these explicit copies supplement the original snapshot. Red/green logs and the reproducible offline re-adjudication script/result are in the same finding directory with the `audit-attribution-` prefix.

This follow-up changes only the QA CLI and its tests/documentation. New CLI processes load the installed fix directly; no gateway restart, live browser call or Slack post is required or was performed. Coordinator and independent review confirmed the source, tests, re-adjudication and unchanged evidence hashes; the canonical finding is **verified** on this local and preserved-real-evidence basis. The earlier exact-thread collection mechanism is exercised by these concurrent same-owner runs; automatic rollback remains locally tested, without a deliberately induced live activation failure.
