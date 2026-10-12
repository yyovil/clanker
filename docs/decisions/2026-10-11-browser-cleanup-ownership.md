# Do not reap another live process browser sessions

## Finding

During local regression tests, the native browser exit cleanup attempted to reap old socket records belonging to the still-running gateway. Age and absence from this process memory were incorrectly treated as ownership.

Evidence: [original Slack task](https://clanker-global.slack.com/archives/D0C6F49F2KD/p1791658186913709); QA run `r20261011-001947-add-13-inch-3755`; Hermes session `20261011_001950_ba8abced`. The original benchmark ran late 10 October through early 11 October 2026 IST. Time-only Kernel correlations are intentionally excluded pending exact-thread recollection.

## Change

Exclude socket records owned by another live process from the orphan reaper. Preserve existing cleanup for dead owners and this process own untracked idle sessions. Probe tests also disable process-global browser cleanup so fixtures cannot touch live host browser records.

## Validation and limits

22 cleanup tests passed, including preservation of a live foreign-owner session and cleanup of an idle own-process record. Gateway read-only health remained connected. This was discovered during diagnosis; it is not established as the cause of the original Apple failure.

Status: activated through the QA restart workflow on 11 October 2026 at 02:44 IST (gateway PID 58797; Slack connected). Real-site verification is in progress; no new benchmark pass is claimed.
