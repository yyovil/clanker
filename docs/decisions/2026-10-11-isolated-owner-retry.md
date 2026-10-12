# Resume approved retries in their isolated task

## Finding

The private Google retry was approved but rejected at the home/profile check. The guard always expected the member home, although channel tasks correctly execute in their own isolated home.

Evidence: [original Slack task](https://clanker-global.slack.com/archives/C0C6J277ZNG/p1791659821917299); QA run `r20261011-004702-move-company-offsite-8304`; Hermes session `20261011_004725_d4e62a52`. The original benchmark ran late 10 October through early 11 October 2026 IST. Time-only Kernel correlations are intentionally excluded pending exact-thread recollection.

## Change

Resolve the expected profile and home through the persisted channel-task route, then check workspace, owner, chat, profile and home before resuming. Ordinary owner DMs retain their existing checks.

## Validation and limits

21 retry tests passed: isolated owner retry, owner retry button and code retry suites. Google provider acceptance remains unverified; an approved retry is not a successful sign-in.

Status: activated through the QA restart workflow on 11 October 2026 at 02:44 IST (gateway PID 58797; Slack connected). Real-site verification is in progress; no new benchmark pass is claimed.
