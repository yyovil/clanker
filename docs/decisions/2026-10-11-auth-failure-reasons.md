# Preserve safe sign-in failure reasons

## Finding

The resume message reduced provider-reported sign-in failures to a generic blocker, preventing diagnosis of expired human input versus bad credentials or unsupported authentication.

Evidence: [original Slack task](https://clanker-global.slack.com/archives/C0C6J277ZNG/p1791659821917299); QA run `r20261011-004702-move-company-offsite-8304`; Hermes session `20261011_004725_d4e62a52`. The original benchmark ran late 10 October through early 11 October 2026 IST. Time-only Kernel correlations are intentionally excluded pending exact-thread recollection.

## Change

Keep a fixed allowlist of provider reason codes and map it to bounded, non-secret explanations. Unknown upstream text is never copied. A failed flow still requires a genuine owner retry event.

## Validation and limits

The auth regression batch passed 292 tests, including five new failure-reason cases. This improves diagnosis; it does not claim to repair provider timeouts or bypass site challenges.

Status: activated through the QA restart workflow on 11 October 2026 at 02:44 IST (gateway PID 58797; Slack connected). Real-site verification is in progress; no new benchmark pass is claimed.

The later Google attempt `qrsn7lhnos2qx7ancd6z63s3` exposed a further omission: the known `flow_failed` code was collapsed to `provider_failure`. A regression reproduced that loss; the fixed-code allowlist and bounded resume explanation now preserve it while excluding raw provider text and making no credential/timeout inference. The canonical runner passes 187 checks across failure-reason, auth-client, Managed Auth and redirect-policy probes. This follow-up was activated through idle QA restart at 04:18 IST (PID 75440, Slack connected) and improves diagnosis only; the hosted Google failure is separately documented in [its trace report](2026-10-11-google-managed-auth-flow-failed.md).
