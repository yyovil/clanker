# Connect an authenticator through the private account dashboard

## Finding

GitHub sign-in required a person to provide an authenticator code. The product had no owner-facing way to attach an existing authenticator seed to a saved Managed Auth credential. Normal login does not reveal that seed.

Evidence: [original Slack task](https://clanker-global.slack.com/archives/D0C6F49F2KD/p1791658186338419); QA run `r20261011-001946-sign-github-saved-a5d4`; Hermes session `20261011_001950_56560b98`. The original benchmark ran late 10 October through early 11 October 2026 IST. Time-only Kernel correlations are intentionally excluded pending exact-thread recollection.

## Change

Add an authenticated, CSRF-checked private dashboard action with explicit consent and a masked input. The backend forwards the seed transiently to Kernel using a TOTP-only credential PATCH; it preserves password fields, stores no seed locally, strips returned codes, and never exposes this operation as an agent tool. The form clears its input after dispatch. No website security settings are changed automatically.

## Validation and limits

Ten new enrollment tests passed, within the 292-test auth regression batch. Owner isolation, consent, CSRF, origin, no local seed persistence and response redaction are covered. This extends secret custody to transient trusted web/backend memory; Kernel remains the sole persistent store. No real seed has been enrolled and unattended GitHub reauthentication is unverified.

Status: activated through the QA restart workflow on 11 October 2026 at 02:44 IST (gateway PID 58797; Slack connected). Real-site verification is in progress; no new benchmark pass is claimed.
