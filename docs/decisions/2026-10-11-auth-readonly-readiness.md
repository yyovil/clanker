# Google and GitHub authentication readiness

Read-only assessment recorded on 11 October 2026 at 09:14 UTC. This is a metadata assessment, not a new benchmark attempt or website acceptance test. Local coordinator SQLite was opened with `mode=ro`; Kernel reads used the existing CLI account and project `ofp3osdo37cq0d0wuohxb3oj`. No login, logout, challenge, browser creation, credential change, approval, or message was issued.

## Google blocker

The benchmark requester's exact Docs connection `z7h5r07wbvau693wjvpvlg84` still reports `NEEDS_AUTH`, `FAILED`, `COMPLETED`, and `flow_failed`. Its allowed domains are `docs.google.com` and `accounts.google.com`. It reports `can_reauth=false` with `no_prior_successful_login`. The redirect-domain correction therefore remains present, but it did not make this flow succeed. The provider's `last_auth_at` timestamp records the ended attempt; it must not be interpreted as successful authentication.

The same requester's earlier identity connection `ms7vp7ty6kmigsndebo64gyo` reports `NEEDS_AUTH`, `FAILED`, `awaiting_input_timeout`, and no prior successful login. The other tester's retained failed identity connection `r3grty3q8y7wz02rynyi17ko` also reports `NEEDS_AUTH`, `FAILED`, `flow_failed`, and no prior successful login. That other tester's credentials do not authorize the benchmark requester.

The latest diagnostic reservation, `clanker-auth-e38621804dc9cd71f05d2af06af140147fc2ebe6`, still returns an empty exact-domain/profile connection list. Its local state remains `create_unknown`, with no connection ID. An empty lookup does not prove that the timed-out create never reached the provider and does not authorize repeating it.

All local Google Managed Auth flow records are failed, deleted, or `create_unknown`. The benchmark requester's Docs account has no saved Managed Auth credential. Separate ready Vault metadata for an opaque Google login is not proof that those fields are correct or that a website session is authenticated. No verified owner-bound Google session is available to justify continuing Docs without a person. This assessment does not inspect cookie contents or claim that every unrelated browser is signed out.

The cause of the corrected-domain `flow_failed` remains unresolved. See [the provider failure report](2026-10-11-google-managed-auth-flow-failed.md) and [the ambiguous diagnostic create](2026-10-11-google-auth-telemetry-retry.md). No concrete defect in `kernel_auth_client.py` was established by these reads, so no speculative auth mutation or transport change was made. The owner is unavailable; human sign-in and upstream trace follow-up remain parked. Support has already been contacted.

## GitHub authenticator coverage

The owner-bound GitHub connection `lneg9071zdil9zw5ko1b5eyw` reports `AUTHENTICATED`, `SUCCESS`, `COMPLETED`, and `can_reauth=true` with `totp_reauth_allowed`. The bound credential's metadata confirms `has_totp_secret=true` and `has_values=true`. Neither the seed, password, nor a generated code was requested or retained in this report.

The connection's `last_auth_at` is still `2026-10-10T18:55:30.835069Z`. Its first timeline page contains one successful login, completed at `2026-10-10T18:55:31.144887Z`, and no later reauthentication event. The existing session can support authorized GitHub work, but reuse is not a fresh authenticator challenge. **Fresh GitHub TOTP challenge acceptance remains unverified.** No logout or challenge was induced solely to create coverage.

This supersedes the older enrollment note's statement that no real seed had been enrolled: current provider metadata confirms enrollment. It does not supersede that note's warning that unattended reauthentication is unverified. Functional repository/issue results and local enrollment tests remain separate evidence.

## Replay privacy review

Existing `_arm_privacy` runs before secure Vault and payment browser writes. It does not cover restored authenticated pages, Managed Auth profile selection/login, or model-readable personal details later typed through ordinary browser tools. Managed Auth requests already disable their own session recording. A single late fill hook cannot guarantee that restored private content was never captured.

The replay lane therefore owns the stricter preparation: deny capture for Managed Auth, saved-account, and Vault-attached sessions rather than claiming that after-the-fact detection makes them safe. No auth-entry hook or runtime activation was made in this assessment.
