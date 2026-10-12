# Vault Slack sessions and unconfirmed sign-in recovery

The hosted vault previously expired both its Slack identity cookie and server
session after one hour. That forced another Sign in with Slack flow on later
visits. The frontend already reused an existing cookie before offering sign-in;
we have no client evidence that a retained cookie failed within that hour.

New successful Slack sign-ins now receive a fixed 30-day session. The cookie and
SQLite session share one lifetime constant. Sessions do not renew indefinitely;
existing sessions keep their original expiry. Secure, HttpOnly, host-only and
SameSite=Lax cookie settings, current workspace membership, request ownership,
Origin and CSRF checks remain enforced. Different browsers or vault hostnames
still have separate cookie storage.

The reported Nike secure-link failure had a separate cause. Sanitized operator
diagnostics recorded a POST to `/auth/connections` timing out after 15,003 ms,
without an HTTP response. The request remained `create_unknown` without a
connection ID. The generic delivery queue nevertheless published the private
link while the provider creation was unconfirmed. Retrying the link could not
open a hosted sign-in, and the old state blocked subsequent attempts.

Read-only checks of that exact task's profile and domain found no matching
connection, with complete pagination, and no profile resource. These checks do
not establish whether the original POST was received or why it timed out.

## Changes

- Authentication creation and login use a 60-second timeout, matching the
  [official Kernel SDK default](https://github.com/kernel/kernel-python-sdk#timeouts).
  Mutations still dispatch once, without automatic retries.
- A lost creation acknowledgement can be reconciled through the official
  [filtered connection list](https://www.kernel.sh/docs/api-reference/managed-auth/list-auth-connections).
  Exact domain/profile, complete pagination, uniqueness, account, invitation,
  settings and proxy checks are required. Only an unused connection can be
  recovered; a fresh owner retry event is required before its first login.
- If the original request has expired, a complete empty lookup plus exact
  profile absence can retire the failed local attempt. A fresh owner retry
  rechecks absence before creating a new request. Ordinary continuation,
  resending a link and replaying the original event cannot restart sign-in.
- The private delivery queue verifies a live, owned hosted sign-in before
  returning or publishing its link. Failed creation cannot produce another
  broken link through background delivery.
- Authentication failure wrappers retain the sanitized diagnostic reference
  without exposing provider payloads or hosted capabilities.

Unknown login dispatch remains blocked when its exact generation cannot be
verified. This change does not copy credentials from Kernel Vault into Managed
Auth or establish a successful Nike login.

## Verification and activation

The Slack CLI verified the configured bot's workspace with `auth.test`, verified
the supplied yyovil DM with `conversations.info` and `users.info`, and read the
linked Tanishq DM thread's parent and all eight replies through the final page.
The supplied yyovil DM and linked Tanishq DM are distinct conversations.

Regression coverage exercises persistent HTTP sessions, ownership, expiry,
revoked membership, delayed acknowledgements, complete pagination, provider
absence, late connections, cancellation during reads, fresh-event retry gating,
and premature or ended-flow link delivery. The canonical isolated runner passed
829 tests across 24 files with zero failures. The changed Managed Auth file was
rechecked after a documentation-only edit; all 71 checks passed and final source
hashes stayed unchanged. An independent scoped review found no actionable issues.
Protected test receipts are under
`.local/kernel-only-20261008/vault-session-auth-recovery-tests-20261009.json`.

Slack access and production provider diagnosis stayed read-only. No Slack
messages, permission changes, login retries, SMS requests, purchases, production
database repairs or gateway restart were performed. The source fix requires an
approved gateway restart before the running service uses it; a fresh owner
request is still required to retry Nike sign-in.
