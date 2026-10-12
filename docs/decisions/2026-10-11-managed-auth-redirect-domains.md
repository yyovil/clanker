# Managed Auth redirect domains

## Finding

Goa Docs run `r20261011-033246-help-plan-12-01ab`, private [task thread](https://clanker-global.slack.com/archives/D0C6EAXPKEE/p1791669777480919), stopped during hosted Google sign-in. The owner supplied the failure screen. Read-only Kernel connection and timeline inspection confirmed connection `con8roh7wvdrr2iczhzxha9l`, primary domain `docs.google.com`, allowlist containing only that hostname, and terminal `domain_not_allowed` at 2026-10-10T22:07:51Z. The provider did not identify the exact blocked hostname in the retained error. Earlier task browser navigation had independently observed Docs redirecting to `accounts.google.com`.

The connection creation path hardcoded a singleton hostname. The response parser also replaced `domain_not_allowed` with a generic failure, hiding the actionable cause. This is an integration failure, not evidence that the email supplied to the hosted form was wrong.

Separately, Hermes session `20261011_033300_ee73792c` showed the earlier opaque saved Google identifier being filled, followed by Google's account-not-found response. This does not establish which stored value or binding is wrong. No secret was retrieved for diagnosis; the saved credential needs private validation.

## Change

Native Google application hosts now include `accounts.google.com` as a credential destination, using a fixed exact-host policy. Other sites retain their previous domain restriction. Page content cannot add destinations, and no wildcard, unrestricted list, or suffix-based trust was introduced. This follows Kernel's [published connection schema](https://www.kernel.sh/openapi.json), whose allowed domains govern credential entry.

Old singleton connections remain readable for verified cleanup. A terminal domain-policy failure with an outdated list is replaced only after the existing owner retry authorization; an active flow is never silently broadened. Cleanup and creation preserve the existing owner/profile/proxy checks and unknown-dispatch guards. Known domain failures now reach the task as a safe configuration explanation, without raw provider messages.

## Validation and limits

Before the fix, five new checks failed: Docs/Drive redirect policy, old-policy retry before/after expiry, and safe error propagation. After the fix the canonical test runner passed 186 checks across `test_managed_auth_domains.py`, `test_auth_failure_reasons.py`, `test_kernel_managed_auth.py`, and `test_kernel_auth_client.py`.

An additional 49 reuse/security/dispatch checks passed. Activation completed through the idle QA restart at 03:50 IST (PID 67711, Slack connected). A new successful hosted Google login remains pending. No live connection was changed with the CLI and no credential values were read. The failed benchmark attempt remains recorded.

The subsequent run `r20261011-035105-help-plan-12-01ab` verified the corrected live allowlist on connection `z7h5r07wbvau693wjvpvlg84`. Its hosted login nevertheless ended with `flow_failed` at 2026-10-10T22:26:43Z, without a website error. Timeline event `qrsn7lhnos2qx7ancd6z63s3` maps to browser `z3hz0ltjq0q06dg0mxoh64z9`; it lived about 303 seconds with a 900-second browser timeout. Browser audit requests succeeded, and no page telemetry was retained. This proves the connection configuration changed, not successful Google authentication or the cause of this new failure. The separate `google-managed-auth-flow-failed` finding retains that uncertainty; further blind retries were withheld pending the owner's last visible login stage.
