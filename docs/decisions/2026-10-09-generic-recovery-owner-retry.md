# Generic recovery guidance and owner retry handling

Activated on 9 October 2026 after the user approved a gateway restart.
The gateway was idle (zero active agents) before replacement. The old process
(15593) exited, and replacement process 22756 reports running, Slack connected,
and session storage healthy. The permanent tunnel remained running, and
https://vault.yyoreel.com/health returned HTTP 200 with `ready: true`.

The product-wide execution policy now requires an evidence-backed next step for
blockers, explains what that step enables, respects an already requested
recovery, and forbids prescribing a known-broken retry or promising unscheduled
background work. It specifies no merchant, error-specific script, fixed sequence
of tools, or fixed UI copy.

The shared retry-intent parser accepts conversational affirmative introductions
and collective requests, including “yeah! lets retry.” Existing rejection of
negation, conditional requests, quoted instructions, and replayed events remains.

Managed Auth can recover an expired local request on a fresh owner retry event.
It verifies the exact remote connection generation, rechecks request and access
state after the provider read, and confirms connection/profile cleanup before
opening another login. It does not adopt a late success, replay unknown login
mutations, or override cancellation or revoked access. Recovery retains the
original request goal and source rather than replacing the goal with “retry.”
Live provider login, SMS, and mailbox access have not been attempted by this chat.

Verification: 182 tests passed across Managed Auth, natural-language retry
permission, saved-session reuse and security, private-link delivery, and vault
Slack sessions. Coverage includes fresh-event conversational retries, expired
requests before and after result delivery, cleanup failure, cancellation during
provider reads, and the existing late-success protections.

The independent vault-session change already present in source gives new Slack
identity sessions a fixed 30-day lifetime. Existing sessions retain their prior
expiry, and host-only cookies do not transfer across vault hostnames or browsers.
That code predates the current gateway; this receipt does not claim a live
30-day browser session has been exercised.
