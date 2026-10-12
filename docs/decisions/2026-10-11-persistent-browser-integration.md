# Persistent browser profile integration

## Scope

The browser profile registry owns durable personal and shared-account identity.
Kernel automation still owns each live browser and CDP connection through its
authenticated requester, execution home and Slack thread. A persistent profile
does not make a browser or Hermes execution home shareable.

Private startup resolves and authorizes its principal before attaching vaults.
Public discovery uses an anonymous browser without personal cookies or vaults.
Each principal has one durable writer lease, shared by automation and Managed
Auth. Automation waits at most 60 seconds outside the execution-home lock,
allowing the previous task to stop. This is bounded waiting, not a durable FIFO
queue. A trusted gateway may retire an idle browser only after verifying its
exact ownership and excluding pending code forms, approvals, undelivered
resumes and unresolved purchases. Auth connections and unknown dispatches are
never treated as expired browser sessions.

Normal stop verifies browser closure, releases its exact lease and keeps the
principal profile. Revocation cleanup closes only the recipient's execution
contexts and preserves the shared profile for the remaining authorized users.
Legacy task profiles are quarantined locally for explicit reconciliation; this
change neither adopts nor deletes them. Existing native browser and CDP owner
claims are unchanged.

## Vault boundaries

A shared browser attaches only its selected credential's dedicated vault.
The owner and authorized recipients use that same shared principal. Personal
browsers attach their owner's personal vault and unshared dedicated items;
invited vaults are excluded. An owned item is also excluded when an active
grant or a historical shared principal identifies it as shared.

Hosted fills recheck the current principal and credential. Shared mode refuses
personal-info, direct-item and formatted-value fills before private values are
read or temporary items are created. Only the selected shared login and its
authorized verification flow may fill the shared browser. These controls do
not claim to be general DLP for manually supplied text or website content.

## Lifecycle regressions

Two integration failures were reproduced and repaired during implementation:

- When a new authentication binding replaced the current browser but kept the
  same principal, closing the browser released the idempotently acquired lease.
  Startup now reserves again outside the home lock before creating a replacement.
- Revocation immediately before writer dispatch correctly prevented a browser
  POST but left an unknown-dispatch marker. Known pre-dispatch refusals now clear
  that marker and release only the reserved lease. Actual uncertain provider
  outcomes retain their durable block.

## Verification

Canonical local tests use real SQLite, real requester/grant resolution and the
real registry, with fixture Kernel/CDP I/O. Initial integration red was four
failures and one pass. Focused regressions separately reproduced the released
lease, pre-dispatch marker and personal/shared vault-boundary failures.

- `integration-scope-green.log`: 153 passed, 8 existing expected failures across
  six files, including 18 new integration cases.
- `integration-fill-related-green.log`: 167 passed across personal information,
  saved-login browser recovery, fill dispatch, split OTP and retry authorization.

Logs are under `.local/clanker-qa/findings/persistent-browser-principals/`.
Saved-login recovery tests now reproduce an actual personal-to-shared profile
switch, because changing an ordinary personal thread must preserve its profile.
All owner, unrelated-refusal and stale-form recovery assertions remain.

This is local verification. It does not prove deployed cookie persistence,
website login, cart continuity or benchmark completion. No live browser,
production database, remote profile or gateway was changed by these tests.
