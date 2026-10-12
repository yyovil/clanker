# Vault invitations and requester authorization

The vault has one **Invite to vault** button. The owner chooses a current Slack
member, checks which saved logins, API keys and payment cards to share, then
confirms use of only that selection on their behalf. Nothing is checked for a
new member, and credentials added later stay private. **People with access**
groups each member's shared credentials; **Edit access** reopens the checklist
with that member's existing selection, and **Remove** revokes their access.
The member sees **Shared with you** in their vault. An
invitation takes effect immediately. When the selection adds credentials,
Clanker sends one private Slack DM to the recipient with the sharer's Slack
mention, the number of newly shared credentials, and an **Open vault** button.
The message includes no credential titles, identifiers, grant handles, secrets,
or authenticated link tokens. Unchanged saves and removal-only edits send no DM.
The vault confirms Slack delivery or reports that delivery could not be
confirmed; access remains saved in either case. Delivery is bounded to ten
seconds and is not retried automatically. Slack's own notification settings
control whether the DM also produces a push notification.
The saved credential remains in the owner's encrypted native vault. The guest
receives a grant handle and metadata, not a copied vault entry.

This implements explicit delegation. It does **not** establish that the reported
Gmail disclosure is fixed in the running system. The gateway has not been
reloaded, no real invitation has been created, and the consumer browser
provider's isolation and cookie-deletion behavior remain unverified.

## Permission boundary

Slack OIDC establishes the owner of the vault web session. Owner and workspace
come from that session, never request-body fields. CSRF and exact-origin checks
cover invite and revoke. Only native items in that owner's vault can be invited;
guests cannot pass an invited handle to create another invitation.

A durable grant binds workspace, owner, recipient and selected credential.
Saving a member's checklist validates the entire selection and applies all
permission additions/removals in one database transaction. Invalid or foreign
items cause no partial changes. Still-selected credentials retain their grant
handles; unchecked credentials and their pending approvals are revoked before
browser cleanup. Selecting credentials grants no wildcard access to the vault.
Its identity binding includes kind, origin, account identifier and creation
time. The runtime resolves that grant for the authenticated requesting member,
checks current membership of both parties, and verifies the selected native item
still exists with that binding. An unrelated native handle, another member's
grant, a removed or changed account, or a disabled member is denied. Reinvitation
after revocation produces a new grant handle.

These are credential-use permissions. A login can provide the full website
account access available to that login; an API key can provide the permissions
the service gives that key. The implementation does not impose a new read-only
role inside either service. Preventing onward grants is an application rule;
it is not a guarantee that an authorized recipient cannot copy account data or
that a third-party browser provider cannot access an entered credential.

## Execution

Logins fill the requester's supervised local browser, after exact origin and
supported-field inspection. The selected owner password is supplied by the
trusted backend, without switching the active Hermes home to the owner. Owner
TOTP or a hosted owner-only code form can satisfy verification. The one-use code
is consumed in the original requester's task, and automatic resume retains that
requester's source, home and DM.

API requests use `clanker_api_request`: the backend adds the owned or invited key
to a supported authentication header. Calls accept relative paths on the saved
HTTPS origin, reject authentication/Host/Cookie overrides, reject private or
local DNS addresses, pin the connection to a resolved public IP, and verify TLS
against the original hostname. Redirects do not forward authentication. Request
and response sizes are limited. Key values are registered for redaction and
scrubbed from responses. Synthetic transport tests verify these restrictions;
no real external API operation was performed for this change.

Cards use only the requester's supervised local checkout. An invitation lets
the member request a purchase; each exact purchase still needs the **card
owner's** hosted approval and current CVV. The owner sees merchant, order, total,
checkout text and requester. Approval does not transfer the task to the owner.
The handler rechecks the original browser, task, conversation and checkout,
consumes approval and CVV before fill/submission, and refuses replay. Submitted
is not paid; the merchant receipt must be checked. Unsupported payment frames,
wallets, subscriptions and bank approval retain their existing limits.

## Revocation and cookies

Revocation is committed before cleanup and cancels pending delegated code/card
approvals. Secret-bearing browser use is recorded before handoff, with an atomic
active-grant check. This covers a revoke racing between handle resolution and
the usage record. Work already in flight may finish before interruption; the
implementation cannot undo earlier disclosures or completed external actions.

For local Chromium, revoke interrupts the original requester task, closes their
private browsers and deletes their Chromium cookie profile under the guest
execution lock. Cleanup conservatively removes all of that recipient's private
browser state, including sessions used for other valid grants. It preserves the
owner's browser and native vault. An active grant can be used again in a fresh
guest browser after cleanup. API requests have no reusable browser cookies.

If cleanup fails, the grant remains revoked and the recorded usage keeps future
browser/terminal execution blocked. The web UI shows **cleanup pending** and
offers retry. **People with access** also exposes orphan invitations whose
native credential was removed, so that member's access can still be removed or
cleanup retried.

Consumer Browser Tool exposes task stop but no reviewed cookie/session deletion
operation. Its stop result now reports `profile_retained: null` (unknown),
correcting the previous unsupported claim of cookie deletion. A required purge
stops the task, keeps a blocked tombstone, and returns cleanup pending. Repeated
stop/retry does not clear that block. Operator cleanup needs an actual provider
deletion/reconciliation capability before a verified reset can be recorded;
this implementation does not supply that capability.

## Browser routing and unresolved incident work

New cloud state keys include workspace, authenticated requester and resolved
home, independent of the short session name or a shared conversation profile.
State carries an explicit owner marker. Provider session IDs are recorded with
that owner/context, and a recorded collision is refused and quarantined. Legacy
state is not silently adopted by the new namespace. Unknown dispatch outcomes
retain their retry block.

These controls govern Clanker's assignments and known grants. They do not prove
a fresh remote browser lacks another account's pre-existing cookies. Provider
ownership collisions are detected on acknowledgement, after task dispatch;
that check cannot undo observations the provider made before acknowledging.
Free-form remote task instructions are not an account-authorization boundary.
The reported disclosure therefore still requires tracing and invalidating
affected legacy/provider state, a provider-enforced requester isolation and
pre-read authorization design, and real two-requester/DM-handoff acceptance.
Existing login state alone must never be used as permission.

## Verified locally

The canonical Hermes test runner passed **79 tests across five affected files**:
invitations, vault, payments, consumer Browser Tool and managed cloud browser.
Coverage includes all three credential kinds, owner/recipient/workspace checks,
CSRF and forged identity fields, persistence, onward-sharing denial, revoked
access, cleanup failure, same session names/shared profile names, recorded
provider-session collisions, delegated code and payment resume, origin-bound
API requests, TLS/DNS pinning and redirect rejection. Checklist coverage adds
multi-credential sharing, atomic rejection without partial permission changes,
stable handles for retained credentials, revocation of unchecked items, no
automatic sharing of later credentials, and removal of an inactive member.

The actual sandboxed Chromium probe exercised A → B → A with two disposable
homes: owner login, denial of the owner's raw handle to the guest, invited login
fill, owner-only HTTP approval, one guest dummy checkout with an observed dummy
receipt, payment replay denial, CVV consumption, no copied guest vault entry,
guest cookie-profile removal when the login is unchecked in that member's
selection, and preservation of the owner's browser.
The same guest task/session can start a fresh browser after cleanup, while the
revoked login remains denied and an unrelated active card grant remains listed.
Its receipt is
[`2026-10-06-invitation-local-browser.json`](../../verification/evidence/2026-10-06-invitation-local-browser.json).

The visible UI check uses disposable identities and dummy credentials on
loopback. The owner initially selected login and API key; the guest saw those
two entries and no card. Edit access restored that checklist; unchecking the
login and checking the card made guest reload show only API key and card, with
the per-purchase owner-approval label. Desktop and mobile checklists and the
member-level sharing list were visually checked. Removing the member through
the single member row then made guest reload show no saved or invited access.
Screenshots are saved as
`output/playwright/vault-invite-selection-desktop.png`,
`vault-edit-selection-mobile.png` and `vault-sharing-members-mobile.png`.
Earlier per-credential Invite
screenshots represent the superseded design. The missing favicon is unrelated
to invitation behavior.
No mailbox content, real credential, live Slack message, real card
charge or production configuration change is used as verification evidence.
