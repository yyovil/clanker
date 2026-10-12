# Persistent personal and shared-account browser profiles

## Finding

The requested topology is one persistent browser identity for each authorized
Slack member, plus a separate identity for each shared login. The current
workspace has three ready members and one shared Swiggy login, so its intended
steady state is four profiles. Profiles are allocated on use; this is not a
global four-profile limit for future members or shared accounts.

Read-only inventory on October 11 found 34 provider profiles: 15 retained task
profiles and 19 Managed Auth profiles. All matched local ownership metadata.
The two benchmark participants own 18 and 16 respectively; the third member
has none. Six auth connections still reported authenticated success. Historical
claims and execution directories are not additional live browser profiles.

Ordinary cleanup also lost useful sessions. In the [earlier Goa
task](https://clanker-global.slack.com/archives/C0C6J277ZNG/p1791715417473369),
the model called `clanker_browser_stop` at 16:27:28 IST; cleanup finished at
16:27:37.611. The auth flow became deleted at 16:27:37.602. Its successful login
had occurred at 16:21:30. The implementation retained canonical private-home
auth flows but deleted the connection and profile for an isolated execution
home. Its saved credential reference survived. This was task cleanup, not a
human logout. The unconditional `profile_retained` response concealed the
distinction.

## Change

Browser identity and task execution identity now have separate responsibilities.
Persistent personal keys contain workspace and member identity. Shared keys
contain workspace, credential owner and immutable saved-item identity. After a
login becomes shared, its owner and current authorized recipients select that
same dedicated profile. A shared profile never adopts a whole personal profile.
Current membership, exact credential metadata and current grants are checked
on selection, browser use and immediately before writer dispatch. Task homes,
Slack source bindings, native task IDs, remote browser claims and CDP claims
remain requester-scoped.

A SQLite reservation permits one writer per profile, across task homes and
browser/auth workers. It is recorded before dispatch and survives process
restart. Unknown dispatch outcomes do not expire into another writer. Confirmed
preflight non-dispatch can release its reservation, and confirmed remote closure
releases an active writer. Cleanup is idempotent without releasing a later
writer. Waiting occurs outside execution-home locks so the preceding task can
finish. Persistent state does not imply live synchronization: [Kernel saves a
complete snapshot and permits one safe writer](https://www.kernel.sh/docs/browsers/profiles/concurrency).

Managed Auth connects multiple site-specific connections to a personal profile,
as supported by [Kernel's Managed Auth contract](https://www.kernel.sh/docs/auth/managed-auth).
Each consuming task selects its own authorized credential handle; the original
flow creator's grant is not authority for a later recipient. Normal task stop
releases task/browser bindings while retaining authenticated profile state.
Explicit account disconnection quarantines residual session state until its
cleanup is reconciled; deleting one site's credential must not silently erase
unrelated sites from the personal profile.

Private browser startup resolves its profile before selecting vault attachments.
Shared mode attaches only the selected credential's dedicated vault. Public
discovery does not load a member's personal cookies. Revocation closes the
revoked recipient's browsers and clears their task references; it does not
delete the shared profile belonging to the remaining authorized users.

The [checked migration](2026-10-11-browser-profile-migration.md) preserves two
explicitly reviewed personal profiles and their exact existing connections.
It neither merges cookies nor transfers historical task approval. Remaining
legacy state stays separate pending verified replacement and cleanup review.
A new canonical profile does not recover cookies from an already deleted one.

Separate startup provisioning creates the two reviewed missing identities:
the third member's empty personal profile and an empty shared Swiggy profile.
Its manifest binds exact principal names, current members, the credential's
metadata hash and the complete active recipient set. Every target is checked
before the first profile POST and again between provider operations. Existing
registry reservations reconcile an uncertain POST by exact-name GET rather
than issuing another creation. This stage creates no browser, login, grant or
credential. Two retained profiles plus two new ones leave 36 physical profiles
until the 32 legacy profiles have been separately cleaned up.

Both startup stages require the actual gateway process lock, PID and launch
home. Protected outcome receipts contain the manifest hash, current PID and
timestamp. Activation must verify these fresh receipts and Vault availability;
Slack connectivity alone does not establish successful migration.

## Validation and limits

Implementation and verification are in progress; this document is not a live
deployment or four-profile inventory claim. Canonical test logs and independent
security review are recorded under
`.local/clanker-qa/findings/persistent-browser-principals/`.

The registry tests use real SQLite and independent instances. They cover three
personal identities plus one shared identity, cross-user/workspace refusal,
revocation and credential rotation, competing browser/auth writers, unknown
creation reconciliation without another POST, and forged cleanup evidence. A
red/green regression also covers a crash between lease deletion and the
caller's cleanup receipt: replaying the old cleanup cannot release a newer
writer. Browser and Managed Auth integration checks exercise actual runtime
imports against temporary execution homes with provider I/O fixtures.

The isolated registry/authority suite passes 41 checks. Fifteen writer-handoff
checks cover the uninterrupted browser-to-auth reservation and stale cleanup.
Seventeen provisioning checks cover exact topology, changed grants/credentials,
unknown POST reconciliation, guarded startup and sanitized process-bound
outcomes. Two startup receipt cases failed before their fix; the initial
provisioning-module absence is not a behavioral regression. The combined activation run passed 1,013 checks across 49 files with zero
failures, eight existing expected failures, and no file retries. The exact
file list and log are `activation-tests.json` and `activation-green.log` in
the finding directory. Independent review passed the profile, migration,
provisioning, and scoped-reset boundaries. Live results remain pending.

Provider login dispatch has no force-clean-session parameter. A fresh login
generation is not proof that an authenticator challenge occurred. Autonomous
TOTP still requires live challenge/completion evidence. Owner-only email/SMS,
push or other external authentication steps remain human actions when the
website actually requires them. None of these local checks changes the
historical benchmark outcomes or establishes 12/12 success.
