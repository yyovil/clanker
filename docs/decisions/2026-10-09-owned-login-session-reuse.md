# Reuse successful owned logins across private DM threads

## Evidence

The Slack CLI authenticated as Clanker (`U0C5Z1ZQHQX`) in workspace
`T0C6J1XCDE0`. `conversations.info` confirmed that linked conversation
`D0C6EAXPKEE` is the DM with Tanishq (`U0C688SF7DZ`). Both
`conversations.replies` reads reached the final page: the
[original iCloud mail task](https://clanker-global.slack.com/archives/D0C6EAXPKEE/p1791494671575999)
contained its parent and three replies; the
[Gouri follow-up](https://clanker-global.slack.com/archives/D0C6EAXPKEE/p1791495668195229)
contained its parent and two replies. The original task reported a completed mail
search, and the follow-up requested another sign-in roughly two minutes later.

Read-only inspection of the exact local auth records found the original flow
already `deleted` with its request `cancelled`, six seconds before the completion
reply. The next thread had a separate `pending` login. Both belonged to the
requester's canonical private profile and the same owned iCloud account. The
Kernel credential reference survived, but the successful browser profile did not.

Two implementation choices caused the repeated prompt: auth flows and browser
attachments were selected only by Slack thread, and normal browser stop deleted
the successful Managed Auth connection and profile along with the task browser.

## Change

Successful owned logins can now outlive an ordinary task in the requester's
canonical private DM. Explicit thread selections point to a verified auth flow.
Selecting the same saved handle or exact origin can reuse a successful flow
from another thread, without creating a request, starting login or delivering a
sign-in link. Multiple accounts for an origin still require account selection.

Reuse checks workspace, requester, canonical execution home, account ownership,
handle, credential metadata binding and proxy. The existing provider observation
also verifies connection/profile ownership, the exact successful flow generation
and current authorization. Selections are rechecked transactionally after the
provider read. Browser attachment revalidates access and provider state again.

Each thread still gets its own automation browser. It loads the saved profile
with `save_changes: false`, consistent with
[Kernel's documented profile snapshots and concurrency model](https://www.kernel.sh/docs/browsers/profiles).
The backend does not export cookies or credentials. Invited accounts and isolated
shared-task homes remain scoped to their individual tasks.

Normal stop verifies browser deletion before releasing its selection. A verified
successful owned DM login is retained. Pending and unsuccessful flows retain
cleanup behavior. Explicit purge, account removal, privileged home cleanup and
invitation revocation retain hard deletion and fail-closed cleanup behavior.

Existing unambiguous original selections migrate once when the new bindings
table is first created. Creation and backfill are atomic and follow the legacy
sign-in guard, so a refused startup cannot strand existing selections. Restarts
do not recreate deliberately released selections. Already deleted auth profiles
cannot be recovered by this migration.

A retained session that loses authentication is marked as needing fresh sign-in.
An ordinary task cannot restart it. A fresh owner retry creates a new request,
connection and profile, including after the original request has expired; it
never changes another thread's saved login generation.

## Verification and activation

The canonical isolated runner passed **266 checks across eight files**, with
zero failures. Runtime sources and tests stayed unchanged across the run; hashes
and the test log digest are recorded in
`.local/icloud-reuse-20261009/verification.json`. The suite includes ten new
functional reuse checks, nineteen independent security/migration checks, and
existing auth, frontend, transport, private-link and browser lifecycle coverage.
An independent scoped review found no remaining blocking issue.

Three broader legacy suites still fail 78 checks. An isolated copy of pre-change
sources reproduced the exact same failing cases: 58 old browser/local-vault
fixture checks, five unchanged prompt-string assertions and fifteen old channel
task/local-vault checks. The comparison is recorded in
`.local/icloud-reuse-20261009/legacy-baseline-comparison.json`; those failures
were not changed by this fix.

Slack access and production state inspection were read-only. No Slack message,
permission change, production database repair, provider mutation, login retry or
gateway restart was performed. Activation requires an approved gateway restart.
The previously deleted iCloud profile requires one fresh sign-in; no live Apple
acceptance or mail search was performed during this fix.
