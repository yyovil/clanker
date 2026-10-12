# Dispatch a new shared request after a private handoff finishes

## Finding

Round-six Goa run `r20261011-161337-help-plan-12-01ab` created and saved the
initial itinerary after one human Google sign-in. The website reported Saved
to Drive, and a read of the document export returned the itinerary content.
The original shared thread received the actual document link. The subsequent
request to apply both participants' latest preferences was acknowledged in
Slack but never reached a private worker.

- [Original planning thread](https://clanker-global.slack.com/archives/C0C6J277ZNG/p1791715417473369)
- [Unexecuted same-document update](https://clanker-global.slack.com/archives/C0C6J277ZNG/p1791716444100749?thread_ts=1791715417.473369&cid=C0C6J277ZNG)
- Shared Hermes session: `20261011_161342_07f1db82`.
- Private Hermes session: `20261011_161350_d49f3f4d`.
- Initial document browser: `n0mvgdkqp6tqrekber4npme7`.
- Relevant window: 11 October 2026, 16:27–16:33 IST. The private session's
  last result preceded the shared update; its durable inbound identifier
  still named the earlier authentication resume.

`VaultService.move_private` reused a linked active task whenever
`channel_form_status` found any historical form. In this case that form was
already cancelled after the original browser closed. The transfer was
`resumed`, so neither delivery nor the pending-transfer drain dispatched a
new request. The tool nevertheless said automatic continuation would occur.

Sanitized transfer metadata is retained as
`shared-followup-not-dispatched.json` in the run's evidence directory. The
run remains failed with `functional_completion: false`: initial Doc creation
succeeded, but the latest preferences were not saved. No compensating private
message was used to change that verdict.

## Change

The coordinator now distinguishes a pending access step from form history.
It considers the latest form bound to the exact owner, workspace, private
thread and execution profile. A live waiting form, an unhandled saved form,
or uncertain provider creation retains its existing continuation. Expired
waiting forms and cancelled or resumed forms do not. A saved form whose
authentication-resume result is already committed is also historical, even
if the form's own acknowledgement has not committed yet.

A new owner request after the previous turn ends uses the existing durable
fresh-handoff path. It carries the current shared conversation and authorized
recalled document URL into a new isolated task; it does not select or copy an
older task's private browser or history. This follows the original
[channel handoff contract](2026-10-06-channel-login-detour.md). Retrying the
same inbound event remains idempotent.

The coordinator refuses to fork a currently running worker, pending dispatch,
or pending result delivery. Reusing genuinely pending access now explicitly
reports that the latest shared request was not forwarded; it cannot claim
those changes are queued or being applied. Another participant in the same
shared thread remains bound to their own account and is not held behind the
first participant's private work. No schema, tool or queue was added.

## Validation and limits

The canonical Hermes runner reproduced nine failures before the fix. The
final focused regression has eleven passing cases, including the historical
saved-form crash gap, expired/cancelled/resumed forms, live saved/waiting forms,
uncertain provider creation, active/pending workers, A → B → A isolation,
exact recalled Doc URL transfer, and duplicate-inbound idempotence.

Seven current boundary suites pass: **132 passed, 0 failed**. These cover the
new shared followup regression, recalled handoffs, task continuation, Kernel
Vault service/store, private link delivery and private access responses.
The tests use real temporary profiles, SQLite and native dispatch with fixture
Slack/model/provider I/O; they send no live messages or provider writes.

A broader legacy sweep has **64 failures** in five suites still using retired
local credential storage or missing Kernel fixtures. An isolated copy with
the exact pre-fix service/store snapshots reproduces the identical 64 test
identifiers, with 35 passes and no newly failing identifiers. Those failures
are preserved in `related-baseline.log`, `related-green.log` and
`baseline-comparison.json`; this is not a full-suite-green claim. A concurrent
destination-rule regression from a separate repair was observed mid-edit and
is not included in this repair's passing count.

Root review approved the narrow selection, busy guard and truthful response
contract. No live rerun or gateway restart was performed by this lane after
the fix. A fresh controlled rerun must still verify that saved authorization
can open the same document in the new isolated task, persist both participants'
latest preferences, and report the outcome to the original shared thread.
