# Channel tasks with private login detours

Status: implemented and verified locally. On explicit owner approval, the
gateway was restarted on 6 October and reconnected to Slack; the hosted vault
health check and live schema migration passed. A real channel login/result
end-to-end task remains unverified. See the
[verification receipt](../../verification/evidence/2026-10-06-channel-login-detour.md).

## Approved behavior

A member can request an authenticated browsing task in a shared Slack thread.
Clanker privately collects missing login details, verification codes, API keys
or purchase approval in that member's DM. After access is available, the task
continues and its final requested text result is posted in the original shared
thread. Starting such a task authorizes sharing its requested result with that
thread's audience. Sensitive task requests should start in a DM.

People who can read the shared thread can read its messages and Clanker's
published result. Reading or replying grants no access to the requester's vault,
private conversations, browser cookies or worker. Another member's follow-up
binds to that member's identity and authorized accounts. Account invitations
remain explicit and revocable.

Ordinary DM tasks and previously persisted private handoffs retain private
results. The change applies to newly created channel task detours.

## Identity and isolation

The gateway persists the workspace, requester, original channel/thread,
inbound message identifier, original goal and private worker source in the
protected `.clanker-vault/requests.sqlite` coordinator database. The
`transfers.reply_mode` and `task_state` columns distinguish channel work from
legacy private handoffs. This state survives gateway/service restarts.

Each channel task gets a fresh `profiles/task-<transfer-id>` execution home,
native session database and browser context. Personal DM files, memories,
history and browser profiles are not copied. The native agent skips personal
memory, context files, SOUL, prefill and background review; middleware also
rejects memory/session-search tools. Shared follow-ups cannot select or reuse
the task home.

Credentials remain encrypted in the requester's personal vault. Trusted fill
and API handlers resolve owned or explicitly invited handles against that
vault, validate the target origin and use the separate worker browser. Newly
saved credentials go to the personal vault; one-time codes remain encrypted
and single-use. The task home receives no credential-vault copy.

A native `IsolatedGatewayTask` capability connects the worker to its result
handler. It is never serialized into Slack input or session-source dictionaries.
Only the durable, owner-validated coordinator resume attaches it. Membership,
source fields, task state, served home and original destination are checked
again during routing and publication.

## Result publication and recovery

Native streaming, interim replies, tool progress, task cards, voice and media
egress are suppressed for this worker. The trusted login handler still sends
forms privately. A model reply while a form is pending is not a final result.
The form also records its originating gateway event, so that turn's waiting
reply stays suppressed even if the form is saved before the reply or restart.

The final text is encrypted into a SQLite outbox before optional vault reads or
Slack I/O. Before publication the handler scrubs current owned/invited secret
values and applies native redaction. If redaction or Slack fails, publication
retries the retained answer. A persisted native completed reply can also be
adopted after the coordinator-write crash gap without starting another agent
turn. Publication validates current original-channel membership.

Each result uses a stable `client_msg_id`. The handler pages the original thread
via Slack `conversations.replies` to reconcile an acknowledgement lost before
SQLite marks completion. The Slack app must have the relevant thread-history
and write permissions. The same inbound message deduplicates its detour; a new
message can create another task even when its text matches.

An unfinished interrupted website operation may run again after restart. This
does not provide exactly-once semantics for website mutations or purchases.
Existing purchase approval and unknown-outcome rules still apply.

## Stop and revocation

`/stop`, `/new` and `/reset` in the original thread cancel that requester's
linked forms and private worker, stop its browser contexts and invalidate
pending result publication. Other members and other threads retain their tasks.
Disconnect cancels the owner's outstanding tasks and clears their recorded
browser contexts before removing the credential.

An invited credential records every execution home that used it. Revocation
cancels those workers and attempts cleanup for each home. Failed cleanup stays
pending and blocks reuse; success for one home does not erase another home's
marker. Provider cleanup attempts every recorded session even when an earlier
session fails.

## Integration and activation

`runtime/vault/channel_tasks.py` owns task execution and publication;
`channel_control.py` owns validated cleanup. Generic Hermes changes are recorded
in `patches/hermes/channel-task-return.patch`; the runtime routing mirror has a
separate upgrade patch. `scripts/apply-hermes-mods` verifies the audited Hermes
pin and reapplies the complete patch stack idempotently.

This acceptance covers text results with fixture Slack/model/provider execution,
real profile provisioning, SQLite, encryption and native middleware. Attachment
export and a real Slack/browser end-to-end run are still unverified. Live
end-to-end acceptance requires a controlled owner task covering
private login/code save, original-thread return, another member's follow-up and
original-thread stop.

The local Mac operator and existing Seatbelt/provider trust boundaries remain
those documented in the [execution decision](2026-10-05-local-execution-boundary.md).
