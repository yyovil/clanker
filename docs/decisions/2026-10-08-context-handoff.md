# Carry task context into DM and publish separate shared outcomes

The offsite interaction exposed two independent gaps. The requester opened a
new DM thread while the trip discussion was stored in a shared-channel profile.
Personal recall searched that DM twice, found no trip context, and had no path
to use the later channel referral. The actual private task handoff did preserve
the originating conversation, but its worker replies were copied to the shared
channel. A private greeting and checklist therefore appeared publicly as if
the channel were a DM.

The user asked for internal context continuity, no redundant copying, and
intended-user mentions in shared-channel replies. An initial DM-only correction
went too far: other participants still need task progress and the outcome.
Private dialogue remains in DM, while a separate public update path keeps the
originating group informed. This supersedes both automatic worker-reply copying
and the intermediate all-results-private interpretation.

`clanker_recall` now accepts an optional shared-channel ID/mention and thread
timestamp from the requester's owner DM. The protected shared profile selects
a relevant thread; authenticated Slack reads retrieve its published replies,
including assistant checklists absent from the shared profile's saved model
transcript. Workspace, requester, bot and live channel membership are checked
before reading and again before returning. This does not read other private
DMs, isolated worker databases or account state. Retrieved messages are source
evidence, not new instructions or transaction approval. Output is bounded and
reports truncation.

When a shared-channel user asks to continue privately, the existing handoff
captures the conversation and confirmed choices in protected task state. The
channel reply links the DM once. Native DM replies remain bound to that task
and owner after restart. Greetings, questions and ordinary replies use the
DM outbox only; the original thread receives no automatic copies. Previously
pending public-target records also recover to the authenticated owner DM and
retain the ongoing task relation. Private account access remains isolated.

`clanker_task_update` publishes meaningful milestones and the final group-facing
outcome to the original shared thread. Progress uses short backend templates
for working, waiting on details/access/approval, or blocked. A final update
requires a fresh concise summary of the observed result; receiving details or
signing in does not mean the requested task succeeded. The destination and
requester mention come from the authenticated original task. Passenger names,
birth dates, contact/account details, credentials and private form links stay
private. This tool is unavailable outside an authorized linked private task.

Public summaries have a separate encrypted durable outbox; they cannot
overwrite a pending DM reply. Repeated current statuses are suppressed, final
outcomes supersede unsent progress, and retry recovery uses stable Slack
message identifiers. Delivery rechecks membership, cancellation and original
and private request edits. The linked DM remains available after a public
outcome. Ordinary DM answers do not append public-delivery receipts.

Later shared-thread questions receive the latest already-published summary as
public evidence, including questions from another authorized participant.
This does not attach that participant to the requester's private worker or
expose its dialogue, pending DM replies or private form status.

Shared-channel replies address the current transport-verified Slack requester,
using `metadata.user_id` rather than a display name or the shared session's
opening author. The opt-in `gateway.platforms.slack.mention_reply_user` applies
to sends, edits and sealed native streams. Existing intended mentions are kept;
DM replies are untagged. Clanker defaults enable this presentation.

The generic Slack capability note now directs the model to loaded plugin
schemas instead of declaring all channel lookup unavailable when native Slack
administration tools are absent.

Validation and activation status are recorded in
`verification/evidence/2026-10-08-context-handoff.md`.
