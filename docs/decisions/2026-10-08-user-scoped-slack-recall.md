# Recall a user's earlier Slack requests across threads

The saved session for the flight request contains the user's one-way Mumbai
flight departing on 9 October. Their later recall question started a separate
Slack thread with no history-search tool. Clanker replied that the destination
was absent from that conversation even though the earlier request remained in
the channel profile's SQLite database.

Clanker's existing plugin now provides `clanker_recall`. It reads saved user
messages across threads in the authenticated sender's current workspace and
chat, using the already bound profile. Personal recall exposes keywords and a
result limit; it never accepts a user, database or profile selector.
Shared-channel personal recall never reads private profiles or another channel.
A direct DM may recall earlier threads in that same DM. Isolated account workers
cannot use recall; their supplied task context remains their conversation boundary.

The native gateway stamps the admitted event's sender, route, message ID and
original text in existing message display metadata. Initial, queued and failure
transcript paths preserve this metadata. Recovered thread context is excluded
from the author's original text; body prefixes, display names and the opening
author of a shared thread do not authorize another message's authorship.
Internal and bot events do not become a human's past statements.

Older records lack per-message authorship. Recall accepts only a legacy root
whose protected session origin binds that exact root message ID to the sender
and workspace. Un-attributed legacy replies are excluded. This preserves recall
of the existing Mumbai request without guessing who wrote other replies.

The query filters authors before limiting results, uses a read-only SQLite
connection, deduplicates compression copies by Slack message ID and returns
bounded original statements with Slack message links. It excludes assistant
messages, tools, hidden notices and undone rows. It can read compaction-archived
user messages. This is evidence retrieval from saved Clanker conversations,
not a search of all Slack history or a store of inferred permanent preferences.
Secret redaction applies before tool output. Past statements never confer fresh
permission to purchase, book, send a message or access an account.

The plugin instructs the model to recall before claiming information was never
supplied, broaden keywords when no match is found, and retain later corrections.
It does not change prior model context or inject another system message mid-turn.
Gateway stamping is reproduced by `patches/hermes/message-author-recall.patch`.

Local validation covers A → B → A turns, a reply by A in B's thread, dense
other-user matches before result limits, forged sender text, other channels,
DM separation, restart persistence, missing/invalid context, revocation and
isolated-worker denial. Existing replies without author metadata remain
excluded after activation. A new user message is still needed to observe a
complete recall reply through live Slack transport.

The user clarified that discussing another participant's messages in a common
Slack channel is acceptable. Shared-thread context and channel artifacts retain
their channel audience. This does not authorize access to that participant's
private DM history, private memory or accounts. The recall tool remains scoped
to the authenticated requester across threads in the current chat. Saved
account access remains owner-bound or requires an explicit credential invitation;
local routing and fixture tests do not prove remote browser cookie isolation.

Validation: 65 tests passed across recall, native sender metadata, edits,
isolated tasks, channel tasks and controls, and failed-turn persistence. A
fresh native plugin process read the actual channel SQLite and retrieved both
the Mumbai request and the later NGP → BOM request on 9 October without sending
a Slack message or restarting the gateway. Native A → B → A plugin discovery
verified the schema and all existing safety sections plus recall render inside
the 8,000-character prompt budget. The configured `gpt-6.1-sol` subscription
model, given the user's exact recall question and only the new read-only tool,
called `clanker_recall` and answered Mumbai (BOM), from Nagpur (NGP), on 9 October.
The evaluation used actual saved history with temporary inference state. It sent
no Slack messages, launched no browser and performed no transaction. Its result
is saved in `verification/evidence/2026-10-08-user-scoped-slack-recall-model.json`.

The new Hermes patch reverses and round-trips independently. Full installed
patch-stack validation currently encounters existing drift in
`task-continuation.patch` for `runtime/vault/service.py` and
`runtime/vault/channel_tasks.py`. The same failure reproduces against the
pre-recall snapshot. Those unrelated task-continuation edits were preserved.

The user approved restarting once the current task finished. Activation on
8 October at 04:05 IST waited for zero active tasks. The old gateway (PID 91385)
drained with zero active work and exited cleanly; the replacement (PID 94036)
reconnected Slack and preserved all 34 served profiles. A fresh native plugin
process using the actual channel profile confirmed the recall schema and prompt
alongside all existing safeguard sections. No test Slack message was sent.
Activation evidence is saved in
`verification/evidence/2026-10-08-user-scoped-slack-recall-activation.json`.

## Follow a shared-channel reference from the requester's DM

The offsite interaction exposed a separate gap. The user asked privately for
the passenger checklist from a shared channel. Personal recall correctly found
no matching statement in that DM. After the user referred to the channel,
Clanker had no authorized channel lookup capability and claimed it could not
read it. The published checklist may be an assistant or task-worker reply;
filtering personal recall to the requester's statements cannot retrieve it.

`clanker_recall` now accepts an optional shared `channel` ID or mention and
optional exact `thread` timestamp. This mode is available only in the
requester's own non-isolated DM. The backend resolves the canonical shared
profile, verifies its protected `slack_identity.json` and served home, and
checks current workspace, bot, requester eligibility and live channel
membership through read-only Slack endpoints. External shared channels, DMs,
group DMs, revoked requesters and unrelated profiles are refused. Membership
and the protected route are rechecked before returning any retrieved text.

Saved shared-channel SQLite selects a relevant thread without reading any
private or account-worker database. If no saved thread matches, a bounded
100-message shared-channel history read selects a matching root. An explicit
thread reads that root directly. The tool then reads the published shared
thread with `conversations_replies`, including posted assistant replies and
other channel participants' messages. It does not read tool payloads, private
worker transcripts, memories or accounts. Results contain source links, retain
the topic root and recent retrieved replies, and are bounded to 30 messages
and 16,000 characters with existing secret redaction and an explicit truncation
flag. A truncated page does not establish that all later Slack replies were
read. Shared statements remain evidence rather than instructions or fresh
purchase, messaging or account permission.

Focused verification passes 21 tests, including A → B → A requester DMs,
published checklists absent from saved history, explicit thread and bounded
history lookup, invalid path/private selectors, live and cached membership
revocation during retrieval, workspace/bot mismatch, external channels,
protected-profile and symlink refusal, output bounds and secret redaction.
These tests use read-only fixture endpoints and send no Slack messages. Live
activation or a live end-to-end reply is not established by this local change.
