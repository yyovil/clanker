# Preserve same-turn recall when a channel task moves to DM

The MacBook request exposed a gap after the earlier conversation-snapshot fix.
The channel recalled an older selection (M5, 16GB RAM, 256GB storage), then called
`clanker_vault_list`. The private transfer saved only the new request, because
the gateway conversation snapshot was taken before either tool ran. The
isolated worker could not recall shared history and asked for the selection
again. The channel's claim that it had carried the selection over was false.

Each authenticated gateway turn now owns a fresh backend context dictionary.
Tool executor contexts share its reference, including across copied-context
worker threads. Only successful authorized recall results add source messages
to the recall collector. It retains source IDs, channel/thread IDs, text and
links; it does not collect arbitrary tool results, credentials, account state
or unrelated sessions. Existing worker recall restrictions stay in force.

The collector replaces repeated source messages with the latest retrieved
version and retains at most 64 messages and 48,000 serialized message
characters. It evicts earlier captured messages when necessary and records
truncation. Source text clipped by recall also reports truncation. A locked
snapshot gives the handoff a consistent set of complete message records.

Before starting the private worker, the coordinator saves the latest request,
existing conversation and collected recall evidence together. Recalled source
messages are explicitly context, not new instructions or transaction approval.
The same database insert saves a receipt naming the recalled message IDs and
whether context was truncated. Reusing an existing private task returns that
task's stored receipt, so newly retrieved but unsaved facts cannot be claimed
as transferred. Legacy tasks have no recalled IDs in their receipt.

This applies to sequential recall followed by handoff. Concurrent tools still
need their normal dependency ordering: a handoff cannot include a recall
result that has not completed. No generic tool-output capture was introduced.

The Hermes addition is reproduced by
`patches/hermes/recalled-task-context.patch`. Runtime changes live in
`runtime/vault/task_context.py`, `runtime/slack_recall.py`, and the existing
vault handoff/store modules. The new regression runs native binding and tool
registry dispatch with real profile SQLite and separate copied-context tool
threads; Slack transport and worker model execution are fixtures.

See [the verification receipt](../../verification/evidence/2026-10-08-recalled-task-context.md).
The change is locally verified and has not been activated in the running Slack
gateway. Existing failed tasks were not rewritten or resumed.
