# Preserve the conversation when a channel task moves to private execution

The flight request in Slack thread `1791396352.709549` asked for the earliest
one-way Mumbai flight on 9 October. Clanker asked the origin and received `NGP`.
The originating session retained both earlier messages and attempted a flight
search. Calling `clanker_vault_list` then created an isolated worker whose
durable task contained only the latest reply, `NGP`. That worker's response was
`What would you like me to do with “NGP”?`.

The failure was in the private handoff, rather than Slack session identity or
the main model's interpretation of the clarification answer.

The native gateway now binds an immutable text snapshot of the current
conversation alongside the authenticated source and latest message. The vault
handoff saves that conversation and latest answer together in the existing
durable transfer record. A coordinator restart resumes the same task context.

The snapshot includes conversational user and assistant text, retaining speaker
labels already present in the originating session. It excludes system messages,
reasoning, tool calls, tool results, and image bytes. Account authorization still
comes from the authenticated source and validated transfer, never the snapshot.
No private memory, unrelated sessions, or another profile's files are read.

The Hermes changes are reproduced by `patches/hermes/task-context-handoff.patch`
after the existing patch stack. Runtime formatting remains in
`runtime/vault/channel_tasks.py` and transfer binding in `runtime/vault/service.py`.

Regression coverage exercises the native turn wiring and the flight
clarification handoff with real temporary profiles and SQLite, in A → B → A
order and after coordinator restart. Slack transport and model execution are
fixtures; these checks do not prove a live provider flight search or purchase.

Validation: 55 tests passed across the native isolated-task wiring, channel
tasks, channel controls, and vault flow. Both added regressions failed before
the fix. The complete installed Hermes patch stack reverses cleanly in scratch
space, and the new patch round-trips to the exact modified source. One existing
execution-gate fixture needed its missing profile home field. The final suite
ran with one file worker after concurrent fixtures exhausted temporary disk
space. Pre-activation validation performed no live Slack message, gateway restart, or provider request.

The same trace also contains a public-search rejection because a route city
matched a registered private value, and an account detour while a browser run
was still active. This change repairs context loss; those execution decisions
and the public-search redaction policy remain separate issues.

The user approved activation on 8 October. The gateway restarted successfully;
Slack reconnected and all 24 served profiles were preserved. A fresh-process
probe verified the flight goal, question, and answer remain in the handoff. No
live Slack replay message was sent, and the separate search-filter issue remains.
