# QA replies in private handoff threads

## Finding

The travel run `r20261011-162819-sort-out-travel-67e0` reached its owner-bound private thread, but the QA driver's `send --root` rejected that thread as unknown. Transcript collection already used durable handoff records to correlate it. No tester message was sent by the rejected call, and this was a QA driver defect rather than a Clanker response failure.

Evidence: [public handoff request](https://clanker-global.slack.com/archives/C0C6J277ZNG/p1791716299112579) and [private continuation](https://clanker-global.slack.com/archives/D0C6EAXPKEE/p1791716309788959), 16:28–16:34 IST on 11 October 2026.

## Change

Explicit reply roots are resolved from the driver's existing owner-bound causal thread set. A destination must be unique and belong to the sending tester's own Clanker DM or the test channel. Unknown, unrelated, ambiguous, foreign-owner, and foreign-DM destinations remain refused. Successfully used handoff roots are then recorded so later followups stay in the same thread.

The external driver and its test file were copied with SHA-256 metadata before editing because the driver's snapshot command accepts only project files. Those copies are in the local `qa-private-handoff-reply-root` finding. The decision document used the normal snapshot command. No gateway restart or production-state write was required.

## Validation and limits

The new regression first failed for the legitimate owned handoff while four negative cases passed. After the fix, all 75 driver tests passed through the canonical Hermes test runner. The live followup then posted successfully to the verified owner DM at `1791716672.544959`. This establishes QA routing, not completion of the travel scenario.

An earlier 53-second watcher timeout in this run was caused by the coordinator choosing a timeout shorter than the driver's normal settling window. A subsequent normal watcher reported the same turn settled; the short wait is retained as evidence and is not counted as a Clanker failure.
