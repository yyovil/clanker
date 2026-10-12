# Report an explicit stop without stale working progress

## Finding

Finding `slack-working-status-after-stop` is associated with Instamart run `r20261011-042248-open-instamart-start-906e` ([private task](https://clanker-global.slack.com/archives/D0C6EAXPKEE/p1791672768652429)), Hermes session `20261011_042255_d1690c90`. On 2026-10-11, the user stopped the task at 04:24:05 IST. The gateway acknowledged an ordinary correction at 04:24:08 and emitted a new working status at 04:26:39. Its final stopped report arrived at 04:27:40.

The pending navigation was dispatched at 04:24:02, before the stop, and returned at 04:26:50. Only browser cleanup was dispatched afterward. The partial report at 04:31:54 was accurate and used no tools. Functional cancellation therefore passed in this run; the misleading status failed the QA assessment at severity S3. Evidence is in the run's `evidence.md`, `transcript.md`, and `evidence/trajectory.md`. A Kernel session was unavailable after cleanup, so provider audit logs did not independently establish remote settlement.

The busy-message path treated a plain-text cancellation as a correction, while the heartbeat checked active ownership without a cancellation state. Review also reproduced a misleading receipt when the correction path demoted an interrupt behind active subagents or compression, and when an interrupt failed. Further lifecycle review found that cached typing text could survive cancellation, a slow receipt could let a queued report outrun source cleanup, and suppression could leak into legitimate recursive successors.

## Change

Recognize a narrow, complete cancellation instruction from an authorized external text event. Task limits, negations, questions, quoted text, fenced code, and ordinary corrections retain their existing behavior.

Use the existing `request_hard_interrupt` primitive for cancellation immediately. It already handles compression cancellation and child-agent propagation. Cancel background delegations only for the current session and invoke the existing source-scoped plugin stop cleanup. Supersede queued human work with the stop/report event while preserving claimed internal completions. Retain the active session slot and its generation so the existing follow-up drain can report after the interrupted executor settles. The full slash-stop cleanup path deliberately releases and invalidates that slot, so it is not used for this reporting flow.

Only an accepted interrupt sets the per-turn stop state. It receives a stopping receipt even when an ordinary acknowledgement would be debounced. A missing or failed control reports that work has not stopped; it neither queues a success report nor suppresses progress. Accepted cancellation clears the cached live phrase, pauses the owning session's typing refresh while other threads continue, and suppresses subsequent working heartbeats, fallback sends after a failed heartbeat edit, and tool-progress updates.

An owned completion task joins the stopping receipt and source cleanup. Normal queue drain, exceptional turn cleanup, and native session reset wait for it before releasing or advancing the stopped session. Cancelling the receipt handler cannot detach cleanup from that barrier, and repeated stops share the pending operation. The vault control hook recognizes only the exact originating stop context, avoiding a self-wait or cancellation of its own reporting carrier while retaining normal cleanup for other sessions. Cleanup failures and pending results become a safe report note. Suppression persists for the exact cancellation-report event; the real recursive handoff resets it and resumes typing for a subsequent request. Ordinary correction routing and its subagent/compression protections remain unchanged.

## Validation and limits

The initial regression was red with 6 failures and 5 passes. Review regressions reproduced false acceptance with 4 failures and 20 passes; requiring immediate hard cancellation, queue supersession, and truthful failure produced 12 failures and 12 passes before the correction. The lifecycle regressions were red with 14 failures and 14 passes. Logs are `/tmp/clanker-stop-status-red.log`, `/tmp/clanker-stop-status-acceptance-red.log`, `/tmp/clanker-stop-status-hard-cancel-red.log`, and `/tmp/clanker-stop-lifecycle-red.log`.

The canonical runner (`bash hermes/scripts/run_tests.sh --file-retries 0 -j 1`, using absolute test paths) passes **177 Hermes checks across 23 suites**, including all 124 prior checks. Results are in `/tmp/clanker-stop-lifecycle-final.log`:

- Stop status and lifecycle: 31; busy acknowledgement: 13; redirect anchors: 3; steer origins: 21.
- Busy authorization: 3; multiplex busy routing: 24; internal-event protection: 1.
- Progress interruption: 5; progress cleanup: 2; session cleanup: 3.
- Subagent protection: 6; compression demotion: 1; real interrupt propagation: 11; compression interrupt protection: 7.
- Typing timeout: 6; typing toggle: 1; Slack typing lifecycle: 3; queued delivery: 2; queued processing hooks: 7; native stopped hooks: 4; background delegation stop: 2; chat-scoped stop: 16; sibling-thread stop: 5.

Nine current Kernel/control checks also pass in `verification/probes/test_clanker_channel_control.py`, selected with `-k 'configured_kernel_control or original_thread_controls or message_edit or kernel_stop_attempts'`; `/tmp/clanker-stop-kernel-control.log` records the result. These include real source-hook re-entry with SQLite ownership and a synthetic Kernel transport. Five other tests in that file instantiate the removed local `VaultStore` and fail at its constructor; the unchanged pre-edit test snapshot reproduces those failures (`/tmp/clanker-stop-control-baseline.log`). Those obsolete fixture paths were not rewritten as part of this fix.

The stop tests exercise real hard-interrupt propagation, an unresolved executor future, failed controls, internal-completion retention, normal corrections, and the heartbeat edit/fallback race. Lifecycle checks use the real typing loop across two threads in one chat, held receipt/cleanup events, handler cancellation, repeated stops, exceptional release, and the real recursive queue handoff without manually clearing turn state. External Slack and provider acceptance remain unverified.

The fix was activated by the idle QA restart around 05:17 IST (historical gateway PID 88444). Live acceptance `r20261011-051755-open-instamart-start-906e`, Hermes session `20261011_051800_768570f8`, passed in the [exact Slack thread](https://clanker-global.slack.com/archives/D0C6EAXPKEE/p1791676075407169). The stop at 05:18:50 IST received a stopping receipt at 05:18:52 and final stopped report at 05:19:15. The pre-stop snapshot was abandoned and only cleanup followed. No correction acknowledgement, new working status, cart mutation, payment or order appeared. The 05:20:14 partial report matched the trajectory and used zero tools. The finding is verified.

Historical native typing events are unavailable; local lifecycle tests cover typing suppression and delayed cleanup races. An already-dispatched provider request or Slack edit can still finish after cancellation is requested; the receipt does not claim those operations have already stopped.
