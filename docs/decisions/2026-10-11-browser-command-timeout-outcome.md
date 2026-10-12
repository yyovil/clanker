# Browser command timeout outcome and bounded character input

## Finding

The Goa verification run `r20261011-171531-help-plan-12-01ab` failed during a document edit, before any of its three scripted preference followups. Its [public planning root](https://clanker-global.slack.com/archives/C0C6J277ZNG/p1791719131684689) handed off to [this private task](https://clanker-global.slack.com/archives/D0C6EAXPKEE/p1791719144303049). The private Hermes session was `20261011_171545_950ff79b`, native task `ck-e6b1ec28ee180fdd993229acd02f6c17b066358d`, Kernel browser `d6h35wvxblzvbgrmrlogv7vm`.

At 17:26:38 IST on October 11, the agent submitted 1,650 characters with `browser_type` in character mode. The profile's logs reported the native `type` command timing out after 30 seconds at 17:27:19. Timeout teardown removed the CDP supervisor while retaining the remote browser. `KernelBrowser.finish` then replaced the actual timeout with the generic 409 instruction to open the requester's browser. The document retained a partial, visibly garbled insertion. Later recovery closed/reopened the browser and requested another sign-in; the tester cancelled the bounded attempt instead of supplying another login.

This is a harness failure, not evidence that Google rejected the original authenticated session. The exact run retains its failed outcome. The unrelated shared-followup worker repair remains unexercised by this attempt.

The preserved agent-browser v0.31.1 source at commit `d851d3490cc4faa4a3ffedf020d69c23bf51f8ed` explains why a larger outer timeout alone would be unsafe:

- `interaction.rs::type_text_into_active_context` awaits a CDP operation for every character (two for newline, carriage return or tab), with zero default artificial delay.
- `commands.rs` gives `type` no operation-timeout field. `connection.rs::read_timeout_for` therefore uses a 30-second socket read timeout.
- `connection.rs::send_command` may resend transient failures five times. This is an upstream replay risk; the live evidence does not establish how many internal sends occurred in this particular call.

The exact primary sources, URLs and hashes are preserved in `.local/clanker-qa/findings/browser-context-lost-during-doc-edit/upstream/` and `upstream-provenance.json`.

## Change

Native cloud/CDP timeout teardown now stamps its replacement client record with host-generated timeout provenance. Partial stdout/stderr are removed without returning or logging them for cloud/private commands. The wrapper returns an explicit `browser_command_outcome_unknown` code and never invokes its own retry or Chrome fallback after that timeout.

Kernel finish recognizes only that trusted record marker, validates the authenticated requester, home, task, native record, remote session, CDP endpoint and browser binding, and discards the entire supplied result. It emits a fixed message explaining possible partial completion and directing a fresh snapshot of the same task before reconciliation. It does not forward even an apparent success, image, or error payload. No ownership or privacy guard is removed, no login is replayed, and no browser is automatically closed. Normal preparation reattaches the existing owned remote browser; stale private-document guards still fail closed.

Character mode now accepts at most 256 characters, refusing longer requests before any clear or browser command. Its schema and refusal direct long text to the existing single-insertion `fill` mode and require verifying application acceptance. The 256-character boundary is a conservative admission limit, not a guaranteed performance estimate. Native character typing is capped at 25 seconds, below the upstream socket retry threshold; lower explicit timeouts remain effective. Other commands retain their existing timeout policy. No new rich-editor mode or automatic chunking was added.

## Validation and limits

All tests used the canonical Hermes runner with `--file-retries 0`, no live browser or Slack calls:

- `timeout-red.log`: five expected failures and one pass before the core repair, reproducing masked timeout, wrong ownership-error classification, cloud partial-output leakage, and fallback entry after a dispatched timeout.
- `input-prevention-red.log`: three expected failures before the input guard/cap, including the real registered `browser_type` path clearing and typing an oversized request.
- `timeout-related-final.log`: **143 passed, 8 expected legacy xfails**, across nine files. The new boundary tests prove partial mutation precedes timeout, raw/image output cannot escape, foreign owner/session bindings are rejected, A→B→A keeps separate existing browsers, privacy guards survive reattachment, and oversized character input leaves the field untouched while direct fill remains available.

The nine files are `hermes/tests/tools/test_browser_command_timeout_outcome.py`, `test_browser_private_command_output.py`, `test_browser_open_timeout.py`, `test_browser_suspect_recycle.py`, `test_browser_type_modes.py`, `test_bot_desktop_browser_fence.py`, plus `verification/probes/test_kernel_browser_command_timeout.py`, `test_clanker_kernel_browser.py`, and `test_vault_privacy_recovery.py`.

Peer review separately checked trusted provenance, ownership, private output suppression and the new input limit. These checks prove local contracts, not successful Google Docs editing or a full benchmark pass. Wrapper tests establish one Hermes dispatch, not the absence of all upstream retry behavior. The 25-second deadline preempts the known 30-second character-command retry in ordinary scheduling; it is not a hard real-time guarantee. A timed-out action still requires inspection because its external outcome is unknown. Deployment and a new authorized live verification remain separate steps.
