# Saved login browser reopen contract

## Finding

QA finding `vault-fill-missing-supervisor` (S2) was reproduced in Nike run
`r20261011-144306-add-one-pair-640d`,
[Slack root](https://clanker-global.slack.com/archives/D0C6F49F2KD/p1791709986214739),
Hermes session `20261011_144311_98e8637c`, on 2026-10-11 from 14:49:43 to
14:53:05 IST (09:19:43 to 09:23:05 UTC).

The bag was verified, but the saved-address follow-up could not advance.
`ManagedAuth` selected the requested saved login and returned
`saved_login_available` with an instruction to use the current task browser.
Account selection had actually switched from the current anonymous shopping
profile to an earlier retained profile for that same owned login. This is the
intentional policy documented in
`2026-10-11-retained-profile-account-switch.md`; it retired the current browser
without starting another one.

Kernel browser `i259ul8hwbx842pkyau965vw` was deleted at 09:22:35 UTC, before the
saved-login result at 09:22:43. The exact task had no selected browser or native
supervisor afterward. Two subsequent vault-fill calls returned HTTP 409:
`Open this task's browser form before using Kernel vault.` That guard correctly
prevented filling an absent or stale browser form. No phone dispatch or retained
phone readback occurred, so this run did not exercise the separate phone-format
repair. Full functional completion was false; no purchase or payment occurred.

## Change

The saved-vault branch of `runtime/vault/managed_auth.py` now reads the owned
browser state after account selection and reports `browser_reopen_required`.
Only the specific missing-selection 409 becomes a reopen hint; ownership and
unrelated failures still propagate. A selected session keeps the existing
current-browser instruction.

When no selected session exists, the result instructs the agent to call
`browser_navigate` to the intended origin and inspect a fresh snapshot. It
explicitly invalidates old form references and requires checking the account
and reconciling the cart before continuing. It does not promise that an
anonymous cart transferred to the retained profile. Both `clanker_authenticate`
and login requests through `clanker_request_access` share this response.

This changes only the recovery contract. It does not create browsers, fill
credentials, change account/profile selection, relax ownership, or bypass the
vault supervisor check. The canonical QA snapshot precedes all three changed
files for rollback.

## Validation and limits

The new regression suite uses the real account/profile selection, owned state,
teardown and native registry with fake remote clients. Before the fix, five
tests failed and one passed. After the fix, all eight pass, covering unchanged
anonymous/admitted browsers, an older saved-account profile replacing a current
anonymous browser, explicit reopening, no initial browser, account-in-use
refusal and an ownership failure during the post-selection read. Two additional
guard cases directly verify that unrelated selected-browser 403/409 errors
propagate unchanged rather than becoming reopen hints.

Canonical runner from `hermes/`:

```sh
bash scripts/run_tests.sh --file-retries 0 \
  ../verification/probes/test_saved_login_browser_reopen.py \
  ../verification/probes/test_saved_login_routing.py \
  ../verification/probes/test_kernel_task_profiles.py \
  ../verification/probes/test_kernel_managed_auth.py \
  ../verification/probes/test_kernel_vault_service.py
```

Result: **155 passed, 0 failed** across five files. Independent read-only review
found no blocker. These tests establish the response contract and preservation
of account isolation; a session ID alone is not a general proof of supervisor
or provider liveness.

The fix was activated by the idle QA restart at 09:39 UTC (gateway PID 98832).
The unchanged Nike verification `r20261011-151057-add-one-pair-640d`
([Slack root](https://clanker-global.slack.com/archives/D0C6F49F2KD/p1791711657132759),
Hermes `20261011_151103_f2543029`) then exercised the actual transition. At
09:49:46.120 UTC, saved-account selection returned
`browser_reopen_required: true`. Clanker followed it with `browser_navigate`,
completed at 09:50:25.776, and a fresh login interaction in Kernel browser
`aezvkk5m1ewze7fyqjklaanu`. At 09:51:29.759, vault fill succeeded with one field
filled and retained readback `expected: 1`, `matched: 1`, `nonempty: 1`. The old
missing-supervisor 409 did not recur. This verifies the repaired browser-reopen
contract and separately supplies live proof for the saved-phone readback fix.

That is not full Nike task acceptance. At 09:53:28.425 UTC, the site's login
modal displayed `Failed to execute 'json' on 'Response': Unexpected token '<',
"<HTML><HEA"... is not valid JSON` and remained at Get OTP. No HTTP status or
verification step was observed, and the evidence does not establish invalid
credentials or which upstream layer supplied HTML. The saved address was not
applied. The last visible bag quote was INR 7,495 with free delivery, explicitly
reported as not address-confirmed. No owner sign-in intervention or purchase
occurred. The run's `evidence/mechanism-verification.json` retains the exact
sanitized tool timestamps and outcome; no phone or form values are included.

The full run finished `fail`: subsequent bag navigation and screenshot capture,
including one bounded correction, were refused by the separate observation
protection guard. That symptom is tracked as `post-vault-observation-lockout`;
it does not undo the verified reopen or retained phone-readback mechanisms.
