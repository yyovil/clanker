# Recover from stale private-observation bindings without bypassing protection

## Finding

Finding `post-vault-observation-lockout` follows [the Nike task](https://clanker-global.slack.com/archives/D0C6F49F2KD/p1791711657132759), run `r20261011-151057-add-one-pair-640d`, Hermes session `20261011_151103_f2543029`, Kernel browser `aezvkk5m1ewze7fyqjklaanu`. A saved-phone fill was retained in the intended field. The merchant's Get OTP request then showed an HTML/JSON response error. Between 15:25 and 15:29 IST, navigation, image observation and one Escape attempt returned the same generic private-observation refusal. No screenshot or address-confirmed checkout was completed.

The owned browser and its one persisted privacy guard remained present. Observation uses the secret socket only while its original document binding matches. A full navigation or supervisor reattachment can make that binding stale or absent. The native-tool middleware checks privacy both before the action and in the result-processing path afterward. Consequently, an action can run and then have its result withheld; subsequent actions cannot reach execution. The old error gave no safe recovery instruction, while the browser policy required keeping unfinished login tasks open.

The live generic error discarded the underlying typed reason, so the exact first live refusal phase is unknown. In particular, the first navigation may already have occurred. The document-change lockout is reproduced locally; this is not proof that Nike's upstream login response caused the binding change.

## Change

For only explicit `success: false` results typed `active_page_changed` or `active_page_unbound`, keep the 409 refusal and direct the model to call the existing authenticated `clanker_browser_stop`. Reopen through `browser_navigate` only after stop confirms completion, then inspect fresh state. The instruction warns that the preceding navigation or action may already have happened, invalidates old references, and forbids replaying login, codes, fills, submissions or other mutations.

No guard is removed, rebound or bypassed by the refusal. No cleanup or retry runs automatically. The existing stop route still selects the authenticated thread, verifies owner claims and remote deletion, removes that closed browser's guard metadata, and retains its profile. Failed deletion leaves the session and guard in place. Foreign sessions remain untouched. Unrelated or untyped errors retain the old generic refusal, and visible sensitive fields still block image observation.

The static browser policy has one narrow exception for explicit backend stale/unbound private-observation recovery instructions. Ordinary login errors, owner input and payment waits still require keeping the browser open. The browser paragraph was compacted to fit the aggregate prompt budget while preserving account ownership, private authentication, OTP, secret-argument, public-update, payment and terminal restrictions. It still requires inspecting the live page after OTP entry failure, reusing Managed Auth, and verifying successful sign-in. No dynamic prompt data or per-turn cache mutation was added.

## Validation and limits

The new regression first failed twice with five passes after its fixture was configured. It then passed with the related suites: **150 passed, zero failed, eight expected legacy failures**, with zero file retries. The five canonical files were `test_vault_privacy_recovery.py`, `test_kernel_vault_service.py`, `test_kernel_vault_split_otp.py`, `test_clanker_kernel_browser.py`, and `test_kernel_task_profiles.py`, all under `verification/probes/`.

The regression executes the real middleware, browser ownership/profile storage, private evaluation wrapper and stop route with fixture browser I/O. It proves navigation dispatch before post-action refusal, withholding private output, refusal before later native actions, explicit owned stop/reopen with a new browser and the same profile, preservation of another owner's browser, failed-cleanup locking, no automatic rebind/replay, and unchanged generic-error handling.

The targeted browser-policy test passes (one test, also passed within the final full routing run). It checks every registered section's complete content survives prompt formatting, in addition to the 7,900-character budget. Its equivalent payment phrasing checks were aligned with the current owner-instructed private-card policy. The final `test_kernel_only_routing.py` run has **29 passed and four pre-existing failures**: two expect an older payment phrase, and two expect more detailed personal-read guidance absent from the current policy. Those unrelated assertions were preserved, not weakened or counted as passing. Full-file baseline and final logs document this limit.

Snapshots and logs are under `.local/clanker-qa/findings/post-vault-observation-lockout/`: `recovery-focused-red.log`, `recovery-green.log`, `recovery-policy-green.log`, and `recovery-routing-full-final.log`. This repair does not resolve the merchant's Get OTP failure, prove phone authentication, or complete Nike's saved-address/screenshot criteria. No live retry or benchmark success is claimed.

The canonical idle QA restart activated this repair at 15:51 IST on 11 October (PID 98832 → 4624; `clanker-qa-restart-20261011T102123Z.log`). Slack reconnected with zero active agents and no pending human gate. Status is **deployed, live recovery verification pending**. No further Nike attempt was launched.
