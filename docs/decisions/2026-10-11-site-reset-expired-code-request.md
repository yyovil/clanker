# Retire proven unused expired verification forms

Status: locally tested and independently reviewed; activation and live GitHub verification pending.
Finding: `site-reset-expired-code-request`.

## Finding

The final-acceptance GitHub run `r20261011-211537-sign-github-saved-a5d4` stopped before any site reset or fresh authentication. Its exact Hermes session was `20261011_211543_3d416729`, [Slack root `1791733536.916259`](https://clanker-global.slack.com/archives/D0C6F49F2KD/p1791733536916259), gateway PID 82415. At 21:15–21:19 IST on October 11, the reset broker correctly reported an unresolved owner request, but that request was an old unsubmitted verification form whose Kernel collection had already expired at 20:31:32 IST.

`KernelVaultService.poll` marked the collection expired and attempted provider credential deletion without retiring the parent request. Later polls excluded the expired collection, leaving its parent `waiting` indefinitely. Read-only metadata confirmed that the exact old code request had no fill attempts across any version, linked authentication flows, purchases, payloads or resume activity. The reset guard treated that durable terminal form as live work. The sibling cleanup guard had the opposite weakness: its timestamp-only check could skip an expired saved or uncertain code request.

Evidence is preserved in the failed run's `fresh-auth-blocker.json` and the canonical finding directory `.local/clanker-qa/findings/site-reset-expired-code-request/`. No production metadata was changed during diagnosis or repair.

## Change

`KernelStore.expired_unfilled_code_request` is a shared, read-only proof. It accepts only an expired `waiting` code request with an already `expired` collection and exactly matching team, owner, home, task, handle, origin and owner-vault identity. It rejects any fill attempt or orphan outcome for any version, even a completed attempt; resume markers, encrypted payloads, grants, linked authentication flows, purchases and unresolved owner approvals also prevent the proof. A deadline by itself never resolves a provider effect.

Normal polling now revisits historical expired code collections. A new owning store method revalidates scope and proof under `BEGIN IMMEDIATE`, then changes only a qualifying parent status to `expired`. The proof and parent retirement are atomic; collection expiration remains an earlier transaction. All collection, request-source and effect records remain available for audit. Login and API-key requests and unrelated legacy create-unknown flows are not retired by this path. A terminal or expired collection still cannot become ready or claim a fill.

Site reset uses the same proof in a read transaction, so an old terminal row does not block a reset merely because the next poll has not run. That guard does not mutate the old request. Cleanup now blocks all saved requests regardless of age and requires the terminal proof before ignoring an expired waiting code request. Its prior treatment of expired waiting login/API-key requests is unchanged. Existing owner, profile, lease, explicit reset intent, approval and uncertain-purchase guards remain.

This change neither retries provider credential deletion nor treats an unconfirmed deletion as successful. Provider cleanup uncertainty is separate from browser-fill uncertainty: a locally terminal, never-filled code form cannot be resumed or filled. No fresh code, login, reset or browser action is dispatched by lifecycle reconciliation.

## Validation and limits

The canonical runner, with zero file retries, reproduced 36 lifecycle/reset/poll failures (3 existing safety cases passed) and 5 cleanup failures (33 passed). After repair, all 256 tests in seven files passed: the new lifecycle contracts, Kernel metadata store, Vault service, dispatch, creation retirement, site-reset broker and cleanup integration. Logs: `lifecycle-red.log`, `cleanup-red.log`, `lifecycle-green-initial.log`, and `related-green.log` in the finding directory.

Tests exercise real SQLite lifecycle and ownership, all-version dispatched/unknown/partial/completed fills, orphan outcomes, mismatched metadata, saved/resumed work, payloads, auth and purchase links, owner approvals, historical polling, failed provider deletion, real reset/lease handoff and cleanup refusal. Independent source and test review passed.

The read-only production projection at 21:31:52 IST found exactly one qualifying terminal code request, the observed blocker. Five expired waiting login requests remain unchanged; the stricter cleanup checks introduce no current additional blockers. This is local correctness evidence, not proof of a successful GitHub reset, fresh sign-in or autonomous TOTP. The historical failed attempt remains unsuccessful. The coordinator must activate the fix after live writers settle, then run the authorized verification.
