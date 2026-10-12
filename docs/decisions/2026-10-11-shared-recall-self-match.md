# Shared recall excludes the current request from implicit earlier-plan lookup

## Finding

Fresh final-acceptance reschedule run `r20261011-222708-move-company-offsite-8304`, Slack root `1791737828.344409`, Hermes shared session `20261011_222713_8baad117` called recall with `offsite`, `Goa`, then no query. All three successful responses selected its own just-posted root and returned only that request (messages 1352–1357, 22:27:19–22:27:37 IST on 11 October 2026). The model then asked for the already-published plan link at message 1358, 22:27:42.

The existing older plan was root `1791735618.931279` in the same authorized channel. Fresh recall row 10 had retrieved that plan and its Doc without tester correction in session `20261011_221906_353631d3`, message 2487 at 22:19:22. Thus the plan existed; newest-match selection hid it behind the current shared request. Evidence: [failing Slack root](https://app.slack.com/archives/C0C6J277ZNG/p1791737828344409), `.local/clanker-qa/batches/2026-10-11-final-acceptance/GOA_RECALL_DIAGNOSIS.md`, and `11-move-company-offsite-8304/runs/r20261011-222708-move-company-offsite-8304/evidence/trajectory.md` in that final-acceptance batch. These recall calls used no browser.

## Change

For an implicit shared-channel lookup, exclude the authenticated caller's exact current shared root, matching the existing isolated-worker behavior. Apply the same exclusion to saved history and the bounded live-history fallback. Explicit thread selection, unthreaded callers, existing access checks, history bounds, and evidence-only semantics remain unchanged. No caller-selected owner, home, channel permission, or broader history access is introduced.

## Validation and limits

The reviewed patch was applied only after the coordinator confirmed all live tasks stopped and no active agents/profile leases remained. Test-first canonical validation reproduced **7 failed, 7 passed** on the unchanged source: all six saved/live query variants selected the current request, and the current-only case also returned it. The explicit-read, unthreaded and authorization cases already passed. `red.log` is preserved under `.local/clanker-qa/findings/shared-recall-self-match/`.

After the narrow source change, the canonical runner from `hermes` with `bash scripts/run_tests.sh --file-retries 0` passed all four requested suites: `test_shared_recall_self_match.py` **14**, `test_isolated_shared_recall.py` **12**, `test_clanker_recall.py` **23**, and `test_clanker_recalled_handoff.py` **2**. Total **51 passed, zero failures and zero retries**, preserved in `green.log`. Tests use real temporary profile/SQLite history and owning routing/recall code with fixture Slack transport; no production/provider calls occur. Source/test/doc hashes and snapshot-relative `fix.patch` are recorded in the finding's `freeze.json`.

The new regression covers an older authorized plan and a newer same-keyword current request for both saved and live discovery, queries `offsite`/`Goa`/empty, explicit current-thread reads, current-only and unthreaded behavior, private-data non-selection, unauthorized channel/DM refusal and revocation before disclosure. Existing isolated-worker tests must remain green.

No gateway restart, deployment marking, new QA start or live re-verification was performed by this repair. This addresses the observed self-match only. It does not make one-thread search universally resolve multiple unrelated earlier plans, nor fix row 09's model decision to stop after an explicit current-thread lookup. Preserve both original benchmark outcomes and activation hashes. No extra live QA start is authorized by this patch.
