# TODO: Reuse Clanker browser profiles and retire abandoned login profiles

Recorded: 2026-10-11 (Asia/Kolkata)
Status: Scheduled with a strict dependency check; implementation not started.

## Dependency

Implement after **Set up Clanker QA tester auth** finishes working.
Codex chat: `01a12671-b566-7e21-8834-91ee7b060847` (local).

Before starting implementation, obtain a fresh status for that exact chat and
confirm its latest turn completed, it is no longer working, and its final result
reports completion or an explicit end to the work. While it is working, waiting
for input/approval, or its status is uncertain, only check the prerequisite; do
not start implementation or testing. If it resumes, defer further changes until
it finishes again.

Checked on 2026-10-11: the chat was idle, its latest turn completed, and its final
report said the benchmark stopped with 6 of 12 tasks completed. This historical
observation must be revalidated before execution; it does not mean every
benchmark scenario passed.

## Agreed behavior

Personal tasks should reuse the task creator's persistent browser profile across
tasks and Slack threads. Keep shared credentials, including shared Swiggy access,
in a separate browser profile. Do not merge shared-account cookies into personal
profiles or change the current credential-sharing model.

For the discussed setup, the intended durable inventory is three personal
profiles plus one shared-account profile. This is an identity-based target, not
a hardcoded global limit of four. Vaults and browser profiles remain distinct
resources.

## Work

- [ ] Select personal profiles using a stable workspace/user identity instead of
  allocating another durable profile for every task or Slack thread. Preserve
  task authorization and user isolation.
- [ ] Reuse the dedicated shared-account profile only for authorized access;
  preserve permission/revocation checks and coordinate concurrent writers.
- [ ] Ensure failed, expired, canceled, and superseded login flows reach cleanup
  after any deliberate retry-retention period. Reconcile uncertain provider
  outcomes before retiring resources.
- [ ] Inventory existing profiles and prepare a migration/cleanup plan that
  preserves useful authenticated state. Review live deletions and migration
  separately before execution.
- [ ] Verify cross-thread reuse, stop/reopen, browser timeout, failed-login
  cleanup, concurrent tasks, user isolation, and shared-account access. Record
  live website login reuse separately from fixture-test results.

## Required acceptance test

After implementation, rerun the full existing 12-scenario Clanker QA benchmark.
The user's required outcome is **100% functional completion: 12 of 12 scenarios**,
compared with the previous 6 of 12 baseline.

- [ ] Run every scenario against the implemented version using the same success
  criteria. Human sign-in remains allowed under the existing benchmark rules.
- [ ] Count blocked, skipped, and partially completed scenarios as unsuccessful;
  do not drop scenarios or relax criteria to produce a 100% score.
- [ ] Investigate and resolve remaining failures, including failures outside
  profile reuse when needed, and rerun the full suite to verify the final result.
  The profile changes alone are not assumed to guarantee 100%.
- [ ] Record the final run's evidence and exact numerator/denominator. Retain
  normal login, sharing, payment, and other action-approval requirements.

This is a future acceptance requirement. No benchmark run starts from recording
this TODO, and implementation is not complete until the measured result meets it.

## Investigation evidence to recheck before implementation

The 2026-10-11 read-only Kernel CLI inspection found 22 profiles: 13 attached to
failed login flows, 5 Kernel-reported authenticated profiles, and 4 task profiles.
There were 4 vaults: 3 user vaults and 1 dedicated credential vault. These are
historical observations, not a deletion list.

Relevant source:

- `runtime/cloud_browser/task_profiles.py`: task profile allocation and reuse.
- `runtime/cloud_browser/kernel.py`: profile attachment and stop/purge behavior.
- `runtime/vault/managed_auth.py`: thread-dependent profile keys and auth cleanup.
  At investigation time, `poll()` selected only `pending` and `cleanup_pending`,
  leaving terminal failed-flow profiles outside periodic cleanup.

Done when new tasks/threads reuse the correct authorized profile, abandoned login
profiles no longer accumulate, and useful personal/shared login state survives
browser replacement without crossing the agreed ownership boundaries, with a
verified full benchmark result of **12/12 (100%)**.
