# Preserve account identity when selecting a retained browser profile

## Finding

Review of the new persistence path found that a stopped thread's retained profile could be relabeled with a different owned Vault login. Cookies belonging to the first account would then travel under the second handle. The regression reproduces the problem using two synthetic accounts owned by the same person; no live cross-account exposure was observed.

## Change

Only adopt a retained profile whose credential handle is absent or matches the selected login. Otherwise retain the prior profile under its original handle and reserve a separate profile for the selected account. Switching back selects the first account's original profile. Existing owner checks and concurrent-writer checks remain in force.

## Validation and limits

The switching regression failed before the change. The profile and saved-login suites then passed 16 tests, covering two-account switching, owner isolation, profile persistence, stale and live writers, and saved login dispatch. Real multi-account acceptance has not been claimed.
