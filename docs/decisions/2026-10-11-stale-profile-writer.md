# Release expired profile writers before opening the next task

## Finding

The first post-fix Instamart run stopped before browser creation because the new single-writer guard trusted historical session IDs. Kernel returned not-found for all three stored writers of the selected account profile. Their existence in the local context did not imply a live browser.

Evidence: [Slack task](https://clanker-global.slack.com/archives/D0C6EAXPKEE/p1791666907033519), QA run `r20261011-024507-sign-instamart-saved-e402`, Hermes session `20261011_024513_33ef3326`, 11 October 2026 02:45 IST. Read-only Kernel lookups returned not-found for `uz063jqemh7ineglies5n32i`, `d8ulgq3tfrqdjglstiu2ul4y` and `lus5qxripi0tnmo0gbfm4xeu`.

## Change

Before rejecting a second profile writer, verify the earlier browser's protected ownership record and query its live existence. An absent browser goes through verified cleanup before the new task continues. Live browsers, unacknowledged creations and unknown provider liveness still block concurrent writing. Apply the same rule to saved Vault profile selection and Managed Auth reauthentication.

## Validation and limits

The regression first failed for expired and unknown-liveness cases. After the change, 95 browser/profile/auth-browser tests passed; eight legacy local-secret tests remain strict expected failures, excluded from the pass count. Unknown provider liveness preserves the prior writer. A real rerun is required before marking this finding verified. The failed initial run remains in history and is not silently replaced with a pass.
