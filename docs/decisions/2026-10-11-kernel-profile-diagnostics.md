# Preserve metadata for failed Kernel profile requests

## Finding

Nike run `r20261011-043851-add-one-pair-640d` ([private task](https://clanker-global.slack.com/archives/D0C6F49F2KD/p1791673731324189), Hermes `20261011_043855_27d514a2`) failed before browser creation. At 04:39:28 IST, profile provisioning returned a generic 503 after 30.02 seconds. The next navigation returned a profile-reconciliation 409 at 04:39:35. No diagnostic reference or `kernel_upstream_failure` event survived.

The profile client caught every exception without recording its diagnostic event. It therefore erased the distinction between transport failure, an HTTP rejection and an invalid response. The duration alone does not establish a timeout or provider outage.

Read-only local inspection found an owner-bound pending reservation, no provider profile ID and no browser session. The SQLite ownership claim matched the context. Given this reservation and the response parser, the subsequent 409 implies an absent profile lookup; it is not evidence that a replacement should be created. No provider mutation or production state repair was performed.

## Change

Wrap profile create, read and delete operations in the existing diagnostic context. Preserve a bounded failure category, method, profile route template, request timing, transport-attempt metadata, upstream status and request ID when available. Return the diagnostic reference with the existing generic 503.

Profile response bodies and exception text are excluded. Neither opaque profile names nor request payloads enter the event. Successful reads and expected GET/DELETE absence remain quiet. Existing GET recovery and single-dispatch write behavior are unchanged; unknown creation followed by an absent lookup still keeps its reservation and cannot automatically issue another POST.

## Validation and limits

Eight new diagnostic cases failed before the fix because no event was emitted. The canonical runner then passed 171 checks across `test_clanker_kernel_client.py`, `test_kernel_task_profiles.py`, `test_clanker_kernel_browser.py` and `test_kernel_read_recovery.py`. Eight pre-existing removed-local-vault cases remain expected failures, not passes. Coverage includes transport and HTTP failures, invalid responses, payload silence with normal redaction disabled, expected absence and preservation of an unknown creation across browser-service reconstruction without a duplicate POST.

This fixes an observability defect. The original profile-creation cause remains unknown, and Nike phone formatting was not exercised by this run. Activation and live diagnostic verification remain pending; no restart, login, order or payment was performed by this work.
