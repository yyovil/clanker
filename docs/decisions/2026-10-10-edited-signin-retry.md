# Preserve the owner's request text for website sign-in retries

## Finding

The Clanker bot identity and the tanishq DM were verified through Slack CLI.
The [supplied thread](https://clanker-global.slack.com/archives/D0C6EAXPKEE/p1791586074361539)
was read through its final page: one parent and six replies. The task executed
in `owner-b-real`, Hermes session `20261010_041757_b8c479ae`; read-only SQLite
inspection linked its initial and retry messages by platform timestamp.

Kernel CLI retrieved the matching Managed Auth connection
`ihcajl2jvpe2xqz31paoq2gj` and its complete one-event timeline using the existing
runtime service key. Current project discovery resolved the active project as
`Default` (`ofp3osdo37cq0d0wuohxb3oj`); the historical `yyopc` name no longer
resolved. Provider history confirms a login beginning at
`2026-10-09T22:48:08.293033Z` and failing at
`2026-10-09T22:59:56.083938Z` with `awaiting_input_timeout`. It reports
`NEEDS_AUTH` and no prior successful login. This establishes a timed-out
sign-in attempt, not the expiry of a confirmed authenticated iCloud session.

The local secure-link request was already `resumed` and expired when the
owner's later retry arrived. The retry's platform ID was
`1791619675.650219`, distinct from the original flow event. Slack delivered
an edit, so the gateway prefixed its text with an edit notice and a
`[New message]` marker. Managed Auth tested that enriched multi-line prompt
for retry intent. The conservative retry parser rejects multi-line text, so
the owner's ordinary `retry` never reached the existing expired-flow cleanup
and replacement path. The tools returned 409; a subsequent browser attempt
returned 410 from the still-expired request. Slack identity/OIDC was not the
failing guard.

The second Slack blocker was a separate model turn. The original root request
was replayed immediately after the edited retry's response. Retained INFO logs
do not contain its raw incoming Slack envelope. A dummy adapter reproduces
admission of an unchanged historical root's metadata update after restart when
neither a process-local claim nor a persisted revision exists. That is a
candidate explanation, not confirmation of the historical ingress subtype;
the separate replay behavior is unchanged by this fix.

## Change

Initial and queued gateway turns now carry authenticated `event.text` separately
as `request_message`. Model input and persisted prompt context retain the edit
notice. Vault bindings consume the raw owner text for Managed Auth retry and
verification retry authorization. No parser strips a user-supplied wrapper;
explicit empty text remains empty, and ingress metadata cannot supply this
field. Existing owner/account/home checks, current-event checks, and protection
against replaying a failed attempt are retained.

For an expired failed attempt, an edited owner retry can now retire the exact
old provider generation and create one fresh request and sign-in link while
preserving the original task. Repeated calls reuse the new pending link.

The four gateway source changes and gateway regression file are captured in
`patches/hermes/gateway-request-text.patch`, registered after the existing
private-access-response patch. Its reverse and reapply were verified in scratch
space against byte-identical source. The older complete patch stack was not
reconstructed or applied to the live checkout.

## Validation and limits

Six new runtime cases failed against the previous behavior and now pass,
including the expired/resumed failure through a real gateway context and vault
binding, preservation of the task, exactly one fresh link, negation, empty text,
and forged wrappers. Nine directly relevant suites passed **252 checks with
zero failures and zero file retries**. Four additional gateway suites passed
15 checks; the total across all 13 distinct suites is **267**. Independent
review found no actionable defect in the focused changes.

Kernel audit search covered `2026-10-09T22:45:00Z` through
`2026-10-10T08:16:00Z` for the exact connection, and returned its original
login and hosted exchange POSTs. No owned automation-browser session mapping
exists for this thread; the matching Managed Auth record has browser telemetry
and recording disabled. Browser session telemetry/process logs therefore could
not be correlated or retrieved. The provider timeline and local task records
support the findings above; they do not establish Apple acceptance or mailbox
access.

Slack, production SQLite, and provider inspection remained read-only. No
production repair, login retry, Slack message, browser control, gateway restart,
or deployment occurred. The fix is local and requires an explicitly approved
gateway restart before the running service uses it.
