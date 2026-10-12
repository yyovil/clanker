# One opening Clanker persona

The runtime loaded the profile's SOUL identity at the beginning and appended
`display.personality=concise` at API-call time. Both identified Clanker, but
the appended block also contained task and personal-detail instructions absent
from the opening. Its blanket confirmation rule conflicted with vault-first
reuse of saved primary details.

The default SOUL now contains the complete identity, response style, task
ownership and personal-detail summary. The fallback reads that same canonical
text, so isolated workers receive it without loading an owner's custom SOUL.
The default personality overlay is disabled and the former concise definition
is removed. Specialized plugin policies retain their original positions.
Confirmation now applies to genuinely ambiguous choices and required emails
known only from another site's owned login metadata; saved primary details
needed for an authorized task are reused without retyping or reconfirming.

Native profile seeding and exact-template migration supply the opening to new
and existing default profiles. Customized SOUL files remain untouched. The
style configuration and provisioning code enforce the empty overlay. Replay
probes now include the opening SOUL rather than relying on the old overlay.

Native A–B–A rendering verified one identity, no default overlay, migration,
custom preservation and isolated-worker exclusion of owner-specific content.
The canonical test runner passed 295 prompt/config/provisioning tests with
five host-specific skips. The managed placement patch applies to its prior
files and reverses cleanly.

All 36 live profiles were migrated after an idle check. Only the personality
selection and obsolete concise definition changed in each configuration;
other configuration values and all 71 credential files were preserved. The
approved controlled restart reconnected Slack and local/public form health
returned HTTP 200 with ready. Existing conversations were not reset. No model
call, Slack message or purchase was made for this change.

The channel-independent complete Markdown export verifies one Clanker
identity and no appended persona. Receipts are in
`verification/evidence/2026-10-08-clanker-single-persona-*.json`.
The persistent build change is
`patches/hermes/clanker-persona-placement.patch`.
