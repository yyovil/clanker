# Remove the retired local credential engine

Kernel Vault owns Clanker's credential collection, storage, and browser fills.
The former local encrypted credential engine is removed from this checkout.

Removed code includes the Fernet credential-file reader/writer, personal-record
importer, local login backend, local CLI collection wizard, browser save-login
collection, and card storage/payment executor. Old entry points retain only
explicit errors before file access or credential prompts, so cached calls cannot
recreate a local vault. The desktop RPC source list no longer advertises a local
credential backend; local add/remove RPCs refuse without reading submitted values.

Shared field definitions, exact-origin validation, consent-based personal reads,
and privacy filtering remain because Kernel's implementation uses them. Local
Slack ownership, invitation permissions, task continuation, and delivery metadata
also remain. Their encrypted task payloads are not credential storage.

The encrypted recovery archive is preserved. This change removes implementation
code; it does not delete recovery data or modify credentials held by Kernel.
No live gateway restart, merchant action, or Slack message is part of this change.

`patches/hermes/local-vault-removal.patch` is appended to the audited Hermes patch
stack so a newly prepared checkout removes the legacy engine after the older
patches. Its reverse/apply round trip is checked in a temporary directory against
all seven affected native source paths. That check does not claim the entire
historical patch stack has been revalidated.

Obsolete tests of local encryption and local collection are replaced by refusal
tests. Kernel browser, API-key access, personal information, owner isolation,
sharing, and privacy checks remain the acceptance coverage. The Kernel fixtures
now use Kernel personal stores explicitly rather than an empty local importer.

Validation: 249 checks passed across 11 files using the canonical Hermes runner
with one worker. The native patch reverse/apply round trip passed for all seven
source paths. Python parsing and the targeted Git whitespace check also passed.
