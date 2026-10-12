# Consented model access to personal fields

The owner approved Clanker's model reading saved names, addresses, phone numbers,
email and dates of birth to adapt those details to actual website forms. This
changes ordinary personal information access; passwords, card details, tokens,
authenticator seeds and verification codes remain on opaque credential paths.

## Scope and consent

Access defaults to denied. A trusted operator can record or revoke consent in the
owner's encrypted PersonalStore using `set_model_access(bool)`. There is no agent
tool to grant consent. The rollout enables only the approving Slack member
`U0C6M6DMWAW`; other members retain model-blind autofill. Gender was not part of
this approval and cannot be read through this tool.

`clanker_vault_list` still returns masked availability, plus
`personal_model_access`. With consent, `clanker_personal_read(fields)` returns
only the requested saved primary fields and lists required fields that are
missing. It accepts no owner, profile, credential handle or website-supplied
field name. Live membership, authenticated requester, private DM/task route and
delegated-execution checks apply. Shared-channel calls move into the linked
owner-only private task before any values can be returned. The read never
resolves owned or invited credential records.

## Form handling and disclosure

Clanker maps the returned data to actual visible controls using native Kernel
snapshots and input actions. English label regexes are not required for this
consented path. Native `browser_type` supports ordinary replacement fill and a
character insertion mode for incremental input. The pinned driver uses native
`Input.insertText` for printable characters; it does not promise keydown events.
Command success alone does not prove that a controlled form accepted the value.
Before character insertion, the wrapper checks that the exact referenced field
is empty. A rejected or unconfirmed clear stops insertion; private readback and
transport error payloads are excluded from diagnostics and tool responses.
Browser ownership, page guards, lease fences and Kernel-only routing
continue to apply. Reading or filling grants no purchase, signup, messaging or
account-change authorization; automatic payment remains disabled.

Personal values remain registered for presentation/log redaction and public
Slack updates. The private model tool result and subsequent tool arguments may
persist in private conversation history and be sent to the configured model
provider. Revoking consent blocks future reads; it does not erase data already
received by the model or its conversation history. Existing encrypted primary
storage remains encrypted. No central secret-redaction exception is added.

## Verification

The canonical runners passed 380 checks across 18 files, including owner consent,
field minimization, private routing, revocation, encrypted persistence, actual
tool dispatch and private transport diagnostics. A real Kernel synthetic phone
field accepted native incremental insertion; a rejected controlled clear safely
refused further typing. Full address and merchant acceptance remain unverified.
See [the verification evidence](../../verification/evidence/2026-10-08-consented-personal-model-access.md)
for the partial live proof and activation status.
