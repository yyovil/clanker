# Managed Auth with persistent browser principals

This is locally tested implementation, not an activation or live acceptance
claim. It implements the authentication portion of
[persistent personal and shared profiles](2026-10-11-persistent-browser-principals.md).
The 34 inventoried legacy profiles are retained pending a separately reviewed
migration. No cookies were copied, exported or deleted by this work.

## Ownership and lifecycle

New Managed Auth flows reference the registry's persistent principal. A personal
principal supports multiple exact-site connections; a shared principal supports
its one selected account. Removing the old `UNIQUE(profile_name)` constraint
preserves every existing flow and adds nullable principal and lease metadata.
Legacy rows retain their old lifecycle; an already selected legacy row cannot
silently become a principal-backed flow.

Each consuming task records its own credential handle alongside its workspace,
requester, execution home and thread binding. The original flow creator's grant
does not authorize another recipient. Current membership, execution context,
account metadata and grant are checked on selection and again after provider
observation before returning a browser binding. Revocation during that GET
cannot return the removed recipient's authority.

An authenticated principal connection survives ordinary task stop and task-home
cleanup. Those operations release the task's binding; they do not delete the
persistent profile. Explicit account removal quarantines affected principal
state and deletes that account's connection and saved provider credential.
Other domains' connections and the profile are preserved pending verified
session cleanup. Quarantine is not a claim that residual cookies were erased.

Ready Vault logins remain a separate credential path. With a principal registry,
a current grantee can use the exact ready login from its owner's dedicated
credential vault. Shared mode checks that dedicated mapping and selects the
shared principal; it does not create an empty Managed Auth connection or copy
saved fields. The returned result still requires website account verification.

## Writer and request generations

Authentication reserves the same global single-writer lease as browser
automation. Preparation runs after the execution-home lock is released, allowing
an existing writer to close. Reservation precedes provider mutation;
connection acceptance binds the exact remote ID and the lease remains active
through login. A verified terminal result or confirmed connection deletion
releases it. Unknown creation or login outcomes remain locked and are not
automatically repeated.

A current authorized retry creates a new request/event generation on the same
connection and profile. The explicit fresh-login path retains its owner-intent
checks and deduplicates the same event. It does not create another profile.
An expired/cancelled request cannot adopt a late provider success; a new owner
retry is required after the old writer is confirmed terminal. Cancellation
immediately after a reserved renewal releases only that lease nonce, leaving
the prior authenticated generation intact.

[Kernel profile persistence](https://www.kernel.sh/docs/browsers/profiles) is a
saved whole-profile snapshot, not live synchronization between writers.
[Managed Auth login parameters](https://raw.githubusercontent.com/kernel/kernel-python-sdk/main/src/kernel/types/auth/connection_login_params.py)
does not guarantee a fresh TOTP challenge. Successful dispatch, saved
authenticator metadata and reused cookies remain insufficient proof of
autonomous TOTP submission; that acceptance requires a later live challenge.
Recording remains disabled, and no credential values or auth URLs are added to
evidence by this implementation.

## Validation

The canonical runner used the lab virtual environment and `--file-retries 0`.
The final six-file run passed **183 tests**, including **17 principal tests**,
85 existing Managed Auth tests, 10 reuse tests, 19 reuse-security tests, 48 fresh
authorization tests and four saved-login routing tests.

Evidence lives under
`.local/clanker-qa/findings/persistent-browser-principals/`:

- `auth-red.log`: original lifecycle behavior failed the three new baseline
  cases before implementation.
- `auth-race-red.log`: two revoked-caller binding cases and the shared Vault
  route failed, with 13 prior cases passing.
- `auth-renewal-cancel-red.log`: the renewal reservation remained stranded;
  16 other cases passed.
- `auth-freeze-green.log`: 183 passed, zero failed, zero retries.

The focused tests use actual temporary stores and the real principal registry
for grant revocation, membership removal, shared dedicated Vault routing,
unknown provider outcomes, competing writers, request expiry, cancellation and
schema migration. Provider I/O is synthetic. Independent source review passed;
activation, legacy adoption/cleanup, browser-site persistence and benchmark
completion remain separate verification steps.
