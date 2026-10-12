# Completed provisioning survives normal account lifecycle changes

Status: implemented and locally verified; activation pending.
Finding: `provisioning-completed-manifest-replayed`.

## Finding

Startup retained its reviewed profile-provisioning manifest and fully reapplied it on every restart. Even after both empty profiles had been created successfully, the original exact grant list, credential binding, ready-member checks and no-writer requirement ran again. A legitimate grant addition or revocation, disabled member, credential rotation/quarantine, or active lease could therefore prevent the whole Vault service from starting. This is a source/fixture-confirmed lifecycle defect; no production grant or credential was changed to reproduce it.

## Change

Successful provisioning now records an exact-manifest completion receipt in the owning SQLite database only after every target passes the existing checks. The receipt contains workspace, immutable profile identities and completion time. A repeat returns `already_provisioned` after checking the receipt and current registry identity, reading each exact provider profile ID/name, and rechecking the local identity and receipt after those GETs.

Historical completion is not present access authority. The consumed path does not restore or revalidate obsolete grants, old credential bindings, member readiness or writer absence, and it does not create profiles or change leases. It accepts a profile's intended quarantined state while leaving that quarantine intact. Normal credential/browser requests still use current membership, grants, account bindings and lease authorization.

The exact principal key, kind, workspace, owner, account handle, provider profile name and provider ID must still match. A changed identity or provider lookup failure refuses startup. No earlier outcome file is imported as authority. If the receipt is absent, including after an interrupted or older deployment, the original complete validation runs; existing ready profiles are reconciled by GET without another POST, then completion is recorded. If old authority has changed before a receipt exists, an explicit new review is required rather than inferring completion.

## Validation and limits

The canonical red run had **6 failures / 16 passes**: five real lifecycle refusals plus the new repeat-status assertion. The final four-file run passed **76 tests**, zero failures or retries: 30 provisioning, 15 principal lifecycle, 26 principal security and 5 startup tests. Coverage verifies consumed restarts after revoke/add/disable/rotation/active lease, continued current-access refusals, unchanged leases, six immutable identity substitutions, provider-ID changes, changed identity during GET, missing completion receipts and unknown creation outcomes without a completion receipt or repeated POST. Independent review passed.

Evidence is under `.local/clanker-qa/findings/provisioning-completed-manifest-replayed/`, including `provisioning-completion-red.log` and `provisioning-completion-final-green.log`. No runtime restart, production receipt, profile operation, grant change or credential mutation was performed for this correction. The next coordinated startup must establish the receipt for the already-created profiles using the current unchanged setup authority. Receipt-based startup still performs metadata GETs and can refuse on provider unavailability; it does not silently accept a replaced remote profile.
