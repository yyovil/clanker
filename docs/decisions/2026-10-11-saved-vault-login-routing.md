# Use ready saved Vault logins before starting empty hosted sign-in

## Finding

Nike had a ready opaque saved phone login, but the Managed Auth dispatcher started a separate empty sign-in path. The existence of a saved handle therefore did not cause its phone field to be filled.

Evidence: [original Slack task](https://clanker-global.slack.com/archives/D0C6F49F2KD/p1791654214720759); QA run `r20261010-231334-add-one-pair-640d`; Hermes session `20261010_231341_68c95df4`. The original benchmark ran late 10 October through early 11 October 2026 IST. Time-only Kernel correlations are intentionally excluded pending exact-thread recollection.

## Change

For an owned ready Kernel Vault login with no Managed Auth credential or active selection, return the secure-fill route. Kernel fills only declared fields into observed exact-origin controls. Bind the browser to the access handle before secret-bearing I/O, including uncertain fills, and reuse its owned retained profile across threads. The existing private code workflow handles verification without exposing values. Hosted Managed Auth remains preferred when its credential or selection exists.

## Validation and limits

The latest saved-login/profile/Vault/ACL batch passed 66 tests, and the broader auth batch passed 292. Cross-owner and cross-origin access remain denied. Website field acceptance, real Nike sign-in and SMS completion remain live acceptance work. A filled form is not proof of login.

Status: activated through the QA restart workflow on 11 October 2026 at 02:44 IST (gateway PID 58797; Slack connected). Real-site verification is in progress; no new benchmark pass is claimed.
