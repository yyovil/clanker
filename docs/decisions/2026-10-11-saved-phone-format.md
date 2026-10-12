# Format an owned saved phone for the observed login form

## Finding

Nike run `r20261011-033244-add-one-pair-640d` ([private task](https://clanker-global.slack.com/archives/D0C6F49F2KD/p1791669764318209), Hermes `20261011_033251_8921f6b7`) received a provider fill acknowledgement, but the bound input remained empty. The visible form separately displayed the calling code and required ten national digits. Read-only inspection of the exact owner's saved phone confirmed an international representation with twelve digits and a leading plus. No phone value was printed or saved in the diagnostic artifacts. The login fill path forwarded the saved representation unchanged, unlike the existing personal-information formatter.

This establishes a format mismatch in the harness. The specific site's controlled-input reset behavior and its subsequent observation failure still require a live retest; the original empty input alone does not prove the saved phone itself was wrong.

Review also reproduced two incomplete checks: changing the bound input's public constraints during temporary-item creation still allowed a write, and a provider acknowledgement with a nonempty but incorrect phone readback was reported as retained.

## Change

For an owned SMS login with an ordinary backend-readable phone field, apply the existing phone formatter using the uniquely observed control and its public country-code context. Missing, conflicting or ambiguous context cannot truncate an overlong number. Invited and opaque credentials retain the existing provider-only path.

Preserve the original account binding, origin checks and durable submission claim. Only when formatting changes the representation, create a temporary Kernel item and let Kernel perform the write. Recheck page, country context, the original input's public descriptor and saved credential identity/version before dispatch, then delete the confirmed temporary item. The input check reads the existing stamped node without tagging a replacement. Privately normalize and compare the retained phone against the formatted value; a nonempty incorrect value produces only a `value_mismatch` stage in the closed outcome schema and durable failure record. Do not rewrite the original login or return phone values to the model. An uncertain creation or fill remains spent and cannot be automatically repeated. Unknown creation or cleanup failure can leave the temporary item in the owner's hosted vault; no local copy is retained.

## Validation and limits

The original five contract cases failed before the change. An additional credential-change-during-preparation case reproduced a dispatch race and now denies it. Eight further regressions failed before the review fix: five public-control changes and three nonempty incorrect readbacks. The canonical runner now passes 304 checks across eight suites: saved-phone formatting (21), Kernel Vault service (45), personal details (58), client (67), account ACLs (10), split OTP (28), fill outcomes (42) and metadata store (33). These cover a correctly retained national number, unchanged original credential, no values in returned results or local state, mismatched/ambiguous country codes, credential replacement, country/control changes, uncertain creation/fill, cleanup and replay denial. Four cases execute the public-control probe in Node against synthetic DOM objects, checking descriptor agreement with the original inspector, changed length, an unstamped replacement and duplicate targets. The provider and browser integration remain synthetic.

This change was activated through the idle QA restart at 04:18 IST (PID 75440, Slack connected). Nike retest `r20261011-042036-add-one-pair-640d` then encountered Kernel transport failures before reaching the phone field, so live field acceptance remains unverified. No live credential was changed, no code was requested, and no order was placed by this fix work.

## Live field verification

The later Nike verification `r20261011-151057-add-one-pair-640d`, [exact Slack thread](https://clanker-global.slack.com/archives/D0C6F49F2KD/p1791711657132759), exercised this repair on gateway PID 98832 and Hermes session `20261011_151103_f2543029`. After saved-account selection explicitly required a browser reopen, fresh navigation and login-form observation preceded secure fill. At 09:51:29 UTC, `clanker_vault_fill` returned `success: true`, one filled field, and a completed provider operation. Its retained readback independently reported `expected: 1`, `matched: 1`, and `nonempty: 1`.

This verifies retention of the owned, formatted phone in the live field. It does not establish successful login, acceptance of an OTP request, saved-address application or checkout. The subsequent Nike sign-in modal displayed `Failed to execute 'json' on 'Response': Unexpected token '<', "<HTML><HEA"... is not valid JSON` at 09:53:28 UTC and remained at Get OTP. No HTTP status was captured. This establishes an HTML/JSON response mismatch in the login flow, not bad saved credentials or a provider outage. No phone, password or code appears in the sanitized evidence at `.local/clanker-qa/batches/2026-10-11-reliability-round5/nike-verify/runs/r20261011-151057-add-one-pair-640d/evidence/mechanism-verification.json`. The phone-fill finding is **verified** on this narrow mechanism; the complete Nike task remains unsuccessful.
