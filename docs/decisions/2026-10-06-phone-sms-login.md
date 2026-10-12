# Phone number and SMS login

Implemented and verified locally on 6 October 2026. The running Slack gateway
has not been restarted to activate this change. Real Swiggy/Nike sign-in and
SMS delivery have not been exercised.

The original Swiggy task opened a `type=tel`, `id=mobile` login field. The
password/email-only detector rejected it twice before creating a private link.
Phone-only login now uses the existing owner-bound hosted flow in two stages:

1. Request private login access on the actual HTTPS phone login page. Local
   `auto` mode recognizes a visible phone field without a password field;
   `login_method=sms` selects it explicitly. `password` remains available for
   sites that ask for a password after a phone identifier.
2. The authenticated owner saves only their number in the private form. Numbers
   accept 7–15 digits, optional leading `+`, and ordinary formatting separators.
   The native encrypted login vault stores the number; metadata exposes only
   its final four digits and the SMS login method. No dummy password is stored.
3. Saving resumes the original task. `clanker_vault_fill` fills the number in
   the same authorized browser origin. The agent requests the website's SMS
   using the website controls.
4. `clanker_vault_enter_code` sends a private one-time code form. Submission
   resumes the same task; that tool enters the code and the agent finishes and
   verifies the website login. A subsequent login requests a fresh code.

Existing code storage remains encrypted, owner/handle/origin/task-bound,
short-lived and single use. Invited logins request SMS codes from the credential
owner. Revoked invitations cannot submit or use pending codes. Shared-channel
tasks continue through the existing isolated requester-owned private detour.

Visible fields are inspected with the native classifier. Phone detection rejects
OTP fields, hidden fields, country-code fields, extension fields and ambiguous
phone inputs. SMS codes support a single field and 4–8 adjacent one-character
boxes, including widgets without autocomplete labels. The code length must
match a split widget. Phone numbers that exceed a site's field length are
refused rather than truncated.

Both cloud adapters pass phone numbers through a separate secret binding and
keep them out of task text. Browser Tool still relies on provider-reported
origins; it cannot independently infer a phone form, so its agent must choose
`login_method=sms`. Local supervised browsing takes precedence when active.

Verification: 123 tests passed across vault, phone/SMS, both cloud adapters,
invitations, payments, channel tasks/control and native vault compatibility.
The actual Seatbelt Chromium probe ran A→B→A with two encrypted homes, private
HTTP submissions, native phone and six-box code fills, two automatic resumes,
one-use code checks and number/code output redaction. Slack delivery and the
SMS website were fixtures. Playwright verified desktop/mobile forms, failed
save preservation, retry, SMS submission and confirmation.

- [Verification receipt](../../verification/evidence/2026-10-06-phone-sms-login.json)
- [Browser acceptance](../../verification/evidence/2026-10-06-phone-login-browser.json)
- [Phone form](../../output/playwright/phone-login-form.png)
- [Mobile phone form](../../output/playwright/phone-login-mobile.png)
- [SMS form](../../output/playwright/phone-login-sms-code.png)

`patches/hermes/phone-sms-login.patch` reproduces and reverses this task's native
vault change against the preserved pre-change source. It is appended to
`scripts/apply-hermes-mods`. A full existing-stack reverse check stopped at an
unrelated pre-existing mismatch in `slack-acknowledgement.patch` against
`hermes/plugins/platforms/slack/adapter.py:2274`; that code was left untouched.

No real account, SMS, purchase, Slack message or gateway restart was performed.
