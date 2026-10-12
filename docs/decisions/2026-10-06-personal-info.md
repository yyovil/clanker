# Reusable primary personal info

Implemented and verified locally on 6 October 2026. The live Slack gateway has
phone/SMS login but has not loaded Personal info or the repeat-login correction
below. Real Swiggy/Nike login, SMS delivery and checkout remain unverified.

The private vault now has an Instinct-inspired Personal info section. The owner
can add, edit or remove one primary email, phone number and address. The phone
requires an international number; an optional calling code supports national
phone fields. Addresses include street, optional apartment and state, city,
postal code and country. The mobile address dialog keeps Save and Cancel visible
while the fields scroll.

## Storage and owner access

Primary values use the native encrypted vault engine in a separate
`vault/personal.json.enc` file inside the requester's private profile. They are
not conversational memory, credential invitations or shared vault items.
Authenticated owner identity, same-origin requests and CSRF checks protect the
details, save and remove endpoints. Ordinary listings return only availability,
a masked email, the phone's final four digits and a generic address summary.
The private owner form can load full values for editing; closing it clears the
fields. Personal values are not saved in browser localStorage or sessionStorage.

## Reuse

- New local SMS sign-in requests can use the primary phone without asking for
  the number again. The handler creates a normal encrypted login bound to the
  inspected HTTPS website origin. Existing website-specific numbers take
  precedence. `use_primary=false` opens the private form for a different number.
- An existing SMS login is reused even if no primary phone exists. Multiple
  website accounts return an account-selection result rather than another
  number-entry form. Saving the first valid international phone or email through
  an authenticated website login also remembers it in Personal info. Later
  accounts never replace a primary. Removing a primary leaves an encrypted
  opt-out so later website saves cannot silently restore it. National numbers
  remain website-specific unless their country code is known.
- Private password login forms offer the primary email only when the website
  login has no saved identifier. Existing website identifiers take precedence.
- `clanker_personal_fill` resolves email, phone and address inside the requesting
  owner's supervised local browser. It checks the exact HTTPS origin, browser
  ownership, visible fields, ambiguity and field length before filling. An
  explicit national phone field with a saved calling code, or a matching nearby
  calling code, can use the national part of the number. A nearby calling code
  also supports a first saved international number without separate country-code
  metadata. Address input, textarea and select controls are
  supported through the native classifier and fill machinery.
- Tool results report availability and fill counts without returning full
  primary values. Personal values and the filled representations are registered
  with the existing browser/terminal output redactor in private turns.
- The tool does not submit a form. Saving personal info does not authorize a
  purchase, registration or unrelated task. SMS codes remain fresh, temporary
  and single use through the existing private code flow.

Changing or removing a primary value does not rewrite or remove previously
saved website logins. This is stated in the owner form. Multiple saved accounts
on one website require deliberate account selection. Primary personal-info
fills currently require the supervised local browser; cloud adapters retain
their existing website-bound credential flows. Saving primary details in the
management page does not automatically resume a pending agent task.

## Verification

134 tests passed across personal info, vault, phone/SMS, both cloud adapters,
invitations, payments, channel tasks/control and native vault compatibility.
Python compilation and JavaScript syntax checks passed.

An actual Seatbelt Chromium probe ran A→B→A with two encrypted owner homes,
dummy contact details, owner-authenticated HTTP saves and controlled DOM forms
at two HTTPS origins. It confirmed repeated cross-site SMS, email and address
fills, national phone formatting, output redaction, wrong-origin refusal and
separate owner stores. No repeat contact form or Slack contact message was sent.
The HTTP tests also exercised CSRF, owner/origin rejection, durability, website
overrides and keeping personal entries out of invitations.

Playwright verified actual UI save, edit, remove, reload persistence, clearing
closed fields, browser-storage checks and mobile Save visibility. The verified
desktop, mobile and address-edit screenshots were added to the clanker
Lunagraph project's Page 1 and focused at Zoom to selection. They are exact
screenshots of the tested implementation, with dummy data.

- [Verification receipt](../../verification/evidence/2026-10-06-personal-info.json)
- [Chromium receipt](../../verification/evidence/2026-10-06-personal-info-browser.json)
- [Desktop](../../output/playwright/personal-info-saved.png)
- [Mobile](../../output/playwright/personal-info-mobile.png)
- [Mobile address editor](../../output/playwright/personal-info-address-mobile.png)

During the original UI acceptance, no real personal data was collected or saved, and no real account login, SMS,
purchase, Slack message or gateway restart was performed. The phone number in
the user's reference screenshot was not copied into the vault.

## Repeat-login diagnosis and correction

The user's live Swiggy attempt had one encrypted website SMS login but no
encrypted Personal info record. The gateway process started before the
Personal info source changes: the new endpoint returned 404 on the live
loopback service. Canvas values are design fixtures and are not persistent
owner records. The saved-login lookup also incorrectly depended on a primary
phone existing; this is now corrected. The authenticated private form offers an
unambiguous website-specific saved identifier before the primary default.

140 focused tests passed after the correction. They cover authenticated save
followed by same-site and cross-site reuse, owner and CSRF rejection, explicit
different-number requests, account selection, site overrides, primary edits
and removal, and refusal to invent a country code. Both cloud providers retain
their exact-origin secret bindings; their phone task now asks the provider to
use national digits only when a separate visible calling code matches the saved
prefix. This cloud formatting instruction has not been accepted on a real site.

The follow-up Chromium probe saves dummy phone and email through real private
login HTTP endpoints, then fills phone, email and address across two controlled
HTTPS pages with A→B→A owner isolation. The acceptance receipt is
`verification/evidence/2026-10-06-personal-reuse-browser.json`.

For the requesting owner, the existing unambiguous Swiggy SMS login was copied
directly from the native encrypted vault into the separate encrypted primary
phone record. Membership, request ownership and the private profile were
verified first. The website login handle and encrypted website-vault bytes were
unchanged. The primary file is mode 0600; no phone value was printed or written
as plaintext, and no email or address was inferred. The correction and migration
receipt is `verification/evidence/2026-10-06-personal-reuse.json`. No gateway
restart, Slack message, real SMS request or purchase was performed.
