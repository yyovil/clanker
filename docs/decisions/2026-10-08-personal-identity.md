# Reusable name, date of birth and gender

The owner repeatedly needs these details for flight bookings and account forms.
Extend private Personal info with optional name, date of birth and gender,
alongside the existing phone, email and address. Name should match the owner's
travel document. These are owner-scoped personal defaults, not shared items or
inferred conversational memory.

## Reuse

Check `clanker_vault_list` and the current task before asking for personal
details. Reuse required saved values with `clanker_personal_fill` in the task's
authorized private browser on the exact HTTPS origin. Ask only for required
missing details or a genuinely ambiguous choice; omit optional fields. Form
errors require recovery, not asking the owner to repeat saved values.

Names, dates of birth and gender stay out of Slack replies and task text.
Never infer gender from a name, or treat saved gender as an answer to a field
explicitly asking for sex or a travel-document marker. With multiple travelers,
identify the owner's fields explicitly and never apply their defaults to anyone
else. The fill tool advertises all six personal categories and accepts up to six
requested categories. Autofill does not submit or authorize a registration,
purchase, message or account change.

## Verification and activation

The canonical runner passed 82 checks across personal identity and the existing
personal-info suite. Coverage includes owner-authenticated HTTP create/edit/remove,
encrypted persistence, A → B → A redaction, wrong-owner/origin/CSRF refusal,
real emitted JavaScript execution and combined Kernel browser integration.
Duplicate traveler fields are refused even when only one has autocomplete.
Dates use native date controls, explicit text formats or day/month/year fields;
gender supports explicit text/select fields without inferring document sex.
When a form has no separate middle-name field, given-name filling preserves the
saved middle name alongside the first name.

An isolated loopback browser fixture with synthetic details verified saving all
three categories, reload persistence, private editing and clearing closed forms.
The UI hides unsupported menu items until the serving backend supports them,
so a running older gateway cannot offer forms it would reject.

Live activation still requires loading the updated backend in the gateway.
No real personal values were collected or changed during verification.
The running gateway had an active task and was left untouched; restart approval
is pending. Verification receipt: `verification/evidence/2026-10-08-personal-identity.json`.
