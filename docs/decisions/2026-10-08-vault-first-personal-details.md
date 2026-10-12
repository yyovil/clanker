# Check saved personal details before asking

The user reported a delivery task where Clanker said the storefront still
needed a delivery location/sign-in even though their address was already in
Personal info. The screenshot does not establish which vault/browser tools the
worker called. Existing guidance mentioned checking saved details but did not
make the lookup an explicit prerequisite for reporting that blocker.

## Decision

The product execution policy and Personal info system section now require
`clanker_vault_list` plus the current task conversation before a personal-detail
question or delivery-location/login blocker. An unchecked vault or a browser
worker's generic location request is not evidence that a value is missing.

Reuse required saved primary email, phone and address for the authorized task
without asking the user to retype or reconfirm them. Inspect the real form and
ask only for required unknown fields or a genuinely ambiguous personal choice.
Omit unnecessary optional fields. An email known only through another site's
owned login remains a candidate requiring confirmation; an invited account's
identifier must never become the requester's personal default.

Saved personal data is still filled through the private local browser using
`clanker_personal_fill` on the exact HTTPS origin. When cloud browsing reports
a delivery-location blocker, the coordinator must open the relevant local form
and reuse the saved address. Cloud autofill limits, ambiguous fields or browser
errors require recovery of that form, not recollection of saved data. This
does not add cloud personal-data release or bypass login/purchase approval.

The vault-list tool description and result reinforce this workflow. When
personal autofill encounters absent requested data, its existing
`personal_info_needed` result now includes `available_fields` alongside
`missing`. Fill those available fields separately, then request only required
missing fields through private Personal info. Neither result exposes values.

## Verification

- The canonical runner passed 36 payment/personal-info tests with one file
  worker and no retries. The added regression uses real owner-scoped encrypted
  stores in A → B → A order to verify correct available/missing categories and
  no cross-owner or raw-value leakage.
- A separate canonical run passed all 23 vault workflow tests. Total: 59
  passing tests across three files and two runs.
- Native A → B → A plugin assembly passed with cloud and local browser
  configuration. All sections remained present, within the 8,000-character
  limit: 7,902 characters for cloud and 7,875 for local. API-key guidance was
  compacted without changing its supported operations or privacy requirements.
- The opt-in model probe uses the assembled production policy and synthetic
  tool handlers for saved details, a missing phone, an ambiguous form, and a
  shared-channel private handoff. The existing known-email model replay checks
  candidate confirmation, optional-field omission, prior confirmation reuse,
  and exclusion of invited identities.

All eight model cases passed. In the saved-details case, the first tool call
was vault lookup, followed by local inspection, address/phone autofill and
preview verification, without a user question. The missing-phone case filled
the saved address and requested only that phone through private Personal info.
The ambiguous-form case recovered locally and retried without recollecting
saved data. The shared-channel case moved to isolated private execution and
ended without exposing or requesting personal details in the channel.

Receipts are saved under `verification/evidence/2026-10-08-vault-first-*.json`.
The model checks use no real private values, browser execution, Slack message
or purchase. They do not prove a live Instamart checkout.

## Activation

Used the gateway restart authorization already given in this chat for this
follow-up policy update. The gateway initially had one active agent; it was
left running until execution became idle. Immediately before the controlled
restart it reported zero active agents and zero active work.

Restarted on 8 October 2026 at 04:42 IST. The replacement gateway (PID 157)
reported running and reconnected to Slack. All 38 snapshotted configuration
and credential files remained byte-identical; startup contained zero ERROR
lines. Local and configured public private-form health returned HTTP 200 with
`ready: true`. A fresh process assembled all revised sections in the served
root profile at 7,902 characters.

Existing conversations retain their cached prompts; new conversations load
the updated system policy. Backend tool-result guidance and missing/available
metadata use the updated implementation. No conversation history was reset,
Slack test message sent, or browser/purchase task replayed.

Activation receipt:
`verification/evidence/2026-10-08-vault-first-activation.json`.
Gateway log:
`.local/hermes-lab/vault-hosting/gateway-vault-first-20261008.log`.
