# Owner-approved payment cards in the local POC

Clanker can collect a card in the private vault form, save the reusable number,
expiry and optional cardholder name, and use it in a particular checkout after
the owner approves that purchase. This implementation is local POC code. Real
merchant payment acceptance, production hosting and payment compliance have not
been verified.

## Flow

1. Prepare a one-time card checkout with `browser_exec` in the owner's private
   local browser. `clanker_request_payment` takes its exact `checkout_url`, the
   merchant, item/quantity/delivery summary, final `amount_minor` including fees,
   currency, and an optional saved-card handle.
2. The backend checks that the browser endpoint belongs to that profile, finds
   the exact checkout tab, and captures its origin, URL, visible contents and one
   visible Pay/Place order button. A recognizable final-total line must match
   the requested amount. Unsupported or ambiguous totals fail before collection.
3. The existing private Slack handoff sends an owner-bound vault link. The same
   Slack OIDC session and CSRF controls protect the form. The owner sees the
   merchant, origin, summary, amount and expandable actual checkout text. Card
   fields are masked. Approval is explicit and specific to one purchase.
4. Saving encrypts reusable card fields in the owner's native Hermes VaultStore.
   CVV is excluded from that item. It is separately encrypted for this approval,
   expires within five minutes, and is cleared on use, cancellation or expiry
   cleanup. Saved-card reuse shows the last four digits and asks for current CVV
   and fresh approval. The approval link expires after fifteen minutes.
5. The task resumes with a request ID, never card values. `clanker_pay` verifies
   owner, profile, task, conversation, exact browser, page contents and stamped
   button. It consumes approval durably before card-bearing browser I/O, rechecks
   the checkout in the same JavaScript operation that fills and clicks, and
   returns `submitted`. The merchant receipt must establish payment success.
   Unknown outcomes cannot replay that approval and require reconciliation.

## Supported scope and trust

- Cards and approvals are tied to the exact checkout origin. Current currencies
  are INR, USD, EUR, GBP, CAD and AUD, all with two minor-unit decimal places.
  The final-total parser is deliberately conservative; it does not claim
  compatibility with any particular real merchant's checkout layout.
- Current fill support requires main-page card fields and one clear final
  button. Hosted payment iframes, wallets, subscriptions and automatic bank/3DS
  completion are not implemented. Bank approval requires owner action.
- Card data is delivered directly over the owned local CDP WebSocket, not through
  a cloud browser task, model tool arguments, Slack, process argv or environment.
  Cloud Browser Tool cards are refused because that provider can log request
  payloads. Login routing prefers the local supervisor when one is active.
- The guarded card release and one-use approval rules are enforced by the
  dedicated payment handlers. Generic browser code is still capable of clicking
  a merchant-saved payment method; instructions prohibit doing that. This is
  not an enforcement boundary against arbitrary malicious agent code or a
  compromised merchant. Browser inspection is not proof of what a merchant's
  backend will charge.
- The gateway/operator host remains trusted. Encryption keys are local beside
  encrypted data. Existing host access, generated-code and profile-isolation
  limitations remain relevant. Temporary encrypted CVV deletion is logical
  cleanup, not a claim of forensic erasure across backups or disk snapshots.
- Removing a card cancels pending owner requests through the existing disconnect
  flow. A saved-card approval validates that the handle still exists and belongs
  to the owner on the captured origin.

## Verification

The canonical Hermes runner passed 117 distinct tests across the payment, hosted-vault,
Browser Tool, cloud browser, native store and native browser-vault suites. The
payment suite covers A → B → A HTTP approval/storage/resume, wrong owner, CSRF,
link replay, expiry, cancellation, changed checkout, wrong task/thread, uncertain
submission and mismatched final totals. The initial six-file run passed 116;
after adding the resumed-purchase `/stop` cancellation case, the two affected
suites passed all 40 tests. Cancellation revokes the temporary CVV before card
release even after the approval has resumed its task.

`verification/probes/clanker_payment_browser_probe.py` passed seven checks with
real sandboxed Chromium and dummy cards: tool discovery and owned endpoint,
first-card submission and receipt, saved-card reuse after fresh HTTP approval,
CVV cleanup, changed-cart refusal, a checkout change between inspection and
write, and foreign-profile refusal. The controlled Example.com DOM replaces the
checkout and generates local dummy receipts. No payment network or real Slack
message is used. Receipt: `verification/evidence/2026-10-06-payment-local-browser.json`.

The local UI fixture at port 8769 shows the actual form and confirmation code.
Approval cleared all inputs and link fragments, hid the form and displayed
Purchase approved. Decline displayed Purchase declined and cleared the form.
Screenshots are under `output/playwright/clanker-payment-*`.

Fresh plugin discovery is verified in temporary profiles. The currently running
Slack gateway predates these handlers; activating them requires a reload after
its active work is accounted for. No live Slack purchase has been performed.

## Files

Implementation: `runtime/vault/payments.py`, the existing vault HTTP/form assets,
and `runtime/seatbelt/plugin.py`. The minimal native store change makes CVV
optional for reusable payment items. Its patch and corresponding native test
are in `patches/hermes/payment-vault.patch`, included by
`scripts/apply-hermes-mods` after the API-key patch.
