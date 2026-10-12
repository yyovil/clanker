# Payment instructions and remembered cards

New payments no longer collect item summaries, total-element selectors, receipt
text or receipt selectors. The agent supplies the observed amount in paise for
the Pay ₹X card and Kernel's purchase contract. The harness does not regex the
checkout or freeze its item text. Browser, URL, final button and one-attempt
submission binding remain. Amount accuracy relies on the agent's observation.

The owner asking to proceed with payment authorizes use of a remembered card.
If Kernel returns ready, continue immediately without another Clanker approval
page. Otherwise show the required private provider step. Without a remembered
card, show Pay ₹X with a remember choice and open Kernel-hosted card enrollment.
No card values are stored locally or accepted through ordinary tool arguments.

Use native Kernel wallet/card items. Kernel prohibits credit-card data in generic
credential items. Mastercard needs no hosted spend approval; Visa requires a
passkey spend approval even for a remembered card. Native purchases remain limited
to 50,000 minor units (₹500). These are upstream constraints, not extra Clanker
approval rules.

New completion uses the agent's observation of explicit merchant success or a
definite failure, without receipt parsing. A click is not success. Unknown
outcomes remain unresolved and cannot be replayed. Close the owned browser before
releasing privacy guards; remove temporary cards after resolution. Existing
legacy purchases retain their old reconciliation path.

The payment page has no receipt wording. Local fixture checks do not establish
real issuer/merchant acceptance. No live restart, enrollment or payment was made.

Sources:
- https://github.com/kernel/cli (Vaults: card data must not use credential items)
- https://github.com/kernel/kernel-python-sdk/blob/main/src/kernel/types/vaults/kernel_card_vault_item_spec.py
- https://github.com/kernel/kernel-python-sdk/blob/main/src/kernel/types/vaults/kernel_card_state.py
