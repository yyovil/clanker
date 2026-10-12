# Native Kernel card purchases

Clanker uses `provider: kernel` wallet/card items and the merchant's existing
**Pay by card / Add New Card** checkout. AgentCard and Link are not involved.
This implementation is local; no gateway restart, real enrollment or charge has
been performed. Provider/project access, Indian issuer eligibility and Zepto
acceptance remain unverified.

1. In the requester-owned private task, inspect the card checkout and bind the
   visible item summary, INR total, HTTPS page, browser and final Pay button.
2. Deliver a private **Pay ₹X** Slack card. The authenticated review page freezes
   those facts and accepts approval plus a remember-card choice. No card fields
   are accepted by Clanker. Kernel hosts card/email enrollment and Visa approval.
3. Poll advertised eligibility and create/authorize one purchase-specific card.
   Resume through the existing durable gateway path when ready.
4. Fill through Kernel and click the bound Pay button once. Bank OTP collection
   uses a private Kernel credential form, with a separately bound verification
   page/button. Neither a fill nor a click is payment success.
5. Resolve only a visible merchant receipt with explicit paid status, matching
   amount and an order ID. Remove a temporary wallet after resolution; failed
   removal blocks reuse and is retried. Remembered wallets remain owner-bound.

The initial implementation supports INR/India and the provider's 50,000-minor-unit
limit (₹500). Hosted approval links are validated against `vault.kernel.sh`.
Uncertain mutations/submissions remain durably claimed and are not replayed.
Cancellation closes an unsubmitted purchase's browser before retiring its token;
it cannot cancel or refund a potentially charged order.

Ordinary browser tools are blocked while filled payment fields might remain,
including cross-origin frames. The payment status tool reads only restricted
page text/control metadata, never input values or screenshots. The current bank
challenge discovery and receipt selectors rely on observable page DOM; arbitrary
cross-origin bank challenges, non-English receipts and real merchant behavior
still require acceptance testing. An unsupported challenge stays unresolved.

Verification uses real local request/HTTP stores and frontend JavaScript with
synthetic provider/browser I/O; it is not evidence of a real payment:

```sh
PYTHONPATH=runtime:hermes hermes/.venv/bin/python -m pytest -q \
  verification/probes/test_kernel_native_payments.py
```

Contracts: [native wallet](https://github.com/kernel/kernel-python-sdk/blob/main/src/kernel/types/vaults/kernel_wallet_vault_item_spec.py),
[native purchase](https://github.com/kernel/kernel-python-sdk/blob/main/src/kernel/types/vaults/kernel_card_vault_item_spec.py),
[charge-observation boundary](https://github.com/kernel/kernel-python-sdk/blob/main/src/kernel/types/vaults/kernel_card_state.py).
