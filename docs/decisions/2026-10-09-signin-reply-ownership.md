# One reply for a private sign-in request

The supplied [iCloud Mail thread](https://clanker-global.slack.com/archives/D0C6EAXPKEE/p1791494671575999)
contains one sign-in card at `1791494705.672179`, followed by an ordinary model
reply at `1791494711.550339` linking to that card. Slack's second response includes
an attachment with `is_msg_unfurl: true` and the first card's timestamp. The card
was posted once; the subsequent reply and its unfurl repeated its instruction.

The saved tool result for that exact turn explicitly instructed the model to
share `link_delivery.message_url` after confirming that the card was sent.
The tool schema gave the same instruction. Normal DM response delivery lacked
the reply ownership check already used for isolated channel tasks.

## Change

A committed Managed Auth card satisfies the reply for its own authenticated
Slack request. The check requires the configured requester, their private DM,
the exact workspace/user/chat/thread/profile, an associated auth flow, and a
durable delivery receipt for the initial request event or an explicit resend.
An existing pending login alone does not suppress any reply.

A process-local typed receipt blocks subsequent model deltas and commentary
for that exact event. Existing previews finish without adopting the redundant
final, and stream reconciliation and queued first-response delivery honor the
same ownership. Ordinary final delivery checks the durable receipt. No Slack
message needs to be deleted or edited to apply the fix.

Later questions, resumed task results, and notices to someone requesting access
to an invited owner's account still use normal delivery. Failed, partial, or
interrupted turns retain their diagnostics. If another authentication call in
the same turn confirms success, it releases the receipt so useful continued
work can be delivered. The tool instructions now describe the card as the reply
and reserve its permalink for later questions about locating it.

## Evidence and activation

The Slack CLI loaded the existing bot credential through its environment without
printing it. `auth.test` returned team `T0C6J1XCDE0` and bot user `U0C5Z1ZQHQX`.
`conversations.info` confirmed DM `D0C6EAXPKEE` belongs to `U0C688SF7DZ`.
`conversations.replies` returned the parent and all three replies, with no next
cursor and `has_more: false`. Protected evidence is under
`.local/slack-signin-duplicate-20261009/`.

The regression failed before the delivery fix. The final canonical isolated
runner passed 139 tests across 11 files with zero failures; source hashes stayed
unchanged during that run. Concurrent edits to Managed Auth were preserved, and
the affected four files were rechecked with 113 passing tests and stable source.
An independent scoped review found no remaining issues. The new Hermes patch was verified by reversing and reapplying it in
scratch space. A full historical patch-stack reconstruction still fails at
`task-continuation-recovery.patch`; the same failure was reproduced using the
pre-change sources. That existing reinstall drift was left untouched.

The local fix is not activated. Slack and production state remained read-only:
no messages, deletions, permission changes, provider mutations, or gateway
restart were performed. Activation requires a separately approved gateway
restart, which may resume pending work and produce Slack messages.
