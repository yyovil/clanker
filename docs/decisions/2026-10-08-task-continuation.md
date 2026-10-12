# Continue a channel task through its linked private Slack thread

The flight request in [this Slack thread](https://clanker-global.slack.com/archives/C0C6J277ZNG/p1791398395717379) retained its original booking selection in the coordinator store, but ordinary human replies in the linked DM entered the member's personal profile. The isolated worker remained waiting for its own verification request while a separate personal-profile request reported verification success. Subsequent replies therefore lost the selected flight and contradicted the channel's status.

## Decision

Admit a native human reply to the existing isolated task only when its workspace, requester, DM channel and thread match the persisted private destination. Refresh authorization to the original shared thread, provision the same isolated profile, clear the member session identity and attach a backend-created task capability before native dispatch. Serialized ingress cannot supply this capability. Cancelled tasks stay cancelled; unrelated DM threads retain normal member routing.

Carry the persisted original goal and confirmed conversation choices into private replies and each credential, code or payment continuation. Authentication is a step in that goal. The continuation guidance preserves route, dates, passengers, selected options and price decisions, and asks only for missing details.

Keep each response in the encrypted outbox with its own event/revision identity and Slack client message ID. A human reply while a private form is waiting publishes to that DM and leaves the task active. A newer admitted reply also keeps the task active until its response is handled. Other worker responses return to the original shared thread. A completed worker turn records delivery, not proof of booking or payment. Delivery recovery rebuilds owner-scoped redaction before publishing.

Shared-thread follow-ups receive only coordinator status for the same requester's linked task. A saved verification form means submitted to the backend; it does not prove merchant acceptance. Reuse an active handoff that already has a form, and return a Slack permalink when available so the requester can find its private thread.

Do not register generic city, state or country names as global secret substrings. Continue scrubbing saved street/unit/postal, phone and email values, plus vault secrets. Public routes and airline names such as Nagpur and Air India remain readable.

## Verification and activation

See [the verification receipt](../../verification/evidence/2026-10-08-task-continuation.md). The patch is included in `scripts/apply-hermes-mods`; all 15 patches reverse and reapply to identical bytes. After explicit user approval, the gateway was restarted on 8 October 2026 at 02:17 IST. Slack connected, the continuation schema was present in the live coordinator database, and both local and public private-form health endpoints returned HTTP 200. A fresh human booking continuation through Slack/browser remains unobserved.
