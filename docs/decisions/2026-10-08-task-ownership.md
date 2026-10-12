# Keep ownership when a website fails

The provider-specific guidance recorded below is superseded by
[`2026-10-08-generic-task-recovery.md`](2026-10-08-generic-task-recovery.md).
The current recovery policy names no booking provider or task category.

The user reported a flight-booking response that stopped after IndiGo and
Cleartrip checkout failures and told them to book the selected flight in the
IndiGo app. That handed the requested work back to the user while other
providers and booking entry points remained unexplored.

## Decision

Strengthen `runtime/clanker_policy.py`, the shared system-prompt policy
registered by `runtime/seatbelt/plugin.py` independently of reply personality.
The agent must own authorized work through verified completion and must never
substitute instructions to finish the task manually for its own recovery.

Search alternative providers, aggregators, entry points and permitted tools
exhaustively. Attempt each distinct viable route, track observed failures and
remaining leads, and stop retrying an unchanged failing route. Include
Booking.com as a travel lead when it offers the requested route; the user's
example is not proof that a live checkout or this flight currently works there.
Search results require browser verification.

Keep the selected flight or item, dates, people, budget and stopping point.
Changes to material terms require a user choice. A browser worker's blocker
must trigger coordinator recovery, not a manual-work instruction forwarded to
the user. Worker prompts must carry the task constraints and require attempted
alternatives, observed outcomes and remaining leads.

The agent may ask for a genuinely missing personal detail or choice, private
access, required human verification, or purchase approval. Ask only for that
specific step, complete independent work and resume afterward. Preserve private
access and per-purchase approval; reconcile uncertain side effects before a
retry. When all permitted viable routes are exhausted, report the actual
attempts and blockers without handing off the job, claiming unverified success,
or promising background work that is not running.

The global Codex instructions in `~/.codex/AGENTS.md` now carry the same task
ownership rules for agents working with this user.

## Prompt budget and verification

The existing plugin prompt occupied 7,979 of the allowed 8,000 characters.
Compact payment, personal-info and browser wording so the expanded recovery
policy does not silently exclude another section. Retain the existing account,
secret handling, SMS, local checkout, human approval and receipt requirements.
Unsupported checkout handling now seeks a compatible authorized checkout;
bank approval requests only that necessary owner step.

The native temporary-profile probe exercises A → B → A with both cloud and
local browser configuration, verifies the actual exposed tool surface, checks
that every policy section renders, and enforces the aggregate prompt limit.
The cloud prompt is 7,896 characters; the local prompt is 7,869 characters.
The probe performs no provider request, Slack message, browser launch or live
profile change. Receipt:
`verification/evidence/2026-10-08-task-ownership-profiles.json`.

The model behavior probe adds the reported selected-flight continuation,
including repeated search results that leave other viable routes to try, and a case
where all additional viable fixture checkouts fail. Booking.com and Expedia
responses are fixtures; they do not demonstrate real merchant compatibility,
availability, payment or booking. Model evidence is saved to
`verification/evidence/2026-10-08-task-ownership-model.json`.

In the initial run, all existing recovery cases and the exhausted-route case
passed. The selected-flight case correctly rejected a simulated checkout report
without a checkout URL or sufficient page evidence. Preserve that initial
receipt as `verification/evidence/2026-10-08-task-ownership-model-initial.json`;
repair the fixture to return the inspected checkout URL, itinerary, final total,
passenger readiness and unsubmitted payment state. The probe accepts verified
success via a known alternative without imposing a public-search query quota.
No production policy was weakened to accept unverifiable checkout claims.

After correcting the fixture, both flight cases passed. The selected-flight
case reached the alternative checkout, retained the itinerary and requested
approval for the observed final total without a manual-work fallback. The
exhausted-route case attempted the remaining providers, broadened discovery
again and reported their concrete errors without claiming a booking or asking
the user to finish it. The combined receipt contains all six passing cases
across two runs and identifies each original raw receipt.

The canonical test runner passed 35 existing tests across payment and
personal-info workflows, with one file worker and no retries.

## Activation

The user approved activation. Restarted the live gateway on 8 October 2026 at
04:27 IST after confirming zero active agents and zero active work. The prior
gateway (PID 94036) exited cleanly; the replacement (PID 97690) reported running
and reconnected to Slack. All 36 snapshotted configuration/credential files
remained byte-identical. Startup verification found zero ERROR lines.
Both local and configured public private-form health endpoints returned HTTP
200 with `ready: true`.

A fresh process using the served root profile rendered the revised execution
and browser-handoff policies alongside all existing sections at 7,896
characters. Existing conversations retain their cached system prompt; new
conversations load the revised policy. No histories were reset and no Slack
test message, browser task or purchase was replayed.

Activation receipt:
`verification/evidence/2026-10-08-task-ownership-activation.json`.
Gateway log:
`.local/hermes-lab/vault-hosting/gateway-task-ownership-20261008.log`.

This verifies policy assembly and service activation. The booking responses
were fixture-only checks; a fresh human Slack/browser checkout has not been
performed for this change.
