# Proactive task recovery

Clanker owns routine recovery across tasks. When a website, source or method fails, it investigates alternatives, preserves the user's constraints and stopping point, and continues authorized reversible steps. It recommends one concrete option instead of asking the user to invent another platform. Missing personal choices, account access and material changes still require a concise question.

The shared policy lives in `runtime/clanker_policy.py` and is registered by the native Seatbelt plugin independently of reply personality. Browser handoffs include the goal, constraints, selected option, target URL and stopping point. A worker's blocker becomes input for the coordinator's next decision. Existing private-access, purchase approval and uncertain-outcome reconciliation requirements remain in force.

## Public discovery

Two model tools are available when `clanker.public_web.enabled: true` and the protected Composio consumer connection uses `browser_tool`:

| Model tool | Composio action | Model arguments |
| --- | --- | --- |
| `clanker_web_search` | `COMPOSIO_SEARCH_WEB` | `query` |
| `clanker_web_fetch` | `COMPOSIO_SEARCH_FETCH_URL_CONTENT` | `url` |

Every call binds to the trusted gateway turn and validates workspace membership, requester authorization and delegation state. The model cannot choose the owner, connection, toolkit or action. The existing browser transport remains browser-only; discovery uses a separate session restricted to these two public actions, with instant billing, workbench, proxy execution, connection management and multi-execution disabled.

Fetching accepts a public HTTPS page without embedded credentials or sensitive query parameters. Ordinary document anchors are stripped; authentication fragments are rejected. Known protected values are rejected in inputs and redacted from output. Query, page and result sizes are bounded. Results are explicitly untrusted evidence, with `availability_verified: false`; prices, availability and consequential outcomes require website verification. Failure returns a blocker rather than fabricated results.

The schemas were inspected through the protected runtime connection. The reviewed catalog version is `20260903_00`. Each dispatch rejects catalog version drift. Tool Router execution has no version field: this check does **not** pin provider execution or eliminate a catalog-change race. See the primary [toolkit catalog](https://docs.composio.dev/toolkits/composio_search), [session configuration](https://docs.composio.dev/reference/api-reference/tool-router/postToolRouterSession) and [execution contract](https://docs.composio.dev/reference/api-reference/tool-router/postToolRouterSessionBySessionIdExecute).

## Profiles and activation

Future workspace profiles inherit the discovery flag from the shared defaults. `scripts/configure-clanker-discovery` previews existing root, workspace-marked and explicitly bound legacy profiles; `--apply` adds only the discovery flag. Foreign workspace markers and symlinks are excluded. Custom prompts, personality, models and privacy settings are preserved. The existing 23 profiles were updated and semantically compared against their prior settings.

This change does not restart the gateway, reset conversations or alter a recorded Slack task. The running bot still needs its normal controlled restart and a fresh conversation to load the new code and prompt. Existing conversations retain their cached prompt and tool contract.

Hermes limits aggregate plugin prompt content, including framing, to 8,000 characters. Browser guidance was compacted to fit the new policy. The native profile probe verifies that payment, API-key, personal-info and browser guidance all render alongside it, rather than silently being skipped.

## Evidence

- The canonical test runner passed 57 tests covering discovery boundaries, trusted A→B→A binding, browser transport, cloud adapter, workspace profiles and vault workflows.
- A native temporary A→B→A plugin probe verified the public tool surface and all prompt sections, without Slack or provider requests.
- Live read-only Composio search and page-fetch checks succeeded. These do not establish autonomous checkout or live Slack UX.
- The configured `gpt-6.1-sol` subscription model passed four fixture-only behavior checks: flight recovery, shopping recovery, recovery from a broken research URL, and asking for a missing required personal field. The first three continued without asking the user to devise the next method. The form case requested the missing birth date rather than guessing it. `verification/probes/clanker_recovery_behavior_probe.py` saves the tool calls and final answers; these are model behavior checks, not real provider acceptance.

Receipts are in `verification/evidence/2026-10-07-*.json`. No live gateway restart or fresh human-task acceptance has been performed for this change.
