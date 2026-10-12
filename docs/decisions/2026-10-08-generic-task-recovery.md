# General task recovery

The earlier task-ownership rule encoded a flight-booking example as a permanent
instruction to try a named provider. That narrowed the agent's recovery strategy
to a particular task and website instead of expressing the general behavior.

`runtime/clanker_policy.py` now applies the same recovery principle to any task:
preserve the requested outcome and constraints, identify the blocked step,
gather evidence, discover materially different viable approaches, and attempt
them without handing execution back to the user. A failed method does not prove
the goal impossible. Neither a retry quota nor a preset list proves exhaustion.
Record attempts and remaining leads, avoid unchanged retries, and verify the
result. Reconcile uncertain side effects before attempting another action.

Necessary user choices, private access, human verification and purchase
approvals remain explicit boundaries. Check task context and relevant saved
sources before declaring information missing. Personal-detail discovery still
requires the requester-scoped vault tool. These are capability and authorization
contracts, rather than task-specific fallback recipes.

The web-search tool remains a general query tool. Recovery does not require a
particular search tool, provider, website or fixed sequence; use the capabilities
available in the current task. The opening persona already expresses general
task ownership and needs no additional identity or personality override.

The behavior evaluation uses fictional additional provider domains discovered
from fixture results, along with shopping, research and required-information
cases. The exhausted-route check evaluates attempted routes, renewed discovery
and an honest failure report rather than provider names in the final wording.
These evaluations do not establish live merchant or transaction compatibility.

Verification receipts are under `verification/evidence/2026-10-08-generic-recovery-*`.
The current complete prompt for review is
`.local/hermes-lab/prompt-review/2026-10-08/clanker-system-prompt.md`.

All six fixture behavior cases passed, and native A–B–A discovery passed for
Composio, local and Kernel configurations within the existing prompt budget.
The initial exhausted-route check failed solely because the final answer did
not repeat fixture provider names; the agent had attempted both discovered
routes and reported their errors. The revised check passed on a fresh replay.

The current runtime has switched to Kernel independently of this policy edit;
the refreshed full export reflects its current tool surface. Activation of
this edit is deferred because the live gateway still has active Slack agents.
No gateway replacement was attempted, and no histories were reset. The
activation receipt records this pending state rather than claiming deployment.
