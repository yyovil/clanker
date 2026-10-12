# Keep all Clanker policy sections inside the Hermes prompt budget

## Finding

The live cart continuation run [r20261011-030835-open-instamart-cart-d750](https://clanker-global.slack.com/archives/D0C6EAXPKEE/p1791668315389339), Hermes session `20261011_030840_c80c7de3`, logged at 03:08:42 IST that `clanker.recall` and `clanker.task_handoff` exceeded the 8,000-character aggregate plugin budget and were skipped. The real renderer reproduced both omissions with the complete Clanker plugin registration. This is an instruction-delivery defect; it does not by itself prove the cause of every historical recall failure.

## Change

Condense repeated wording in API-key, personal-detail and browser guidance while preserving the private-secret, ownership, retry, payment and continuation rules. Keep the upstream prompt limit and per-session caching behavior unchanged. A regression test registers the actual plugin and requires the real Hermes renderer to retain every registered section, with Kernel enabled and disabled.

## Validation and limits

The enabled-Kernel regression failed before the change, omitting exactly recall and handoff, then both configurations passed. The new regression, Kernel-only execution and recalled-handoff suites passed 25 checks in the canonical runner. QA restarted the idle gateway to PID 63671 and reconnected Slack. At 03:32:49–51 IST, all eight sections loaded in four new sessions across both owner DMs and the shared channel: `20261011_033250_9265f676`, `20261011_033248_45810322`, `20261011_033251_8921f6b7`, and `20261011_033250_5094bc61`. Both formerly omitted sections are present. This verifies instruction delivery, not task completion. Existing sessions keep their frozen prompt; they must not be silently rewritten.
