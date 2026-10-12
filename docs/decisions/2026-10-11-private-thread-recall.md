# Recall published private results before changing a cart selection

## Finding

The later cart task failed to retain the previously verified noodle selection. Existing personal recall returned user messages but did not reliably recover the published assistant result describing the selected product.

Evidence: [original Slack task](https://clanker-global.slack.com/archives/D0C6EAXPKEE/p1791658155156099); QA run `r20261011-001915-open-instamart-cart-d750`; Hermes session `20261011_001926_e9426b8e`. The original benchmark ran late 10 October through early 11 October 2026 IST. Time-only Kernel correlations are intentionally excluded pending exact-thread recollection.

## Change

Use the owner home database only to find an earlier DM thread pointer, then fetch the published Slack thread after checking workspace, bot, exact owner DM and membership. Never return internal assistant reasoning or tool data. An explicit thread without a channel reads only the current owner DM. Browser profile persistence is addressed separately.

## Validation and limits

Four new private-thread tests passed within the 41-test recall/handoff batch. The regression includes an internal canary and foreign-DM rejection. This is one confirmed capability gap, not proof that all original cart loss came from recall; stock and website state still require live verification.

Status: activated through the QA restart workflow on 11 October 2026 at 02:44 IST (gateway PID 58797; Slack connected). Real-site verification is in progress; no new benchmark pass is claimed.
