# Send bounded progress while a browser turn is running

## Finding

Long browser turns remained silent for several minutes; the Apple run had roughly thirteen minutes before its first substantive response.

Evidence: [original Slack task](https://clanker-global.slack.com/archives/D0C6F49F2KD/p1791654214720759); QA run `r20261010-231334-add-one-pair-640d`; Hermes session `20261010_231341_68c95df4`. The original benchmark ran late 10 October through early 11 October 2026 IST. Time-only Kernel correlations are intentionally excluded pending exact-thread recollection.

## Change

Configure Slack generic progress at 60 seconds per profile and have the existing heartbeat honor that profile interval. Edit the same generic notice rather than repeating messages. Keep raw tool names and arguments out of progress, and stop notices when the turn ends.

## Validation and limits

35 progress/gateway/kernel-only execution tests passed. This fixes silence, not underlying browser or model latency. The rerun must measure both completion latency and first progress time.

Status: activated through the QA restart workflow on 11 October 2026 at 02:44 IST (gateway PID 58797; Slack connected). Real-site verification is in progress; no new benchmark pass is claimed.
