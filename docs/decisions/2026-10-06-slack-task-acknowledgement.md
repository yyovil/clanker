# Slack task acknowledgements

Date: 6 October 2026 (Asia/Kolkata). Implementation and local verification are complete. The user approved the installed Slack permission change, and the local gateway was activated at 01:50 IST.

Clanker acknowledges an admitted human message with a reaction selected by the configured model, then keeps Slack's native working indicator active during the task. The reaction is a receipt and stays after completion. Task outcomes are communicated in the reply. Commands, bot posts, synthetic reaction triggers and rejected messages do not receive the new acknowledgement.

The separate classifier receives only the current message, capped at 4,000 characters, under the message's routed profile scope. Its output must be one of `thumbsup`, `eyes`, `wave`, `heart`, `pray`, `raised_hands`, or `muscle`. A four-second timeout, unavailable model or invalid output falls back to neutral `eyes`. The call uses the existing auxiliary router and does not change the main conversation prompt or history. The existing typing refresh starts before selection, so work is visible while the reaction is being selected.

Interim messages preserve processing status and cannot seal a native response stream. Final replies and existing failure/cancellation cleanup clear the indicator. The opt-in default is off for stock Hermes deployments. Existing Clanker profile defaults already disable dynamic per-tool status phrases.

## Configuration

Merge these fields into the shared Slack adapter configuration. Remove the old explicit `typing_status_text: is typing...` so the modern `processing`/`active` API renders Slack's native working label.

```yaml
platforms:
  slack:
    typing_indicator: true
    extra:
      reactions: true
      acknowledgement_reactions: true
```

An optional `auxiliary.slack_acknowledgement` block can select a different provider/model through Hermes's existing auxiliary routing. The current Clanker model works after correcting the Codex auxiliary pool's model selection: a stored cooldown for a different model previously made every model appear unavailable. Known Codex models now respect only their own cooldown, preserving credential-wide limits.

## Verification and activation

Two behavior tests cover six Slack cases using the real auxiliary router and Slack SDK over loopback HTTP: A→B→A credential routing, duplicate-start handling, persistent receipts, status refresh, interim/final delivery, model failure, timeout, invalid output and disallowed completion emojis. A separate real credential-pool test reproduces the Codex selection bug before the fix and verifies both allowed and blocked models afterward. Existing Slack and queued-follow-up checks also pass.

Live model checks returned `thumbsup` for an ordinary task (3.613s), `wave` for a greeting (2.916s), and the neutral fallback for a sensitive message that exceeded four seconds. These checks made no Slack posts or reactions.

The checked-in manifest requests `reactions:write`. Slack's [reaction method](https://docs.slack.dev/reference/methods/reactions.add/) requires that scope; its [status method](https://docs.slack.dev/reference/methods/agents.sessions.setStatus/) uses lifecycle status values. After the user's explicit approval, only that bot scope was added at [Clanker OAuth & Permissions](https://app.slack.com/app-settings/T0C6J1XCDE0/A0C78PBUKQQ/oauth), and the app was reinstalled to the existing `T0C6J1XCDE0` workspace. The existing bot token's live `auth.test` scope header now includes both `reactions:write` and `assistant:write`. No token replacement was needed.

The latest root configuration was backed up and merged with the four UX settings above, with the old custom typing text removed. A semantic comparison confirmed all other configuration values stayed the same. The real gateway configuration loader confirmed the new values. Immediately before replacement, the gateway had zero active agents and no active work. Gateway PID `63285` replaced `56183`, connected to Slack, and retained all five served profiles. The prior gateway exited cleanly; restart notifications remain disabled.

Activation receipts are under `.local/slack-ack-20261006/`: `installed-scope.json`, `config-activation.json`, and the pre/post gateway snapshots. Live rendered acknowledgement/status behavior on a fresh human task remains unobserved; transport tests and installed scopes do not establish visual acceptance.
