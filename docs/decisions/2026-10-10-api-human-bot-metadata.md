# Allowlisted Slack API human messages

## Finding

The first bounded QA batch sent two independent scenario openings concurrently,
one from each tester's verified Slack user token. Neither received a reaction,
reply, or matching Hermes session. Both runs were closed as failed admission;
the scenario actions were not exercised. The batch stopped after these two
openings, with no retries or additional scenarios.

Evidence from 2026-10-10 17:25–17:30 UTC:

- [Tanishq opening](https://clanker-global.slack.com/archives/D0C6EAXPKEE/p1791653100347229).
- [yyovil opening](https://clanker-global.slack.com/archives/D0C6F49F2KD/p1791653101467629).
- [Manual mention](https://clanker-global.slack.com/archives/D0C6EAXPKEE/p1791653316692289)
  and [ordinary manual DM](https://clanker-global.slack.com/archives/D0C6EAXPKEE/p1791653354227109)
  from Tanishq both received reactions and replies.

The API posts have the correct human `user`, plus `app_id`, `bot_id`, and
`bot_profile`, and no `client_msg_id`. The manual messages have `client_msg_id`
and no bot markers. The API posts' bot IDs differ from the receiving gateway's
bot ID. Token identity, scopes, DM ownership, active tester allowlist, and Slack
connection checks all pass.

The adapter's synchronous bot classifier rejects `bot_id` or `bot_profile`
before considering `api_human_users`. The allowlist previously covered only
the `app_id`-without-`client_msg_id` shape. Captured message metadata therefore
exposes a concrete rejection bug. The gateway ran at INFO, so its logs do not
prove the exact live drop point or contain the inbound Socket Mode envelope.
No Hermes or Kernel session was correlated to either opening.

Sanitized metadata and run evidence are under
`.local/clanker-qa/findings/api-human-bot-metadata/` and the corresponding
`.local/clanker-qa/runs/` directories. These files contain no credentials.

## Change

Verify an allowlisted API sender against Slack's workspace-scoped `users.info`
before relaxing the transport's bot markers. Only a matching, explicitly human
account may be normalized. Apply that normalized event consistently to admission,
peer-bot filtering, and message-source classification. Keep the original event
unchanged and retain rejection for bots and unverifiable identities.

The change does not enable general bot traffic or relax workspace membership,
authorization, or private-account boundaries.

## Validation and limits

The new inbound regression first failed against the original adapter (one failed,
19 passed), then passed after the fix. The canonical runner passed 268 tests
across `test_slack_api_human_senders.py`, `test_slack.py`,
`test_slack_unfurl_duplicate_turn.py`, and `test_adapter_authz_secret_scope.py`:

```sh
cd hermes
bash scripts/run_tests.sh --file-retries 0 \
  tests/gateway/test_slack_api_human_senders.py \
  tests/gateway/test_slack.py \
  tests/gateway/test_slack_unfurl_duplicate_turn.py \
  tests/gateway/test_adapter_authz_secret_scope.py
```

After a test-only cleanup and adding A→B→A workspace checks, the focused file
passed all 20 cases again. The tests exercise the real adapter inbound path
with a fake Slack transport: successful human-source delivery, acknowledgement
tracking, workspace separation, and rejection of bot, mismatched, missing,
unverifiable, or forged identity evidence. Read-only live `users.info` confirms
both tester IDs belong to the expected workspace and explicitly have
`is_bot: false`, `is_app_user: false`, and `deleted: false`.

The durable Hermes patch passes forward/reverse validation and is registered in
`scripts/apply-hermes-mods`. Live verification requires another explicitly
requested batch; the current batch is stopped at the user's two-scenario limit.
Gateway activation is recorded in the protected QA finding separately from live
scenario verification. No shopping-site action is verified by these tests.
