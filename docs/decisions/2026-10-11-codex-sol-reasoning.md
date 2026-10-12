# Use the supported reasoning levels for Sol 6.1

## Finding

Finding `codex-sol-title-reasoning` came from stop verification `r20261011-051755-open-instamart-start-906e`, [Slack thread](https://clanker-global.slack.com/archives/D0C6EAXPKEE/p1791676075407169), Hermes session `20261011_051800_768570f8`. Three title calls failed because the provider rejected `none` for `gpt-6.1-sol`, listing `low`, `medium`, `high`, `xhigh`, and `max` as accepted. The deterministic title fallback preserved task completion, but the extra failed requests were a real S3 defect.

The shared vocabulary treated this exact model as legacy: it permitted `none` and clamped `max` to `xhigh`. Disabled auxiliary reasoning emitted that unsupported `none` value.

## Change

Declare the evidenced vocabulary for the exact `gpt-6.1-sol` identifier, including its ordinary vendor-qualified spelling. Do not classify it as Astra or infer support for future model names. Auxiliary disabled requests use the shared clamp to choose `none` when supported or the supported minimum otherwise. Non-reasoning routes still omit reasoning, and the xAI disabled path retains its existing contract. Main enabled requests preserve `max` and clamp unsupported lower efforts to `low`.

The focused patch is registered as `patches/hermes/codex-sol-reasoning.patch`; it preserves unrelated auxiliary-client changes.

## Validation and limits

The nine intended regressions first produced eight failures and one pass (`/tmp/clanker-sol-reasoning-red-main.log`). The imported test harness was aliased to prevent accidental duplicate test collection. After the fix, the canonical runner passed **285 tests across six suites**: the new Sol cases, auxiliary client, reasoning-effort module and wire translation, route effort selection, and sibling transport call sites (`/tmp/clanker-sol-reasoning-final-main.log`).

An initial broad run had 284 passes and one environment failure because the optional Anthropic SDK was absent. Installing the repository's exact existing `anthropic==0.87.0` pin resolved it. `hermes/.venv` resolves to the lab virtualenv shared with the gateway, so this added that optional SDK and `docstring-parser==0.18.0` to the shared environment; no dependency declaration changed. The gateway uses the Codex route, and its running process was not restarted for this install. The final test run has no failures.

The idle QA restart activated this fix at 15:09 IST on 11 October (PID 88444 → 98832; `clanker-qa-restart-20261011T093904Z.log`), with Slack reconnected and zero active agents before verification. The subsequent Nike run `r20261011-151057-add-one-pair-640d` used the live `openai-codex` / `gpt-6.1-sol` auxiliary title route. Read-only SQLite inspection of exact session `20261011_151103_f2543029` confirmed a generated title with `title_source=llm`, establishing successful model output rather than deterministic fallback. The receipt is `.local/clanker-qa/batches/2026-10-11-reliability-round5/title-live-verification.json`. The finding is **verified**; Nike task completion is assessed separately. The entire repository test suite is not claimed green.
