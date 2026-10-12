# Google Managed Auth diagnostic retry stopped before browser creation

## Outcome

The one authorized diagnostic attempt did not reach Google sign-in. Clanker dispatched one `POST /auth/connections`, received no HTTP response within its 60-second read timeout, and retained `create_unknown`. It did not dispatch a login POST, issue a confirmed private sign-in link, or retry the mutation. No auth browser was confirmed or available for the scoped telemetry patch. **Telemetry was not enabled, and the earlier “Use email” failure was not reproduced.**

The [private diagnostic task](https://clanker-global.slack.com/archives/D0C6EAXPKEE/p1791674638196929) used tanishq's own DM through the QA driver. Isolated run `r20261011-045358-adhoc-481617` ended `infra`; its isolated loop is stopped. This attempt is separate from the benchmark campaign and does not change its scores. No Google document was created or edited, gateway restarted, canonical QA state changed, or support email sent by this branch.

## Evidence

| Reference | Value |
| --- | --- |
| Project | `ofp3osdo37cq0d0wuohxb3oj` |
| Reserved profile | `clanker-auth-e38621804dc9cd71f05d2af06af140147fc2ebe6` |
| Configured residential proxy | `vt7zgebqdab3k10yay8ynzav` |
| Local diagnostic reference | `21950643aea24e01a423829f3bbc2aa5` |
| Connection / login event / browser IDs | None confirmed for this attempt |
| Local flow state | `create_unknown` |
| Local request state at final read | `waiting`; no confirmed private link |
| Submitted sign-in choice | None; owner input was never requested |

All timestamps below are UTC on October 10, 2026 (IST is October 11):

1. **23:23:58.196929 / 04:53:58 IST:** the QA driver posted a single request for a fresh Google Docs sign-in, with instructions to wait, avoid document changes, and avoid automatic retries.
2. **23:24:06.595407 / 04:54:06 IST:** the owner-bound local flow reservation was created for `https://docs.google.com`.
3. **23:25:06.600 / 04:55:06 IST:** the gateway logged the diagnostic reference above. Its one transport attempt was `requests.exceptions.ReadTimeout`, elapsed **60,003.84 ms**; operation elapsed **60,004.13 ms**, timeout **60 seconds**, upstream HTTP status **null**. This is evidence of a client-side read timeout on connection creation, not proof of the provider's internal cause or final mutation outcome.
4. **Approximately 23:25:19:** an exact domain/profile lookup returned HTTP 200 and no matching connection.
5. **23:27:30.765066 / 04:57:30 IST:** a second exact lookup returned HTTP 200, an empty array, `X-Has-More: false`, and `X-Next-Offset: 0`. Owner equality remained verified and the local connection ID remained null.

A Kernel audit search for `/auth/connections` over `23:23:50Z`–`23:26:30Z` returned no records. This absence does not prove that the POST never reached Kernel. No unconfirmed mutation was replayed or manually adopted, and no local ownership, vault, proxy, or profile binding was repaired speculatively.

Sanitized artifacts are in `.local/google-auth-diagnostic-20261011/`: `result.json`, `creation-failure.json`, and the isolated QA transcript. The observer was stopped without dispatching a telemetry PATCH. No credentials, MFA codes, cookies, response bodies, or sensitive control URLs were written to these artifacts. The original failure remains documented in [the earlier report](2026-10-11-google-managed-auth-flow-failed.md).

## Supported upstream diagnostics

Installed CLI: **Kernel 0.45.0**, commit `3b5ccb525583e4b2a35cc05f3a22d509ad2953d0`. Current [Managed Auth login API](https://www.kernel.sh/docs/api-reference/managed-auth/start-login-flow) supports a per-login `browser.telemetry` override and an independent `record_session` override. Existing browsers support a scoped telemetry update. Connection settings can also be changed, but that would affect future attempts on that connection.

The authenticated `GET /org/entitlements` response confirmed effective plan `START_UP`, base plan `FREE`, `is_trialing: true`, status `ACTIVE`, trial end `2026-10-22T08:59:54.952Z` (October 22, 14:29:54 IST), and Managed Auth enabled. The published entitlement schema has no separate browser-telemetry entitlement; the plan alone is not proof of access to internal auth traces.

The reviewed capture map is:

```json
{
  "record_session": false,
  "browser": {
    "telemetry": {
      "enabled": true,
      "browser": {
        "connection": {"enabled": true},
        "system": {"enabled": true},
        "platform": {"enabled": true},
        "control": {"enabled": false},
        "captcha": {"enabled": false},
        "console": {"enabled": false},
        "network": {"enabled": false},
        "page": {"enabled": false},
        "interaction": {"enabled": false},
        "screenshot": {"enabled": false}
      }
    }
  }
}
```

This is a **prepared configuration, not an applied or verified capture**. The [category documentation](https://www.kernel.sh/docs/browsers/telemetry/categories#data-sensitivity) and [current OpenAPI schema](https://www.kernel.sh/openapi.json) show that network/control/page/interaction/screenshot data can contain sensitive content. Connection, system and platform event payloads provide operational metadata. The generic event `source.metadata` remains arbitrary and must be omitted from local output even for these categories.

Explicit false flags are necessary: the OpenAPI schema says category settings layer onto the operational defaults. This conflicts with the overview's description of category-only selection. A future attempt must check the actual browser readback for every category and verify at least one real metadata event; a successful configuration response or `telemetry_captured` flag alone is insufficient to verify event delivery.

## Capture limitations and next implementation dependency

The running Clanker `KernelAuthClient` explicitly sends `telemetry.enabled=false` on both connection creation and every login. Merely changing connection defaults would be overridden. This branch prepared an observer that would patch only the new, owner-bound browser and validate capture before human input. Such a patch would miss the initial discovery seconds. The telemetry patch never ran because connection creation remained unconfirmed.

For capture from the first login operation, the exact local proposal is a temporary, trusted-backend diagnostic override keyed to one authorized owner/request or connection, passed to `start_login`. It should send the explicit map above while preserving profile, domain policy, proxy, credential selection and recording=false. It must consume a one-attempt claim before dispatch, leave normal defaults disabled, handle unknown outcomes through GET reconciliation, verify the actual browser configuration, and allowlist SSE/telemetry fields before persistence. No secret-bearing logs, recordings, or global telemetry switch are required. This proposal needs focused transport/privacy tests and parent-coordinated gateway activation; it is **not implemented or deployed here**.

Public Managed Auth SSE exposes current flow states, field types, available choices and terminal errors. The timeline exposes attempt metadata. Neither documents an internal reasoning/choice-execution trace. Available choices do not prove which choice the owner submitted. Even after safe capture succeeds, Kernel support may still be needed for the internal condition that produced the original `flow_failed`.

## Evidence for the existing support case

Please correlate project `ofp3osdo37cq0d0wuohxb3oj` with the connection-creation request around `2026-10-10T23:24:06.595Z`, reserved profile `clanker-auth-e38621804dc9cd71f05d2af06af140147fc2ebe6`. The single client request timed out after 60 seconds without an HTTP status; exact-profile lookups were empty, including a fully paginated response at `23:27:30.765Z`. Was creation received or committed, and is there a sanitized server request/trace ID? No browser or login event ID is available for this new attempt. This is an additional failure before login, separate from original connection `z7h5r07wbvau693wjvpvlg84`, login event `qrsn7lhnos2qx7ancd6z63s3`, browser `z3hz0ltjq0q06dg0mxoh64z9`, whose internal choice/failure trace remains needed.
