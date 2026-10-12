# Google hosted login fails after an accepted choice submission

## Finding

Benchmark run `r20261011-035105-help-plan-12-01ab` did not produce the Google Doc. The prior `domain_not_allowed` configuration defect was corrected and independently checked on the new connection. The owner reports entering an email address, seeing choices including “Use email”, “Try another way” and “Enter password”, and selecting “Use email” before the generic failure screen.

Read-only Kernel evidence:

| Reference | Value |
| --- | --- |
| Project | `ofp3osdo37cq0d0wuohxb3oj` |
| Connection | `z7h5r07wbvau693wjvpvlg84` |
| Login timeline event | `qrsn7lhnos2qx7ancd6z63s3` |
| Browser session | `z3hz0ltjq0q06dg0mxoh64z9` |
| Allowed domains | `docs.google.com`, `accounts.google.com` |
| Terminal state | `FAILED / COMPLETED / flow_failed` |
| Website error | None returned |
| Reauthentication | `no_prior_successful_login` |

All timestamps below are UTC on 2026-10-10:

1. Login POST returned 200 at 22:21:40.832.
2. Hosted exchange POST returned 200 at 22:25:06.304.
3. Hosted submit POST returned 202 at 22:25:28.828.
4. Hosted submit POST returned 202 at 22:26:05.140.
5. Flow failed at 22:26:43.555, about 38.4 seconds after the last accepted submission.

The recorded flow expiry was 22:51:40.659, so it did not reach that expiry. The browser lived about 303 seconds with a 900-second timeout. This timing does not establish an internal timeout. Two browser DELETE 404s in the broader benchmark window preceded the login and were not attributed to this run.

## Change

No speculative authentication patch or repeated login was issued for this failure. The benchmark records an unsuccessful outcome. The configured domain policy was verified, while successful authentication remains unverified. Kernel owns the hosted choice-discovery/submission state machine; Clanker returns the hosted URL. The [published API schema](https://www.kernel.sh/openapi.json) does not make HTTP 202 proof that the selected choice executed successfully.

## Validation and limits

Connection metadata, the one-entry login timeline, scoped audit records and browser metadata agree on the failure. Recording and telemetry were disabled for this private auth browser, and a bounded read-only event-stream check returned no historical transitions. No credential values, codes, cookies or hosted control URLs were exposed or persisted during diagnosis.

The retained evidence cannot distinguish a choice-mapping defect, provider execution failure or Google-side behavior. It does not establish incorrect credentials or a CAPTCHA. The local safe-error parser previously mapped `flow_failed` to `provider_failure`. The [safe failure-code correction](2026-10-11-auth-failure-reasons.md), activated at 04:18 IST on October 11, now preserves that fixed code and a bounded explanation. This improves diagnosis but does not itself repair login.

## Provider trace request (sent)

The owner-authorized support request was sent once to Kernel support. Gmail confirmed the `SENT` label for message `1a12a27431be0f9b`, thread `1a1281f2582e6c23`, subject “Google Managed Auth fails after ‘Use email’ — request for internal trace”. The request also included the later connection-create timeout from the [telemetry reproduction attempt](2026-10-11-google-auth-telemetry-retry.md). No credentials or sign-in/control URLs were included. The support address came from the signed-in official Kernel dashboard; no duplicate request is needed.

Please inspect connection `z7h5r07wbvau693wjvpvlg84`, login event `qrsn7lhnos2qx7ancd6z63s3`, browser `z3hz0ltjq0q06dg0mxoh64z9` in project `ofp3osdo37cq0d0wuohxb3oj`. Both Google application and identity-provider domains were allowed. The owner selected “Use email” from the hosted method choices. Submissions were accepted at 22:25:28.828Z and 22:26:05.140Z on 2026-10-10; the flow returned `flow_failed` at 22:26:43.555Z with no website error, before its 22:51:40.659Z expiry. Which canonical choice was processed after the last submission, and which internal condition produced `flow_failed`? Please provide a sanitized transition/error trace without credentials or auth control URLs.
