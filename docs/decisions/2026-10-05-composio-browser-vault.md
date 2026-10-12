# Clanker: Composio Browser Tool and the local vault

Active choice: `browser_tool` through the signed-in `itsyyovil@gmail.com` consumer account. Composio CLI 0.4.2 is installed for operator setup; Clanker calls the fixed backend API directly. It never invokes the CLI with a vault password, because the CLI persists tool arguments in local history. No other Composio toolkit is enabled.

The For You billing page stated "No credit card and no subscription." The resolved project is CONSUMER with instant usage disabled. Each runtime session explicitly disables instant usage, workbench, proxy execution, connection management, search and multi-execute, and allows only the five reviewed Browser Tool actions. The response must confirm the browser restrictions and disabled instant usage before any browser task is sent. There is no paid provisioning or automatic switch to a developer project. This does not establish unlimited future free usage.

## Credential path

1. The Slack sender and conversation identify the private Hermes profile. The model supplies a saved vault handle, never an owner or remote browser ID.
2. The backend checks private-DM membership, resolves that handle in that profile's encrypted vault and checks the provider-reported HTTPS page against the saved exact origin.
3. The selected password alone is passed as `secrets={saved_hostname: password}` to CREATE_TASK, along with the saved session ID. The nonsecret account identifier is supplied separately in the fill instructions. The task directs the provider to use the hostname secret only in a password field and stop before submitting. The current login page is preserved when reusing a session; a fresh session starts at the saved exact origin. The password is absent from task text, local state and tool output. Browser Tool and Composio receive that password; the full vault is not uploaded.
4. Provider output is scrubbed against saved secrets and encrypted prior redaction values before returning to Clanker. State and operator keys are in the protected gateway home.

The consumer project's existing log setting is `show_all`; it was not changed. Composio may retain tool arguments, including the selected credential. This handoff is not a claim that provider logging, its internal agent or browser content cannot access secrets. Current host-generated-code permissions also do not independently establish a secrets boundary.

Browser Tool reports the page URL but does not document a CDP/login-field inspection API. Origin checking therefore trusts its URL report; it is weaker than the existing local supervised DOM check. Verification codes now use the private vault's single-use code form and a run-scoped `verification_code` secret. The fill task checks for a visible code field and stops before submission; a wrong origin fails before consuming the code. This path has automated coverage and real Google code entry and sign-in were verified on 2026-10-06. ChatGPT sign-in and CAPTCHA acceptance remain unverified.

## Browser ownership and lifecycle

The initial backend assigned sessions to conversation/profile contexts; it never accepted provider IDs from the model. The 2026-10-06 invitation patch additionally binds new state to workspace, authenticated requester and home, and refuses recorded provider-session ownership collisions. It does not adopt legacy state automatically. A consistent short session name reuses that requester's cookies between completed tasks. Before reuse, the backend checks whether the browser has stopped; an expired browser starts fresh without automatically resending credentials. STOP_TASK stops a task; it does not establish that cookies or the remote browser profile were deleted. Stop now reports profile_retained=null (unknown). Revocation that requires a verified purge remains blocked and reports cleanup pending for this provider. Vault logins remain saved. A missing dispatch acknowledgement blocks automatic retry until an operator reconciles it. A confirmed upstream HTTP 422 body-validation rejection clears that attempt flag, preserves the previous task/session, and returns HTTP 422 without replaying it. The exact upstream HTTP 400 stopped-browser rejection also releases the failed attempt and discards its expired browser IDs; other HTTP 400 responses remain unknown.

The service connection belongs to the operator. This POC does not give each Slack member a separately authorized Composio account. A live synthetic cookie A→B→A test observed an empty fresh B browser and A's cookie on reuse of A; this is evidence for the exercised sessions, not a production tenant-isolation guarantee.

## Verification on 2026-10-05

- 48 focused tests passed after the rejection, browser-expiry and verification-code fixes: Browser Tool and Browser Use adapters, encrypted vault behavior, ownership checks and Slack membership.
- Native Hermes profile discovery A→B→A exposed three browser wrappers, four private-access tools and terminal; no other Composio tools.
- The real consumer API ran a read-only example.com task and the synthetic cookie test with instant billing disabled. Test browsers were stopped afterward.
- A live public demo login passed through the encrypted native vault and Browser Tool, including credential fill and a separate login submission. The demo browser was stopped afterward.
- A Google-only test ran through the existing private Clanker DM and selected native vault login. Browser Tool reported a wrong-password response after submission, so Google sign-in is not verified. A network outage interrupted the Slack agent response, and the cloud browser subsequently stopped. Its exact upstream rejection was reconciled before starting another attempt. A fresh browser reached normal password entry, and Clanker sent a fresh private login form. The original free vault tunnel had expired, so the form could not load. A replacement HTTPS tunnel is running, with a pending local configuration; Slack app-owner access is required to register its callback before activation. The owner sign-in page is open for the user. No account recovery or password reset was completed.
- No paid signup, purchase, commit or publication was performed.

Sources: [Browser Tool schema](https://docs.composio.dev/toolkits/browser_tool), [consumer project authentication](https://docs.composio.dev/docs/consumer-agents), [session restrictions and instant billing](https://docs.composio.dev/reference/api-reference/tool-router/postToolRouterSession), [tool log payloads](https://docs.composio.dev/reference/api-reference/logs).

## Password-fill rejection repair

The real Google fill on 2026-10-05 was rejected by Browser Use V2 before task creation: HTTP 422, `body.secrets`, because the key included `https://`. Composio's public schema advertises URL keys, but its hosted action passes them directly to the V2 endpoint, whose validator accepts hostname characters. The adapter now uses the bare saved hostname and preserves the already inspected login page. Classified input rejections do not strand a session behind the unknown-outcome lock; network failures and ambiguous responses still do.

The existing Google request was not automatically replayed. Its confirmed rejection is reconciled separately against the provider log and the saved session. No Google password reset is required.

## Password-only field repair on 2026-10-06

The latest real Google fill used an input action with `<secret>accounts.google.com</secret>` directly in the password field. That secret held the whole `identifier:password` string. The masked screenshot contained exactly as many password dots as that combined string, rather than the saved password. Google subsequently showed Wrong password. This was a field-binding defect, not evidence that the newly saved password was invalid.

The adapter now sends only the password under the hostname key and supplies the account identifier separately. It encrypts the full supplied secret for output redaction, including passwords containing colons. The field-substitution regression and the existing ownership, vault, lifecycle and membership checks passed: 51 focused tests. Gateway PID 56183 is running the fix. The replacement vault callback and yyovil Slack OIDC are verified. A new Slack test pauses after filling for inspection before Google submission.

The corrected Google submission advanced to the existing phone-number verification challenge (suffix 42). The password was accepted, but full sign-in still requires the owner’s verification. The provider live session is open in Aside for that private step; no account recovery, password reset, or Gmail action was performed.

Live Google verification-code handoff is now exercised: the owner submitted the SMS code in the private vault form, the task resumed automatically, the single-use encrypted payload was consumed, and Browser Tool filled and submitted it. Google advanced to a Redmi 10 Power notification challenge (number 60). Full sign-in remains pending that owner action; no code or password value is stored in repository evidence.

## Final Google E2E acceptance on 2026-10-06

After owner device approval, Clanker’s account inspection and the provider screenshot both confirmed the signed-in Google Account email itsyyovil@gmail.com. The exercised flow passed: Slack private request, encrypted vault password, Browser Tool password fill, private SMS-code form, automatic resume, code submission, device approval, and final account verification. The 51 focused checks also passed. No Gmail, ChatGPT signup, recovery, reset, purchase, commit, or publication action was performed.

Clanker called STOP_TASK after verification. The prior claim that this removed cookies (profile_retained=false) was not supported by a cookie-deletion receipt and has been corrected. The encrypted vault password remains available. The earlier pending callback, SMS, and device-challenge notes above describe resolved test phases. Runtime result_verified remains false for provider reports alone; this acceptance additionally uses operator screenshot review and the owner’s confirmation. It does not establish cross-requester account authorization. See the [invitation and isolation limits](2026-10-06-vault-invitations.md).
