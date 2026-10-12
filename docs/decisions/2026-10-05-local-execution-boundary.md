# Local execution boundary: sandbox-exec

Decision: 5 October 2026. The user selected macOS `sandbox-exec` for the current MacBook POC, accepting its deprecation as a documented tradeoff. This is the local fallback to the broader VM/container execution design. The container recommendation discussed during investigation is deferred; it does not change the current local choice.

## Status

Implemented and enabled across all five served private/shared contexts. The actual Browser Use Python executor, terminal shells, persistent harness daemons and Chromium process tree launch through Seatbelt. The real third Slack member completed ordinary browser requests in its DM and both shared channels. Eleven native boundary checks, cold onboarding/recovery checks and live receipts are recorded in [execution evidence](../../verification/evidence/2026-10-05-browser-execution.md).

## Implemented boundary

Use one common Sandbox Profile Language (`.sb`) template with trusted parameters for each execution context. Personal DMs receive the member's task workspace and browser state; shared channels receive their shared audience workspace and browser state. Derive paths and browser-control access from the authenticated Slack/profile mapping, never from model-supplied identity or an unrestricted path argument.

Apply the boundary to the actual processes that execute model-generated Python and terminal commands, including the persistent Browser Use executor and any browser processes with access to context state. Wrapping a client that forwards code to an existing unrestricted daemon is insufficient. Sandbox children must retain the restrictions.

Start from deny-by-default rules. Allow only required runtime resources and the assigned context's permitted workspace/browser resources. Keep Slack transport credentials, inference credentials, protected credential storage, other contexts' files and browser-control connections outside executable-code access. Sanitize subprocess environments and close unintended inherited handles before launch; a sandbox does not erase capabilities already handed to a process.

If the mechanism is unavailable, policy application fails, or readiness checks fail, report browser execution as unavailable and retain a retryable provisioning state. Do not retry generated code without the sandbox or silently switch to an owner context. Ordinary chat can remain available.

## Acceptance completed

1. Verify an ordinary browser task through the same resolved profile and tool path used by Slack, without requiring the member to name Browser Use or activate tools.
2. Verify two personal contexts and a shared channel context: normal permitted reads/writes work, while foreign files, credentials and browser-control connections are denied.
3. Exercise child-process attempts, symlink paths, daemon reuse, inherited handles/environment, concurrent requests and restart recovery under the enabled tools.
4. Confirm that failure keeps browser capability unavailable without running code unrestricted, and that readiness/welcome text describes only the verified capabilities.

All four categories passed the scoped checks in the evidence report. Cold browser-ready onboarding uses fixture Slack transport with a fresh native profile; the earlier real join proves automatic profile activation before first contact, followed by live browser acceptance after this change.

## Material limits

- **Chromium's inner sandbox is disabled with `--no-sandbox`.** On this host its initialization failed inside Seatbelt (`forbidden-sandbox-reinit`). Its entire process tree still requires the outer Seatbelt policy. The existing headless shell avoids full Chrome's additional macOS app-registration permissions; Chromium receives narrowly required power-monitor/Mach rendezvous grants.
- `sandbox-exec` is deprecated. The tested host is macOS 26.5.2 arm64 with Browser Use 0.13.10, harness 0.1.13, agent-browser 0.31.1, Python 3.13.13, Node 22.22.3 and Chromium headless shell 145.0.7632.6.
- File metadata and installed runtime/system contents can remain visible. CPU, memory, disk and process-count quotas are not implemented. The trusted gateway, installed code and local OS account remain trusted. These probes establish the tested resource denials, not universal or portable production isolation.
- Public web access uses a DNS-validating broker with pinned public destinations; private/metadata targets, mapped IPv4 and NAT64 embedded private targets remain blocked. Context IPC and CDP access are scoped. Browser readiness fails closed on unavailable policies, protected manifests or broker.
- Website login, credential handoff/filling, TOTP, broader revocation acceptance and closed-lid operation require separate work. Joining Slack connects no website account.

## Assignment note

The original *Zonko Labs Engineering Assignment*, page 2, asks for thoughtful choices, honest limits, improvements to make next, and a brief note on access-management choices and known limits. It does not prescribe `sandbox-exec` or a particular fallback technology.

Suggested submission wording:

> For the local MacBook POC, generated browser Python and terminal commands run through macOS `sandbox-exec`, with a common policy parameterized for each private or shared context. The actual executor and Chromium process tree are constrained, with recorded file/control-access denial, concurrency and recovery checks. This is a local fallback to VM/container workers. Apple marks the command deprecated and does not support custom policies for third-party development. Chromium's inner sandbox is disabled because it cannot initialize inside Seatbelt on the tested host; the outer boundary remains mandatory. A future version would use maintained isolated workers, retain Chromium's own sandbox and add resource quotas. Website credential handoff and TOTP remain separate work.

This execution decision does not establish secure credential collection, browser credential filling, TOTP, broader access revocation or the assignment's full acceptance criteria; those require their own verified paths.

Sources: the original assignment PDF supplied by the user; the Mac's `sandbox-exec(1)` and `sandbox(7)` manuals; [Apple's explanation of deprecation and custom-policy support](https://developer.apple.com/forums/thread/661939).
