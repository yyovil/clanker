# Preserve the originating Slack thread in private continuations

## Finding

The durable handoff retained and validated the correct originating channel and root, but neither the initial private worker event nor its authenticated resume exposed that reference to the model. An older planning root was visible in correctly labelled recall. The worker explicitly selected that older root for shared progress even though the new opening requested its result in the current thread.

Evidence: [current request](https://clanker-global.slack.com/archives/C0C6J277ZNG/p1791719131684689), QA run `r20261011-171531-help-plan-12-01ab`, Hermes session `20261011_171545_950ff79b`, private continuation root `1791719144.303049`. The compared earlier root is `1791715417.473369`. Initial handoff and access-resume attribution is preserved in `.local/clanker-qa/batches/2026-10-11-reliability-round6/goa-verify/runs/r20261011-171531-help-plan-12-01ab/evidence/handoff-context-attribution.json`, covering the 17:15–17:23 IST continuation window on 11 October 2026. No private account or credential values are required for this diagnosis.

The owning omission is in `VaultService.resume` event construction and the private branch of `ChannelTasks.admit_event`. `request_context` preserves the user task and optional conversation/recall but does not expose the bound source. The durable `original_source` already supplies the authoritative reference; recalled history must not substitute for it.

## Change

A small coordinator helper revalidates the durable originating source through the existing membership and shared-channel checks, then supplies only its channel and root in a labelled context block. The block identifies what “here” means in the original shared request and retains explicit requests for another authorized destination, including an earlier planning thread. Recall alone does not select an output destination.

Both transfer and access resumes append the context after all prefix selection, including Managed Auth and recovery prefixes. Admitted private replies also receive it after preparing their isolated task. Request text and stored recall remain unchanged. The context is regenerated from the validated task row after restart rather than embedded into potentially recursive saved request text. Ordinary replies and private details stay in the DM.

Public-update selection, alternate-target same-turn recall requirements, live root checks, owner authorization, outbox delivery, cancellation and deduplication are unchanged. Private reply admission performs one additional existing destination validation to obtain the reference; no new Slack post or provider action is introduced.

## Validation and limits

Prepared in `.local/clanker-qa/findings/handoff-source-thread-context/isolated/`; live source has not been changed or restarted. The canonical runner reproduced six missing-context failures before the candidate, with two revoked-access controls passing. All eight new cases then passed: three distinct owner/root transfers, saved-access resume after restart with ordinary and Managed Auth prefixes, real Slack private reply admission after restart, another-owner isolation, and refusal after source access is revoked.

The six related suites passed 123 tests with zero retries: task continuation (3), recalled handoff (2), public destination (10), isolated shared recall (12), shared followup (11), and Kernel Managed Auth (85). Together with the new cases, 131 checks passed. Independent read-only review found no blocker. Normal-location tests remain required after coordinator integration; the broad retired-local-vault baseline was not rerun for this isolated candidate. The tests exercise real coordinator events, durable records, membership and destination checks with fixture transport and model execution. They do not prove that a model will choose correctly in a live run. Same-scenario live verification and coordinator-controlled idle activation remain required. This candidate does not change or resolve the separate website or document-input failures in the run.

## Integrated validation

The coordinator applied the reviewed four-file candidate with base/stage hash checks after all live lanes were stopped. The normal-location canonical run passed **117 tests across eight files, zero failures and zero retries**. Log: `.local/clanker-qa/findings/handoff-source-thread-context/integration-tests.log`. Coordinator and independent peer source review passed. This changes only newly constructed event context, preserves cached history/system prefixes, and leaves existing destination authorization unchanged. Live activation and verification remain pending.
