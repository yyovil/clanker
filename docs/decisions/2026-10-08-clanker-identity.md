# Clanker identity at the beginning of the prompt

The assembled prompt began with the default “You are Hermes Agent” SOUL
identity and ended with the configured “You are clanker” personality. Isolated
workers skipped SOUL and received the same Hermes fallback identity.

The Clanker build now uses “You are clanker.” for both the default SOUL seed
and the runtime fallback. The existing behavioral guidance is preserved.
Hermes help guidance identifies Hermes as Clanker's underlying runtime rather
than the agent's name. Profile creation continues through the native SOUL
seeder, so newly created private, channel and task profiles receive the same
identity.

The native legacy-template migration recognizes the exact previous default
SOUL text, including its ASCII-dash variant. Customized identities are not
rewritten. The changes are recorded in
`patches/hermes/clanker-identity.patch`, registered in the pinned patch stack.
The patch applies to its pre-change files and reverses cleanly on the current
files. A full patch-stack recheck refused the existing
`slack-unfurl-admission-race.patch` conflict; those unrelated edits were not
overwritten.

Native A–B–A profile rendering verified default migration, custom SOUL
preservation and the fallback identity of isolated workers without loading a
custom owner's persona. No model call or Slack message was used. The
channel-independent Markdown export is rebuilt from the native prompt
assembler after the correction. Existing cached prompts are not rewritten.

## Verification and activation

The canonical runner passed 289 tests across the native prompt builder,
system prompt assembler and configuration suite, with five host-specific
tests skipped. All 36 live profiles now have the Clanker default identity;
35 required migration during the explicit pass, and one had already migrated
through native initialization.

Reused the gateway restart authorization from this chat after confirming
zero active agents. The replacement gateway (PID 5736) started at 05:01 IST
on 8 October 2026 and reconnected to Slack. All 107 snapshotted config, auth
and environment files remained byte-identical. Startup logged no ERROR
lines. Local and public private-form health returned HTTP 200 and ready.
No conversation was reset, Slack test message sent or model call made.

Receipts: `verification/evidence/2026-10-08-clanker-identity-*.json`.
Updated complete template:
`.local/hermes-lab/prompt-review/2026-10-08/clanker-system-prompt.md`.
