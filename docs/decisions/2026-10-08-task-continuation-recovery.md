# Automatically recover the pre-fix verification profile split

Submitting a private verification form already creates a durable saved request that the coordinator resumes automatically. The earlier routing fix preserves the original task for new submissions. It did not recover a historical task whose code was already consumed in a different member profile while its actual worker remained waiting. Asking the requester to say “continue booking” was a manual workaround for that remaining gap.

The coordinator now recognizes this bounded legacy state: an active channel task with no post-fix inbound/result event, a waiting worker code request, and a later consumed/resumed code request from the same requester, owner home, private thread, origin, handle and grant. The misplaced request must identify its authenticated human message and use the current member profile. Completed, cancelled, unrelated and superseded work is excluded.

Persist one deterministic recovery intent before dispatch. Revalidate membership, the original shared destination and the isolated execution route. Retry the same intent after a busy session or restart. Atomic admission lets a newer human reply take priority, including one that arrives during authorization awaits.

Expire only the matched obsolete worker form after authorization and admission. Resume the original isolated worker with its saved goal, without importing the other profile's conversation, code, cookies or payment approval. The worker checks its own browser and requests fresh private verification if necessary. A new secure form or delivered response owns further continuation and ends this recovery intent.

This coordinates a new turn; it does not assert that another profile's login authorizes this worker or that the requested transaction is complete. Model/browser follow-through still needs live evidence.

See [the verification receipt](../../verification/evidence/2026-10-08-task-continuation-recovery.md). The recovery patch follows the original continuation patch in `scripts/apply-hermes-mods`.
