# Retire an idle private browser writer before account continuation

## Finding

Instamart checkout run `r20261011-033243-take-noodles-instamart-3942` ([thread](https://clanker-global.slack.com/archives/D0C6EAXPKEE/p1791669763188809), Hermes `20261011_033250_9265f676`) could not open the saved account at 03:33 IST. The completed cart thread still owned live Kernel browser `ykvimravo07biucj0sqt3256`. The profile guard treated every live browser as active work even though the prior gateway turn had finished. Clanker then handed browser cleanup back to the owner.

## Change

Keep one writer per retained account profile. Before a new owner DM thread reuses it, the harness can retire a previous live browser only when its protected requester/context claim matches, both threads belong to the same ordinary owner DM/home, the trusted gateway reports the previous thread idle, and no private form, queued resume, owner approval, uncertain creation or unresolved payment remains. Isolated workers and unknown gateway contexts remain locked. Remote profile/vault/proxy identity is checked before confirmed browser closure; the saved profile survives.

Expired browser reconciliation keeps its previous behavior. The helper is shared by retained Vault account selection, browser preparation and Managed Auth preparation.

## Validation and limits

The new test reproduced the original failure for both Vault and Managed Auth profiles. The canonical runner now passes 110 checks across idle-writer, task-profile, Kernel browser, Managed Auth browser and saved-login-routing probes. Eight removed-local-vault cases remain strict expected failures. The new guards cover running turns, waiting/saved/unconfirmed code forms, owner approvals, unresolved payments, foreign owner context and unavailable gateway state.

Activation completed through the idle QA restart at 03:50 IST (PID 67711, Slack connected). Checkout rerun `r20261011-035104-take-noodles-instamart-3942` passed with saved Home selected, INR143 total and the independently verified fee breakdown. This verifies checkout recovery, but does not prove that the live idle-writer release path ran rather than the prior browser having already expired. That narrower activation proof remains open. The original failed attempt stays in benchmark history. No production browser or database record was manually changed.
