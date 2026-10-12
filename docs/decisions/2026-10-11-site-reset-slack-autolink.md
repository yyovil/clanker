# Exact-host Slack autolinks in site-reset authority

Status: implemented and locally verified; activation and live fresh-auth verification pending.
Finding: `site-reset-slack-autolink`, linked to `scoped-site-session-reset`.

## Finding

The reviewed fresh GitHub opening failed in [the yyovil task](https://clanker-global.slack.com/archives/D0C6F49F2KD/p1791728365855949) on gateway PID59666. Slack encoded the bare hostname as an HTTP autolink. The generic strict owner-text filter rejects angle-bracket markup, so `reset_requested` rejected this transport representation before any site reset or new auth request. The model passed the intended saved handle, exact HTTPS origin and both fresh/reset flags, and truthfully reported the refusal.

Hermes session `20261011_194933_e04295e0` and owned Kernel browsers `uu13w0i48kblb7ut8k3u2yxb` and `pznjczzk7top67ub5qbijxz3` cover the 14:19–14:28 UTC attempt. The existing GitHub session belonged to yyovil; the requested repository already existed and the actual page showed Private. Both original repository follow-ups completed. This does not satisfy the additional fresh-auth or autonomous-TOTP requirement. The sanitized observer never bound a new generation and ended with `run_ended`. There was no human intervention. The scoped stop closed the browser and left zero leases for the exact task.

## Change

Only the site-reset authority parser normalizes Slack's exact literal `<http://host|host>` or `<https://host|host>` spelling, where both occurrences must equal the saved origin's host. No URL is fetched, and the reset destination remains the separately verified HTTPS origin. A different target or label, subdomain, path, query, fragment, userinfo, port, alternate scheme or encoded hostname remains unrecognized and is refused.

The original input-length limit applies before normalization. The entire normalized owner request still passes the existing closed-clause fresh-login and reset checks. Quotes, negation, withdrawal, synthetic message IDs and unrelated suffixes remain refusals. The global text filter, owner/account/profile bindings, CDP protocol and lease lifecycle are unchanged. This module is imported directly from the Clanker runtime; no Hermes mirror or patch registration is involved.

## Validation and limits

The canonical runner reproduced **4 failures / 67 passes** before the correction. The successful autolink cases failed both in the actual reset broker and in real ManagedAuth same-connection renewal with provider doubles. The corrected four-file suite passed **151 tests**, zero failures or retries: 71 scoped-reset, 48 fresh-auth, 17 principal-auth and 15 handoff tests. New negative cases prove rejected links or owner restrictions cannot call the reset protocol or close a browser. The real renewal cases preserve one login dispatch and refuse replay after an unknown outcome.

Evidence is under `.local/clanker-qa/findings/site-reset-slack-autolink/` (`autolink-red.log`, `autolink-green.log`) and the `github-totp-observe` lane's run folder. This correction has not been activated or retried against GitHub. Provider SUCCESS, saved authenticator metadata and reused login cookies remain insufficient evidence of an actual autonomous TOTP challenge.
