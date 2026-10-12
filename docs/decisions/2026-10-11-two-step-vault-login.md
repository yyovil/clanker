# Allow distinct username and password fill stages

## Finding

The default Kernel Vault fill attempt key contained task, message, handle, origin and credential version, but not the selected fields. On a two-page login, the username fill therefore consumed the password step's attempt key. A synthetic test reproduced the refusal before any website run; this is not claimed as the proven cause of the historical Google outage.

## Change

Include the sorted declared field names in the default operation key. A username-only page and a password-only page can each be filled once during the same authorized turn. Repeating the same stage remains rejected. An already dispatched key from the previous implementation stays spent across upgrade. Explicit caller operation IDs and one-time code collection IDs retain their existing behavior.

## Validation and limits

The new two-page regression failed before the fix and passes afterward, including refusal to repeat the final stage. 117 saved-login/Vault/ACL/personal tests passed across the final runs, including rejection of a previous-version dispatched attempt. Real Google website acceptance remains unverified. No real credentials were read or submitted by the regression tests.
