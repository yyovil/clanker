# Kernel API-key execution

On October 8, 2026, the owner approved backend-readable API keys in Kernel Vault
so Clanker can make authenticated API requests without restoring custom credential
storage. The model continues to receive opaque handles rather than keys.

API keys use credential fields with `type: "text"`, `required: true` and
`sensitive: false`. Kernel returns populated values in authenticated item
responses under `state.fields.<name>.value`. This setting permits authorized
backend reads and hosted-form prefilling; it does not make the value public.
It deliberately changes API keys from write-only credentials to readable fields.
Kernel recommends sensitive fields for API tokens, so Clanker must enforce the
approved narrower execution boundary itself. Passwords and TOTP seeds remain
sensitive and opaque. [Kernel credential field behavior](https://www.kernel.sh/docs/vaults/credentials)

The restored `clanker_api_request` tool accepts an opaque credential handle and
a JSON request. The trusted backend checks current requester or invitation
permissions and the stored exact HTTPS API origin, reads the key privately, and
injects authentication only for that request. Keys stay out of model context,
tool arguments, generated code, shell environments, logs and active local
credential stores. Generated scripts do not receive raw keys; authenticated API
work goes through the scoped tool. Local metadata records ownership, handles,
claims and outcomes without credential values.

Kernel has no API export path for sensitive Vault values. Field type and
sensitivity are immutable, so an existing sensitive API-key item requires a
replacement item and private recollection or an independently available source.
The reviewed live inventory had zero saved API-key items; no recollection is
needed for this rollout. Browser fill followed by scraping is not a migration or
execution mechanism. [Kernel Vault read behavior](https://www.kernel.sh/docs/vaults/overview)

This decision covers scoped JSON API requests. It does not provide arbitrary
secret-bearing code execution, change merchant login or SMS handling, or enable
automatic purchases or payments. Restoring the tool and passing local tests do
not prove a live API provider accepted a request; that requires separate evidence.
