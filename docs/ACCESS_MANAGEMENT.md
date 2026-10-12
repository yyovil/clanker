# Access management

Known product limits are listed separately in [KNOWN_LIMITS.md](KNOWN_LIMITS.md).

**Website sign-in.** Slack-authenticated access links redirect the account owner
to Kernel Managed Auth's hosted login. Kernel discovers the login flow, collects
passwords and fresh SMS/email codes, and saves a successful authenticated profile.
Clanker resumes the original task only after this exact flow reports success.
Pending flows are reused without restarting; failures are not automatically
retried. First migration sign-in may require credentials again: write-only Vault
passwords cannot be imported into Managed Auth through a documented bridge.
Use `clanker_authenticate`; the old login-fill/code tools are compatibility aliases.

**Collection and storage.** Kernel Vault continues to store personal details and
API keys. Existing Vault login items remain protected. Clanker's local database keeps
ownership, opaque handles, consent, request status and fill claims. Its former
credential forms and encrypted credential writers are disabled. A protected
encrypted migration archive is retained outside active profiles for recovery.

**Use and reuse.** Clanker receives credential handles and metadata. A handle is
an ID, such as `vault_a1b2c3d4e5f6`, pointing to a saved credential. It contains no
secret and does not grant access by itself. The backend checks the requester's
permission before starting Managed Auth. Passwords, codes and authenticator seeds
are not returned to Clanker. API keys use the separately approved backend read
path below and stay out of model arguments. Each requester and account has an
isolated Kernel auth profile. In the owner's canonical private DM, selecting the
same saved account can reuse its successful login across Slack threads after
checking current authorization, provider status, flow generation and proxy.
Each task still gets a separate browser. Automation loads the successful snapshot
with `save_changes: false`; it never copies cookies or writes back to the profile.
Stopping an ordinary DM task deletes its browser and releases its account
selection while retaining the successful owned login. Account removal, explicit
purge and privileged home cleanup still delete the connection and profile with
absence checks. Invited accounts and isolated shared-task workers retain their
separate task profiles and cleanup. Fresh login and SMS/email verification can
still be necessary when the website session expires; verification uses a fresh
interactive code.
Cookies alone do not
authorize using an account; Clanker requires owned or explicitly invited access.

**Personal details.** Names, addresses, phone numbers, email and dates of birth
are model-blind by default. An owner can explicitly allow Clanker's model to read
only the saved primary fields required for a private task and adapt them to the
website's actual form. This consent is owner-scoped; it does not expose invited
accounts, gender, passwords, cards, tokens or verification codes. Public Slack
updates still redact personal values. Authorized reads can persist in private
model conversation history; revocation stops future reads without erasing data
already seen. Kernel stores ordinary details as non-sensitive fields so the
trusted backend can format them for a website; gender remains opaque. The model
consent check is separate from that backend access. See [the consent policy](decisions/2026-10-08-consented-personal-model-access.md).

**Private continuation.** A task can move from a shared Slack thread to the
owner's DM while retaining its context internally. Private questions, values and
ordinary replies stay there. Shared-thread updates identify the intended member
and contain meaningful public milestones or the verified outcome, not copied DM
dialogue.

**Sharing.** Owners invite a Slack member to use selected credentials. Invitations
grant neither the whole vault nor onward sharing, and newly saved credentials are
not automatically included. Managed Auth grants use a separate recipient/task
profile and a saved Kernel credential reference. Legacy Vault credentials must
have a dedicated Kernel vault; recipients never attach the owner's general vault. The migration preserves
the existing shared login in a dedicated vault. New invitations for credentials
in a general vault are refused until an isolated mapping is provisioned.
Membership and grants are checked at use time.
Sharing a login inherits that website account's permissions; it does not create
read-only access.

**Payments: current limitation (2026-10-10).** For the review with Sahan and
Nishank, present payments as a current POC limitation. The reported SBI attempt
completed card enrollment, but did not obtain the agentic network token needed
by the native Kernel payment flow. Successful end-to-end Indian card payments
have not been verified. Agentcard through Kernel also requires a recognized
browser checkout request: its [published adapter coverage](https://www.kernel.sh/docs/integrations/wallets/agentcard)
does not include Juspay. [Zepto uses Juspay](https://juspay.io/customer-stories/zepto),
and its exact browser checkout remains unverified; a Juspay request cannot be
assumed compatible merely because it routes to a supported processor later.
Agentcard therefore does not establish general merchant coverage. Payment code
is retained unchanged; this note does not disable or alter the existing flow.

The existing implementation targets INR purchases up to ₹500 from the owner's
private task. Card details are entered in Kernel's hosted form; Clanker does not
store card values or accept them through tool arguments. Without a remembered
card, the owner approves a private Pay ₹X request and can choose to remember the
card. With a remembered card, the owner's instruction to pay is enough; Kernel
still requires a passkey approval for Visa, while Mastercard has no hosted
approval step. Remembered cards are scoped to their owner. Clanker fills the card
through Kernel, clicks the bound Pay button once and never retries an uncertain
payment. The agent supplies the amount from the checkout it observed. The backend
enforces the ₹500 limit, owner scope and single submission; the owner's payment
instruction is followed by the agent rather than checked by the backend. A click
is not success: the agent confirms the merchant's result before reporting a paid
order.

**API integrations.** The owner approved storing API keys as Kernel credential
fields with `type: "text"` and `sensitive: false`. This setting makes the value
readable through authenticated Kernel item responses; it does not make the key
public. Kernel remains the credential store. Clanker keeps only ownership,
opaque handles and execution claims locally, with no active local key copy.

The scoped `clanker_api_request` tool accepts an opaque handle and a JSON request.
The trusted backend checks owned or explicitly invited access and the credential's
exact HTTPS API origin, then injects authentication for that request. Keys do not
enter model context, tool arguments, generated scripts, shell environments or
logs. Code tasks use this tool for authenticated requests instead of receiving a
raw key. Passwords and TOTP seeds retain their opaque, sensitive representation.

Existing sensitive API-key fields cannot be exported or changed to readable
fields because Kernel field types and sensitivity are immutable. They require
a replacement item and private recollection or import from an independently
available source. The reviewed live inventory contained no saved API-key items,
so this rollout needs no recollection. API execution is being restored; a passing
local check does not establish acceptance by a live API provider. See
[the approved execution boundary](decisions/2026-10-08-kernel-api-key-execution.md).

**Revocation.** Revoking an invitation denies further credential use and cancels
pending handoffs. If it was used in a browser, the recipient's affected context
stays blocked until cleanup succeeds. Kernel cleanup requires confirmed remote
browser deletion followed by an API response showing that session is absent.
Uncertain cleanup stays recorded and blocks reuse. Deleting a browser is not
merchant-side logout or revocation of the underlying website account.

**Trust and limits.** Kernel hosts the browser and therefore receives entered
website secrets and page content. The adapter verifies requester ownership,
remote session identity, exact authenticated profile and origin before private fills;
attachment to another requester's general vault is disabled. Kernel
fill can emit untrusted input events. Provider success and nonempty DOM controls
do not establish website acceptance: observe the actual login or checkout state.
Managed Auth transport and profile handoff are tested separately from real
merchant login and SMS verification, which still require user participation.
Encryption does not protect
against a compromised host or browser provider. These controls need continuing
live acceptance evidence and do not create narrower permissions inside a shared
website account. Historical Composio records do not represent an active browser
connection or prove deletion of old provider resources.