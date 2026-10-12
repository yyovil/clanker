# Indian residential routing for Kernel

The user requested residential proxy setup and a real Slack test ordering one
pack of Ching's Secret Instant Hot Garlic noodles from Instamart or Blinkit.
Earlier evidence showed Blinkit explicitly blocking the browser, while
Instamart displayed a temporary-glitch page. The newer Hot Garlic attempt
failed during Kernel browser creation, before either site could load. Those
are separate failures; changing the proxy cannot establish that all are fixed.

The authenticated Kernel entitlement check returned
`features.managed_proxies.enabled=true`. The initial proxy list was empty.
The selected managed proxy targets `IN` with type `residential` and no city,
state, ASN, bypass hosts or other targeting restrictions. Kernel recommends
the least-specific targeting that works to preserve the available pool.
[Residential proxy documentation](https://www.kernel.sh/docs/proxies/residential)

The protected backend configuration stores only the selected proxy ID, type
and country. The pinned provider source remains unchanged; the adapter supplies
the fixed ID through its existing proxy resolution method. Model arguments,
member environment files and process environment cannot select another proxy.
Live proxy identity/type/country and browser proxy binding are checked before
browser use and saved-secret fill. Missing or changed routing is refused.
Requester isolation, disabled persistent profiles and disabled local fallback
are preserved. This does not change the browser VM region.

Each new browser entry captures its proxy policy. Existing browser sessions
retain their original routing expectations; a global configuration change does
not move a signed-in session to another exit. A fresh Slack thread exercises
the newly configured route without clearing unrelated failed-creation markers.

The operator previews before applying, checks the entitlement and complete
proxy list, creates a stable named proxy only when absent, verifies health,
and saves a private configuration snapshot before changing the backend.
An unknown creation acknowledgement is retained for reconciliation rather than
blindly issuing a second create. Local configuration writes require the
gateway to be stopped. The operator does not restart the gateway or delete
remote browsers or proxies.

A successful proxy health check establishes connectivity, not website access
or checkout success. Kernel residential exits can change between connections.
The live Slack test must separately verify page access, product/stock,
requester-owned account/location handling, cart total and delivery estimate.
Payment requires approval of the concrete total before an order is placed.
Verification and activation evidence are recorded separately.

Activation on 2026-10-08 adopted the unique existing
`clanker-india-residential` proxy. Kernel returns its country as lowercase
`in`; remote validation accepts case differences only, while protected
configuration retains `IN`. The health check confirmed availability and the
operator saved a SHA-checked rollback snapshot before updating configuration.
The restarted gateway connected to Slack, and local/public vault checks
returned HTTP 200 with `ready=true`. Browser/client checks passed 113 tests;
the operator passed 34 fixture tests. A fresh human-authored Slack request is
the remaining website/ordering acceptance check.

The later Apple audit exposed a coverage limit: purchase preparation is
explicitly routed to the separate private local `browser_exec` browser. That
browser uses the local public-egress broker, not Kernel's managed residential
proxy. The proxy is live for Kernel sessions but does not cover this checkout
path. The Apple failure was a GET form submission ending on Page Not Found;
network/console evidence is still needed to attribute the failed handler.
Do not describe this activation as end-to-end residential ordering support.
