# Automatic TLS first migration and recovery

New Business and Direct Storage installations use `TLS_ENABLED=true` and
`SERVER_NAME=4399.com` (use the node's own DNS name or bare public IPv4/IPv6).
An IP identity does not require a DNS record. Do not include brackets, an IPv6
zone, a port or a URL in SERVER_NAME. Storage also retains its
existing endpoint, pairing, revision and identity configuration. Relay Storage
uses `STORAGE_TRANSPORT=relay`, `STORAGE_PORT=8443` and an HTTPS endpoint on 8443.
No installation requires a prepared certificate, Certbot or host service.
Public HTTP-01 needs reachable TCP 80; Direct HTTPS uses TCP 443. Relay releases
80 after each bounded challenge and never opens 443.
Business `compose --wait` includes a trusted local Nginx TLS handshake and
managed-fingerprint check; a running HTTP bootstrap cannot count as ready.
The controller waits for its private Challenge route before contacting the CA,
without treating that check as proof of public reachability.
Serving verification then uses the configured DNS or IP HTTPS entrance with normal
chain, hostname and fingerprint checks. An inaccessible entrance or a proxy
serving another certificate remains unconfirmed/degraded; local TLS success
cannot conceal it. The node must be able to reach its own advertised entrance.

## Existing deployment boundary

Image replacement cannot create the new certificate services and private,
published and control volumes. Online upgrade/rollback controls are retired.
The first conversion and later updates are operator-maintained Compose
operations; preserve both certificate services and verify the actual serving
certificate before reopening traffic. Across an old topology or database
generation, recovery requires the independent old Compose/database copy. See
[operator-managed releases](master-self-release.md).

Before changing topology, retain an independent cold recovery copy of database,
media, runtime secrets, node identity, pairing relationships, original Compose
files, `.env`, image digests and certificate/account volumes. Drain active
uploads, streams and mutations through the existing maintenance commands. A
certificate backup alone is not a business-data recovery backup. Do not use
`docker compose down -v`, remove identity files or recreate database volumes.

### Previously product-managed certificate volumes

The controller recognizes the previous private `current.json` generation layout
inside its fixed private volume. It verifies chain, DNS name, time and key before
adopting the pair into CertMagic. A valid existing P-256 ACME account is reused;
invalid assets remain available for offline recovery and are never trusted.
Preserve the old named volume by mapping the new `certificate_state` volume to
that exact existing volume. This is storage migration, not a user-selectable
certificate path. Remove the old optional certificate overlay and run only one
controller against that volume.

### Previously external certificates

`scripts/ops/stage_legacy_tls.py` is an optional one-time operator script. It
discovers the current owned container mounts, verifies its currently served
public-CA HTTPS identity, saves a private recovery archive, and stages that same
identity in a **new** project certificate volume. It accepts project, exact
published revision and backup destination; it accepts no certificate/key paths
or uploaded material. It refuses an existing target volume, ambiguous replicas,
unmounted assets, untrusted HTTPS or a certificate different from the live leaf.
It leaves existing services and certificates intact. Run it on the original
node from a reviewed repository checkout, with the exact target image already
pulled and verified. The script shares the publisher's current schema-generation
gate and rejects both old and future-generation images. Go performs final
chain/key validation during adoption; staging alone is not migration success.

Keep the exact Compose project and all business/storage mounts. Remove retired
SSL_CERT_PATH, SSL_KEY_PATH, STORAGE_TLS_CERT, STORAGE_TLS_KEY, ACME_WEBROOT and
old optional certificate overlays. Preserve old configuration only in the
protected recovery copy. Retired certificate variables produce name-only
warnings and never select files. Nonstandard HTTP_PORT/HTTPS_PORT values fail
startup. No certificate upload, path selector or manual renew control is added.

Under maintenance, stop the old certificate controller if present; start the
new certificate-init/controller and then replace consumers using the new
Compose definition. Business Nginx remains ACME-only until a verified generation
is available. Storage remains alive but fails TLS handshakes until ready.
Require `docker compose exec -T web /app/frontiercloud certificate-ready`, the
actual public HTTPS fingerprint and application readiness before reopening.
On failure retain maintenance, stop new components and restore the original
Compose/images/mounts from the independent copy. Never downgrade to plaintext or
disable trust checks to finish a migration.

Changing a Direct Storage endpoint from 8443 to 443 additionally requires the
existing fenced `storage-endpoint` / Master `storage-rebind` operation while
quiescent. Preserve the same node identity and relationship; update its transport
profile consistently. Certificate migration does not authorize database edits
or silently changing resource mode.

## Restore and relocation

Back up the complete private account/cache, published generations and business
data with restrictive permissions. Restore them before starting one controller.
Same-identity, still-valid cached certificates resume without reissuance after
container recreation. A new DNS name or IP requires new authorization. Moving
machines requires the identity's validation and serving traffic to reach the
new machine; DNS changes apply only to DNS identities. The CA makes the final
decision. Expired, wrong-identity, corrupt or mismatched material never becomes healthy.
Damaged published material is restored from a verified private cache without
reissuing the identity. A corrupt lifecycle record is preserved under a private
recovery name and replaced with a five-minute conservative cooldown; the
controller stays diagnostic. Explicit TLS-disabled Business mode leaves old TLS
state untouched. A new fingerprint cannot inherit an old affirmative serving
proof while its real TLS handshake is still pending.
Keep recovery data outside cache/temporary cleanup paths. Protect archives as
private keys. Physical host reboot and a real production-CA migration remain
separate operational checks from local mock-CA tests.

Public IP certificates use automatic `shortlived` issuance and renewal; they
cannot inherit another project's certificate or an unrelated DNS certificate.
Keep account/cache/published volumes private to this deployment. Preserve the
old endpoint and relationship until the new IP SAN and actual HTTPS entrance
are verified through the existing fenced endpoint/rebind procedure. An IP
certificate does not authorize endpoint, identity or role changes by itself.

Reserve HTTP-01 ingress for FrontierCloud. A cohosted application can keep
an independent HTTPS entrance on a separate port with its own static certificate
and key, with manual renewal owned by its operator. Removing its HTTP listener
does not provide automatic renewal. Back up that separate pair and validate its
independent HTTPS entrance when the operator changes it.
Future HTTP-01 renewal needs an explicitly coordinated maintenance window,
never an automatic background takeover of 80 or a shared certificate.
See [shared-host responsibilities](storage-certificate-control.md#public-ip-identities-and-shared-hosts).
