# Automatic node TLS

TLS_ENABLED is the only TLS switch. True always means Go-managed ACME issuance,
renewal and recovery. There is no manual certificate mode or renewal toggle.
First installation requires public DNS and reachable TCP 80 for HTTP-01, not
prepared PEM files, Certbot or a host service. Business HTTPS uses Nginx on 443;
Direct Storage uses native Go HTTPS on 443; Relay Storage uses its configured
communication high port (default 8443). Relay has no idle 80/443 listener.

The required certificate-init and certificate-agent services are included in the
base Compose files. The storage agent shares the host network solely to open 80
for the bounded HTTP-01 operation. All success, failure and cancellation paths
close that listener. Port conflicts fail visibly without taking over another
application. Business uses a private challenge listener behind Nginx. Bootstrap
allows ACME challenge only and does not expose business APIs or Admin over HTTP.

Private account/cache/journal, controller socket and complete published pairs
use three separate persistent project volumes. The account is root-private;
serving consumers see only a read-only published volume. Updates publish a fully
validated generation before atomically changing its pointer. Go uses
GetCertificate for new connections; Nginx validates and gracefully reloads fixed
local configuration with a serialized control helper and no Docker socket.
A serving TLS handshake independently verifies hostname, chain and fingerprint.
Older generations are reclaimed only after that proof, preserving failed-load
recovery. Back up all three volumes with the deployment's identity and data.

## Read-only Admin facts and downloads

Node management shows DISABLED, PENDING, VALIDATING, ISSUING, ACTIVE, RENEWING,
DEGRADED or FAILED, plus actual SAN, issuer, validity, remaining lifetime,
renewal result/plan, last error, controller liveness and serving agreement.
HTTPS availability and agreement with the newly managed generation are separate
facts: a valid old certificate can keep service available during a failed reload.
A process being alive is never proof that HTTPS is ready.

The owner explicitly allows downloading each node's certificate/private-key
pair. The authenticated, CSRF-protected action is audited and returns no-store
responses. Storage wraps its complete validated pair to a fresh browser P-256
key using HKDF-SHA256 and AES-256-GCM. The Master forwards only the ciphertext;
plaintext is produced and saved in the browser as one PEM bundle. Fresh wrapping
keys/nonces and authenticated hostname/fingerprint/request nonce bind the export.
There is no upload, certificate/path selection, manual renewal or disable action.
Protect downloaded private material just as the node's private backup.

## Diagnostics

Run in this deployment's Compose directory:

```sh
docker compose exec -T certificate-agent /app/frontiercloud certificate-status
docker compose logs --tail 100 certificate-agent nginx
```

Storage selects docker-compose.storage.yaml instead. certificate-healthcheck
checks controller liveness only; certificate-ready requires a verified served
identity (or explicit TLS disabled on an eligible business deployment).
Storage deployment waits for HTTPS before generating a fresh five-minute
one-use pairing package. Failure to become ready is a deployment failure, not a
successful pairing; the controller remains available for bounded retries.

DNS, occupied 80, HTTP-01 reachability, authorization, CAA, CA rate limit/service,
clock, cache/journal persistence and certificate/serving errors have distinct
bounded diagnostics. CertMagic owns account persistence, ACME transactions,
storage locking, renewal scheduling and ARI when the CA supplies it. A failed
renewal preserves the valid old serving pair. Nginx logs sanitized
nginx_validation/nginx_reload codes for failed switches; the controller keeps
serving agreement false until a real handshake confirms the replacement.

SSL_CERT_PATH, SSL_KEY_PATH, STORAGE_TLS_CERT, STORAGE_TLS_KEY, ACME_WEBROOT,
STORAGE_CERTIFICATE_DIRECTORY, STORAGE_CERTIFICATE_SOCKET and
CERTIFICATE_ACME_DIRECTORY are retired. Residual values produce name-only
warnings and never select key files. HTTP_PORT and HTTPS_PORT are retired;
nonstandard public-port values fail startup. Remove the former optional
certificate Compose overlays. Existing deployments need the separately backed-up
[automatic TLS migration](automatic-tls-migration.md); changing an old .env is
not a certificate, database, identity or endpoint migration.

## Development verification

scripts/test-storage-certificate-containers.sh exercises Business, Direct and
Relay Compose profiles with a compiled test-only local CA fixture, real Nginx
and native Go serving processes. It issues real ACME orders/challenges/CSRs,
checks actual serving fingerprints, recreates serving containers, restores the
controller account/cache and verifies online renewal. Fixture trust/CA options
exist only in the test binary. No product CA/path override, public CA request,
host port publication or host service is added. Python is the operator/test
harness language and is not packaged into any product image.
