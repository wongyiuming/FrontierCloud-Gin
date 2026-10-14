# Automatic TLS implementation audit

Scope: inspected release `c35501f18497cec2a1a3a7f5785d733e8e976dfc`
and development `836599f7fa4f5d38034a0999eee9db05f9cc2a8f` before changing
the certificate architecture. This document records findings and the accepted
replacement contract, not completion or test evidence.

## Actual starting implementation

Business `docker-compose.yaml` and `docker-compose.gin.yaml` terminate TLS in
Nginx. Web is a private HTTP listener on 8000. The MySQL variant extends the
same business services. The Nginx entrypoint chooses static HTTP or HTTPS
templates; HTTPS requires existing certificate bind mounts. Nginx waits for
Web health. IP-security rendering already performs a bounded, local `nginx -t`
and reload; business Web has no Docker socket.

Storage is a standalone Go server, with no Nginx, Redis or updater. The release
contract requires an explicit high HTTPS port and external certificate files.
Development adds an optional independent Compose certificate controller, private
Unix control and atomically published certificate generations. Its account key
and generations share a volume, which is unsuitable for exposing that volume
to a root Nginx process. Automatic renewal defaults off; the GUI can request
renewal and change that policy. This optional architecture is being replaced.

The existing ACME implementation uses `golang.org/x/crypto/acme`, rather than
implementing ACME messages itself. It persists an account and a small journal,
but does not cover mandatory first installation, Nginx bootstrap/deployment,
ARI, the full failure state machine, or certificate-chain trust verification.
Storage startup currently rejects a missing certificate and creates pairing
information immediately after starting its TLS server. These behaviors cannot
meet the new no-certificate startup contract.

The host-side operator pins Web/Nginx images and preserves recorded service selections.
New controller/init services must use the Web image and participate in that
same release proof and recovery operation. Existing source/build workflows,
startup fixtures, real native matrix and browser fixtures also contain old
certificate paths and random/high public ports; changing examples alone would
leave real deployment and acceptance paths inconsistent.

## Accepted replacement contract

- `TLS_ENABLED` selects TLS. When true, certificate lifecycle management is
  mandatory for both deployment types. No alternate manual mode, upload, path
  selector, renewal button, or automatic-renewal toggle remains.
- Remove operator-facing `SSL_CERT_PATH`, `SSL_KEY_PATH`, `STORAGE_TLS_CERT`,
  `STORAGE_TLS_KEY`, `ACME_WEBROOT` and certificate directory/socket variables.
  Internal certificate/cache/socket mountpoints are fixed program details.
- Business public HTTP is always 80 and HTTPS 443. Retire `HTTP_PORT` and
  `HTTPS_PORT`, rejecting nonstandard business origins and legacy port values.
  The final owner policy is Direct Storage HTTPS on 443 and Relay Storage on
  its high communication port (8443 by default), with STORAGE_TRANSPORT bound
  to the authenticated node identity. Storage HTTP-01 occupies host 80 only
  during validation; Relay never publishes host 443. Both profiles release 80
  after validation. No port remapping may bypass the Direct 443 policy.
  Private business HTTP remains private 8000; STUN is a separate UDP protocol.
- Storage retains Go TLS termination and online certificate rotation. Business
  retains Nginx. Only the edge may execute fixed local configuration validation
  and reload commands. No host service installation or Web Docker access.
- Certificate accounts/private state and published complete TLS generations
  reside in separate persistent volumes. HTTP bootstrap serves challenge and
  restricted health routes only; no temporary plaintext business or self-signed
  substitute. Failed renewal retains the last valid generation.
- AdminGUI displays observed controller, certificate and actual serving status.
  The owner's explicit supplement permits certificate/private-key downloads;
  use authenticated, audited, uncached export. Storage private keys must remain
  opaque to the Master while it relays an export to the requesting browser.
- Existing identities, authentication, databases and media survive migration.
  Endpoint changes require the established fenced identity-preserving handover,
  including Master relationship rebind; deleting and re-pairing is not a
  migration shortcut. Backups preserve certificate accounts and generations.
- External user-owned CD is outside product runtime and may continue using
  systemd. Do not refactor it as part of this change.

Historical Python operator scripts are retained. The old persistent DIND
provisioner and Admin/whole-fleet client explicitly refuse the automatic TLS
checkout because their legacy manual-certificate/high-port topology and Storage
Admin APIs are retired. Use scripts/test-native-matrix.sh for the supported
private-CA five-node acceptance fleet. This does not remove Python scripts or
introduce Python application/runtime components.

## Operator clarification and RN retirement

On 2026-10-11 the owner explicitly decommissioned RN preproduction and its
external CD, pending a future independent IP. Preserve RN production storage
and other applications during that retirement. The subsequent clarification
finally assigns Direct Storage to public 443 and Relay Storage to its private
high communication port. Only HTTP-01 validation temporarily needs public 80
on storage; Relay does not publish 443. No shared SNI entrance is introduced.
The retired preproduction deployment is no longer a live release acceptance
target. Development acceptance and exact-source CI/public-image evidence remain
required; no successful staging/CD result may be fabricated or substituted.

## Library review

The inspected [CertMagic v0.25.6 source](https://github.com/caddyserver/certmagic/tree/v0.25.6)
provides persistent ACME storage locks, account handling, asynchronous retries,
automatic renewal and ARI scheduling. The reviewed API supports independent
caches and event callbacks. Any integration must still validate and atomically
deploy certificate generations, distinguish issuance from actual serving, and
restrict edge privileges; the library alone is not proof of those properties.
