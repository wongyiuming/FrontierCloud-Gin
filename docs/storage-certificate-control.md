# Storage certificate and serial network observation contract

## Ownership and admission

Master Admin / Nodes shows the served certificate status, expiry, automatic
renewal policy, current job and temporary port-80 state for active storage
members. Query is explicit; the GUI does not fan out over nodes. Renewal/policy
changes require an authenticated Admin session, CSRF token, HTTPS, active
downstream ownership and a before-dispatch audit record. The storage endpoint
verifies existing protocol-v2 relationship authentication/nonces and its active
upstream Master. Revoked, pending and unrelated peers cannot reach the agent.

`GET /api/v1/media/admin/nodes/{identifier}/certificate` returns status.
`POST` accepts only `{"action":"renew"}` or
`{"action":"auto","enabled":true|false}` and returns accepted job state,
not a claim that issuance succeeded. Query again for the terminal result.
The signed internal `POST /internal/v1/certificate` exists only on storage.
It never accepts a hostname, CA, key, command, host path or query parameters.
The serialized control lane has a five-second remote deadline; a concurrent
request is refused for retry rather than queued or fanned out.

The storage host retains private ACME-account and TLS keys. Status is limited
to hostname, validity dates, public SHA-256 fingerprint, renewal policy and job
metadata. A background local monitor polls every 15 seconds, with a two-second
deadline, separately from heartbeats. Agent outage does not affect HTTPS
readiness, media or successful heartbeat observations.

## Optional host provision (reviewed release only)

Bridge-mode Docker cannot free a permanently published port 80 by merely
closing an in-container listener. Therefore this optional control service runs
the same static native binary directly on the host. The business container
retains one Go process and receives read-only TLS/control-directory mounts.
No Docker API, shell execution, privileged container or permanent HTTP proxy
is needed. Initial pairing still requires an existing, valid trusted certificate.

1. Install the **same reviewed exact-release** `/app/frontiercloud` binary as
   `/usr/local/libexec/frontiercloud` on the storage host. Copy it from the
   verified Web image using operator tools; never build on production. Make
   the installed file root-owned and executable, mode 0755.
2. Provision the dedicated host account before starting systemd; a numeric
   container UID alone is not a registered host user. Install
   `scripts/ops/frontiercloud-certificate.sysusers` in `/etc/sysusers.d/`, then:

   ```bash
   systemd-sysusers /etc/sysusers.d/frontiercloud-certificate.sysusers
   test "$(id -u frontiercloud-certificate)" = 10001
   test "$(id -g frontiercloud-certificate)" = 10001
   ```

   If UID/GID 10001 belongs to an unrelated host account, stop installation;
   do not reassign or delete that account. The registered identity and the
   container's UID/GID must match before any private state is provisioned.
   Create `/opt/frontiercloud-storage/certificate-state`, owned by that
   UID/GID, mode 0700. Do not put this state on a shared/NFS volume. Preserve
   this private directory in node recovery backups; it includes the ACME account.
3. Create root-owned `/etc/frontiercloud-certificate.env`, mode 0600:

   ```dotenv
   CERTIFICATE_HOSTNAME=storage.4399.com
   CERTIFICATE_ACME_DIRECTORY=https://acme-v02.api.letsencrypt.org/directory
   ```

   For an initial CA validation rehearsal, use the approved Let's Encrypt
   staging directory `https://acme-staging-v02.api.letsencrypt.org/directory` on
   an isolated fixture. Staging CA certificates are not publicly trusted and
   must never replace a production certificate. The hostname and directory
   are fixed locally; API callers cannot alter them. The hostname must match
   storage `SERVER_NAME` and `STORAGE_ENDPOINT`.
4. Install `scripts/ops/frontiercloud-certificate.service` to
   `/etc/systemd/system/`, reload systemd, and enable/start this service. It
   runs as 10001 with only `CAP_NET_BIND_SERVICE`, one Go scheduler, 5% CPU,
   128 MiB memory and no swap. Its private socket is
   `/run/frontiercloud-certificate/control.sock`; no TCP control listener exists.
5. Add `docker-compose.storage-certificate.yaml` to the storage Compose files
   while retaining existing data/secrets/bootstrap-certificate mounts. Its
   defaults mount the state directory and socket directory read-only, matching
   the supplied unit. Start the storage project normally; do not use `down -v`
   or regenerate identity. In Master Nodes, query the certificate before
   enabling automatic renewal or requesting the first managed certificate.

The optional override configures `STORAGE_CERTIFICATE_DIRECTORY` and
`STORAGE_CERTIFICATE_SOCKET` together as absolute container paths. Empty
defaults leave existing deployments working with status-only observation.
Custom `STORAGE_CERTIFICATE_STATE`/`STORAGE_CERTIFICATE_RUNTIME` host paths
require a matching operator-reviewed systemd unit. Do not give Web write access
to TLS state. Compose publishes HTTPS and UDP STUN, never TCP 80/443 for storage.

## Issuance and failure behavior

Native ACME v2 uses ECDSA P-256 and certificate-verified HTTPS to the approved
Let's Encrypt CA. HTTP-01 temporarily listens on host 80 only for the exact
configured Host and challenge path. Other paths/methods/hosts return 404. One
HTTP connection, short read/write deadlines and an overall three-minute job
limit bound resource use. The listener closes before certificate publication,
and on failed issuance, shutdown or cancellation. SIGKILL releases sockets via
the OS; restart records any running journal as `failed/interrupted`, never
reopens its old listener. A private OS lease prevents two agents owning the
same state directory or resetting another live job.

One job runs per host; repeated requests coalesce while it is running. A
managed valid certificate with more than 30 days left is a no-op. Other attempts
respect a durable one-hour cooldown. Auto-renew defaults **off**, persists when
changed from Master, and checks every six hours. The first managed issuance may
replace a still-valid bootstrap certificate because it establishes this
agent's ownership; no implicit import of externally managed private keys occurs.

Failure codes include `port80_busy`, `issuance_failed`, `publication_failed`,
`timeout_or_shutdown`, `interrupted`, `journal_io` and `agent_unavailable`.
An occupied port is never taken from another application. If a shared host must
keep 80 continuously, use its existing certificate manager and status-only mode,
or introduce a separately reviewed DNS-01 provider/delegation integration;
DNS credentials are not accepted by this API. Firewall/DNS must permit public
HTTP-01 validation during the operation, though nothing listens on 80 at rest.
Expired certificates cannot be renewed through an untrusted/expired node HTTPS
connection: recover the certificate locally, retaining TLS verification.

New pairs are checked for matching key, exact hostname and current validity,
written as private complete generation directories, fsynced, then committed by
an atomic `current.json` pointer. Keep current plus one preceding complete pair.
Web refreshes this pointer at most once per five seconds; existing connections
continue. Invalid or partial generations retain the last valid served pair;
expired certificates fail closed. Master observes the **actually served** pair,
not merely an issuer's successful response. No media restart is required.

## STUN and deterministic playback

All active paired downstream nodes are included after Master's own address,
ordered by stable node ID. Signed heartbeat `stun_port` supports shared hosts
with a custom UDP port; old nodes use 3478. Revoked/pending/upstream relations
are excluded. If a staging Master already owns UDP 3478 on a shared host,
configure storage `WEBRTC_STUN_PORT` to a distinct available port, such as 3480,
and allow that UDP port through the firewall. Existing installations must be
upgraded before their new native responder is available.

The responder handles only bounded RFC 5389 Binding requests, IPv4/IPv6
XOR-MAPPED-ADDRESS and FINGERPRINT. It has one sequential packet loop and a
global ten-datagram/second budget including malformed traffic; excessive loads
may cause diagnostics to time out, never create worker fan-out or TURN traffic.
Its failure does not terminate business HTTPS. Browser probes likewise run
serially with exactly one ICE peer and one STUN URL, close before advancing,
wait 250 ms between nodes and three seconds maximum per node, then wait at
least 30 seconds before another round. Web Locks prevent same-origin tabs
overlapping where supported; the fallback remains serial per page. Hidden
pages stop advancing; navigation cancels the peer. Diagnostics do not gate
playback and cap reports at eight IPs without truncating the node list.

Media with equal priority keep deterministic path/ID order for every playback
session, including cache hits. File priority remains the primary sort key.

## Verification scope

Native tests exercise real Unix/TCP/UDP/TLS sockets, port conflicts, failure and
shutdown cleanup, coalescing/cooldown, durable interrupted-job recovery,
atomic hot loading, wrong-host rejection and expired-certificate failure.
Node tests cover signed control, role/revocation/audit admission and serialized
dispatch. Browser smoke tests cover more than four STUN nodes, timeout,
connection-close order, origin leases and navigation cancellation. Production
CA issuance additionally requires public DNS/port-80 validation on the target
host; hermetic development evidence does not claim a live production issuance.
