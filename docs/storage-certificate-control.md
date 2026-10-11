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

## Optional Compose certificate control

All product components stay in Docker/Compose. Do not copy executables onto the
host, create host accounts, install systemd units or invoke systemctl. The
optional certificate container uses the same reviewed exact Go Web image/build,
no separate unreviewed artifact or installer. Existing storage stays one business
process; optional certificate control is a separate bounded container.

Prepare reviewed exact images through the bounded build/pull path, then enable
the storage and certificate Compose files together:

```bash
docker compose -f docker-compose.storage.yaml -f docker-compose.storage-certificate.yaml up -d --no-build
```

For production, prepare the reviewed exact images through the bounded build/pull
path before `up --no-build`; never compile on production or replace node identity.
Initial pairing still needs an existing valid trusted bootstrap certificate.
Preserve the existing data/secrets/bootstrap mounts; never use `down -v` on an
owned node. No new CA/hostname is selected through the network API.

The exiting `certificate-init` initializes only three mounted volume roots;
it refuses to operate without those mounts. `certificate-agent` runs with a
read-only rootfs, no-new-privileges, dropped capabilities, 0.05 CPU, 128 MiB,
no swap and 24 PIDs. Container UID 0/GID 10001 is needed for temporary low-port
binding; this creates no host user. The default Linux temporary mode grants only NET_BIND_SERVICE; the shared
webroot overlay drops that capability and uses bridge networking.
The private TLS/control volumes persist across agent recreation. Web mounts them
read-only as UID/GID 10001; it can read the 0750/0640 complete TLS generation
and connect to the 0660 socket through its 0710 directory. ACME `account.key`,
job journal and lease remain 0600 and root-private. No PID namespace sharing,
privileged container, Docker socket, shell or service-manager operation exists.

## Shared HTTP-01 (existing public route required)

The optional webroot overlay opens no HTTP listener. It selects bridge networking
and writes only the exact CA token into an existing public challenge directory.
That directory must already be served for the fixed storage hostname by the
existing HTTP service. This is an explicit operator prerequisite; an unserved
project volume is never selected as the default validation path. Keep TLS/account
volumes separate from the public directory.

When an existing HTTP service already has the desired public validation route,
reuse its exact challenge directory with the optional webroot overlay:

```bash
# Only public proof files belong here; never point this at private TLS state.
export STORAGE_CERTIFICATE_HTTP01_DIRECTORY=/opt/existing-acme/.well-known/acme-challenge
docker compose -f docker-compose.storage.yaml -f docker-compose.storage-certificate.yaml -f docker-compose.storage-certificate-webroot.yaml up -d --no-build
```

The existing directory must already exist and be writable by container UID 0
or GID 10001; Compose refuses to silently create it. It mounts only this directory,
not host root, service-manager paths or Docker state. This is a fixed operator
configuration; network calls cannot select paths. Existing server/other-domain
routes and other issuers remain unchanged. Verify and remove a harmless public
sentinel before requesting issuance. Nodes must report `shared_http01`.

Only the exact CA token is created, at most 512 bytes, mode 0644. Existing files
and symlinks are never overwritten. Success, failure and cancellation remove
only the owned proof. Restart reclaims only bytes matching the private journal;
unknown/replaced files stay untouched. A crash-created empty proof is preserved
for inspection. Other services are not stopped, scanned or pruned.

## Temporary HTTP-01 (default Linux network exception)

An ordinary bridge container with `ports: 80:80` permanently reserves the host
port even while its Go listener is closed. Therefore temporary mode uses
default host networking, with only NET_BIND_SERVICE and no Docker port
publication:

```bash
docker compose -f docker-compose.storage.yaml -f docker-compose.storage-certificate.yaml up -d --no-build
```

This shares only the Linux network namespace; no host process/filesystem/service
control is granted. The service binds only the fixed port during a bounded job,
then closes it. An occupied port returns conflict; it never stops the existing
owner. Nodes reports `temporary_port80`. Use the webroot overlay on hosts that already serve HTTP, after verifying
their existing public challenge route. The optional temporary overlay explicitly
reselects the default temporary mode. Host-network temporary mode requires native Linux
Docker host networking; no host sysctl or systemd changes are made.

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
An occupied port is never taken from another application. Shared hosts can
delegate their existing HTTP-01 entrypoint as above; otherwise the explicit
conflict retains the old certificate. DNS-01 would require a separately reviewed
provider integration; DNS credentials are not accepted by this API.
Firewall/DNS must permit public HTTP-01 validation. The temporary-listener
mode owns no listener at rest; shared mode never owns one.
Expired certificates cannot be renewed through an untrusted/expired node HTTPS
connection: recover the certificate locally, retaining TLS verification.

New pairs are checked for matching key, exact hostname and current validity,
written as complete generation directories with read-only storage-group access,
fsynced, then committed by
an atomic `current.json` pointer. Keep current plus one preceding complete pair.
Web refreshes this pointer at most once per five seconds; existing connections
continue. Invalid or partial generations retain the last valid served pair;
expired certificates fail closed. Master observes the **actually served** pair,
not merely an issuer's successful response. No media restart is required.

## STUN and deterministic playback

All active paired downstream nodes are included after Master's own address,
ordered by stable node ID. Signed heartbeat `stun_port` supports shared hosts
with a custom UDP port; old nodes use 3478. An explicit zero indicates a failed
or stopped responder and is excluded until binding recovers. Revoked/pending/upstream relations
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
overlapping where supported; reports have a two-second deadline and navigation
abort so a stalled request cannot retain that lease. The fallback remains serial
per page. Hidden pages cancel probing and omit incomplete reports; visibility recovery
and back-forward cache restoration resume after the same cooldown. Navigation
cancels the peer and report. Diagnostics do not gate
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
