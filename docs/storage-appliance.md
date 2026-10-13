# Storage appliance (`only_stroge`)

This is the new storage-only product mode; the spelling `only_stroge` is the
deployment contract. It does not serve an independent site or Admin GUI.

## Resident components

Use `docker-compose.storage.yaml` alone, not as an overlay on business Compose.
The native Go HTTPS/file/control service and bounded Go certificate controller
remain resident. `secrets-init`, `media-init` and `certificate-init` run once
and exit. There is no Nginx, Redis,
MySQL, coturn, updater, Docker socket or version synchronization on storage.
SQLite is an embedded library for local identity, permissions, quotas and
durable file-operation journals; it is not a database container or a copy of
the Master's business database.

An Nginx-only appliance cannot implement the signed-capability, quota and
transaction-recovery protocol. The Go listener must remain available after
pairing for uploads, Range reads, heartbeats and policy changes. Idle work is
bounded; storage has no player, login, captcha, karaoke manager, business
security publisher or business-backup builder.

## Fresh installation

1. Extract the public operator bundle with `scripts/get-fc.sh`; see the
   [operator manual](operator-manual.md). No source checkout or host compilation
   environment is required. Explicit developer builds remain separate.
2. Copy `.env.storage.example` to `.env` and set the domain and endpoint.
3. Point the node domain at this host and allow public HTTP-01 on TCP 80.
   TLS_ENABLED=true automatically issues and persists its certificate; no
   certificate paths, external tools or manually prepared keys are required.
4. Run `./fc --role storage doctor`, then `./fc install storage`. The source-repo
   `scripts/deploy-storage.sh` delegates to the same client. Installation refuses
   existing state, verifies public images and pins digests before initialization.
   After HTTPS readiness, retrieve the one-use pairing package privately with
   `docker compose -f docker-compose.storage.yaml -f .fc-images.json exec -T web /app/frontiercloud storage-pair`.
   Import it on the Master within five minutes. Treat it as a temporary credential.
5. Master Admin sets storage enablement/capacity and backup enablement.
   Direct/Relay follows the signed deployment transport profile; changing
   transport requires an explicit quiescent redeployment and endpoint handover.

Direct Storage HTTPS is fixed at 443. Relay Storage uses a high communication
port, default 8443 (1024–65535), matching STORAGE_ENDPOINT. STORAGE_TRANSPORT
defaults to direct. The native bounded STUN responder uses UDP 3478 independently.
Go occupies public 80 only during bounded HTTP-01 validation and releases it
after success, failure or cancellation; Relay never opens public 443. A port
conflict is diagnosed and retried rather than stealing another application's
listener. TLS failure never opens plaintext business.
For a new unpaired node, startup also emits a package. If it expires, run
`docker compose -f docker-compose.storage.yaml exec -T web /app/frontiercloud storage-pair`.
Restarting a paired node preserves its identity and does not emit another
package. The mandatory [Compose certificate controller](storage-certificate-control.md)
publishes complete TLS generations for hot loading without restarting media.
Pairing begins only after actual HTTPS readiness, giving a fresh five-minute
credential rather than consuming its lifetime while waiting for issuance.

## Existing data: do not use fresh installation as migration

Deleting a Master relationship, regenerating node secrets or pairing a fresh
NodeID does **not** reattach existing media metadata. Master ownership refers
to stable node IDs and object IDs, not just disk paths. Preserve data roots,
SQLite state, secrets and the Master database together. Never use `down -v`,
`reset-identity` or direct SQL deletion as a migration shortcut.

Startup rejects silently changing a fixed identity's endpoint. The offline
`storage-endpoint` / `storage-rebind` commands provide an explicit endpoint
handover under closed maintenance gates, retaining IDs, signing keys, pairing
credentials, object IDs and capacity policy. The Master must verify a signed
identity challenge over certificate-verified HTTPS at the new endpoint before
rebinding its exact existing relationship. Both commands reject pending work,
identity/relationship races and write audit records in the same SQL transaction.
They never reopen maintenance automatically or regenerate identities.

This handover requires full offline backups of both endpoints, stopping all
writers and preserving the existing secrets/data mounts. It is not a fresh
pairing flow. A failed second step leaves the old relationship and data intact;
retry the exact handover or restore the offline snapshot while fenced. Do not
resume the Master until the storage is healthy and its endpoint/key proof passes.
Production use requires a validated release and an operator-reviewed mount plan.
For deliberately emptied nodes, revoke their empty relationships through Master
Admin before removing their projects; old revocation tombstones are retained.

## Cold backup

The Master produces a fenced, consistent business recovery artifact. Storage
receives bounded chunks, checks order, length and SHA-256, then atomically
publishes a complete file under `DATA_DIRECTORY/.cold-backups`. SQLite holds
small receiving markers and manifest metadata, not the completed backup bytes.
The newest two ready generations are retained. A failed receive never replaces
the previous ready generation; replay and checksum failures fail closed.

This artifact is **not** full disaster recovery: it excludes private identity
keys, node relationships and mutation journals, and does not include media.
Keep an independent complete offline backup before migration. For SQLite,
stop all writers and close connections before copying, or use SQLite's backup
API / `VACUUM INTO` for a live snapshot. Copying only the `.db` file while WAL
is active can lose committed data. For MySQL business deployments, use a
consistent logical export; never hot-copy its data directory. InnoDB
`mysqldump --single-transaction` requires avoiding concurrent schema changes.
Do not start a database container on storage merely to hold a backup file.

## Retired RN preproduction

The owner retired the RN preproduction Master and external CD on 2026-10-11.
Production Storage and unrelated applications remain. No live staging gate is
available until a new independent preproduction IP is provisioned. Do not infer
an available staging site or recreate its deleted business data. Production
Storage migration remains a separate operation with preserved identity/media.
See [first automatic TLS migration](automatic-tls-migration.md).
