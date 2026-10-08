# Storage appliance (`only_stroge`)

This is the new storage-only product mode; the spelling `only_stroge` is the
deployment contract. It does not serve an independent site or Admin GUI.

## Resident components

Use `docker-compose.storage.yaml` alone, not as an overlay on business Compose.
There is one resident container: the native Go HTTPS/file/control service.
`secrets-init` and `media-init` run once and exit. There is no Nginx, Redis,
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

1. Build a reviewed exact `main` revision from `wongyiuming/FrontierCloud-Gin`.
2. Copy `.env.storage.example` to `.env` and replace every placeholder.
3. Provide a valid certificate/key for `SERVER_NAME`, readable by UID 10001.
   Master clients verify the normal trust chain. A private CA must be trusted
   explicitly; disabling verification is prohibited.
4. Run `bash scripts/deploy-storage.sh`. This builds, waits for HTTPS readiness
   and prints a signed one-use pairing package. Import it on the Master within
   five minutes. Treat the package as a temporary credential, not a public log.
5. Master Admin sets Direct/Relay, storage enablement/capacity and backup
   enablement. They are not selected on the appliance.

The only published port defaults to 8443. `STORAGE_PORT` and the explicit port
in `STORAGE_ENDPOINT` must agree and must be in 1024–65535. HTTP/HTTPS host
ports 80/443 are prohibited for this mode. No HTTP redirect listener is added.
For a new unpaired node, startup also emits a package. If it expires, run
`docker compose -f docker-compose.storage.yaml exec -T web /app/frontiercloud storage-pair`.
Restarting a paired node preserves its identity and does not emit another
package. Restart after certificate rotation; the running listener does not
watch certificate files.

## Existing data: do not use fresh installation as migration

Deleting a Master relationship, regenerating node secrets or pairing a fresh
NodeID does **not** reattach existing media metadata. Master ownership refers
to stable node IDs and object IDs, not just disk paths. Preserve data roots,
SQLite state, secrets and the Master database together. Never use `down -v`,
`reset-identity` or direct SQL deletion as a migration shortcut.

Startup rejects silently changing a fixed identity's endpoint. The offline
`storage-endpoint` / `storage-rebind` commands provide an explicit high-port
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

## EVOXT dual-purpose host

Production storage uses high-port HTTPS and its own Compose project, data
directory and secrets volume. The preproduction Master at `ml.520mall.cc`
uses 80/443 and separate business Compose state. Never share SQLite files,
media roots, Redis, identity secrets or updater sockets between these two
instances. DNS/certificates must match each endpoint. Public staging tests
start only after the operator has safely freed 80/443; this change does not
stop or rebuild existing production services.
