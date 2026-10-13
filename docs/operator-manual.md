# FrontierCloud operator manual

## First installation

The public Web image contains an operator bundle: `fc`, Compose definitions,
environment examples and this manual. Download the small
[`get-fc.sh`](https://raw.githubusercontent.com/wongyiuming/FrontierCloud-Gin/main/scripts/get-fc.sh)
entry file and run `sh get-fc.sh frontiercloud` on a Linux Docker host. It pulls
one published main Web image and copies its bundle without starting a service.
No full source checkout, Git, Go, Node or Python is required. The destination
must not exist. An old release without this bundle fails explicitly; this
feature becomes publicly available only after reviewed main publication.

For Master HTTPS, create `frontiercloud/.env` with:

```dotenv
TLS_ENABLED=true
SERVER_NAME=media.example.com
```

Run from that directory:

```sh
./fc doctor
./fc install master
```

For Direct Storage, copy `.env.storage.example` to `.env`, set `SERVER_NAME`
and `STORAGE_ENDPOINT=https://your-storage-domain`, then use:

```sh
./fc --role storage doctor
./fc install storage
```

Relay additionally requires `STORAGE_TRANSPORT=relay`, `STORAGE_PORT=8443` and
an HTTPS endpoint with that port. Master must reach that endpoint. HTTP-01 still
requires public TCP 80 during certificate issuance. Direct uses public 443.
The legacy `only_stroge` role and environment names remain compatible.

Use `./fc --database mysql install master` only with the reviewed MySQL overlay
and an appropriate `.env`; MySQL is the only database alternative. Storage uses
embedded SQLite. Database selection does not migrate existing data.

Installation refuses existing containers, declared volumes, nonempty writable
data mounts, identity/state files and prior receipts. Use a separate takeover or
recovery procedure for existing instances; never erase a volume to pass this
guard. `doctor` is read-only: it does not create directories, touch databases,
pull images or bind ports. Public inbound reachability, write permissions and
database generations that cannot be proved read-only are marked **unverified**.

One installation uses one reviewed release revision for every FrontierCloud
component. Registry manifest/config hashes, platform, source, component and
schema labels are checked before initialization. Infrastructure images are
also resolved to digests. `.fc-images.json` and `.fc-deployment.json` preserve
the images, reviewed source, role, project, mount/database binding and config
version. Keep both with the deployment. Failed pulls never trigger compilation.

## Daily checks

```sh
./fc status
./fc --json diagnose
./fc logs
./fc restart
```

`status`, `logs` and `diagnose` are read-only. They check selection/image locks,
containers, application/database readiness and the automatic certificate
controller, database generation, maintenance and authenticated node health facts.
A container being Running is not sufficient. Playback acceptance remains an
explicit unverified check until probed. Stable
exit codes: 0 all checks passed; 2 blocked; 3 degraded/warnings/unverified.
`diagnose` emits allowlisted facts, never environment dumps, raw container
logs, credentials, pairing packages or signed URLs. `logs` emits only selected
structured event facts; arbitrary messages, errors and URLs are omitted.
`restart` modifies running
services, checks the durable binding, uses only pinned images, never pulls
latest, and never deletes volumes.

After Storage HTTPS is ready, retrieve the one-use pairing package privately:

```sh
docker compose -f docker-compose.storage.yaml -f .fc-images.json exec -T web /app/frontiercloud storage-pair
```

Import it in Master Admin within five minutes. Do not attach it to diagnostics.
Restarting a paired node preserves its identity. Master Admin separately enables
Storage/Backup and allocates logical capacity.

## Backup and restore

Built-in business backups are database/business recovery artifacts. They exclude
media bytes, node private keys, media premaster, certificate state and complete
node journals; they are not full disaster recovery points. Preserve those
materials separately. SQLite WAL databases cannot be backed up by copying only
the `.db`; use an approved snapshot or a genuinely stopped-writer boundary.
MySQL requires a consistent logical export, never a hot data-directory copy.
Cross-database/file recovery requires a defined frozen writer boundary for all
nodes. Backup and migration must not overlap ownership commits.

The existing `verify-backup` command inspects built-in business artifacts only.
The operator's deployment archive preserves local data, journals, identities,
runtime secrets/premaster, certificate state, Redis state and locked deployment
configuration. MySQL uses a bounded `mysqldump --single-transaction --quick`
logical export instead of copying its hot data volume. Archives are uncompressed,
streamed with bounded buffers, mode 0600, and contain private recovery material.
Store them in protected backup storage. The machine-readable manifest records
scope, source NodeID, revision, generation, file/directory counts and sizes,
actual SHA-256 values, key references, state classes and missing related-node
recovery material. A local deployment archive does not silently include other
nodes' media and identity; missing node state blocks applying it as a recovery set.

```sh
./fc backup create --freeze --output /protected-backups/deployment.tar
./fc backup verify --file /protected-backups/deployment.tar --sha256 <trusted-archive-sha256>
./fc restore check --file /protected-backups/deployment.tar --sha256 <trusted-archive-sha256> --target /new/recovery-material
./fc restore apply --file /protected-backups/deployment.tar --sha256 <trusted-archive-sha256> --target /new/recovery-material --confirm-node-id <exact-source-node-id>
```

`--freeze` explicitly enters native maintenance and stops this deployment's
filesystem writers. It leaves the deployment stopped/fenced after capture;
backup does not automatically reopen traffic. Without it, writers must already
be stopped and native maintenance enabled. The native lifecycle lease covers
the entire database/files capture and prevents conflicting native migrations,
initializers and resume operations. Pending resource transactions block capture.
MySQL additionally requires `--confirm-external-writers-stopped`; native leases
do not stop unknown external database writers. Offline volume inspection requires
authorized local Unix-socket Docker and filesystem access; remote engines are
refused. Host operation locks prevent simultaneous install/restart/backup actions.

`restore check` only reads, and never creates its target. `restore apply` validates
the expected archive checksum and exact source NodeID, refuses any existing
target, restores original owners/permissions into private staging and publishes
only after actual byte verification and synchronization. It preserves offline
flags, identities and key bytes. It restores **recovery material**, does not start
an instance, and reports `restore_ready=false` / `restored_business_verified=false`.
Use `--deployment --project <new-empty-project>` with `restore apply` to prepare
a relocated Compose project using the recorded images and verified state classes.
It refuses target containers/volumes and leaves the original recovery identity
fenced. The source must no longer run this identity; local running source Web
containers block activation even with an operator confirmation.

```sh
./fc --directory /new/recovery-material/deployment restore activate --confirm-node-id <source-node-id> --confirm-source-offline
./fc --directory /new/recovery-material/deployment restore open --confirm-node-id <source-node-id>
```

Activation starts restored consumers without fresh identity/media initializers,
imports MySQL's logical export into a new private target, verifies original
identity/database generation, resumes only the native fence, and starts services
behind manual maintenance. It checks readiness and actual managed file reads,
including ciphertext descriptor lengths. Only then does its persistent journal
report business verification. `restore open` is separate, repeats verification,
and removes only maintenance owned by this recovery. Preexisting administrator
maintenance is retained. A failed activation stops Web, keeps public maintenance
closed and attempts to restore the native fence; recovery material is retained.
Coordinated multi-node recovery sets remain in progress. Never regenerate identity
as a recovery substitute. Actual isolated SQLite/MySQL HTTP Range/identity/priority
verification is recorded in the development acceptance evidence.

## Approved upgrades

This development runtime uses database generation 5. Its additive migration
preserves existing business data and records durable resource migration facts;
execution integration is still in progress. Generation-4 binaries reject a
generation-5 database. Restore archives require their matching runtime generation;
an old archive must first use its matching operator bundle. See the
[schema contract](../migrations/README.md) before selecting target images.

Keep the current receipt/digests and an independently verified consistent
recovery point. Explicitly select the reviewed published target main SHA and
check schema compatibility before changing any service. Code rollback does not
reverse DDL. Cross-generation rollback requires the matching backup and images,
with an explicit disposition of writes since that backup. Preserve a failed
installation's data/diagnostics and maintenance fence; do not automatically
reopen traffic. See [operator releases](https://github.com/wongyiuming/FrontierCloud-Gin/blob/main/docs/master-self-release.md).

## Resource migration and node retirement

Resource migration and relation revocation are distinct business operations.
Neither authorizes stopping hosts, deleting volumes or erasing disks. The
persistent resource migration/retirement implementation and acceptance are
ongoing; this manual does not claim that a released node can yet be safely
migrated through `fc`. The current dev repository has durable tasks, reservations,
source drains and runner fences, with transactional whole-parent ownership
cutover. The isolated authenticated router tests cover bounded byte copying, media and
recording publication, source cleanup, private anchor retirement, final task
receipts and explicit owned-drain release. Authenticated physical inventory,
whole-task cancellation, independent retirement, GUI/CLI and actual fleet/browser
acceptance remain incomplete; production migration capability is not advertised.
Planning never reserves capacity. Cancelling a task retains capacity until safe
staging cleanup, and does not move committed data back or release another drain.
No host/container/volume deletion is part of this business operation.
Existing owned storage must follow the separate
[storage handover](https://github.com/wongyiuming/FrontierCloud-Gin/blob/main/docs/storage-appliance.md) contract.

## Failure handling

Fix a bad domain/DNS record before requesting issuance again; local outbound
connectivity does not prove that public 80/443 reaches this host. Identify a port
owner before starting, and never modify project-global firewall/SELinux/IPv6
configuration through this tool. Missing images, access denial, network errors,
unsupported architectures and digest/provenance mismatch stop deployment.
Do not build as an automatic fallback. Explicit immutable-source developer
compilation remains a separate workflow. Changing project, mounts, role or
database after installation is refused by the receipt binding; restore the
recorded selection or perform a verified takeover/migration.


### Development retirement observation

On the current dev implementation, an active downstream Storage member card in
Master's existing Nodes module offers a read-only retirement check. It requires the
established Admin session, HTTPS and CSRF protection, and calls
`POST /api/v1/media/admin/nodes/<relationship-id>/retire/check` with the exact
`member_id`. Only one observation runs per process. The page displays bounded
blocker samples, missing expected files, retained backups and suggested repairs.
Historical results retain their timestamp through page refresh and must be rerun.
An incomplete/offline observation never becomes a successful check.

This is a preflight report, not final retirement approval. It does not revoke the
relationship, remove files or stop containers. Final fenced admission, verified
backup replacement/retention and full transaction/reference reconciliation are
still under implementation; the development UI must not be used as evidence that
a disk can be erased. Native browser/fleet acceptance is still outstanding.


### CLI retirement preflight

The dev operator client uses the same Admin API and retirement service as the
node card. Run `fc node retire check NODE_ID --master https://master.example
--credential-stdin --json`, piping an existing Admin or temporary credential into
standard input. Do not place the credential in an argument, URL or environment
variable. Input accepts a single token with an optional trailing newline and ends
at EOF. The client creates an in-memory session, uses the server's CSRF cookie
name, verifies one active downstream relationship for the exact NodeID, and
attempts logout on exit; sessions are never saved to disk. Interrupted or failed
logout leaves only the existing server session expiry policy.

Standard TLS verification remains enabled. An internal CA may be supplied using
`--ca-file /path/to/public-ca.pem`; this is a public trust certificate, not a node
identity or private key. Credential-bearing URLs, HTTP origins, URL paths/queries,
redirects and insecure TLS bypass are rejected. No SQL, SSH or Docker operation
is used for this business command.

Exit 0 means the observation completed with no reported blockers; exit 1 means
it completed with blockers; exit 2 means invalid input, transport/authentication
failure or incomplete observation. Every report remains `preflight_only`: exit 0
never grants permission to revoke a node or erase its disk. Human output quotes
sample paths to avoid terminal control sequences; `--json` emits the bounded typed
report, including available partial observations on failure. `retire apply` is
not yet implemented.
