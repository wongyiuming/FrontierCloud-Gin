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
For HTTPS installation, `fc` independently verifies the native controller's
configured hostname, serving certificate fingerprint and HTTPS readiness before
recording `ready`. Certificate rejection retains the `prepared` receipt and
initialized identity; resolve the certificate failure without reinitialization.

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

Bulk backup, archive verification, restoration and upgrade commands run until
completion or explicit operator cancellation; media size does not impose a
fixed fifteen-minute deadline. Ctrl-C or SIGTERM requests cancellation. Keep
the resulting fence and retained failure materials until their state is checked.
Successful archive creation removes its private deployment/MySQL dump scratch
only after the archive and its directory are durable. Failed capture retains
scratch for diagnosis; source data and prior recovery points are never cleanup
targets.

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
For a complete cluster on one local Engine, use the explicit
[coordinated recovery-set workflow](operator-recovery-sets.md). It freezes every
listed member together and requires the complete reciprocal cluster roster.
An extracted set cannot be activated or opened through a single-member command.
Cross-host coordination is outside that local entry point; independently captured
archives must not be described as one consistent cluster recovery point.
Never regenerate identity as a recovery substitute. Actual isolated SQLite/MySQL HTTP Range/identity/priority
verification is recorded in the development acceptance evidence.

## Approved upgrades

This development runtime uses database generation 7. Its additive migrations
preserve existing business data and record durable resource migration facts and
peer object bindings, plus bounded paged plan records. Older binaries reject newer
database generations. Recovery archives preserve their source generation;
restoration uses the matching source images. The operator supports the explicitly
implemented 6-to-7 upgrade in addition to same-generation upgrades. See the
[schema contract](../migrations/README.md) before selecting target images.

The development `fc upgrade plan`, `apply` and `open` commands now provide an
explicit target/review/NodeID workflow. `apply` preserves a verified consistent
recovery archive and prepares the target under the native maintenance fence;
`open` separately verifies the running target before allowing traffic. Follow
the [approved upgrade procedure](operator-upgrade.md) for exact commands and
generation compatibility limits. Normal `restart` refuses unfinished upgrade or
recovery receipts and coordinated-set markers. Private Compose acceptance is documented separately from
public release evidence.

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
persistent implementation now includes [plan/start](resource-migration-planning.md),
durable tasks, reservations, source drains and runner fences, transactional
whole-parent ownership cutover, source cleanup and
[independent safe retirement](node-safe-retirement.md). Both GUI and CLI call the
same authenticated Master services. This is development code; publication and
native fleet/browser acceptance remain separate gates recorded in the audit.
Master Local is rejected as a migration endpoint. Planning never reserves capacity.
Cancelling a task retains capacity until safe
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

This is a preflight report. Final apply requires typed source NodeID confirmation,
establishes a durable relationship write fence, joins in-flight native requests,
rechecks both SQL ledgers and the actual filesystem, and records durable
revocation receipts. Retained backups and unknown residual files block retirement;
this release provides no backup-purge or force-retire shortcut. A successful
business retirement never authorizes disk erasure. Native browser/fleet acceptance
is recorded separately from package tests.


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
report, including available partial observations on failure. Final apply uses
`fc node retire apply NODE_ID --confirm-node-id NODE_ID` with the same Master,
TLS and stdin credential options. An uncertain reply can be retried with the same
NodeID; a retained retirement fence must be resolved through that workflow.
See [safe retirement](node-safe-retirement.md) for the complete retry contract.


### Existing migration task controls

The dev Master Nodes module lists queue/attention items oldest first in pages
of 16; a separate history view includes terminal tasks. Checkpoint details separately
page through up to 16 objects (48 KiB encoded object-data budget), with aggregate
object/unit states, verified bytes and authoritative committed bytes. Target
publication is not counted as authoritative ownership commit. Historical
checkpoint views show their observation time. Up to four visible active tasks
refresh automatically, and explicit refresh remains available. The task view
shows queue position, waiting node, measured business rates, current object/byte
offset and copy speed. Automatic traffic waiting preserves its checkpoint and
reservation; manual pause is never automatically resumed. See
[migration scheduling](resource-migration-planning.md#heavy-task-scheduling-and-progress)
for the default thresholds and gateway observation behavior.

Task controls call the same authenticated Admin service: pause, resume, retry
and cancel. Each mutation confirms source/target NodeIDs and the displayed task
revision; a stale revision returns a conflict and requires refresh. The SQL
transaction fences current runners and retains reservations until managed
cleanup. Cancelling keeps committed units at the target and does not release
source draining. Releasing a task-owned drain and retiring a node remain distinct
actions; neither is performed by these controls.

The API is under `/api/v1/media/admin/nodes/migrations`: collection GET uses
`after_time`/`after_id`, task GET uses an object `after` cursor, and task
`/control` POST requires `action`, `revision`, `confirm_source_id` and
`confirm_target_id`, with the existing session/CSRF and HTTPS boundaries.
New task planning/start uses the separate
[migration-plans service](resource-migration-planning.md); callers cannot submit
fabricated disk proofs through either API.


### CLI migration task queries and controls

Use `fc node migrate status TASK_ID --master https://master.example
--credential-stdin --json` to retrieve the task revision, source/target NodeIDs,
committed bytes, stage summaries and one bounded object page. Supply
`--after LOGICAL_OBJECT_CURSOR` to retrieve the next object page. A successful
query does not mean the task completed or that the source can be retired.

Controls use `fc node migrate pause|resume|cancel|retry TASK_ID` with the same
Master/authentication options plus `--task-revision N`,
`--confirm-source-id SOURCE_NODE_ID` and `--confirm-target-id TARGET_NODE_ID`.
`--task-revision` refers to the task observation; the existing global `--revision`
continues to refer to a published software release. Refresh status after a
conflict or an uncertain reply before sending another control. The CLI never
automatically retries a mutation or substitutes current confirmations.

Exit 0 means the query or control was acknowledged; exit 2 means invalid input,
authentication/transport failure, conflicting state or an invalid response.
Control acknowledgment is not proof that cancellation cleanup finished.
Committed units keep target ownership; reservations remain until managed cleanup,
and draining remains until a separate explicit release. Human output quotes
paths/error codes; JSON output contains only typed bounded task/status fields.
Credential stdin, normal TLS verification, optional public CA trust, ephemeral
cookies and bounded logout follow the retirement client contract. The plan/start
workflow returns prompt asynchronous observations, then persists a task only
after the exact source/target and reviewed plan have been confirmed.


### Explicit task-owned drain release

After a task is completed or cancelled, the Nodes task card offers a separate
release action requiring typed source NodeID confirmation. The matching CLI is
`fc node migrate release-drain TASK_ID`, with the normal Master/authentication
options and `--task-revision`, `--confirm-source-id`, `--confirm-target-id`.
The dedicated `/nodes/migrations/TASK_ID/release-drain` Admin endpoint uses the
same HTTPS/session/CSRF boundaries, terminal task/version checks and authenticated
source receipt as the existing migration runner service. Offline, stale or
incomplete reconciliation fails; it never substitutes a direct SQL release.

Only this task's migration restriction is removed on source and Master.
Administrator maintenance and other owners' restrictions remain. Repeated
requests reconcile the same facts and do not repeat audit mutations. A lost
reply requires status/reconciliation before an explicit retry. Releasing a drain
neither moves committed resources back nor revokes the node, stops containers
or permits volume cleanup. Final retirement remains a separate, explicitly
confirmed operation with a fresh fenced check; see [safe retirement](node-safe-retirement.md).


The internal managed-content observation endpoint uses each native media or recording mount, authenticates the current upstream Master and hashes exact managed bytes in one bounded worker. Its size-aware deadline budgets one MiB/s plus one minute, with a five-minute minimum and 24-hour maximum, and binds the result to a process incarnation. Target verification/publication and cleanup/cancellation digest work allow the same size budget with a 30-minute minimum, excluding traffic waiting. Inventory cursors retain a separate five-minute idle lease: retirement renews still-live authenticated cursors while preserving the scanner and transcript; expired or closed observations cannot be revived. It does not freeze content, generate a migration plan, reserve space or authorize deletion/retirement. Operators should continue using the exposed node task/retire-check commands; there is no supported direct content-observation operator command. CLI and server retirement scans follow operator cancellation and caller deadlines rather than short control-request timeouts. The edge permits long responses only for the two authenticated retirement routes; ordinary requests retain their existing timeout.

Host operations report a nonzero result if releasing or syncing their owned operation lock fails. Completed archive/receipt state remains available for inspection; the error does not mean that data or a completed operation was rolled back. Inspect the recorded state and retained lock before another mutation. A replacement lock is never removed by an older operation's release callback.

Human and JSON node-command output failures return a nonzero result even when the remote action completed. Query the recorded task revision or retirement state before retrying; an undelivered report does not mean the action was rolled back.

Migration planning renews live inventory cursors without replacing their scanner or transcript. Final peer retirement scans use a separate, one-connection transport owned by caller cancellation, while ordinary control requests retain their short timeout. Deployment receipts bind both security-exempt and trusted-proxy CIDR sets after masking, sorting and deduplication; expanding trust requires explicit deployment review.


Retirement preflight now observes the data directory and the actual native media/recording mounts. Default subdirectories matching those mounts are scanned once; obsolete copies left in default directories after an external mount change are reported as unmanaged leftovers. The report shows per-scope logical bytes and filesystem total/free observations. Different scopes may share one filesystem: never add their free values to estimate target capacity. Writability is unverified until the approved migration admission performs its required checks. An older node without the three-scope observation protocol returns an incomplete check rather than retirement approval. The checks do not delete files or revoke the node.


Retirement reports distinguish verified retained native state from unmanaged leftovers. Recognized items include the exact built-in default lyric and idle coordination inodes; a recording lease additionally needs the local deleted-recording tombstone. Held, nonempty, unknown or changed items remain blockers. Retained items still count toward observed filesystem bytes and should remain with node history. This classification does not authorize deleting node identity, certificates, the database or the volume, and a completed preflight still requires the final fenced retirement operation.


Completed or cancelled migration task labels alone do not satisfy retire check. The server reconciles each peer's task/unit/object roster, role-specific journal outcome and expired grace, and reports live runner leases. A cancelled source can retain receiving history while its files remain authoritative and block retirement. A target's earlier published history can become deleted after a later managed deletion or reverse migration. These are historical facts, not permission to erase disks; mismatched or incomplete receipts require task reconciliation first.

## Retry prepared installation and interrupted restore opening

After a fresh installation has retained a `prepared` receipt (for example,
certificate readiness failed), run `fc --directory DIR install resume` after
repairing the reported readiness problem. This uses the recorded pins and
existing identity; it does not select latest, pull replacement images or repeat
initialization. Configuration drift and recovered deployments are rejected.

Restore preparation records the original source project before replacing its
receipt. Repeat the same preparation after an interrupted `preparing` phase;
the archived source identity/project remain authoritative. For an interrupted
`restore open`, repeat the original confirmed NodeID. Durable `opening` intent
allows recovery after the owned public marker was removed but before the ready
receipt was written. The retry reestablishes owned maintenance and verifies
runtime identity, schema and business facts before finishing. It preserves
administrator-owned maintenance and independent native fences.

The fresh-install receipt records `initializing` before the first Compose startup.
`install resume` can replay the recorded idempotent initializers only in this
fresh-install phase, using the original fixed pins and configuration. It checks
and preserves an already observable identity. Once initialization reaches
`prepared`, resume starts only resident consumers and verifies readiness;
recovered deployments never use fresh initializers.

Restore activation first records `creating_manual` intent. Its generated staged
marker inode is retained through activation/opening, so a retry can finish marker
publication and distinguish it from an administrator-created marker with the
same text. Successful ready publication removes only that generated staging file.

The initializing receipt is durable before its image lock. If interrupted between
those publications, resume reconstructs only that receipt's original pinned
lock after checking the unchanged bare configuration. Complete effective
volume/network/config/secret definitions are bound to the selection hash;
volume driver options cannot silently redirect restored or initializing state.
Verified backups report `cleanup_warning` and `retained_scratch` when removing
only generated scratch fails. This does not invalidate the durable archive;
upgrade journals retain its checksum and cleanup warning while staying resumable.

If `restore apply --deployment` stops after publishing material but before
preparation completes, use the separate non-extracting preparation command:

```sh
./fc restore prepare --file /private/deployment.tar --sha256 ARCHIVE_SHA256 \
  --target /existing/verified-material --confirm-node-id SOURCE_NODE_ID \
  --project new-empty-project
```

It verifies original archive and material, then resumes only matching preparation
intent. It never runs initializers or overwrites a nonempty extraction target.
Administrator maintenance blocks activation before consumers start; after separate
administrator clearance, repeat the same activation rather than claiming that
marker's ownership. Exclusive JSON intent publication is synced and atomic,
with no-overwrite final-name semantics.

`restore prepare` rejects archives with missing related-node recovery material,
even if someone extracted the tar externally. Those archives require the verified
coordinated recovery-set path. Activation/opening enforce the same boundary.
Recovery commands return a nonzero status if their result JSON cannot be written;
completed side effects and recovery artifacts remain available for inspection.

Restore opening records a generated staging cleanup warning before cleanup.
Successful ready-state retries remove only the recorded private ownership stage,
preserving administrator public maintenance. A pending or unverified restore-stage
cleanup blocks another operator backup, preventing that staging file from becoming
unowned material in a later recovery archive.
