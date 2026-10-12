# Operations and resource migration implementation checkpoint

This is an **in-progress** implementation ledger, not final acceptance or a
published release. The requested goal remains active. Nothing was merged,
published, deployed to production or migrated on real nodes.

## Source and development scope

- Work began on clean `dev` at `a6f8e3a5ec960578bc0d08b070afbddc2370243f`.
- No branch outside dev/main was created; main was not modified.
- Delivery/backup foundations were committed on dev as
  `a2cc19d7de8c61ab09ed1747916cc0c22b03db8e`. The next checkpoint adds restored
  deployment activation and its SQLite/MySQL acceptance evidence.
- Restored deployment activation was committed as `181c92a` on dev. The following
  checkpoint adds generation-5 persistence foundations; no migration executor,
  retirement API or GUI is enabled merely by the schema change.
- The owner supplied access to the development host `192.168.6.201`. Its existing
  checkout and unrelated services were retained. Login material is not in source,
  documents, artifacts or ordinary logs.
- Task-owned source/cache/test workspace:
  `/home/wyium/fc-operations-20261012-01a13082`. Local bridge tooling lives outside
  the repository under the Codex temporary directory and reads its password from
  stdin; it contains no stored credential.
- Docker Engine 29.1.3, Compose 2.40.3, Linux/amd64. Go 1.26.8 ran in a disposable
  toolchain container: two CPUs, 3 GiB memory/no swap, GOMAXPROCS=2, managed Go heap
  target 512 MiB, GOGC=25. Go is not installed on the ordinary operator host.

## Implemented so far

Storage ordinary deployment now uses the public Web image without a Compose
build definition. `scripts/deploy-storage.sh` delegates to the guarded `fc`
installer; it never compiles after a pull failure. Developer immutable-source
archives were updated to contain the bundle assets, preserving their separate
explicit workflow.

The Web runtime images contain an extractable operator bundle with a compiled
`fc`, canonical Compose/environment files and the narrow operator manual.
`get-fc.sh` extracts it from one public runtime digest without starting a service.
Normal publication compiles this client in the existing credential-free compile
job; no new permission-bearing job or resident controller was added. Public
availability still requires reviewed main publication and was **not** exercised.

`fc install` verifies reviewed main/source-CI evidence and runtime manifest/config
hashes, source/component/runtime/schema/platform labels; all selected FrontierCloud
components use one revision. Every service, including infrastructure, is fixed
by digest before initialization. Durable receipts bind role, database, mounts,
project and configuration version. Installation refuses existing data, identities,
volumes, receipts and related stopped Compose containers. Changing project/mount
selection cannot hide default data in the same bundle. Host operation locks
serialize installation, restart and backup; interrupted locks need review.

Read-only doctor/status/diagnose, pinned restart and allowlisted logs exist.
Doctor does not initialize data, write probes, create directories/locks, bind
ports, pull or run images. DNS/outbound checks do not prove public ingress.
Status includes database generation, native/manual maintenance, container/app/
certificate readiness and node health facts. Arbitrary peer summaries, errors,
URLs and credential-bearing log messages are excluded. The native
`operator-status` command opens only an existing store and identity.

Deployment recovery archives contain rooted file/directory inventories, original
UID/GID/modes, keys by reference, revision/schema/config version, missing state,
byte counts and actual content hashes. I/O uses bounded buffers and no compression.
Capture holds the existing native offline lifecycle lease throughout, stops local
filesystem writers and refuses unfinished resource transactions. SQLite captures
its stopped data/WAL state; MySQL code uses a bounded consistent logical export,
never a hot MySQL-directory copy. External MySQL writer confirmation is required.
Related-node recovery material is not silently included.

`backup verify` and `restore check` validate actual archive bytes. Check creates
no target. Apply requires the trusted checksum and exact source NodeID, rejects
every existing target, preserves identities/key bytes/offline flags, and publishes
only synchronized verified recovery material. Material-only apply explicitly
returns restore/business readiness as false. Optional deployment preparation
relocates classified state into a new empty Compose namespace with recorded
images. Separate activation imports MySQL when needed, verifies the original
identity/schema and actual managed-file reads, and starts consumers behind manual
maintenance without fresh identity/media initializers. Separate opening repeats
verification and removes only maintenance owned by this recovery. Failure keeps
public maintenance closed and stops Web; material and the persistent journal are
retained. Coordinated cluster restoration remains incomplete.

Generation 5 adds nine durable resource migration tables for tasks, ownership
units, objects/checkpoints, capacity reservations, draining causes, scope locks,
runner epochs, Storage journals and read leases. Generation-4 statements are
preserved exactly in both new snapshots, with a checked canonical DDL checksum.
SQLite applies the migration atomically; MySQL replays additive table creation
before the atomic journal/marker commit. Runtime/image/release generation labels
and current acceptance vectors are aligned; historical vectors remain unchanged.
Both maintenance inspection and journal-free business export refuse pending
migration facts. Database tables are foundations, not implemented byte migration.

The next repository checkpoint adds read-only Master catalogs over all owned
placements (including hidden/encrypted objects) and ready recordings, immediate
parent units, recording locator mapping, identity/content fingerprints, declared
backup state and logical/physical capacity checks. Start atomically rechecks the
catalog, requires complete disk-proof inputs, records tasks/units/objects/scopes,
reserves target capacity and adds an owned source drain. Identical submissions
reuse the task; stale/expired/conflicting plans do not change quota. Persistent
runner epochs fence pause/resume/retry/cancel and lease renewal. Cancel preserves
reservations and source authority until actual cleanup is implemented. Drain
release requires exact source identity and a terminal, fully cleaned task.

Ordinary media/recording allocators skip drained members even after heartbeats.
Conflicting media mutations, recording deletion/account cascades, legacy revoke
and identity reset respect migration facts; unrelated allocation/local mutation
and safe direct preference updates continue. This is repository groundwork:
authenticated peer inventory, streaming, publication/cutover/cleanup, service
workers and GUI/CLI endpoints remain incomplete. The new capability is deliberately
not advertised by the runtime yet. Current in-memory catalog snapshots explicitly
refuse more than 10,000 objects/16 MiB; paginated planning is still required.

## Executed verification and limits

- Native unit tests of image provenance/hashes/error classification, install
  guards, selection locks, read-only doctor, sanitized logs, archive corruption/
  identity/target protection, and native read-only status passed.
- A real SQLite database backup/material restore/business-stream test preserved
  identity, logical media ID, priority and actual bytes. No mock database or
  mock byte transport was used in that test.
- `go test -p=2 ./internal/updater -run Source` passed, covering immutable-source
  archive changes. Full updater/fleet acceptance was not implied.
- `tests/operator_compose_acceptance.py` rendered actual Master SQLite/MySQL,
  Direct and Relay profiles and proved doctor did not change files/create data.
  Wrong domains blocked; ingress and write permission stayed unverified.
  See [doctor evidence](2026-10-12-doctor-evidence.json).
- `tests/operator_recovery_acceptance.py` used actual canonical Compose/private
  runtime images, `fc backup create --freeze`, check/apply, and a separately
  activated isolated SQLite/HTTP instance. It verified unchanged NodeID/media ID,
  directory priority and HTTP Range bytes. Web had one CPU/512 MiB/no swap and
  recovered below 20% CPU for five samples (0.30, 0.31, 0.26, 0.33, 0.26 percent).
  See [recovery evidence](2026-10-12-recovery-evidence.json).
- Private fixture images deliberately use synthetic revision zero, **not** a
  public source/release proof. Their actual image IDs are in the evidence. No
  assertion of ordinary released-image/HTTPS installation is made.
- Subsequent actual canonical Compose acceptance exercised `restore apply
  --deployment`, `restore activate` and `restore open` for both SQLite and MySQL,
  including actual logical MySQL export/import. Original identity, logical media
  ID, directory priority and HTTP Range bytes were preserved. Read-only checking
  and the offline fence were asserted before activation; public maintenance
  remained closed until explicit opening. See
  [SQLite activation](2026-10-12-recovery-activation-sqlite.json) and
  [MySQL activation](2026-10-12-recovery-activation-mysql.json).
  Web ran with one CPU/512 MiB/no swap. Five post-business CPU samples were
  SQLite 0.29/0.30/0.28/0.37/0.38% and MySQL 0.29/0.23/0.38/0.41/0.34%.
  These tests used the above commit plus checkpoint changes and private images;
  they are not released-image or multi-node restoration proof.
- Activation fixture failures exposed archived environment project selection,
  manual-maintenance file ownership and directory metadata being sampled as file
  media. Explicit recovered project selection, inherited ownership and file-kind
  sampling corrected them. Failed private material/volumes were retained and
  failed attempts were not counted as passes. Only task-owned containers were
  stopped/removed; unrelated host services and configuration were preserved.
- After these changes, `go test -p=2 -race ./internal/operator ./cmd/fc
  ./cmd/frontiercloud`, the store recovery-sampling regression test and the
  unchanged-budget local source CI suite passed. Real MySQL verification is the
  Compose acceptance above, not an inferred result of the SQLite unit test.
- Earlier fixture attempts failed because its host-loopback publication had
  been passed into Nginx's container listener setting, HTTP Admin traffic was
  incorrectly sent through a TLS-only edge boundary, a catalog session parameter
  was missing, and test-generated receipt JSON did not match Go struct-field
  serialization. Those failures were corrected without relaxing product guards.
  Their private material/volumes were retained; they are not counted as passes.
- Local `scripts/test-ci-source.sh` passed using the existing Git Bash/Node and a
  Python3 function pointing to the installed Python. The Python suite discovered
  201 tests, passed, and skipped two optional fixture classes. No CI budget was
  raised.
- Development-host `go test -p=2 -race ./internal/operator ./internal/recovery
  ./internal/release ./cmd/fc ./cmd/frontiercloud` passed. These are native unit/
  race checks with isolated SQLite where applicable; external MySQL/fleet/browser
  gates were not configured by this command. The updater Source subset also passed.

- `scripts/test-resource-schema.sh` passed on the isolated development host with
  real SQLite and MySQL 8.4.11, race checking, original generation-4 media/priority
  preservation, injected migration-journal failure, SQLite DDL rollback, replay
  of independently committed MySQL DDL, idempotency and future-generation refusal.
  It also proved real MySQL maintenance/business-backup guards retain pending
  migration records and emit no business snapshot. SQLite guards passed their
  race test. MySQL ran at one CPU/768 MiB/no swap and Go at the compiler budget
  above. New test databases and ephemeral secrets were isolated; successful
  fixture containers/networks/secrets were cleaned. Captured output:
  [schema acceptance](2026-10-12-resource-schema5-acceptance.txt).
- Development-host `go test -p=2 ./...` passed after generation alignment.
  The immutable bootstrap fixture was updated for the operator bundle assets
  required by the earlier archive change. Windows working-copy shell/Go endings
  were normalized according to the existing `eol=lf` attributes before Linux
  validation. Local source CI passed again with the same 201 Python tests and
  two optional fixture skips. This is not full external MySQL/browser/fleet
  acceptance. The prior recovery HTTP evidence is generation 4; generation-5
  recovery and migration end-to-end acceptance remains required.

- Repository transaction/race tests passed on actual SQLite and MySQL 8.4.11.
  They covered 16 repeated starts, one reservation, complete parent grouping,
  hidden/encrypted metadata, recording/nested inventories and locator mapping,
  stale/expired plans, unsupported targets, split ownership, concurrent target
  capacity, drain persistence across heartbeat, mutation/revoke fences and runner
  epoch replacement after pause. Reconstructed repositories read the durable task.
  These fixtures supply synthetic peer/disk facts and capacity; no actual byte
  copying or process/fleet restart is claimed. Captured MySQL output:
  [task transactions](2026-10-12-resource-task-transactions.txt).
- `go test -p=2 ./...` and local source CI passed during this checkpoint; expanded
  SQLite/MySQL repository tests also passed with race checking. Source CI retains
  201 Python tests/two optional skips and the original three-minute budget.
  Full external fleet/browser gates remain outstanding.

## Cutover repository checkpoint

The subsequent cutover repository checkpoint persists target checksum/length
verification and per-object publication receipts. Whole-parent publication requires
every object to be verified; physical publication alone changes no Master owner.
A bounded row stream rechecks all unit members/source versions/descriptors, then
one batch update changes owners in the same transaction as source/target
used/reserved counters, task progress, unit state and audit. Identity bindings and
runner epochs are rechecked; no network/file I/O runs inside this transaction.
Committed units retain source-cleanup dependencies and scope locks. The grace
timestamp is only a minimum delay, not proof that active reads/capabilities drained.
Cancellation preserves committed target authority.

Actual SQLite race tests and actual MySQL transaction/race tests injected a
cutover journal failure after ownership updates began and proved rollback of
ownership/quota/progress. They also covered incomplete publication, wrong SHA,
changed source, paused worker, idempotent successful commit, cache invalidation,
recording ID/title/lyrics/user-quota preservation and cleanup-pending retirement
blocking. These remain repository fixtures with synthetic publication/disk
receipts, not real byte-copy or authenticated distributed publication acceptance.
See [unit cutover output](2026-10-12-resource-unit-cutover.txt). Full Go tests and
unchanged-budget local source CI passed for this checkpoint.

## Private byte staging checkpoint

`internal/migrationdata` stages actual opaque bytes in task-isolated hidden files
with 256 KiB chunks, private fsync/rename journals and per-blob OS leases. The
binding fixes Master/source/target/object IDs, source version, byte count, full
SHA and optional ciphertext descriptor. Restart checks the actual persisted
prefix; crash tails and interrupted private temporary journals are reconciled
without adopting bytes by length alone. Duplicate chunks compare disk bytes.
Full-file disk verification is a separate local step, so a short final-chunk
control timeout cannot repeatedly restart a large full scan. Publication readers
rehash disk and require verified state. Serialized hash internals stay private.
An epoch admission callback runs under the lease and after full verification;
journaled abort removes only that task's private stage, not business files, and
does not refund quota or delete source data.

Actual local byte/race tests passed, including 64 MiB staging, descriptor binding,
disk corruption, restart reconstruction, crash tails/initial journal interruption,
concurrent duplicate chunks, cancellation, epoch rejection, wrong recipients,
path traversal and bounded private abort. A compiled race test binary passed in
a one-CPU/512 MiB/no-swap container with GOMAXPROCS=1 and a 128 MiB Go heap target.
Peak sampled additional Go heap during the 64 MiB append loop was 1,153,376 bytes;
this is heap sampling, not whole-node RSS or authenticated network acceptance.
See [byte evidence](2026-10-12-byte-staging.txt). Compilation used the prior
two-CPU/3 GiB toolchain budget. Full Go tests and unchanged-budget source CI passed.

At this checkpoint the library was not connected to node endpoints. The later
authenticated byte checkpoint below connects private staging and verification;
ordinary media/recording publication, source cleanup and real distributed
acceptance remain required.
Opaque ciphertext bytes/descriptors were tested; valid AES playback was not
implied by that fixture.

## Peer registration checkpoint

Followers now persist resource-only migration headers and normalized object
bindings under their active upstream Master. Registration checks local/remote
identities, relationship IDs, plan fingerprint, expected roster/bytes, source or
target role, and a bounded monotonic runner epoch/expiry. Source registration
adds an owned drain and refuses pending writers. Target registration reserves
capacity once; object registration locks parents, refuses conflicting existing
media/ordinary reservations and binds source versions/disk proofs. Incomplete
rosters, stale epochs, paused commands, wrong operations/roles and unverified
publication are rejected. Native upload/delete/rename/recording/account paths
respect these peer scopes; heartbeat configuration does not erase drains.

Small register/object/fence endpoints are integrated into existing node HTTP
surfaces, using HTTPS, raw-body HMAC, durable nonce protection and active-Follower
authorization. No new secret, Docker authority, business Master database copy or
resident control plane was introduced. The full migration capability is still
unadvertised; data transport/publication/cleanup handlers are not complete.

Actual SQLite race and actual MySQL repository/race checks passed for foreign
Master rejection, full-roster admission, capacity/refund boundaries, duplicate
registration, source-read/target-write roles, pause/resume epoch fencing, cancel
and legacy writer protection. See [peer transaction output](2026-10-12-peer-registration.txt).
A Gin routing/raw-body HMAC test with actual pairing credentials proved unsigned
requests return 401, a paired key cannot declare a different Master (409), and
legal duplicate registration charges capacity once. Its transport is a fixture,
not a real TLS socket/fleet acceptance claim. Full Go tests and unchanged source
CI also passed; the source suite still has 201 Python tests/two optional skips.

## Authenticated byte checkpoint

Followers now expose bounded read/begin/status/append/verify/abort actions under
the existing HTTPS, raw-body HMAC, durable nonce and active upstream checks.
Every action binds the persisted task, runner epoch, source/target identities,
object identity, version, size and expected full SHA. Source reads use existing
managed objects; target writes only task-private staging. Media and recording
roots have adapters, with recording relationship-path mapping retained.

Data requests admit at most two concurrent handlers per follower, chunks are
limited to 256 KiB, and a shared pacer limits admitted raw read/write bytes to
8 MiB/s. JSON/base64 wire overhead is additional. Control and heartbeat routes
do not share these data slots. One joined local worker verifies actual full
disk contents outside HTTP timeouts and SQL/global mutation locks; only its
successful result can persist a peer object's verified state. Querying a
checkpoint does not prove unchanged disk contents or switch business authority.

An actual SQLite/Gin pairing/HMAC fixture uploaded 524,307 bytes through the
ordinary Direct storage upload path, read them in three chunks through Master,
and appended/verifiably persisted them at a Relay target. Duplicate chunks,
wrong source versions, oversized reads, unsigned requests and paused writes
were checked. Target business used bytes remained zero, its reservation remained
charged, its ordinary object/path stayed absent and Master retained source
ownership. See [byte relay output](2026-10-12-migration-relay-bytes.txt).
The transport directly dispatches routers; this is not real TLS/socket or
five-node acceptance. Recording transfer and valid encrypted playback are not
claimed by this fixture.

Actual SQLite/MySQL transaction tests also rejected a false verification SHA
and persisted the matching local proof before admitting publication. See
[peer data transaction output](2026-10-12-peer-data-transactions.txt).
Full Go tests passed; unchanged-budget source CI passed with 201 Python tests
and two optional skips. The full migration capability remains unadvertised.
Managed publication, Master worker orchestration, source cleanup, cancel
capacity reconciliation and distributed restart/fault acceptance remain open.

## Media publication checkpoint

An authenticated publish action queues a local job rather than scanning a large
file inside an HTTP request. It rehashes the private disk material while holding
the object's lease, persists a publishing intent, then acquires the existing
media volume writer coordinator for the short link/SQL phase. The destination
is a hard link to the verified private inode; a different existing inode is
refused even when its name/size match. Replay syncs the destination directory
again. The private anchor persists across failed SQL and process restart, so
publication needs neither another file-sized copy nor another reservation.
Publishing/published material cannot use the private abort path.

The follower transaction registers the original physical ID, validates the
encryption descriptor without receiving file keys, consumes exactly its owned
migration reservation and records published state/audit together. Its used
counter describes local resident storage; Master business authority and Master
capacity cutover are separate. Master continues to resolve the source until
the complete-parent unit transaction commits. Partial publication does not
authorize a node's retirement or source removal.

Ordinary filesystem discovery now locks the node identity before object rows
and refuses assigning a new media ID within a migration parent scope. This
covers the crash gap after the filesystem link but before publication SQL,
including MySQL current-read ordering against scope registration. Existing
registered IDs remain readable; unrelated parents can still register objects.

Race tests injected a database-unavailable error after linking, recreated the
receiver, safely replayed publication and rejected changed on-disk contents.
The authenticated actual-byte fixture published twice without duplicate quota
charge and read all 524,307 bytes through the ordinary target media capability
route while Master ownership still referenced the source. SQLite/MySQL trigger
faults after object/capacity updates verify transaction rollback and retry, and
ordinary discovery cannot invent a replacement ID during that failure window.
See [publication race output](2026-10-12-media-publication.txt),
[actual MySQL output](2026-10-12-media-publication-mysql.txt) and
[full Go output](2026-10-12-media-publication-go.txt). The unchanged source CI
also passed with 201 Python tests and two optional skips.
This is router-transport evidence, not native-process/TLS fleet acceptance.
Recording publication, valid encrypted playback, automatic durable orchestration,
source/anchor cleanup and cancellation reconciliation remain incomplete.

## Immutable peer binding checkpoint

Schema generation 6 adds one resource-only peer binding table, with bounded
object JSON and a SHA-256, atomically written with follower object registration.
The previously normalized journal still owns paths, versions, byte proofs and
phases; admission now checks the persisted full object description against
those facts. Changed retry descriptions, missing bindings and descriptor
substitution are refused. Publication rechecks the recorded kind/descriptor,
and orphan bindings block maintenance capture, business export and identity
reset. Existing generation-5 journals require authenticated canonical Master
re-registration before data actions; missing descriptions are not inferred.

Both canonical backend snapshots, current image/provenance labels and release
manifest gates advance to generation 6. Historical generation 2–5 snapshots and
manifest vectors remain unchanged. Matching recovery material/images are
required; reverting code does not reverse DDL. Actual SQLite/MySQL tests cover
generation 4/5 upgrades, injected journal failure, idempotent replay, historical
ID/playback preservation and future-generation refusal. MySQL's legal long
database-name fixture also exposed the existing 64-character advisory-lock
limit: only overlong lock names now use a bounded hash suffix, preserving old
short lock names. See [schema/binding evidence](2026-10-12-peer-bindings-schema6.txt)
and [full Go regression](2026-10-12-peer-bindings-go.txt). Source CI passed its
unchanged budget, including 201 Python tests and two optional skips.

This checkpoint strengthens the durable resource description needed by recording
publication. Recording publication, the Master runner and the required fleet
acceptance remain incomplete; no full migration capability is advertised.

## Required remaining work

1. Finish consistent multi-node recovery sets and broader restored encrypted/
   recording business acceptance. Local deployment selection rebinding,
   read-only target space checks, maintenance ownership and real SQLite/MySQL
   activation are implemented and verified as scoped above.
2. Add approved upgrade plan/apply using explicit target release, preflight,
   independent recovery point, generation compatibility/migration, pinned switch
   and actual business verification. Cross-generation code rollback is not DDL
   rollback. No upgrade/recovery API belongs in AdminGUI.
3. Connect the implemented repository verification/publication/unit cutover to
   authenticated peer facts and the durable service worker. Carry exact source
   version and runner-epoch fences through each peer action, and integrate the
   existing writer coordinator without holding it across network copying.
4. Implement read-only whole-node migration plans bound to identities/content
   version, including hidden/encrypted media, directories, owned recordings/other
   managed files, backups, physical/logical capacity and conflict inventories.
   Reject Master Local this round unless the same safe protocol can be proved.
   The Master catalog foundation exists; authenticated physical inventories,
   orphan/quarantine/backup details and paginated large-node planning remain.
5. Finish persistent whole-task execution using the implemented authenticated
   chunk transport, target staging, disk SHA proof and media publication journal.
   Add recording publication and orchestration of complete-parent SQL cutover
   and cache invalidation; verify all Direct/Relay pairs. No network I/O inside
   long SQL/global-exclusive transactions.
6. Add version-bound managed source cleanup after old capability/read dependencies
   expire; cleanup_pending must retain target authority. Cover failure windows,
   restarts, quota reconciliation, pause/resume/cancel/retry and explicit draining
   release, without implicit reversal of committed units.
7. Add independently repeated retirement inventory/confirmation using existing
   relation revocation/tombstones, blocking unique backups, orphan/quarantine/
   journal residue, leases/references, remaining resources and offline peers.
   Harden existing ordinary revoke entry points against bypass. No force-delete,
   container/volume/disk cleanup or Master revocation.
8. Add node-module GUI and same-service CLI calls using existing HTTPS/auth/CSRF,
   replay protection and audit, preserving top-level Admin order/upload site-type
   semantics and encrypted file IDs/nonces/descriptors without copying file keys.
9. Run actual private-CA Master/Direct/Relay installs and five-node SQLite/MySQL
   migration/failure/browser acceptance, including real bytes, all four pairs,
   large/small files, encryption, references, concurrent mutations, cleanup faults
   and post-business CPU/memory/bandwidth bounds. Keep this outside hosted CI.
10. Reconcile the final operator manual/evidence and report implemented, verified,
    unverified, known limitations and blockers separately. Do not mark the goal
    complete until these required items are actually addressed.
