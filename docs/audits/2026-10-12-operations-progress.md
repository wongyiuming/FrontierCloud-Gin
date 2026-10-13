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
manifest gates advance to generation 6. Historical generation 2ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â¦ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦ÃƒÂ¢Ã¢â€šÂ¬Ã…â€œ5 snapshots and
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

## Recording publication checkpoint

Recording objects now carry a bounded original filename/content type/creation
binding and, for encrypted lyric snapshots, the original descriptor/metadata
hash. Followers persist these facts in generation 6's existing binding table.
The target's local job rehashes private bytes, validates the actual opaque footer,
links the verified inode under the target relationship/user path and commits
the original recording ID, footer receipt, owned used/reserved accounting and
publication audit together. It does not create a user account, copy a password,
alter Master personal quota or change Master ownership. Publication replay
checks the same recorded description and refuses deleted user accounts.

Reverse recording migration can reactivate only the same deleted physical ID,
user, filename/type, original byte count and full SHA. An encrypted lyric file-ID
tombstone can be restored only for that exact recording and physically verified
original footer; ordinary upload nonce rules are retained. Private publication
anchors stay journaled pending whole-task reconciliation/cleanup.

Actual SQLite/Gin pairing/HMAC tests uploaded, relayed, verified and published
plain and valid AES-GCM encrypted recording footers. The ordinary target read
returned identical full bytes; the encrypted fixture then decrypted the returned
lyric snapshot with its client-only test key. Neither server received this key.
Master ownership/personal used bytes remained unchanged, target owned capacity
was charged once and no target account was created. This router fixture is not
real TLS/native process or browser playback acceptance. Repository SQLite/MySQL
tests cover publication rollback after row/quota writes, duplicate replay,
deleted-account refusal and exact encrypted reverse descriptor/tombstone reuse.
Their repository proof fixture uses synthetic disk receipts; the separate
authenticated fixture transfers actual bytes.
See [authenticated publication output](2026-10-12-recording-publication.txt),
[actual SQLite/MySQL output](2026-10-12-recording-publication-mysql.txt) and
[full Go regression](2026-10-12-recording-publication-go.txt). The source suite
also passed within its existing budget: 201 Python tests, two optional skips
and the existing JavaScript/crypto/UI smoke checks.

Verified publication now restores media/recording read permissions before SQL
completion, including the group access used by Direct Nginx. The earlier media
path omitted this permission change; Go-router reads alone had not exposed it.
Native Nginx/browser verification remains required.

## Master execution checkpoint

The single existing business process now joins one Master migration worker into
shutdown. It selects the oldest runnable task with no live SQL runner, rather
than relying on the GUI's bounded history list. The worker claims a monotonic
epoch, loads the original persisted plan, registers both followers/object rosters,
relays one 256 KiB message at a time and checks the current SQL lease before each
network action. It renews the Master/peer leases between bounded operations.
Typed requests are converted through strict bounded JSON before existing
raw-body HMAC canonicalization; no arbitrary destination URL or file key is used.

Restart/retry reads target offset/hash facts and actual verified/publication
receipts. All objects in a complete parent are verified before publication is
prepared, then every published receipt is persisted before the short unit-owner
transaction. Failed tasks retain stable error/object identifiers and audit facts,
owned reservations/drains and peer fences; they require explicit retry. SQL
pause/resume cannot revive an old runner epoch. Source copies are retained and
the executor stops at cleanup_pending. Cancellation reconciliation, grace/read
dependencies and managed source/anchor deletion remain separate unfinished work.

The actual SQLite/Gin pairing/HMAC fixture moved 524,351 bytes in two files under
one parent. It injected a lost successful append acknowledgement, recreated the
runner, resumed the saved prefix, then failed the unit SQL transaction after
ownership updates. Both owners remained at source, while durable target copies
and target local quota were retained. A further retry reused published copies,
committed the whole parent and read identical bytes through ordinary target media
capabilities. Logical IDs and hidden state were preserved. The fixture opts into
the unfinished capability explicitly and uses router transport; it does not
claim real TLS/fleet or native-process restart acceptance. Repository SQLite/MySQL
checks separately cover scheduling, duplicate-runner rejection, pause/resume
epoch fencing and explicit failure/retry state. Full migration capability remains
unadvertised pending complete planning, cleanup, retirement and fleet validation.
See [actual-byte runner output](2026-10-12-master-runner.txt),
[SQLite/MySQL runner transactions](2026-10-12-master-runner-mysql.txt) and
[full Go regression](2026-10-12-master-runner-go.txt). Source CI also passed its
existing budget with 201 Python tests and two optional skips. MySQL required
bounded standalone task error codes; full failing object IDs remain in the
structured audit rather than exceeding the error-code column.

## Cleanup authorization checkpoint

Master cleanup authorization now requires a committed complete unit, unchanged
current target authority/physical mapping, matching original bytes/SHA/version,
an authenticated fresh target disk proof supplied by the service, elapsed
one-hour capability grace and no unexpired source read lease. A different logical
alias referencing the source physical ID also blocks cleanup. Current peer
identity bindings/health are rechecked under the runner epoch. The returned grant
binds task/plan, unit version, exact object and immutable commit/grace timestamps.

Source repository preparation accepts only its active upstream Master, complete
registered roster, matching full object binding/bytes/SHA and source role. It
persists the unit authorization/deleting journal idempotently, blocks additional
migration reads and leaves source used bytes/draining unchanged. This method does
not delete files. It is not exposed as a browser/CLI proof-input shortcut or
automatically dispatched by the worker yet. Fresh disk proof RPC, source file
transaction adapters, actual read-lease integration, private-anchor cleanup and
task completion/cancellation reconciliation remain required.

SQLite/MySQL tests rejected precommit cleanup, premature grace, stale/wrong disk
proofs, active physical-alias read leases, wrong owners/versions and changed replay
timestamps. Allowed preparation retained source accounting. These repository
fixtures provide synthetic fresh disk proofs and explicitly advance test-only
grace timestamps; they are not actual source-delete or fleet acceptance evidence.
See [cleanup/ledger transactions](2026-10-12-cleanup-authorization-mysql.txt) and
[full Go regression](2026-10-12-cleanup-authorization-go.txt). Source CI passed
the unchanged budget with 201 Python tests and two optional skips.

Ordinary managed deletion also recognizes a migrated target's published ledger
when it has no ordinary upload session. Deletion atomically records the historical
physical journal as deleted with its usual quota/audit transaction. A repository
test reconciles target scopes, deletes the migrated object through the ordinary
path and confirms exactly one refund. This repairs post-migration deletion;
it does not bypass active migration scopes or authorize source removal.

## Fresh target disk recheck

The service now generates a new authenticated request ID for each target disk
proof. The joined local worker rehashes the actual published inode with bounded
I/O, checks its private anchor and current metadata, and durably records that
exact request's result. A failed request invalidates its receipt instead of
reusing an older successful publication. Master accepts only its own fresh
request ID, immutable object binding, complete SHA/length and published state.
This supplies the previously missing disk proof RPC; it does not yet dispatch
source deletion or prove completion of old playback connections.

Actual SQLite/Gin/HMAC byte fixtures moved 524351 bytes, retried lost receipts
and failed SQL cutover, then detected target corruption on a fresh request while
retaining target authority. These use a router transport, not native TLS/socket
or browser fleet acceptance. Filesystem tests additionally rejected replacement
by a different inode with identical bytes and persisted failure across restart.
See [race/actual byte evidence](2026-10-12-target-disk-recheck.txt),
[SQLite/MySQL transactions](2026-10-12-target-disk-recheck-mysql.txt), and
[full Go regression](2026-10-12-target-disk-recheck-go.txt). Source CI also passed
201 Python tests (two optional skips) and the existing JavaScript smoke checks.

## Native follower read dependencies

Native Go media and recording responses now register durable physical read
leases after capability validation and before response bytes. Reads admitted
before migration registration are retained, including different logical aliases
of the same physical object. A short transaction serializes read admission and
source cleanup authorization under the existing node lock. Deleting/deleted
source journals reject new reads. Leases expire after 300 seconds, renew every
30 seconds, cannot revive after expiry, and are released only after the renewal
worker joins. Failed renewal cancels the response and closes its pinned file;
failed release leaves a bounded lease rather than a successful cleanup receipt.
Admission caps persisted active reads at 1024 per follower and removes expired
rows. No schema change or extra daemon was introduced.

The actual 524351-byte router fixture now holds a source response open before
migration registration, observes its durable lease while bytes are being served,
and confirms release and exact response bytes afterward. SQLite/MySQL race
fixtures verify alias blocking, expired-lease rejection, idempotent close and
concurrent read/cleanup admission. Repository cleanup fixtures still use
synthetic grants with explicitly advanced test-only grace timestamps. A focused
worker test injects renewal failure and checks file closure, cancellation and
one joined release; it uses a short test interval rather than waiting 30 seconds.
See [native response/race evidence](2026-10-12-native-read-leases.txt),
[SQLite/MySQL admission evidence](2026-10-12-native-read-leases-mysql.txt), and
[renewal failure/full regression](2026-10-12-native-read-leases-go.txt).
Source CI passed its existing budget (201 Python tests, two optional skips and
JavaScript smoke checks).

This does not observe a legacy Nginx X-Accel connection after the Go handler
returns. Media acceleration retains its existing behavior; it is not certified
for source cleanup. Production still does not advertise the unfinished migration
capability. Before enabling migration, physical inventory/eligibility must reject
that unsupported read path or supply a proven equivalent fence. Source file
transactions, private anchors, task completion/cancellation and retirement remain
unfinished. There has been no production migration or source data deletion.

## Managed source media deletion adapter

The source media adapter now accepts the existing bound cleanup grant, fences
new reads, hashes the pinned source inode with a 64 KiB buffer outside the global
mutation lease, and checks the same inode/length/modification time again under a
short exclusive lease. Full actual SHA must match the original transfer proof.
The source repository rechecks the immutable object binding, content descriptor,
committed unit/grace, active runner and live physical-alias read dependencies.
The adapter uses the existing managed private quarantine and recovery journals;
it never recursively removes the source directory or deletes an arbitrary path.

Optional native delete-manifest task/logical fields bind the ordinary durable
file transaction to the source migration journal. Ordinary preparation rejects
those fields. Source deletion preparation requires the persisted cleanup grant.
Quota decrement, metadata/nonce retirement, source journal state, delete commit
and audit commit together. The audit retains the task/logical binding after the
short-lived file journal is forgotten. Replayed committed operations refund once.
A pending journal restores bytes after restart; a committed journal continues
private cleanup. The adapter checks retained journals before reporting success:
a committed SQL receipt alone is not physical quarantine removal. Failed private
cleanup is retried only for the same task/object and keeps cleanup pending.
Physical-free measurement remains conservative until actual unlink/close and a
subsequent disk measurement; it is not equated with the logical refund.

Real 131075-byte filesystem fixtures cover SHA corruption, an equal-byte inode
replacement after hashing, audit rollback, lost commit acknowledgement, retained
private-cleanup receipt, and restart before/after deletion commit. SQLite/MySQL
repository tests cover ordinary-entry rejection, missing grant, atomic source
ledger/quota commit, one refund and durable audit binding. These fixtures supply
synthetic grants and explicitly advance test-only grace; they do not prove a
complete authenticated Master-to-source cleanup run or production deletion.
See [source filesystem/race evidence](2026-10-12-source-media-cleanup.txt),
[SQLite/MySQL journal transactions](2026-10-12-source-media-cleanup-mysql.txt), and
[full Go regression](2026-10-12-source-media-cleanup-go.txt). Source CI passed
201 Python tests (two optional skips) and the existing JavaScript smoke checks
within the unchanged hosted CI budget.

No new schema generation, process or browser proof-input endpoint was added.
The adapter is not dispatched by production RPC yet. Recording deletion,
historical publication anchors, source cleanup receipts/runner reconciliation,
whole-task completion/cancellation, Nginx read eligibility and independent
retirement inventories still require implementation and actual fleet acceptance.
Production does not advertise the unfinished migration capability.

## Authenticated source media cleanup execution

Master now schedules committed media copies for cleanup only after their persisted
one-hour grace, using a fresh authenticated target disk recheck and the bound
cleanup grant. The native-only HTTPS/HMAC follower route dispatches deletion to
the existing joined worker (one worker, one queued job); it does not hold an HTTP
request or SQL/global exclusive transaction across hashing. Legacy Nginx media
acceleration and recording cleanup are explicitly rejected at this stage.

The source reports a managed-copy deletion receipt only when its physical journal
is deleted and the exact managed delete operation no longer remains. Master
rechecks task/plan/source/target, original ID/version/length/SHA, target authority
and elapsed grace before recording its object as `cleaned`. This object checkpoint
means the managed source copy is removed. Units/tasks stay `cleanup_pending`,
with scopes/drains held, until private anchors and final reconciliation are also
finished. Replayed receipts change revision/audit once and cannot reverse owner
or refund Master quota again.

Source scan failures use the existing per-object `pending` checkpoint plus the
structured failure audit; the physical journal stays `deleting`, so new source
reads remain fenced. This is a follower resource fact, not a copy of the Master
business database. A fresh explicit grant clears the failed checkpoint for retry.
Master retains `cleanup_pending` with stable `source_cleanup` error code, and the
scheduler excludes that error until operator retry. A new runner epoch fences
older jobs. Existing generation-six state constraints remain unchanged; no DDL is needed
for these resource checkpoints.

The actual 524351-byte SQLite/Gin/HMAC fixture now completes both managed source
deletions, blocks a live physical-alias read, detects source/target corruption,
persists source failure, retries a lost deletion receipt, reconciles source used
to zero once, and reads identical business bytes from the target afterward. The
fixture explicitly advances only its isolated grace timestamps; it is not a real
one-hour wait, native TLS/socket, browser or five-node deployment test.
SQLite/MySQL tests cover due/error scheduling, explicit retry, per-object failure
checkpoint reset, receipt binding, one progress revision and retained scopes/
target authority. See [authenticated byte/cleanup and full Go regression](2026-10-12-authenticated-source-cleanup.txt)
and [SQLite/MySQL execution facts](2026-10-12-authenticated-source-cleanup-mysql.txt).
Source CI passed 201 Python tests (two optional skips) and its JavaScript smoke
checks within the unchanged hosted CI budget.

Recording source transactions, historical publication anchors, whole-task
completion/cancellation, physical inventories/eligibility, retirement and GUI/CLI
remain required. Production still does not advertise the unfinished migration
capability, and no production resource or node was migrated or retired.

## Authenticated source recording cleanup

Recording cleanup now runs through the same Master scheduler and authenticated
native-only follower worker as media. The source pins and hashes actual complete
recording bytes outside the global mutation lease, checks its footer descriptor
and same inode, then uses the existing private recording delete intent. A short
repository transaction stages only the exact recording from the persisted cleanup
grant, with current runner/owner/version, complete-unit grace and no live reads.

The private journal carries the migration task. Source recording tombstone,
used-capacity refund, migration physical journal and audit commit together through
the existing recording deletion transaction. Ordinary recording deletion cannot
bypass active migration scopes. Historical target publication journals also become
deleted when their recording is ordinarily removed. The source keeps its immutable
identity and original encrypted footer tombstone; Master personal quota is not
refunded or copied to a Storage account. Retry/recovery removes only the exact
private recording intent/trash, and a retained intent is not a completed receipt.
Prepared recording intents follow the existing forward recovery contract, even
when the old runner has expired. Target authority is retained throughout.

The actual authenticated SQLite/Gin/HMAC tests now migrate and clean both plaintext
and encrypted-footer recordings, reject active reads, inject audit rollback,
restore exact source bytes, retry a lost deletion receipt, reconcile source used
to zero once and read exact target bytes afterward. The encrypted fixture decrypts
the unchanged footer on the simulated client; it is not browser/audio playback
acceptance. Test-only grace timestamps are explicitly advanced. Dedicated actual
file-intent tests restart before/after SQL commit with expired runner and confirm
one refund/audit, deleted source journal, no resurrection and completed private
cleanup. SQLite/MySQL repository tests reject missing grants/ordinary scope bypass
and confirm that unrelated media capacity is retained.
See [recording byte/RPC and recovery evidence](2026-10-12-source-recording-cleanup.txt)
and [SQLite/MySQL cleanup facts](2026-10-12-source-recording-cleanup-mysql.txt).
Source CI passed 201 Python tests (two optional skips) and existing JavaScript
smoke checks within its unchanged budget. No DDL/schema-generation change was
introduced.

Units/tasks still remain cleanup pending: historical publication anchors,
whole-task completion/cancellation, physical eligibility/inventories, retirement,
GUI/CLI, upgrade and full native five-node/browser acceptance remain required.
Production still does not advertise the unfinished migration capability.

## Durable publication-anchor retirement component

The byte receiver can now retire a verified published private hard-link anchor
without changing business metadata, authority or quota. It checks actual complete
SHA/length and the same business inode through the volume adapter, persists a
retiring intent before unlink, syncs the directory, then persists retirement.
Only that exact task/object private file is removed. The published checkpoint
and small lock/journal files remain as immutable reconciliation evidence.

An unexplained missing anchor is rejected. Restart before unlink rechecks the
private inode; restart after unlink is accepted only with the durable intent and
rehashes the actual surviving business file. Replacement by an unrelated inode
or corruption blocks normal retirement. Replayed retirement verifies bytes and
never deletes the business path. A fresh recheck after retirement hashes the
business file and retains the same request-ID freshness contract. Publication
replay cannot recreate a retiring/retired anchor. Media and recording adapters
also check current exact ID/path/descriptors under brief shared volume leases.

Actual filesystem/race tests cover normal unlink, missing anchor without intent,
restart before/after unlink, same-byte different-inode replacement, corruption,
replay and fresh post-retirement disk recheck. See [anchor recovery/race evidence](2026-10-12-publication-anchor-retirement.txt)
and [full Go regression](2026-10-12-publication-anchor-retirement-go.txt). Source CI
passed 201 Python tests (two optional skips) and existing JavaScript smoke checks
within the unchanged hosted budget.
The adapters have no public grant-input shortcut and are not yet dispatched by
the Master runner. These component tests are not complete task, native TLS or
fleet acceptance. No database constraint or schema generation changed.

Required next work is authenticated post-source-deletion admission, durable
Master/peer completion receipts, historical source-anchor reconciliation, scope/
capacity release and explicit drain release, followed by cancellation, inventories,
retirement, GUI/CLI and the remaining full-scope acceptance. Whole tasks continue
to remain cleanup pending; production does not advertise the unfinished capability.

## Authenticated anchor retirement and historical source copies

Source deletion receipts now also require historical publication anchors for that
logical object to be retired. The bounded-batch scanner validates each exact
private checkpoint name, local target identity, same Master, logical/physical ID,
source physical path, original bytes/SHA and descriptors. It never sweeps a whole
directory or accepts another Master/version's copy. Removal has its own persisted
retiring intent, actual SHA verification and idempotent recovery. Retained small
journals/lock files remain historical control evidence, not data copies. Scans
and full hashes run outside the global mutation lease.

After a durable source-deletion receipt, Master obtains a new target disk proof
and creates a grant explicitly asserting the source copy is deleted. The existing
HTTPS/HMAC endpoint dispatches target anchor retirement to the joined local worker.
Initial target admission rechecks freshness, full binding, current epoch, source/
target/plan and published journal; an ongoing job checks current lease/binding
without requiring its original 30-second proof stamp to stay fresh throughout a
large local scan. Once queued, Master polls status instead of resubmitting an old
grant. The private checkpoint preserves a stable retirement error on disk/identity
failure. Rechecks after retirement hash the actual surviving business file.

Actual filesystem tests cover bound historical source-anchor deletion, rejection
of other Master/SHA/corrupt copies and restart after unlink. Existing real byte/
HMAC fixtures now also retire target anchors for media and plaintext/encrypted
recordings while retaining identical target reads and personal quota. These use
SQLite/Gin router transport and advanced isolated grace timestamps; they are not
native TLS, browser playback, reverse-fleet or five-node acceptance. SQLite/MySQL
repository tests reject unverified/unpublished target, missing source receipt and
stale initial grants. See [anchor RPC/race and full Go evidence](2026-10-12-authenticated-anchor-cleanup.txt)
and [SQLite/MySQL grant evidence](2026-10-12-authenticated-anchor-cleanup-mysql.txt).
Source CI passed 201 Python tests (two optional skips) and its existing JavaScript
smoke checks within the unchanged budget. No schema constraint/generation changed.

Master/peer durable unit/final-task completion receipts, scope/capacity release,
explicit drain release and cancellation reconciliation still require completion.
Tasks remain cleanup pending, and no node relation is automatically revoked.
Inventories, retirement, GUI/CLI, upgrade and the remaining full-scope acceptance
also remain required; production migration capability is still unadvertised.

## Durable complete-unit cleanup receipts

Master now generates a bounded completion grant for a whole immediate-parent
unit only after every source object is durably cleaned and current authority
still belongs to the target. The grant binds the immutable peer header/plan,
unit version, commit/grace timestamps, resource/parent, count/bytes and canonical
full-object/proof roster SHA. Each follower independently reconstructs that
roster from its complete registered physical journal and bindings.

The authenticated follower completion route checks retained managed deletion
material and historical source anchors, or published target checkpoints with
retired anchors, before its short SQL completion transaction. Source live
physical-alias reads block completion. Peer completion persists unit `cleaned`,
releases only that member/unit scope and emits a durable receipt. Master accepts
both exact member receipts, rechecks its stored grant/target authority, marks the
unit cleaned and removes only that unit's scopes in one transaction. Replay
preserves the same receipt and increments audit/progress once. There is no
additional refund or reverse owner update.

The actual 524351-byte SQLite/Gin/HMAC test now loses a node unit-completion
reply after peer commit, confirms Master scopes remain held, explicitly retries,
then confirms durable unit completion, scope release and unchanged target bytes.
Plain/encrypted recording byte fixtures also pass unit completion and target
read/client footer decryption. Isolated grace timestamps are explicitly advanced;
these are router fixtures, not native TLS/browser/five-node acceptance.
SQLite/MySQL tests reject unfinished units, one-sided/wrong-roster receipts and
confirm one completion audit, released unit scopes and retained owned drain.
See [unit completion/race evidence](2026-10-12-unit-cleanup-completion.txt),
[SQLite/MySQL completion facts](2026-10-12-unit-cleanup-completion-mysql.txt), and
[full Go regression](2026-10-12-unit-cleanup-completion-go.txt). Source CI passed
201 Python tests (two optional skips) and existing JavaScript smoke checks within
the unchanged hosted budget. No DDL/schema-generation change was introduced.

Whole-task peer/final acknowledgement, capacity/history reconciliation and the
explicit drain-release handshake still require completion. Master/peer tasks
continue to remain active cleanup/control facts until that final phase, and
ordinary drain release remains rejected. Completion does not revoke a node,
stop a host or remove volumes. Cancellation, independent inventories/retirement,
GUI/CLI, upgrade and the remaining full-scope acceptance remain required.
Production still does not advertise the unfinished migration capability.

## Whole-task confirmation and explicit owned-drain release

Master and followers now complete a whole task using a canonical digest of all
persisted completed units, their versions/timestamps, full object roster SHA,
counts/bytes and immutable peer header/plan. Every unit must already be cleaned,
all task scopes absent and this task's capacity reservation zero. Peer task
completion retires zero-capacity facts, persists completed state and expires its
runner; Master commits completed state only after both exact member receipts.
Neither transaction repeats a used-capacity refund or changes current owners.

A completed peer can return the same bound receipt to a newly fenced Master
runner after an acknowledgement is lost. That path checks active upstream
identity, immutable task header, monotonic epoch and completed facts; it never
reactivates data permissions. The scheduler now finds overdue unit cleanup and
all-cleaned task finalization, while excluding operator-visible cleanup errors.
Completed Master runs are idempotent. Retained histories/identity/audit survive.

Owned drain release is an explicit service operation with exact source NodeID
confirmation. It first obtains an authenticated source receipt, then removes the
Master's matching task-owned restriction. Each side checks terminal task, scopes,
units and reservations; the source also rechecks live reads. Replay is harmless.
Administrator/other-task restrictions, writable configuration, node relationships,
containers and volumes are preserved. The service is not automatically called by
task completion, and GUI/CLI exposure remains a later phase.

Actual SQLite/Gin/HMAC fixtures complete media/plain/encrypted-recording tasks,
lose and replay a peer task receipt under a new epoch, retain identical target
reads/client footer decryption and preserve owned drains until explicit release.
The media fixture rejects wrong NodeID, releases both sides twice and confirms
administrator restrictions remain. Isolated grace timestamps are advanced;
these are not native TLS/browser/five-node or live production migrations.
SQLite/MySQL tests reject one-sided/wrong task receipts, reconcile zero-capacity
facts, retain drain at completion and exercise explicit confirmation/replay.
See [task/drain RPC and race evidence](2026-10-12-task-completion-drain-release.txt),
[SQLite/MySQL completion evidence](2026-10-12-task-completion-drain-release-mysql.txt),
and [full Go regression](2026-10-12-task-completion-drain-release-go.txt).
Source CI passed 201 Python tests (two optional skips) and its JavaScript smoke
checks within the unchanged hosted budget. No DDL/schema-generation changed.

Persistent cancellation/reverse-task reconciliation, complete physical inventories,
independent retirement, node GUI/same-service CLI, approved upgrade, multi-node
recovery and full native/fleet/browser/resource acceptance remain required.
Production still does not advertise the unfinished migration capability. No
production task, node revocation, publishing, host stop or volume deletion occurred.

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
   Connect recording/media publication to complete-parent SQL cutover
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


## Unpublished cancellation receipts (2026-10-12)

The authenticated target abort route now persists a SQLite peer-journal `aborted`
receipt after the task-private staging checkpoint has durably removed its bytes.
A lost SQL acknowledgement can repeat this operation. SQL authorization permits
that replay but rejects publishing/published objects; published shadows require
separate managed deletion reconciliation. Reservations and scope locks remain
held until whole-task reconciliation. This is a cancellation protocol primitive,
not a completed Master cancellation runner.

Cancellation before Begin creates a durable empty-prefix tombstone only when
staging material is absent or empty. Nonempty material without a binding journal
is retained and blocks cleanup. Restart cannot reopen aborted staging. Tests use
actual filesystem bytes and SQLite/MySQL transactions. Fleet/browser acceptance
and cancellation of partially committed tasks remain outstanding.


## Cancellation unit reconciliation (2026-10-12)

Uncommitted units now have a distinct cancellation grant and authenticated
`cancel-unit` endpoint. Master and both followers reconstruct the same complete
unit roster digest. Source journals must remain receiving; target journals and
filesystem staging checkpoints must be aborted. Published/deleting/deleted
journals cannot use this path. Cancellation grants have zero commit/grace times,
and cleanup endpoints reject them. Missing roster entries after interrupted
registration can be supplied under the cancelling epoch through the existing
source identity, target collision, count, byte-limit and scope checks; data reads,
copying and publication remain fenced.

Both peers durably record the unit cancellation; the target refunds only its
remaining unpublished reservation, exactly once. The Master requires both matching
member receipts before refunding its reservation and marking the objects/unit
cancelled. Source business ownership and used capacity are untouched. Completed
unit receipts can be repeated after locks have been released. The source drain
remains, and whole-task state remains cancelling until final reconciliation.
Committed units cannot receive this grant and retain target ownership.

Evidence: `2026-10-12-cancellation-unit-go.txt` contains actual authenticated Gin
router transfer, disk abort and lost-receipt replay; this is not a real HTTPS
fleet/browser test. `2026-10-12-cancellation-unit-mysql.txt` covers isolated SQLite
and MySQL transaction/replay checks. Whole-task cancellation runner/finalization,
published-but-uncommitted shadow deletion, mixed committed-unit cleanup and
five-node/browser acceptance remain required work.


## Whole-task cancellation runner and final receipts (2026-10-12)

The joined Master scheduler now selects cancelling tasks without a persisted
error. The fenced cancellation runner registers the immutable roster, aborts
unpublished target staging, reconciles both unit receipts and then both final
peer receipts. Task final grants bind an explicit completed/cancelled outcome,
all terminal unit digests, object/byte totals, committed byte accounting, zero
scope locks and zero remaining reservations. Peers preserve terminal state when
returning a final receipt to a fresh Master epoch. Empty cancellation registration
replays do not reactivate task data permissions.

Cancellation failures retain cancelling/cancel_cleanup, exclude automatic
retries and accept explicit retry without changing back to queued. Durable
unit cancellations release only their reservation once. Source drains remain
until explicit task-owned release, and business owners/used bytes are untouched.
Tests inject lost abort, unit and final acknowledgements after actual successful
operations, then use fresh runners and real source business reads. Real SQLite
and MySQL transactions are separately covered. Evidence is in
`2026-10-12-cancellation-task-go.txt` and
`2026-10-12-cancellation-task-mysql.txt`; the authenticated router transport is
an isolated Go fixture, not native TLS/fleet/browser acceptance.

Remaining cancellation work: managed deletion of published-but-uncommitted
shadows, cleanup of committed units while the task is cancelling, initial peer
admission when the target has become full/unwritable, mixed/reverse/fleet tests.
The runner conservatively records an error for these unfinished cases; it does
not use staging Abort to delete published data or reverse authoritative owners.
Other original upgrade/recovery/inventory/retirement/GUI/CLI/acceptance scope
remains active and the production migration capability stays unadvertised.


## Partially committed cancellation cleanup (2026-10-12)

Cancellation now reuses the existing committed source cleanup, fresh target disk
proof, private anchor retirement and dual-peer unit completion protocols. Only
these cleanup/recheck/status/retire actions remain permitted on cancelling
followers; source migration reads, appends, verification and publication remain
fenced. Every deletion still requires the original committed unit grant, exact
object version, grace, target authority and read-dependency checks. The recording
source deletion and target anchor admission follow the same rule.

The runner cancels uncommitted units while committed cleanup waits for grace.
Scheduler selection distinguishes immediate uncommitted reconciliation, due
committed cleanup and final terminal receipts, so a task waiting only for grace
is not repeatedly run. Mixed cleaned/cancelled unit digests preserve the exact
committed byte total and terminal cancelled outcome. Source/target owners are
never reversed, and an explicit reverse task remains required to move committed
resources back.

`2026-10-12-cancellation-mixed-go.txt` records actual three-object/two-parent
router transfer, a fault after the first committed unit, cancellation of remaining
staging, a lost managed source deletion receipt and recovery. The fixture advances
only its own stored grace times; it does not establish an elapsed-hour test.
Post-cancel business reads, logical IDs and both Master/follower used/reserved
capacity are checked. Backend cancellation cleanup admission and scheduling are
also checked with SQLite and MySQL in
`2026-10-12-cancellation-mixed-mysql.txt`; full Go regression is recorded in
`2026-10-12-cancellation-mixed-full-go.txt`.

Still required: published-but-uncommitted shadow deletion, cancellation before
peer admission when target is full/unwritable, cancellation after a peer has
already returned a normal completed receipt, recording cancellation/fleet/browser
and reverse acceptance, and all remaining original delivery scope. Migration
capability is still unadvertised in production.


## Fresh source proof before shadow deletion (2026-10-12)

Published-but-uncommitted target copies can be the only intact physical copy if
the source has suffered corruption. The new cancellation source verifier reads
the full source object through authenticated, paced, 256 KiB chunks, verifies
chunk lengths/offsets/versions/SHA and then the complete original SHA. Master
keeps no file-sized buffer or disk cache. The still-uncommitted authoritative
unit and SQL runner lease are checked before and after this scan.

The distinct `cancel-read` action is accepted only by the active upstream Master
under a cancelling task with a complete bound roster and a receiving source
journal. It does not re-enable ordinary copy reads, appends or publication and
cannot read a deleting source as an authoritative proof. A shadow deletion grant
binds the immutable cancellation unit/object and a matching source proof no
older than 30 seconds. Stale, wrong-sized/version/hash proofs and committed units
are rejected. No administrator API accepts supplied source proof values.

`2026-10-12-cancellation-source-proof.txt` records actual failed-cutover target
publication, source corruption, authenticated full source scans and preserved
intact target bytes. Backend grant/action fences are checked with SQLite/MySQL
in `2026-10-12-cancellation-source-proof-mysql.txt`; full Go regression is in
`2026-10-12-cancellation-source-proof-full-go.txt`.

This is the safety prerequisite for managed target-shadow deletion. The target
admission, managed file deletion/recovery, private anchor removal and mixed
used/reserved reconciliation for published shadows are still outstanding.
Production capability remains unadvertised and the full original goal continues.


## Durable published media shadow deletion admission (2026-10-12)

The target repository now validates a cancellation shadow grant against its
active upstream Master/runner, complete registered roster, immutable full unit
digest, exact media binding, original source SHA/version/length and fresh source
proof. Committed units, wrong parents/paths, stale initial proofs and live target
read leases are rejected. Admission records a pending, zero-commit cancellation
unit and changes only the exact published target journal to deleting; no bytes,
capacity or business ownership change at this point. Existing deleting/deleted
admission can be replayed without renewing an already durable deletion intent.

The normal managed media deletion prepare/commit path accepts this exact durable
target shadow grant. It consumes only the matching task/object publication ledger
and refunds local used capacity in the same transaction as metadata retirement,
physical deletion journal and audit. Ordinary deletion cannot bypass the grant,
and an expired actor does not prevent recovery of a previously prepared durable
file transaction. Native read admission now blocks deleting/deleted target
shadows as well as source copies, including physical aliases.

`2026-10-12-cancellation-shadow-admission-go.txt` tests SQL admission, live/new
reads, failed refund rollback and repeated commit. The same tests run against real
SQLite/MySQL in `2026-10-12-cancellation-shadow-admission-mysql.txt`; full Go
regression is in `2026-10-12-cancellation-shadow-admission-full-go.txt`. These
backend tests do not prove physical file quarantine or private-anchor removal.

Remaining integration: native media shadow file adapter and bounded worker RPC,
actual target bytes/anchor recovery, cancellation unit reconciliation of deleted
shadows versus unpublished aborted reservations, recording shadows and publication
crash windows. No production capability is advertised and no completed-shadow
cancellation is claimed yet. The full original delivery goal remains active.


## Native media shadow files and private anchor cleanup (2026-10-12)

The native media adapter now consumes persisted target-shadow admission using
the existing managed source-delete file pipeline: pinned inode/full disk SHA,
short exclusive identity recheck, exact task/object delete manifest, quarantine,
atomic metadata/quota/journal commit and ordinary restart recovery. It never
uses a path-only unlink or a new ad hoc physical deletion transaction. Committed
private quarantine must be gone before success. The target's own original
publication anchor is then retired with durable unlink intent and full private
byte verification; business path/metadata absence and the same authenticated
current deletion fact are rechecked before and after the scan.

`2026-10-12-cancellation-shadow-files.txt` contains actual SQLite/filesystem
publication and cancellation shadow deletion tests. Cases cover corrupt bytes,
equal-byte inode replacement, audit/SQL failure restoring quarantined bytes,
lost commit acknowledgement and restart before/after SQL deletion commit.
Each successful replay proves target metadata/used capacity are gone, only one
refund audit exists, no `.part` or quarantine bytes remain and the private anchor
checkpoint is retired. Existing source media cleanup cases also pass with the
shared pipeline. Full Go regression is recorded in
`2026-10-12-cancellation-shadow-files-full-go.txt`.

This native adapter is not yet wired to the bounded authenticated shadow worker
RPC or whole-unit cancellation reconciliation. Recording shadows, publication
crash windows, large-node inventory, retirement, GUI/CLI, upgrades and remaining
original fleet/browser/recovery acceptance are still required. No migration
capability is advertised and no full-goal completion is claimed.


## Authenticated published-shadow cancellation runner (2026-10-12)

Published media shadows now use a bounded authenticated `data/shadow` RPC on
the existing joined single worker/one-job queue. Admission requires the fresh
source-bound grant; polling alone cannot authorize deletion. Native-only gating
rejects accelerated Nginx media, recordings and unadmitted publication. Worker
errors are stored in the follower's existing per-object pending checkpoints,
including errors after SQL deletion while private material remains. Polling
reports shadow_failed, and only a newly validated fresh source proof clears
that failure for explicit retry. The physical journal never rolls back from
deleted to published or refunds the same bytes again.

The Master cancellation runner falls back from staging Abort to fresh source
verification and shadow cleanup for published/deleting/deleted media. It accepts
only exact bound retired-anchor receipts. Dual-peer cancellation unit completion
accepts aborted unpublished objects and deleted published shadows, but requires
the private checkpoint and managed quarantine to be finished for deleted
shadows. Only aborted bytes refund local reservations; published shadow used
capacity was already refunded by its managed deletion transaction. The Master
then refunds its unchanged whole-unit reservation once and keeps source business
owners. Final cancelled receipts retain the source drain for explicit release.

`2026-10-12-cancellation-shadow-runner.txt` records actual authenticated router
transfer/publication with failed Master cutover, corrupt-target worker failure,
explicit repair/retry and lost shadow/unit/final-task receipt recovery. Source
business reads/IDs are retained, target business/private/quarantine bytes are gone
and target used/reserved capacity is zero. This is an isolated Gin/raw-HMAC
fixture, not native TLS/fleet/browser acceptance. Durable failures, fresh retry
and deleted-shadow unit refund replay run against SQLite/MySQL in
`2026-10-12-cancellation-shadow-runner-mysql.txt`; full Go regression follows in
the runner evidence file.

Outstanding original scope includes recording shadows, interrupted publication
before durable peer receipt, initial cancel admission with a now-full/unwritable
target, mixed shadow/aborted/committed fleet cases, terminal normal-receipt race,
authenticated large physical inventories/backup/orphan retirement, GUI/CLI,
upgrade/recovery and five-node/browser/resource-bound acceptance. Production
migration capability remains unadvertised and the full goal remains active.


## Recording shadow deletion repository admission (2026-10-12)

Cancellation shadow admission now accepts fully bound recording objects as well
as media. The target recording staging/commit path consumes the same exact
pending zero-commit unit grant; committed units and unadmitted ordinary deletion
remain blocked. Existing recording metadata/footer snapshot validation, active
read checks, logical recording ID and local ownership binding are preserved.
No new deletion state or schema generation is introduced.

The ordinary owned recording deletion transaction refunds target used capacity,
retires encrypted lyric descriptors into the existing file-ID tombstone and
marks the precise migration physical journal deleted together. A previously
staged recording deletion can finish after lease expiry, and repeated commits do
not refund again. The source business recording/user is never moved or deleted
by this target operation and no karaoke account is copied onto Storage.

`2026-10-12-cancellation-recording-shadow-admission.txt` covers actual SQLite
transactions for plain/encrypted publication and cancellation admission,
immutable binding changes, ordinary-delete bypass rejection, failed audit/refund
rollback, expired executor recovery and stable encrypted file-ID tombstones.
The same cases run with real MySQL in
`2026-10-12-cancellation-recording-shadow-admission-mysql.txt`; full Go regression
is recorded in `2026-10-12-cancellation-recording-shadow-admission-full-go.txt`.
These are repository tests, not physical recording-file cleanup proof.

Remaining recording integration includes native footer/byte verification,
private recording intent/anchor cleanup, authenticated worker/controller wiring
and actual plaintext/encrypted cancellation reads/recovery acceptance. Original
publication-window, inventory, retirement, GUI/CLI, upgrade/recovery and fleet/
browser acceptance remain active; production migration capability is unadvertised.


## Native recording shadows and authenticated cancellation (2026-10-12)

Recording shadows now reuse the existing exact-recording-ID deletion pipeline:
pinned full bytes/SHA/footer check, short inode recheck, durable private recording
intent, tombstone/quota transaction and forward restart recovery. Target private
publication anchors are retired only after the target business path and private
delete intent are gone and the exact tombstone/member/user/bytes/SHA still match.
No ciphertext is decrypted or re-encrypted by a node; its descriptor/file-ID
retirement preserves existing nonce/tombstone semantics.

The joined shadow worker, native-only authenticated RPC, cancellation controller
and dual-peer unit completion now dispatch both media and fully bound recordings.
Source full-byte proof remains required before target deletion. Cancellation
keeps the original Master/source recording owner, source ready state and personal
user quota; target used capacity is refunded once by the recording transaction.

`2026-10-12-cancellation-recording-shadow-files.txt` verifies actual plaintext and
encrypted footer files, corrupt disk bytes, failed audit recovery and restart
before/after SQL deletion commit with expired actors. Successful replay proves
business/private/intended-delete bytes gone, original identity/SHA tombstones
retained and one refund audit. `2026-10-12-cancellation-recording-shadow-runner.txt`
records actual authenticated Gin/raw-HMAC copy/publication, failed Master cutover,
cancellation, lost deletion/unit/final receipts, source business download and
client AES decryption after cancellation. Full Go regression is in
`2026-10-12-cancellation-recording-shadow-full-go.txt`. Repository/MySQL admission
and encrypted refund/tombstone evidence remains in the preceding recording
admission audit; these router fixtures are SQLite and are not native TLS/fleet/
browser acceptance.

Original remaining scope is still active: interrupted publication windows,
full/unwritable initial cancel admission, mixed/reverse/fleet cancellation,
authenticated physical backup/orphan inventories and independent retirement,
GUI/CLI, approved upgrade, coordinated recovery and full multi-node/browser/
resource-bound acceptance. Production migration capability is unadvertised.


## Interrupted publication cancellation byte checkpoints (2026-10-12)

A target can retain a business hard link while its byte checkpoint is publishing
and its SQL publication receipt is unknown. Ordinary staging Abort continues to
reject that state. The new cancellation checkpoint primitive records a durable
publication-cancelling intent before the service's coordinated same-inode unlink,
then durably records business-link removal before retiring the private staging
file. A crash after either unlink replays the corresponding recorded phase.
Published checkpoints are excluded; their existing SQL-accounted shadow deletion
protocol remains separate. A pending publication cancellation also blocks ordinary
staging Abort until business unlink has been acknowledged.

The service callback contract requires absent business metadata and only this
task's same-inode business link; the receiver independently verifies the full
private original SHA, immutable task/object binding and admission before file
work. Neither a missing private file without intent nor unrelated equal bytes
are accepted as recovery proof. This remains a byte-journal primitive, awaiting
native media/recording metadata checks and authenticated repository/worker wiring.

`2026-10-12-publication-cancel-checkpoints.txt` contains actual filesystem/race
checks for corruption, foreign equal-byte inode preservation, lost business unlink
acknowledgement, lost private unlink acknowledgement, restart and replay, plus
existing staging cancellation cases. Full Go regression is recorded in
`2026-10-12-publication-cancel-checkpoints-full-go.txt`. These do not claim complete
SQL/publication-window cancellation or fleet/browser acceptance. Original scope
and production capability restrictions remain unchanged; the goal is active.

Recovery also rehashes any still-present private material after the business
unlink checkpoint. The additional changed_retained_stage case in the full-Go
evidence proves unexpected replacement bytes are preserved rather than reclaimed
solely because an older unlink intent exists.


## SQL admission for interrupted publication cancellation (2026-10-12)

The target now has a distinct publication-abort admission using the same full
immutable cancellation unit/object/roster/source-proof validator. It accepts only
verified, aborting or aborted unaccounted target journals and rejects published
receipts. Initial fresh source proof, absent live business metadata, local read
fences and exact target identity are mandatory. An exact retired recording
ownership tombstone may remain; a live or mismatched recording cannot enter this
path. Existing deletion-based shadow admission still requires published/deleting/
deleted receipts, so the two accounting histories cannot be conflated.

Admission persists aborting plus the zero-commit pending unit and leaves target
reserved bytes untouched. Per-object failures are durable and require a fresh
validated source proof to clear. Internal byte-abort completion records aborted;
only dual-peer unit cancellation subsequently refunds the still-held reservation
once. No used-capacity refund, business ownership reversal or new SQL state/schema
generation is introduced. Ordinary staging Abort now rejects every unfinished
publication-cancelling checkpoint, including already-unlinked business paths, so
it cannot bypass retained private-byte proof on replay.

`2026-10-12-publication-abort-admission.txt` and
`2026-10-12-publication-abort-admission-mysql.txt` cover actual SQLite/MySQL
admission/retry/metadata/published-receipt rejection and reservation replay checks.
`2026-10-12-publication-abort-admission-full-go.txt` includes private checkpoint
recovery/race checks and full Go regression. These repository tests intentionally
do not assert that the native service has removed business links; native metadata
checks and media/recording coordinated unlink plus authenticated worker integration
remain the next required work. Original full delivery scope remains active.


### Native interrupted-publication cancellation adapters

Added media and recording `MigrationCancelPublication` adapters for the verified SQL / publishing byte-checkpoint window. Each derives the byte specification from the authenticated immutable peer binding, repeats publication-abort admission under the existing volume mutation coordinator, and removes only a regular business hard link sharing the private anchor inode. The receiver persists cancellation intent, rehashes actual private bytes, and records business unlink before removing private bytes. SQL abort completion occurs only after an aborted checkpoint and a final coordinated business-path absence check. Live/accounted metadata, foreign inodes and corrupt bytes are retained and rejected. Target used stays zero and reservation remains until whole-unit reconciliation.

Executed actual filesystem + embedded SQLite tests in the isolated development checkout, using bounded Docker Go runtime and `-race`. Media cases cover normal cancellation, same-byte foreign inode, corrupt bytes and missing business link; recording cases cover the same faults for plain and encrypted-lyrics footer snapshots. Successful cases replay a lost acknowledgment. These adapters do not yet connect the interrupted-publication window to the authenticated HTTP worker or Master runner. The encrypted recording fixture checks opaque footer-bound transfer bytes; it is not browser encryption playback acceptance.

Evidence: `2026-10-12-native-publication-abort.txt` and `2026-10-12-native-publication-abort-full-go.txt`. Source CI ran 201 Python tests (two optional skips), policy/schema checks and JavaScript smoke checks. No new schema generation, public capability advertisement, production operations or branch publication.

Remaining: authenticated interrupted-publication worker/runner and accounted-publication checkpoint recovery; complete cancellation edge cases; physical inventories, safe retirement, GUI/CLI, upgrade and multi-node recovery; SQLite/MySQL native TLS/fleet/browser/resource acceptance. Overall request is still incomplete.


### Authenticated publication-abort worker and Master reconciliation

Connected the native interrupted-publication cancellation adapters to `data/unpublish` and the existing joined worker (one bounded queue, task/object deduplication, no additional service). Initial requests validate the immutable roster through read-only status authorization, then persist the cancellation fence using the fresh source proof. Polling consumes that fence; a lost queued worker requests a fresh grant before rescheduling. Actual worker failures persist and surface as `unpublish_failed`, requiring explicit task retry. Completion returns the exact aborted/unlinked checkpoint only after the SQL abort receipt. Nginx acceleration remains rejected for destructive migration operations.

The Master cancellation runner first attempts publication abort after ordinary staging abort conflicts. SQL-accounted publications reject that admission and continue through the existing shadow deletion/refund protocol. Both terminal receipts are checked against the exact immutable byte specification. Source ownership stays authoritative for uncommitted units; reserved target capacity is reconciled only by whole-unit cancellation.

Added actual raw-HMAC/Gin/files/SQLite runner fixtures injecting an audit-trigger SQL rollback after native business-link creation, then cancelling media and plain/encrypted recordings. Tests recover lost publication-abort, unit and task acknowledgments under fresh fenced epochs. Media also checks corrupt target rejection/durable failure and repaired retry. Original source business reads remain valid, recording client AES decryption succeeds, and target used/reserved converge to zero without changing personal quota. Existing SQL-accounted media/recording shadow cancellation tests remain green under `-race`.

Evidence: `2026-10-12-authenticated-publication-abort.txt` (targeted race), `2026-10-12-authenticated-publication-abort-full-go.txt` (full Go). Source CI remains within its existing budget. These are real byte/file/database fixtures, not native TLS fleet or browser acceptance. No public migration capability was enabled.

Remaining: SQL-accounted publication with a lost byte-checkpoint write; full cancellation/fleet/reverse coverage; physical inventories and retirement; GUI/CLI; upgrades/multi-node recovery; required native/browser/resource acceptance. Overall goal remains incomplete.


### Accounted publication with an unfinished byte checkpoint

Closed the published SQL / publishing byte-checkpoint cancellation window. `RetireDeletedAnchor` now accepts that exact checkpoint only after its caller proves the current version-bound managed deletion, and after rehashing the retained task-private bytes. It records historical publication and anchor-retirement intent together before unlinking. Verified-only staging, missing anchors without an unlink intent, denied deletion admission and corrupt bytes remain rejected. This does not publish a new business copy, repeat SQL accounting or reopen a task.

Actual file tests exercise the interrupted publishing checkpoint, deletion admission failure, corruption, unexplained missing bytes and verified-only refusal, plus idempotent retirement replay. Raw-HMAC/Gin/SQLite runner fixtures for media and plain/encrypted recordings restore the persisted prior publishing checkpoint after real SQL publication, then cancel and recover lost shadow/unit/task receipts. The original source remains the business owner and its real business reads succeed; recording client AES decryption and personal quota remain intact. Target used/reserved and private bytes reconcile to zero. The disk-checkpoint fault is deliberately injected in isolated test files; it is not a host power-loss acceptance claim.

Evidence: `2026-10-12-accounted-publication-checkpoint.txt` (targeted race) and `2026-10-12-accounted-publication-checkpoint-full-go.txt` (full Go). Source CI retains its original budget and optional skips. No schema change, public capability advertisement, production operation or publication.

Remaining: complete cancellation admission/restart edge cases and reverse migration; bounded physical inventories, backup/orphan/transaction retirement blockers, safe final revocation; GUI/CLI; approved upgrade and multi-node recovery; native SQLite/MySQL TLS/fleet/browser/resource acceptance. Full request remains incomplete.


The first full regression exposed a fixture ordering error (`2026-10-12-accounted-publication-checkpoint-first-full-go.txt`): immutable logical-ID order differed from fixture filename order. The media interruption fixtures now select the actual target business link and byte count before injecting subsequent faults. Their publication stop condition checks any task-bound fixture path. Production accounting was not changed to accommodate the test assumption. Repeated targeted race tests and the final full regression are recorded separately.


### Fresh reverse migration, real bytes and business reads

Verified the existing protocol supports a new reverse plan/task after forward migration finishes. Added media and plain/encrypted-lyrics recording fixtures that complete forward transfer, whole-unit cutover, managed source cleanup and dual final receipts, explicitly release the task-owned source drain, then create a separate reverse task. Fresh reverse plan proofs hash actual source files and check target business paths are absent. Reverse execution reuses authenticated Master relay, native publication, persistent accounting, retention checks, managed deletion and final receipts; it does not directly reverse business ownership in SQL.

The fixtures check original logical IDs and paths, physical relationship mapping for recordings, source business downloads after the round trip, unchanged recording encryption descriptors, client AES decryption and personal quota. Master and both Storage ledgers converge to the round-trip owner/used totals with zero reservations; retired recording descriptors are reused only for the same logical recording and original opaque ciphertext. This reuses implemented behavior rather than adding a second reverse protocol.

Evidence: `2026-10-12-reverse-media.txt`, `2026-10-12-reverse-recordings.txt` (actual files/embedded SQLite/raw-HMAC Gin fixtures with race detection) and `2026-10-12-reverse-migration-full-go.txt`. Source CI preserves existing policy/budget and its two optional skips. Only fixture retention timestamps are advanced; production retains the one-hour grace. Recording encryption here is the existing encrypted-lyrics footer, not an audio encryption or browser acceptance claim. The tested round trip is Direct→Relay→Direct using in-process authenticated transports; it is not a native TLS four-mode fleet acceptance.

Remaining: cancellation admission/restart edge cases; bounded physical inventories and backup/orphan/transaction retirement blockers; safe final revocation and GUI/CLI; approved upgrades/multi-node recovery; required native SQLite/MySQL four-mode TLS/fleet/browser/resource acceptance. Overall goal remains incomplete, and public migration capability is still not advertised.


### Bounded rooted physical observations

Added `internal/resourceinventory` as a read-only filesystem scanner for subsequent native inventory integration. It traverses every rooted entry, including hidden/nested paths, and reports regular files, directories, symlinks and special entries without following links or opening file contents. It retains at most 64 directory handles/frames, 64 entries per page, one pending entry and one replay page. Entry JSON is capped at 48 KiB per page plus bounded response metadata; paths are limited to 4096 bytes. Directory identity/mtime checks reject active namespace changes, errors invalidate the session, and only an exact latest-page retry or next sequence is accepted. Restart does not adopt an old cursor.

The metadata digest is an observation prefix, not a content SHA or atomic snapshot. Logical byte totals count regular paths (including multiple hard links and sparse logical lengths); they do not represent physical allocated/releasable bytes or quota. Previously completed subtrees still require the caller's mutation/version admission. Unsupported names, excess depth, missing or unreadable entries stop the scan; no incomplete observation is marked complete. The package performs no writes and borrows rather than closes the authorized root.

Actual Linux filesystem/race tests cover 300 nested small files, hidden backup/transaction/private-stage paths, unmanaged files, a 17 GiB sparse file, hard links, an external symlink and an internal loop, exact page replay, invalid/restarted cursors, active directory mutation, deep trees and cancellation. Long control-character paths also force byte-bound pages and verify pending entries are neither lost nor duplicated. Evidence: `2026-10-12-bounded-physical-scanner.txt` and `2026-10-12-bounded-physical-scanner-full-go.txt`. Source CI retains its normal budget and two optional skips.

Remaining: bind scanner sessions to authenticated native identities/roots/expiry; classify entries against actual media, recording, backup and transaction facts; reconcile physical observations with complete version-bound planning and independent final retirement checks. Safe retirement, GUI/CLI, upgrade/multi-node recovery and native SQLite/MySQL TLS/fleet/browser/resource acceptance remain incomplete. This scanner alone does not authorize deletion or node revocation, and public migration capability remains unadvertised.


### Authenticated native physical inventory sessions

Connected rooted observations to `/internal/v1/resource-inventory` in the actual native Storage and normal runtime registration paths. Requests use existing HTTPS/raw-body authentication and nonce protection, require the currently active upstream Master/Follower relationship, and bind the member ID, Master ID, relationship ID and fixed configured `data` scope. No caller-specified path/URL/root/expiry is accepted. Responses contain relative entry metadata and bounded observation pages, never file contents, credentials or private key values. This scope covers the configured DataRoot; it does not claim to enumerate external mounts outside that root.

One scan/replay cache is retained per runtime. A random server incarnation prevents a restarted or expired session from adopting old cursors. Open acknowledgment replay preserves the original five-minute expiry; page replay preserves sequence and prefix counts. A joined local expiry loop closes idle handles, and native HTTP shutdown cancels page work and closes the session/root. Completed or closed scans release capacity for a new observation. The session is observational, not a persisted migration fact or a retirement/deletion grant.

Actual rooted-files/SQLite/raw-HMAC Gin tests verify hidden media and backup-path observations, unsigned rejection, foreign member/scope rejection, no arbitrary root parameters, a single active scanner, open/page acknowledgment replay, and revoked relationship rejection even for a cached terminal page. Session tests use an injected clock for expiry, incarnation changes on restart, foreign-binding rejection, sequence checks, close replay and borrowed-root ownership. The real native Storage route fixture also passes. The initial run revealed that the shared generic control JSON decoder ignores unknown fields; this new endpoint now uses strict decoding. The configured root was never replaced by the ignored parameter. Both initial evidence and corrected results are retained.

Evidence: `2026-10-12-authenticated-physical-inventory-first.txt`, `2026-10-12-authenticated-physical-inventory.txt` (targeted race) and `2026-10-12-authenticated-physical-inventory-full-go.txt`. Source CI preserves its budget and optional skips. These tests are not a native TLS fleet or real five-minute idle acceptance.

Remaining: classify observations against media/recording/backup/transaction facts and reconcile a complete version-bound plan; inventory external state/configured mounts where required; independent final retirement checks and safe revocation; GUI/CLI; approved upgrades/multi-node recovery; native SQLite/MySQL four-mode TLS/fleet/browser/resource acceptance. Public migration capability remains unadvertised and the overall goal is incomplete.


### Native inventory metadata facts and conservative blockers

Added a bounded `PhysicalInventoryRepository` projection and native page classifications. Each page uses a short read-only SQL snapshot, rechecks the local Follower identity and active upstream relationship, and classifies observed paths against exact local media identities, recording member/user/relationship/size bindings, cold backup manifests and compact chunk markers. Backup marker queries read only the bounded SQL prefix/length rather than entire legacy payloads. No accounts, crypto keys, credentials or private identity key columns are queried by this projection. Matching media/recording/backup resources remain retirement blockers; unexpected names, identity/length conflicts, links/special entries, private migration materials and native transaction/quarantine materials remain explicit concerns. Business-backup files without a verified manifest mapping are retained as backup material.

Native classification facts are cached with the original session/page so acknowledgment replay cannot change them after a database mutation. Expiry is rechecked after SQL work. Per-entry fact JSON has a 400-byte cap, and scanner pages reserve that space within their existing 48 KiB data budget. No path string is duplicated in the fact array. Neither metadata SHA nor a stored backup ready state asserts current file content integrity. Unknown node-state files and retained terminal metadata still require further reconciliation before a final retirement result can pass.

Real SQLite metadata tests cover managed media/recordings, cold artifacts/chunks, mismatched lengths, private stages, quarantine files, unknown files, unsupported links and incorrect identity/path requests, with quota and task counts unchanged. Actual-file/raw-HMAC Gin tests verify managed/unmanaged/backup classifications and unchanged replay facts despite an injected metadata change. Adding a managed object correctly makes ordinary relationship revocation fail; the test injects a revocation fact solely to verify stale authentication cannot read a cached terminal page. No resource is deleted by that test. The first run's fixture errors (a missing mandatory chunk timestamp and its previous no-resource revocation assumption) are retained in the initial evidence file.

Evidence: `2026-10-12-physical-inventory-facts-first.txt`, `2026-10-12-physical-inventory-facts.txt`, `2026-10-12-physical-inventory-facts-full-go.txt`, and `2026-10-12-physical-inventory-facts-mysql.txt`. The isolated schema acceptance now includes the new read-only projection test on MySQL as well as SQLite; Storage production remains embedded SQLite. Source CI's hosted budget is unchanged.

Remaining: expected-but-missing resources, bounded logical manifests, external state/mount coverage, terminal metadata and transaction reconciliation, complete version-bound planning and independent final retirement checks. Safe final revocation, GUI/CLI, approved upgrade/multi-node recovery and native four-mode TLS/fleet/browser/resource acceptance remain incomplete. Public migration capability stays unadvertised; metadata classifications alone grant no deletion, migration or retirement permission.


### Expected media/recording manifests and missing-file observations

Added independent local-metadata keyset pages for media and ready recordings, exposed through the authenticated inventory session's `expected` action. Media pages include all audio/video rows without visibility filtering; recording paths use the exact upstream/user/recording mapping and local member ownership. Pages return at most 16 items and cap encoded manifest data at 32 KiB, using object-ID cursors rather than OFFSET or an in-memory full roster. No account/lyric/private-key payload is returned. Plaintext media's expected length remains unknown locally and must be reconciled with authoritative Master metadata; ciphertext and recording lengths retain their available metadata facts.

Expected paths are probed under the already pinned configured data root. Each ancestor is checked for links/types and rechecked for identity/metadata changes; no file content is read. Missing, unsupported, invalid, changed and unverified paths are distinct from present files, and known length mismatches are reported. Session identity/expiry is checked before and after work, while acknowledgment replay preserves the original manifest and presence observations. This is an observation sequence, not an atomic multi-page snapshot or an integrity/deletion/retirement grant.

Actual-files/raw-HMAC Gin tests remove an exact fixture file while retaining its metadata and verify the authenticated expected page reports it missing. Presence tests cover regular files, missing ancestors, directory substitution, symlink ancestors and traversal refusal. SQLite/MySQL metadata tests iterate more than two keyset pages, retain hidden and physically absent media rows, and check recording relationship mapping/expected length. Existing classifications remain unchanged and read-only.

Evidence: `2026-10-12-expected-inventory-initial.txt`, `2026-10-12-expected-physical-inventory.txt`, `2026-10-12-expected-physical-inventory-full-go.txt`, `2026-10-12-expected-physical-inventory-mysql.txt`. Native production Storage still uses embedded SQLite; the MySQL run verifies the shared repository dialect. Source CI remains within its existing budget.

Remaining: expected backup/chunk manifests, complete logical/physical/version reconciliation, external mount/node-state and terminal transaction metadata coverage, independent final retirement checks and safe revocation. GUI/CLI, approved upgrade/multi-node recovery and native four-mode TLS/fleet/browser/resource acceptance are still incomplete. Migration capability remains unadvertised and the overall goal remains active.


### Expected backup generations, chunks and backing distinctions

Extended authenticated expected-inventory pages with backup and backup-chunk resources. Canonical composite keyset cursors preserve Master/generation/index ordering and paginate both current and historical foreign-Master generations; re-pairing cannot hide retained SQL recovery records. The projection reads manifest fields and bounded marker prefixes/lengths, never full SQL payloads or file contents. Existing 16-item/32 KiB page limits remain. Cold files retain their precise expected paths and decoded marker lengths; legacy database payloads and pending generations return separate backing/state observations without fabricated physical paths or integrity claims.

Real embedded SQLite cold-backup tests use the existing Begin/Append/Commit protocol, then remove an exact artifact or still-receiving chunk and confirm metadata inventory and rooted missing-file observations remain. The initial fixture incorrectly expected receiving chunk rows after Commit; inspection confirmed the established protocol materializes the final artifact and deletes chunk rows. The corrected fixture uses separate ready and receiving generations, reusing existing behavior. SQL projection tests cover more than two pages of legacy/historical generations, composite cursor validation and foreign-Master inclusion. Authenticated Gin tests verify database-backed backup observations remain explicitly unverified. Initial and corrected evidence are retained.

Evidence: `2026-10-12-expected-backup-inventory-first.txt`, `2026-10-12-expected-backup-inventory.txt`, `2026-10-12-expected-backup-inventory-full-go.txt`, `2026-10-12-expected-backup-inventory-mysql.txt`. Storage runtime remains SQLite; shared repository dialect tests also execute on isolated MySQL. Source CI retains the existing budget and optional skips.

Remaining: complete logical/physical/version reconciliation and verification of backup replacement/retention; terminal node-state/transaction metadata and external mount coverage; independent final retirement checks and safe revocation. GUI/CLI, approved upgrades/multi-node recovery and native four-mode TLS/fleet/browser/resource acceptance remain incomplete. No migration capability advertisement or retirement/deletion authorization is added by these observations.


### Independent retirement SQL blocker ledger

Added a read-only retirement ledger for the authoritative Master and local Follower repositories, plus an authenticated peer `ledger` inventory action. The check pins the current member/relationship/role, rejects Master Local and foreign members, and returns stable blocker codes, counts, at most eight sample identifiers per category, and next-step codes. Resource ownership, recordings, uploads, used/reserved accounting, active migrations/scopes/capacity, live read leases, cold generations/chunks and local unfinished file transactions are inspected. Master additionally reports backup placement/delivery and offline members. Historical terminal peer journals are distinguished from active/orphan task journals in this diagnostic projection.

The response separates `database_clear` from `requires_physical_verification`; empty database facts do not grant retirement, deletion, retention satisfaction or capability expiration. The ledger does not reserve/drain members, revoke relationships, delete SQL facts or touch files. It remains a short bounded diagnostic snapshot and must be repeated under the eventual final retirement admission. The original relationship-revocation path is not replaced by an unchecked SQL-only shortcut.

Actual SQLite and shared MySQL tests cover Master-owned resources/offline members, local media/accounting blockers, task scopes/journals, live read leases, foreign-member rejection, independent backup generations with zero media quota, and an empty ledger still requiring physical verification. Raw-HMAC Gin tests verify the existing inventory session can read the typed blocker report. Quota and business facts remain unchanged. Evidence: `2026-10-12-retirement-ledger.txt`, `2026-10-12-retirement-ledger-master.txt`, `2026-10-12-retirement-ledger-full-go.txt`, `2026-10-12-retirement-ledger-mysql.txt`. Source CI retains the existing budget.

Remaining: complete member-specific transaction/reference coverage, physical/node-state and terminal metadata reconciliation, verified backup replacement/retention, capability/read lifetime handling and a fenced final revocation transaction with explicit source confirmation. Master coordinator and GUI/CLI, approved upgrades/multi-node recovery, native four-mode TLS/fleet/browser/resource acceptance remain incomplete. No public migration capability or automatic retirement permission is enabled.


### Master retirement observation coordinator

Added `internal/noderetirement.Service.Check` to combine the Master ledger with an authenticated native inventory session. It binds member, Master and relationship identity; validates session expiry, page sequence, entry/byte totals and cumulative observation digest; consumes bounded physical and expected-resource pages without retaining a full roster; caps diagnostic categories and samples; and rereads both ledgers at the end. Session close runs on success and failure with an independent bounded context. Expected missing files and database-backed unverified backups remain explicit concerns, and all backup generations require separate retention handling. The report is always `preflight_only`; `observation_complete` means the bounded observation sequence completed, never that final retirement is allowed.

Executed on the isolated development checkout at 192.168.6.201 using Go 1.26.8 Docker with 2 CPUs/3 GiB: `go test -p=2 ./internal/noderetirement ./internal/httpapi -run TestNodeRetirementCheck -count=1 -v` and `go test -race -p=2 ./internal/httpapi -run TestNodeRetirementCheck -count=1`. The actual-files/SQLite/raw-HMAC Gin fixture streams 90 small files over multiple pages, reports a missing managed media path and an independently retained backup, bounds samples, rejects tampered sequence/binding/digest/cursor responses and offline peers, closes failed sessions, and leaves migration tasks/drains untouched. This transport is in-process HTTP, not native TLS/fleet/browser acceptance. Full `go test -p=2 ./...` passed. Source CI passed with its existing 201 Python tests and two optional skips plus JavaScript/policy/crypto checks.

Remaining: runtime/admin/CLI exposure, complete authoritative logical/physical/version reconciliation, external mounts/node-state/terminal transaction metadata, verified backup replacement/retention, final fenced retirement/revocation and explicit confirmation. Upgrade and multi-node recovery work and native four-mode/resource acceptance remain outstanding. No migration capability advertisement, relationship revocation or host/volume cleanup is introduced.


### Admin retirement preflight API and node-card UI

The native Master registration path now exposes a retirement observation POST under the existing Admin Nodes API, with established Admin sessions/CSRF, HTTPS, strict member/relationship IDs, unknown/trailing JSON rejection, a four-minute request deadline and one process-wide observation slot. Busy requests return 429. Failed observations return a sanitized 409 with an explicitly incomplete partial report, never raw internal errors. No apply endpoint or revoke shortcut is added.

Active downstream Storage cards in the existing Nodes module now offer a read-only check and display bounded physical/expected counts, both SQL ledgers, missing files, backup retention concerns and repair guidance. Results retain a timestamp across refresh and remain historical observations. Text-only rendering handles paths and identifiers; controls do not treat a completed inventory as final retirement approval. The existing Admin API helper attaches structured error data so the panel can display incomplete reports while preserving normal authentication behavior.

Executed on the isolated development checkout: actual Redis 7.4.11 session/CSRF integration with race detection (`go test -race -p=2 ./internal/httpapi -run TestAdminRetirementRedis -count=1`), paired SQLite/raw-HMAC coordinator tests, and the complete-module DOM fixture `node tests/node_retirement_ui_smoke.mjs`. The tests verify anonymous/missing-CSRF rejection, strict inputs, no-store output, sanitized errors, concurrent 429, slot release, bounded samples, text rendering, retained results and partial failure display. The new bounded DOM test joins existing source CI without changing its budget. The first documentation check rejected a Chinese UI label in the English manual; it was changed to English before rerunning. `go test -p=2 ./cmd/frontiercloud ./internal/httpapi` passed, including Redis-enabled existing HTTP tests; source CI passed after the documentation correction (201 Python tests, two optional skips and the JavaScript/policy checks). Native browser, TLS/fleet and production resource-budget acceptance remain unverified.

Remaining: final fenced admission/revocation with explicit confirmation, complete logical/physical/version and transaction/reference reconciliation, backup replacement/retention, CLI and full migration UI, approved upgrades/multi-node recovery and native four-mode acceptance. The overall goal remains active and migration capability remains unadvertised.


### Retirement transaction and worker-reference coverage

Extended the independent SQL ledger with unfinished member worker jobs, indirect authoritative media references, unassigned orphan work and still-live leases even on completed jobs. Conflicting explicit member/media references block each referenced member rather than trusting only one field. Unrelated explicitly assigned work is not counted. Orphan migration binding records and nonterminal storage journal states remain blockers even when their associated task is marked completed/cancelled.

Master now inspects pending durable file mutation manifests using the existing validated global-rename decoder. Valid small manifests block only their referenced member; malformed, foreign-Master, oversized or unexamined manifests produce `unverified_file_transactions`. The diagnostic projection reads at most eight manifest prefixes of 64 KiB characters, caps samples at eight, and never claims the remaining rows are clear. UTF-8 prefixes may occupy up to four bytes per character; this is a bounded diagnostic projection, not a complete final retirement admission. Follower's existing local file-transaction blocker remains independent. The node UI adds repair guidance for worker jobs.

SQLite race tests and isolated MySQL 8.4.11 repository/schema acceptance exercise direct, indirect, conflicting and orphan worker references, completed jobs with valid leases, valid unrelated rename manifests, malformed/oversized/excess manifests, orphan bindings and incomplete journals hidden behind terminal tasks. Tests leave business rows unchanged except explicitly injected fixture faults. MySQL/schema evidence is retained in `2026-10-12-retirement-transactions-mysql.txt`. Final `go test -p=2 ./...` passed on the isolated Go 1.26.8 checkout (2 CPUs/3 GiB test container). Source CI passed with its existing budget (201 Python tests, two optional skips and JavaScript/policy checks). The native Storage runtime continues to use SQLite; MySQL verifies the shared repository dialect. No final revocation or physical cleanup is authorized by this ledger.

Remaining: complete paged/version-bound mutation and physical reconciliation, recovery/reference and capability lifetime coverage, node-state/external mounts, verified backup replacement/retention and fenced final revocation with explicit confirmation. Migration GUI/CLI, approved upgrade/multi-node recovery and native four-mode TLS/fleet/browser/resource acceptance remain outstanding.


### Thin CLI retirement check through the shared Admin service

Added `fc node retire check NODE_ID --master https://MASTER --credential-stdin`, with optional `--json` and a trusted public `--ca-file`. The command reads a bounded token from stdin, logs in through the established Admin API, keeps cookies only in memory, discovers the server's CSRF cookie name, resolves exactly one active downstream relationship and calls the same retirement API/service as the node UI. It attempts bounded logout, never reads the business database or invokes SSH/Docker, and does not implement retire apply. HTTP, credential-bearing/non-origin URLs, redirects and insecure TLS acceptance are rejected. Network/auth errors are sanitized; typed reports and samples are bounded. Human samples are quoted to avoid terminal escape sequences. Exit 0 means a completed observation with no reported blockers, 1 means reported blockers, and 2 means invalid input/authentication/transport/incomplete observation. Every report remains preflight-only; exit 0 is not revocation permission.

Executed isolated Go 1.26.8/Redis 7.4.11 tests with race detection, including a real TLS Admin listener and the shipping compiled `fc` subprocess. The subprocess received its credential through stdin and its fixture public CA through a file, produced both JSON and human reports, found an actual missing media file through the authenticated peer observation, returned exit 1, attempted logout and preserved the active relationship. Unit/transport tests cover certificate refusal, redirects without credential forwarding, ambiguous/foreign authority, oversized replies, excess samples and incomplete partial reports. Evidence: `2026-10-12-retirement-cli.txt` and `2026-10-12-retirement-cli-native.txt`. Complete `cmd/fc` and `internal/operator` tests and final `go test -p=2 ./...` passed on the isolated Go 1.26.8 checkout (2 CPUs/3 GiB test container). Source CI passed within its existing budget (201 Python tests, two optional skips and JavaScript/policy checks).

The Admin leg and executable are real TLS/process traffic; the Storage leg remains an in-process raw-HMAC Gin/SQLite fixture. This does not establish native fleet, browser, four-mode transport or 1-CPU/512-MiB resource acceptance. Final retirement apply/fenced reconciliation, verified backup retention, full migration GUI/CLI, upgrades and multi-node recovery remain incomplete. The original goal remains active and migration capability remains unadvertised.


### Shared migration administration queries and revision-fenced controls

Added a Master-bound migration administration repository and native Admin registration. Persisted task history uses a 16-row descending composite keyset page, while checkpoint status projects aggregate object/unit stages and at most 16 logical objects with a 48 KiB encoded object-data budget. Status avoids loading the plan, encrypted recording payloads or an in-memory full roster and always returns `retirement_ready=false`. SQL role/Master ownership checks reject foreign tasks. Mutations require the expected task revision inside the existing write transaction, preserve runner epoch/tombstone fencing, reuse existing pause/resume/retry/cancel semantics and audit, and retain cleanup reservations. Stale or concurrent conflicting commands fail rather than silently applying to a newer state.

The existing Nodes module displays paged task history, source/target IDs, errors, committed bytes and explicitly refreshed checkpoint observations, with protected controls and a cancellation semantics prompt. Refresh keeps failed tasks visible from SQL. Displayed target publication is separated from committed ownership. Controls bind both member confirmations and the displayed revision; no new plan/start interface accepting caller disk proofs is exposed. No drain release, retirement or host/volume action is automatic.

SQLite race tests start a repository-validated fixture task, verify read-only stage summaries, foreign-Master rejection, stale/duplicate controls, concurrent resume/cancel fencing and retained reservations, and page more than two sets of task/object fixtures. These injected extra rows prove projection behavior, not validated byte transfer. The first fixture used an incorrect plan column; it was corrected from the actual schema before rerunning. Shared MySQL 8.4.11 schema/repository acceptance passed with the same tests. Real Redis-backed Admin tests verify authentication/CSRF, strict payloads, wrong source/target confirmation and stale revisions. Complete-module DOM tests verify failed-task persistence, bounded checkpoint paging, confirmation payloads, cancellation opt-out and text rendering. Evidence: `2026-10-12-migration-admin-http.txt`, `2026-10-12-migration-admin-mysql.txt`, `2026-10-12-migration-admin-mysql-final.txt`. Full `go test -p=2 ./...` passed on the isolated Go 1.26.8 checkout (2 CPUs/3 GiB test container); the subsequent foreign-Master negative case passed SQLite and MySQL race checks. Source CI passed within its existing budget, including the new bounded DOM test (201 Python tests, two optional skips plus policy/JavaScript checks).

Remaining: fresh authenticated paged plan/start service and its GUI/CLI, explicit task-owned drain release UI/CLI, complete final retirement reconciliation/revocation and backup retention handling, approved upgrades/multi-node recovery and native four-mode TLS/fleet/browser/resource acceptance. Migration capability remains unadvertised and the original goal remains active.


### Migration CLI through the shared revision-fenced Admin service

Added `fc node migrate status|pause|resume|cancel|retry TASK_ID` using the existing short-lived Admin client, TLS/cookie/CSRF contract and the same endpoints as the node GUI. Status supports the bounded logical-object cursor and validates task/Master identity, page bounds, cursor order, stage/byte limits and `retirement_ready=false`. Controls require explicit source/target NodeIDs and `--task-revision`, without deriving confirmations, bypassing the server repository or automatically retrying ambiguous writes. Read-only task status and mutation acknowledgments use separate human messages; neither claims task completion or retirement permission. Quoted paths prevent terminal control sequences. No SQL/SSH/Docker business shortcut is added.

The real compiled `fc` process ran against an isolated TLS Admin listener with Redis 7.4.11 sessions and SQLite task facts. It queried state, paused/resumed, rejected a stale revision, cancelled and retried a fixture cancellation failure; SQL assertions confirmed pending capacity and source draining remained. These task/control rows and failure state are explicitly seeded fixture facts, not proof of a real cancellation byte transfer. Existing authenticated missing-file retirement subprocess checks also passed. Race/transport tests cover foreign acknowledgments, malformed cursors, oversized object counts, invalid bytes, forbidden retirement claims and sanitized conflicts. The first executable test found that global `--revision` consumed the task flag; the task option was renamed to `--task-revision` while preserving the release option. Initial failure and corrected evidence are retained in `2026-10-12-migration-cli.txt` and `2026-10-12-migration-cli-final.txt`. Final `go test -p=2 ./...` passed on isolated Go 1.26.8 (2 CPUs/3 GiB test container). Source CI passed within the existing budget (201 Python tests, two optional skips and policy/JavaScript checks).

Remaining: fresh authenticated paged migration planning/start and its GUI/CLI, explicit task-owned drain release, complete final retirement reconciliation/revocation and verified backup retention, approved upgrades/multi-node recovery and native four-mode TLS/fleet/browser/resource acceptance. The Admin leg is real TLS/process traffic; peer inventory remains a raw-HMAC in-process Gin fixture. Migration capability remains unadvertised and the original goal remains active.


### Explicit task-owned drain release in Admin and CLI

Added a separate Admin `/nodes/migrations/TASK_ID/release-drain` POST and `fc node migrate release-drain` command, retaining the current task revision and both NodeID confirmations. The existing Nodes task card exposes this action only for completed/cancelled tasks and requires typed source NodeID confirmation. It calls the existing runner's authenticated source receipt flow, never the repository's SQL release directly. HTTPS/session/CSRF, terminal-task checks, one bounded handler slot and a 30-second request deadline apply. A missing service, stale revision, wrong member, offline peer or incomplete receipt blocks the release. Source and Master remove only this task-owned migration restriction; no retirement, reversal or host/volume operation follows.

The actual-files/raw-HMAC migration fixture transfers 524351 bytes across a complete parent, recovers lost acknowledgment and failed SQL cutover, verifies target business reads, cleans source transactions with fixture-only grace advancement, and then exercises the new Admin TLS/Redis client path. Wrong-source and stale-revision release requests are refused. Repeated releases and the shipping compiled `fc` subprocess succeed through the same service, with existing SQL assertions confirming that administrator restrictions remain on both Master and source. DOM tests verify terminal-only presentation, exact typed confirmation and the independent endpoint. Evidence: `2026-10-12-drain-admin.txt`, `2026-10-12-drain-cli.txt`. Full `go test -p=2 ./...` passed on isolated Go 1.26.8 (2 CPUs/3 GiB test container). Source CI passed within the existing budget (201 Python tests, two optional skips plus policy/JavaScript checks). The Admin leg is real TLS/process traffic; peer traffic remains the isolated in-process authenticated Gin fixture, not full native TLS/fleet/browser/resource acceptance.

Remaining: fresh authenticated paged migration planning/start and its GUI/CLI, complete final retirement reconciliation/revocation and verified backup retention, approved upgrades/multi-node recovery and native four-mode acceptance. Migration capability remains unadvertised and the original goal remains active.


### Managed object lookup and bounded content observations for planning

Added an exact managed-media/ready-recording lookup that reuses the existing expected-inventory projections and short read-only identity/relationship transaction. It resolves a local object identifier to its scoped physical path and metadata digest, rejects foreign members/Masters/relationships, pending recordings, unsupported backup resources and arbitrary path strings, and does not create migration tasks or reservations. Missing physical files remain represented by metadata; lookup is not a content proof.

Added a borrowed-root content observation utility using one file handle, one 64 KiB buffer, bounded ancestor metadata, exact declared length and SHA-256 of actual bytes. It checks regular-file type and inode/size/mode/mtime before/after opening and after reading, detects observed pathname replacement or mutation, rejects links/special files/traversal, and honors cancellation between reads. Unix opens are nonblocking so FIFO replacement cannot stall before fstat/type rejection. The first low-level test showed that `os.Root` resolves links despite relying on an O_NOFOLLOW flag; explicit pre/post checks replaced that assumption. Initial and corrected evidence remain in `2026-10-12-managed-content-observation.txt` and `2026-10-12-managed-content-observation-final.txt`.

SQLite race tests verify media/recording identity/path mapping, missing/unmanaged/foreign refusal and read-only task facts. Shared MySQL 8.4.11 schema/repository tests passed (`2026-10-12-managed-content-mysql.txt`). Actual-file tests hash more than eight fixed-size buffers of raw byte payload, reject incorrect lengths, final/ancestor links and traversal, inject in-place mutation and pathname replacement during the read, handle cancellation/empty files, and verify FIFO opening does not block. Source CI passed with its existing 201 Python tests, two optional skips and policy/JavaScript checks.

This is a planning foundation, not the finished plan/start service. The utility is not exposed as an arbitrary-file HTTP endpoint and does not itself authenticate callers, freeze writers, verify encrypted footers, allocate capacity or grant deletion. Its inode/size/mode/mtime observations cannot prove an immutable version against arbitrary external writers restoring metadata; the authenticated planner and fenced execution must bind/revalidate versions and actual content facts. Native root/mount mapping, queued read-only observations, complete paged catalog/physical reconciliation, plan/start GUI/CLI, final retirement/backup retention, upgrades/multi-node recovery and native acceptance remain incomplete. Migration capability remains unadvertised and the original goal remains active.


### Queued-work acceptance and anchor retirement recovery

The full regression ended with an actual ten-minute timeout in encrypted recording cleanup, not an observation timeout. Its stack placed Master in anchor-retirement status polling while all peer workers were idle; retained failure excerpt: `2026-10-12-managed-content-full-go-failure.txt`. An active-key response previously reported working even when the active job belonged to another operation. A recheck can finish its durable checkpoint before removing its active marker, allowing a retirement request in that interval to be mistaken for an accepted retirement job.

Busy publish/recheck/retire/cleanup/cancellation submissions now return waiting; only an actually enqueued job reports acceptance. Authenticated status captures worker activity before loading the durable checkpoint, avoiding an idle/stale checkpoint ordering race. Master treats an accepted retirement with an idle worker and unfinished checkpoint as a recoverable cleanup failure, never success or indefinite polling. This also covers a lost queued job or admission rejection before AnchorError persistence. Explicit retry reacquires current lease/proofs and preserves the target owner; no unknown bytes are deleted.

The recording forward/reverse fixture passed five repeated runs after the fix. A deterministic accepted-but-not-dispatched retirement fault then passed twice with race detection, verifying prompt cleanup_pending error, explicit retry, target business bytes/client decryption, identity and personal quota preservation. Evidence: `2026-10-12-anchor-worker-regression.txt`, `2026-10-12-anchor-worker-loss.txt`. Final `go test -p=2 ./...` passed after the worker fix (`2026-10-12-managed-content-full-go-final.txt`), on isolated Go 1.26.8 with 2 CPUs/3 GiB. The resourceinventory Windows branch also cross-compiled; Windows runtime was not exercised. Source CI passed within the existing budget. The managed-content/lookup foundation remains a read-only observation facility, not a completed plan/start or retirement permission service.


### Bounded asynchronous content-observation worker

Added a one-slot, one-thread, joined lifecycle for read-only content observations. Requests bind the observation ID, local member/Master/relationship, media or ready-recording identifier, metadata digest and expected byte count. One active read and one current result are retained; there is no unbounded roster or durable migration queue. Identical request replay preserves the original five-minute expiry and random server incarnation. Changed bindings, concurrent requests, unsupported resources and old incarnations are rejected. Cancellation prevents result publication and keeps the slot occupied until the reader exits; expiry clears prior success, and close cancels/joins the worker without closing observer-owned roots. Errors use bounded stable codes rather than raw diagnostics.

Actual-file tests resolve a trusted fixture callback to the bounded content reader, verify SHA-256, immutable response copies, request replay, busy refusal, foreign result refusal, cancellation, injected-clock expiry, sanitized failure and fresh process incarnation. Five repeated package race runs and full `go test -p=2 ./...` passed on isolated Go 1.26.8 (2 CPUs/3 GiB test container); evidence: `2026-10-12-content-observation-worker.txt`. Source CI passed within its existing budget (201 Python tests, two optional skips and policy/JavaScript checks). This worker is ephemeral observation state: restart never restores a success claim. It does not reserve capacity, create migration tasks, copy files or authorize publication/deletion. The observer contract requires independent current authorization and metadata checks before and after reads; the manager does not turn caller-provided metadata digests into trusted facts.

Remaining: native media/recording root adapters, authenticated RPC registration with current membership/metadata revalidation, encrypted-footer checks and mount mapping, paged migration plan/start and GUI/CLI, full retirement/backup retention, upgrades/multi-node recovery and native acceptance. The worker is not yet connected to a public planning endpoint; migration capability remains unadvertised and the original goal remains active.


### Native managed-content adapters and authenticated observation RPC

Native media and recording services now resolve observations through their own borrowed os.Root handles, including separately mounted roots. The RPC accepts managed identifiers, identity binding, expected byte count and metadata digest, never filesystem paths, fetch URLs or key material. The existing raw-body HMAC/nonce and HTTPS checks require the active upstream Master. Exact local SQL lookup revalidates current identity, relationship and ready metadata on every start/status/cancel request and before/after the worker reads. Media additionally rechecks its own object projection and validates the browser encryption descriptor and ciphertext length. Recording bytes remain opaque; neither adapter decrypts or copies keys. Native mutation read leases cover short admission boundaries, not the whole hash; ContentAt observes inode/path/size/mtime before and after bounded streaming. This is still not an immutable version against arbitrary external writers.

The single joined ContentJobs worker is registered in native business and Storage routers. Shutdown cancels/joins it before native roots close. Status requires the exact original request and server incarnation; changed expected length cannot retrieve cached success. Cancellation removes the observation. Identity/metadata changes make cached results inaccessible. Results grant no publication, deletion, capacity reservation, retirement or migration start. The API remains internal and the migration capability remains unadvertised.

Tests exercise actual native media/recording mount roots, metadata-admission failure after reading, stale locator, wrong byte count, recording recovery fence, unsigned requests, unknown path/URL/key fields, stale metadata, actual 190000-byte SHA-256, status request mismatch, cancellation and revoked authentication. The disposable SQLite test first confirms managed media blocks ordinary revocation, then injects only that fixture's revoked relationship to test old credentials. Initial test failures came from unsupported canonical-JSON fixture values, an incomplete repository substitute, reuse of a JSON decode destination retaining an omitted pointer, and attempted revocation correctly blocked by managed files; retained logs document those corrections.

Remaining: recording footer/projection validation beyond opaque bytes, current native mount inventory and physical capacity reports, immutable content version fencing for plan/start, paged planning and GUI/CLI, backup retention and final fenced retirement, approved upgrades/multi-node recovery and full native acceptance. Neither this work nor a successful Go regression completes the original goal.


Validation: the authenticated/native/content-reader tests passed twice with race detection, followed by full `go test -p=2 ./...` on the isolated development host (Go 1.26.8, 2 CPUs/3 GiB test container). Evidence: `2026-10-12-native-content-observation-final.txt`. An additional opaque encrypted-media fixture verifies exact byte hashing with valid metadata and refusal of malformed ciphertext lengths; two race runs passed (`2026-10-12-native-content-encrypted-descriptor.txt`). This tests descriptor/length handling, not decryption or GCM authentication. Source CI passed within its original budget (201 Python tests, two optional skips and JavaScript/policy checks). No native five-node TLS/browser or 1-CPU/512-MiB acceptance is claimed, and this RPC's new exact lookup relies on the earlier SQLite/MySQL repository evidence rather than a newly run MySQL RPC scenario.


### Actual native mounts in independent retirement observations

Physical inventory registration now borrows the exact media and recording os.Root handles used by native services. Three fixed scopes (data/media/recordings) share one scanner slot and retain the existing HMAC/nonce, HTTPS, local-member/upstream-Master binding, incarnation, fixed expiry and bounded pages. No request supplies host paths or arbitrary mounts. Data-root scans omit descent into media/recording defaults only when their inode identity matches the actual native root; two pinned exclusions are rechecked on open and before/after pages. Directory replacement fails the observation. Separately mounted roots are scanned independently, and any regular file in an unused default subtree is reported as unmanaged residual data rather than managed native content. Links/special files remain unsupported blockers. Expected media/recording presence resolves at the actual native mounts, including missing managed resources.

Retirement check requires all three authenticated scope observations, independently recomputes per-scope count/byte totals and SHA-256 page transcripts, and performs the final SQL ledgers after the last scope. Sessions are closed on transitions and failure. Missing volume support, malformed identity/sequence/digest, omitted scopes or invalid filesystem capacity make the check incomplete, with no legacy implicit completion. The report includes scope entries, logical bytes, transcript digest and current filesystem total/free bytes. Free values may refer to shared filesystems and are never summed into target capacity; writability remains explicitly unverified. These observations are not reservations, frozen versions or final revocation permission. Native roots remain service-owned and are not closed by the inventory lifecycle.

CLI and existing node panel display scope observations and the shared-filesystem limitation. The typed CLI client requires bounded ordered scope records, valid transcript hashes and totals matching the aggregate before accepting a completed report. UI DOM checks verify text rendering and the capacity/writability explanation. Tests verify one slot across scopes, default-file deduplication, changed mount identity refusal, legacy-root scope denial, external media/recording mounts, actual mounted file bytes, unused default copies, expected native presence and refusal of unknown scopes. The external-root fixture initially lacked native required category directories and initially inserted recordings before promotion (correctly blocked). It also assumed media was the only file, then assumed paired node-state files were at the top level. The corrected independent tiny-fixture filesystem walk counts all native regular bytes, including nested node state; failure logs are retained. No production guard was relaxed for these fixture corrections.

The real TLS Admin/Redis fixture and compiled fc retirement CLI passed using all three authenticated scope observations (`2026-10-12-native-volume-retirement-cli.txt`, isolated Redis 7.4.11, Go 1.26.8). The peer RPC leg is the existing in-process authenticated transport, not a native multi-node TLS acceptance. The external mount regression passed twice with race detection (`2026-10-12-native-volume-external-mounts.txt`). Source CI passed within the existing budget (201 Python tests, two optional skips, policy and JavaScript/DOM checks). This change has no database schema or SQL change; it does not replace the outstanding SQLite/MySQL native fleet acceptance.

Remaining original work includes reconciliation/classification of node state and terminal native transactions, verified backup replacement/retention, immutable plan/start fencing and paged planning plus GUI/CLI, final safe retirement, approved upgrades and multi-node recovery, and full native fault/browser/resource acceptance. Unusual overlapping configured roots can yield separate namespace observations; their aggregate is not unique physical disk usage. Goal remains active and migration capability remains unadvertised.


Final native-volume verification: all selected RPC, cross-scope session, external-root, fault-response and typed-client regressions passed twice with race detection; full `go test -p=2 ./...` then passed on isolated Go 1.26.8 (2 CPUs/3 GiB test container). Evidence: `2026-10-12-native-volume-inventory-final.txt`. The actual compiled CLI/TLS/Redis test and source CI were executed separately and passed. Test failures preceding the final run are preserved in the inventory race/fixture logs. No final retire apply, native five-node/browser acceptance, 1-CPU/512-MiB resource proof or new MySQL RPC execution is claimed.
