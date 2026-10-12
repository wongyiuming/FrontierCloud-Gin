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
