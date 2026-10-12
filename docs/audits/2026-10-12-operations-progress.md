# Operations and resource migration implementation checkpoint

This is an **in-progress** implementation ledger, not final acceptance or a
published release. The requested goal remains active. Nothing was merged,
published, deployed to production or migrated on real nodes.

## Source and development scope

- Work began on clean `dev` at `a6f8e3a5ec960578bc0d08b070afbddc2370243f`.
- No branch outside dev/main was created; main was not modified.
- Implementation presently consists of working-tree changes on dev.
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
only synchronized verified recovery material. It does **not** activate an
instance, and explicitly returns restore/business readiness as false. Full
instance activation and coordinated cluster restoration remain incomplete.

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

## Required remaining work

1. Finish restore activation/selection rebinding and consistent multi-node recovery
   sets, with real MySQL backup/import/business verification and failure handling.
   Add read-only target space/compatibility planning and retain explicit ownership
   of the maintenance state; never reopen failed recovery automatically.
2. Add approved upgrade plan/apply using explicit target release, preflight,
   independent recovery point, generation compatibility/migration, pinned switch
   and actual business verification. Cross-generation code rollback is not DDL
   rollback. No upgrade/recovery API belongs in AdminGUI.
3. Implement formal shared SQLite/MySQL schema migration for persistent resource
   migration tasks, ownership units, checkpoints, reservations, draining causes
   and scope/runner locks. Historical schema assets must remain immutable.
4. Implement read-only whole-node migration plans bound to identities/content
   version, including hidden/encrypted media, directories, owned recordings/other
   managed files, backups, physical/logical capacity and conflict inventories.
   Reject Master Local this round unless the same safe protocol can be proved.
5. Add persistent execution with bounded authenticated Master-relayed bytes for
   all Direct/Relay pairs, target task staging, disk SHA-256 proofs, idempotent
   publication journals, complete-parent ownership-unit SQL cutover and cache
   invalidation. No network I/O inside long SQL/global-exclusive transactions.
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
