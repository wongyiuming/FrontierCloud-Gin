# Parallel implementation checkpoint

The owner requested parallel execution of the remaining requirements. Work
continues on `dev` from `0fb4a9a`; this is a working-tree checkpoint, not a
release, production deployment or full acceptance report. The original scope
remains unchanged.

| Original requirement | Active responsibility | Completion boundary |
| --- | --- | --- |
| 1. Architecture and development discipline | All implementation lanes; coordinator reviews integration | No new branches, production changes or destructive shortcuts |
| 2. Published-image delivery | Operations lane | Reuse existing pinned bundle; public publication remains an external gate |
| 3. Thin operator commands and inspection | Operations lane | Recheck existing behavior; protect restart during incomplete recovery/upgrade |
| 4. Backup, recovery and approved upgrade | Operations lane plus coordinator for native backup retention | Real Compose upgrade and coordinated multi-node recovery remain required |
| 5–6. Complete node migration and ownership/encryption | Migration lane | Preserve IDs, complete parent units and opaque bytes; backups handled separately |
| 7. Plan, drain, copy, verify, cutover and cleanup | Migration lane | Add authenticated plan/start and repair cancellation before target admission |
| 8. Durable controls and safe retirement | Retirement lane plus coordinator for backup retention | Final write fence, fresh physical/SQL proof and tombstone must all hold |
| 9. Existing Nodes UI and common CLI service | Migration and retirement lanes | No SQL/SSH business bypass; no new top-level module |
| 10. Isolated acceptance | Coordinator with lane-specific fixtures | Both databases, native fleet/TLS/browser/fault/resource tests remain distinct |
| 11. Documentation and final evidence | Coordinator consolidates lane evidence | Full requirement audit required before claiming completion |

Implementation runs concurrently in assigned file areas. Remote tests use
coordinator-controlled snapshots so unfinished shared changes cannot alter an
already running test. Formatted files are fetched before the next source push.
The isolated Go test container uses Go 1.26.8, 2 CPUs and 3 GiB; this does not
prove the product's 1-CPU/512-MiB runtime budget.

## Executed evidence

- Backup SQL/cold-file authenticated observations, actual SHA/length checks,
  and missing/nonempty/held lock behavior passed race tests. The Master client
  additionally rejects identity, generation, hash, length, path, incarnation
  and expiry drift. See `2026-10-12-backup-observation-final.txt`,
  `2026-10-12-parallel-cancel-backup.txt` and the HTTP package results in
  `2026-10-12-parallel-integration-first.txt`.
- Cancellation before target admission passed actual byte and lost-receipt
  tests for full and unwritable targets. The immutable local cancellation-only
  marker does not reserve or refund capacity that was never admitted.
- Native terminal checkpoint observation passed file and authenticated RPC
  tests. First integration found that its strict decoder rejected the new
  cancellation marker. That failure is preserved in
  `2026-10-12-parallel-integration-first.txt`; the corrected repository and
  actual cancellation/RPC tests passed in
  `2026-10-12-parallel-integration-second.txt`.
- The authenticated migration plan test observed real source bytes and actual
  target filesystem conflicts without creating a task, drain or reservation.
  Planner worker tests and operator/CLI package race tests passed in the second
  integration log. Upgrade tests use real recovery archives and a simulated
  Docker runner; they are not native Compose upgrade acceptance.
- Source CI passed at its existing budget, including 201 Python tests with two
  optional skips and existing policy/JavaScript checks. See
  `2026-10-12-parallel-source-ci.txt`. Later UI changes require their own check.
- The stable integration snapshot subsequently passed full `go test -p=2 ./...`
  and the isolated SQLite/MySQL 8.4.11 schema/business race gate. See
  `2026-10-12-parallel-full-go.txt` and `2026-10-12-parallel-mysql.txt`.
  The new cancellation-only, retained-checkpoint and bounded backup manifest
  tests ran against MySQL. The cold-file lease case deliberately skips MySQL
  because native Storage uses SQLite; that case passed separately on SQLite.
  These logs precede later retirement-fence and UI/CLI edits and do not validate
  those later edits.
- Real private Compose SQLite acceptance then exercised approved upgrade,
  independent CLI backup, isolated restore/activation/open, original NodeID and
  media ID, priority and actual HTTP Range bytes. Web ran at 1 CPU/512 MiB/no
  swap; post-upgrade idle samples were 0.29/0.26/0.27/0.19/0.32 percent.
  `2026-10-12-upgrade-native-sqlite.json` records the actual image IDs. Public
  release proof was explicitly injected; source and target fixture images
  contain the same tested binary and differ by a test label, so this proves
  native image-switch orchestration, not compatibility of two public releases.
- `2026-10-12-parallel-plan-cli.txt` records real TLS Admin/Redis and a compiled
  `fc` plan/status/start subprocess. It rejects unknown disk proofs and a
  same-length source-byte change before admission, then starts a fresh plan and
  performs actual peer transfer and target reads. The peer leg is authenticated
  in-process Gin transport, not native fleet/TLS/browser acceptance.

- The same actual Compose upgrade/restore sequence passed with a MySQL Master;
  see `2026-10-12-upgrade-native-mysql.json` and its transcript. Injected target
  preparation failure left the site fenced with its verified recovery archive.
  The first acceptance driver misparsed Compose's JSON-lines status output;
  that original failure remains in `2026-10-12-upgrade-native-failure.txt`.
  After fixing only the parser, the full failure scenario passed in
  `2026-10-12-upgrade-native-failure-final.json` and its transcript.
- Coordinated local backup/check/extraction, archive generation compatibility
  and operator command packages passed race tests in
  `2026-10-12-parallel-recovery-set.txt`. These are real archive/OS-lease tests
  with a simulated Docker runner; coordinated native activation is separate.
- The first final-retirement fence test rejected the native media premaster
  key as unmanaged. Its failed transcript is retained in
  `2026-10-12-parallel-retirement-fence.txt`. The corrected native classifier
  verifies the recorded key identity and pinned inode, and rejects altered,
  missing, replaced and unknown sibling files. These cases, held reader
  barriers, lost retirement acknowledgement, CLI/HTTPS checks and explicit
  capability negotiation passed race tests in
  `2026-10-12-parallel-retirement-second.txt`. Later late-PUT and identity-reset
  fixes require their own run.
- Generation 7 preserves the generation 6 assets and adds formal paged-plan
  tables. SQLite schema tests passed in `2026-10-12-generation7-schema-first.txt`;
  the native fleet entries in that log are explicitly skipped, not executed.
  SQLite/MySQL 4/5/6-to-7 preservation and interrupted-DDL replay, followed by the
  prior stable business implementation's MySQL race tests, passed in
  `2026-10-12-generation7-mysql-third.txt`. The first launch failed before
  testing due to a shell line ending; the second could not allocate a Docker
  subnet. Only empty networks whose project and fixture directory were proven
  by this task's recovery reports were removed. See
  `2026-10-12-owned-empty-networks.txt`; archives, volumes and data remain.
- Generation 7 release/operator/recovery/CLI race tests passed in
  `2026-10-12-generation7-release-first.txt`; the runtime command package had
  one obsolete literal-generation expectation. Its correction needs a rerun.
  The paged implementation's first compilation found an unused import and
  made no runtime assertions (`2026-10-12-paged-migration-compile-first.txt`).

## Remaining original work

The paged plan/start, retirement fence and coordinated recovery lifecycle are
implemented. `2026-10-12-paged-migration-second.txt` records selected race tests
for paged admission, late authenticated requests and upload staging fences.
`2026-10-12-paged-cli-retirement-tls.txt` records actual TLS, Redis and compiled
`fc` plan/status/start, authenticated peer byte transfer and Admin retirement.
The peer transport in that test is in-process; it is not the native fleet.
`2026-10-12-paged-fault-set-latest.txt` adds actual paged-task cancellation,
recovery, reverse migration and encrypted recording reads, plus recovery-set
cancellation refencing and journal tamper rejection. Its native seed tests are
explicitly skipped pending the Compose driver.

`2026-10-12-large-migration-mysql.txt` passes a 10,008-object catalog exceeding
16 MiB, including admission rollback, commit replay and accounting. The same
SQLite race test times out at ten minutes in catalog conflict scanning; see
`2026-10-12-large-migration-sqlite.txt`. This is an unresolved performance
failure, not evidence of acceptable scale. The first full generation-7 suite
also found obsolete fixture constants; their corrected tests pass in the
paged fault transcript, while a fresh full suite remains in progress.

Remaining original gates include large-catalog performance on SQLite, private
native five-node migration and browser acceptance, actual coordinated Compose
recovery, actual generation-6-to-7 upgrade, and first-install success/failure
coverage. Published-image installation cannot be claimed from private test
images, and this task does not authorize publishing or production operations.
Backup resources still independently block retirement; no retention/purge
feature is required to bypass that permitted safe outcome. A ready-byte backup
observation cannot authorize deleting a sole recovery point.

### Serial continuation and corrected migration baseline

Parallel agents have stopped at the owner's request; their changes are retained.
The previously listed remaining gates are historical: private installation
profiles/failure guards, native coordinated recovery, real generation-6-to-7
SQLite/MySQL upgrades and bounded 10,008-object SQLite planning now have separate
executed evidence. They still require the final coherent source acceptance.

`2026-10-12-native-sqlite-dd-second/evidence.json` reports actual native SQLite
Direct-to-Direct migration and real Chromium decryption/Range success. Its images
implement the superseded Master byte-relay design, so it is not evidence of the
new direct-only baseline. It did not select the actual one-hour cleanup wait.

The owner prohibits migration relay in every circumstance. The Relay node type
is a business deployment option, never permission to relay migration through
Master. The new source-signed, target-identity-proved direct protocol replaces
Master read/append calls; old relay endpoints reject authenticated requests.
Cancellation now runs a fresh bounded source-local hash worker and returns proof
metadata. Peers must explicitly advertise `resource-migration-direct-v1`; there
is no legacy relay fallback. `2026-10-12-direct-migration-security-race.txt` passes
the migration/capability regression selection across node, protocol,
migrationdata, resourcemigration and HTTP packages. Tests cover actual bytes,
persisted retry, source corruption, encrypted recording migration, forbidden
relay, endpoint/key/version/range binding, replayed target nonces, and unreachable
source preserving staging offset and original ownership. HTTP routing is real
in-process; this is not native socket/TLS or new five-node image acceptance.

The owner additionally requests durable heavy-task queuing, automatic yielding
to external HTTP byte traffic, sustained low-traffic resume and detailed AdminGUI
progress. That scheduling and traffic-load acceptance are still pending. The
native acceptance topology must now prove direct peer transfer and separately
prove that unreachable peers stop safely; its old forced-relay fixture must be
replaced before new native acceptance can be claimed.

### Traffic-aware queue implementation and current evidence

Serial development now counts actual in-flight Go HTTP body reads/writes with
bounded five-second counters and a one-second burst check. Relay business data
routes count; migration/control and migration UI polling are excluded. The
256-KiB/s stop threshold, 64-KiB/s resume threshold and thirty-second continuous
quiet interval have controlled-clock and actual response-byte regression tests.
Tasks keep durable intent, reservations, drains and checkpoints during automatic
waiting. Manual pause invalidates its lease and is never automatically resumed.
Queue/attention and historical task paging are separate; dispatch and reported
queue position share the same eligibility predicate, including cleanup grace.
Source-local and target integrity scans yield without recording traffic deferral
as corruption. Destructive operations refresh proofs after traffic deferral.
Nodes displays queue position, waiting node, rates/thresholds, stage, current
object/byte offset and failures, with bounded automatic status polling.

`2026-10-13-migration-traffic-race-final.txt` passes the full migrationdata race
suite and the traffic/migration/checkpoint regression selection in
businesstraffic, resourcemigration, HTTP, business store, operator and native
HTTP registration. `2026-10-13-migration-queue-paging.txt` and
`2026-10-13-migration-traffic-ui-final.txt` pass bounded ascending queue cursors,
terminal-history exclusion, traffic/wait details and existing retirement UI
smoke coverage. These are in-process/DOM evidence, not native load acceptance.
The earlier partial-cancellation failure exposed a real atomic journal-read
race. Read-only status now pins a complete regular journal inode before opening
it and accepts that immutable snapshot during atomic replacement; binding/hash
validation and strict mutation-file checks remain. Its concurrent save/status
regression passes. Earlier failing logs are retained.

Nginx X-Accel traffic bypasses the Go counter. Until gateway sampling is connected,
accelerated deployments are held with `edge_traffic_unavailable`; they must not
execute based on a false quiet observation. That gateway integration, current
MySQL traffic/queue coverage, real direct-only five-node/CPU/browser/fault and
one-hour cleanup acceptance, complete coherent-source CI and the final original
requirement audit are still outstanding. All previous relay-image native/browser
results remain evidence of that older implementation only.

### Gateway traffic sampling component acceptance

Nginx now loads a small native counter module built against its pinned 1.30.4
source archive SHA-256. It samples actual request-length/sent-byte changes,
without reading payload buffers or altering sendfile flags. One timer per active
worker tracks long responses across internal redirects; idle workers have no
sampling timer. A bounded shared ring preserves counters/epoch across reload.
Counters contain no paths, identities, bodies or credentials. Their read-only
handler rejects TCP and serves only the shared Unix socket. Web's single joined
poller validates format/version/epoch/freshness, combines gateway and Go rates
without proxy double counting, and restarts the quiet interval after an epoch
change. Missing/stale gateway observations still retain queued work.

`2026-10-13-nginx-traffic-native-upload.json` passes actual HTTP/1.1 sendfile and
HTTP/2 X-Accel transfers that remain unfinished after eight seconds, partial
abort, real 79-byte Range, TCP rejection, reload epoch retention, actual 4-MiB
upload and observation-traffic exclusion. Both unfinished download modes observe
roughly 512 KiB/s; upload also crosses the stop threshold before completion.
The private Nginx fixture has one CPU, 128 MiB and two workers. Its Go byte sink
and redirect upstream are test-only fixtures, not a business application/fleet
acceptance substitute. Only its exactly labeled container was removed; evidence
and fixture files remain.

`2026-10-13-gateway-traffic-go-second.txt` passes gateway epoch/freshness, malformed
sample rejection and joined Unix-socket polling race tests. The complete
businesstraffic/operator/deployment race suites pass in
`2026-10-13-gateway-traffic-recovery-compose.txt`. Master Compose shares the
disposable `traffic_runtime` IPC volume with Web read-only; backup/restore exclude
it from recovery data without relaxing unknown-volume protection. The shipping
Nginx Dockerfile builds successfully as private image
`frontiercloud-ops-test:01a13082-gen7-nginx-traffic` (id `2e15aa9b2178`).

The native harness now mounts the counter socket and uses reachable peer
networks for normal migration. A separate unreachable-peer selection must prove
refusal instead of relay. Its certificate observer's test-only timeout now
permits the existing real one-hour cleanup gate. Harness compilation succeeds;
that command skipped native execution because no fleet opt-in was supplied.
Coherent app/CLI/fleet binaries are being rebuilt in `.ci-out/direct-traffic`.
Native direct-only SQLite/MySQL/four-combination/load/browser/fault/cleanup
acceptance, complete source CI and the final original requirement audit remain
outstanding. No publication, main merge or production operation was performed.

### Serial direct-only fleet verification and peak-traffic correction

Current private coherent application/edge images pass actual five-node SQLite
and MySQL Direct-to-Direct migration, post-restart accounting and real Chromium
decryption/cross-chunk Range acceptance. Both migrate fifty managed objects and
135,660,064 payload bytes. Source copies remain in the normal one-hour grace;
neither run selected the real cleanup wait. Synthetic ID3 fixtures do not prove
audible decoding. Evidence is in `2026-10-13-native-direct-traffic-sqlite-dd/`
and `2026-10-13-native-direct-traffic-mysql-dd/`.

`2026-10-13-native-direct-proof-sqlite-dr/` additionally passes Direct-to-Relay
with actual Docker network byte counters: Master Web ingress plus egress is
4,589,421 bytes during migration, source egress is 183,867,984 bytes and target
ingress is 185,755,161 bytes for the same 135,660,064-byte payload. These aggregate
counts supplement the direct protocol/path tests; they are not a packet capture
or a claim of zero Master signaling. Real Chromium and bounded cgroup/idle CPU
checks pass in that run.

The gateway now checks the merged one-second burst as well as the five-second
rate. Its regression rejects a gateway-only short sendfile burst even before the
five-second average peaks, then requires the complete quiet interval.

The first real peak-load run, retained in `2026-10-13-native-traffic-peak-sqlite-dd/`,
failed its first-visible-wait observation check: a fresh peer refusal could still
display the previous cached quiet sample. The runner now validates the refusal's
authenticated fresh traffic view and replaces the cache before displaying wait;
it also includes a fresh Master view. Unknown peers, running/quiet views and
stale observations are rejected. The focused race suite passes in
`2026-10-13-native-traffic-fresh-wait-build.txt`. The fresh private image
`sha256:becc53b7e256` and second real run now pass in
`2026-10-13-native-traffic-peak-sqlite-dd-second/`: actual business traffic holds
the on-disk receiver checkpoint at 2,097,152 bytes, thirty seconds of continuous
quiet permits continuation, and manual pause holds 3,407,872 bytes for another
32 seconds until explicit resume. The fifty-object migration subsequently
commits and passes native restart/ownership, real Chromium decryption/Range and
five-node idle CPU checks. The entire run takes 254.85 seconds. Master Web total
network traffic is 9,324,455 bytes, including the longer control-observation
interval; source egress is 189,779,441 and target ingress 185,886,352 bytes.
The earlier failure is not counted as successful load acceptance. No real grace
cleanup was selected in this load case.

The native driver now has an explicit separate `--no-direct` refusal scenario.
It isolates source/target peer networks and requires a direct-transport failure,
zero committed bytes, source ownership and zero target journal offsets. Actual
SQLite Direct-to-Direct refusal now passes in
`2026-10-13-native-direct-refusal-sqlite-dd/` (98.29 seconds): mutually unreachable
native peers fail with `direct_peer_transfer`, all source ownership remains and
target journal offsets stay zero. Five-node idle CPU checks also pass. Full
four-combination SQLite/MySQL,
real source cleanup, final coherent-source CI and the original whole-spec audit
remain pending. Work remains serial, on dev, with no public release or production
operation.

### Full matrix, MP3 decoding and remaining long-run gates

The `becc53b7e256` private runtime now has actual native cutover/browser evidence
for all four Direct/Relay combinations on SQLite and MySQL. MySQL peak-traffic
and manual-pause acceptance passes in `2026-10-13-final-native-go-mysql-dd-traffic/`.
The remaining audio matrix is in `2026-10-13-audio-final-*`; the SQLite
Relay-to-Direct case is `2026-10-13-native-audio-sqlite-rd-second/`. These optional
cases use privately generated MP3 tones: real browser decoding, encrypted
decoding, continuous transition on the same media element and original Master
lyric relations all pass. No encoder is added to a product process/image.
Headless decoding is not described as physically audible output. The first
Relay-source fixture omitted CSRF on its Master upload; that client defect and
the lyric fixture's incorrect use of `target_dir` are corrected without relaxing
server authorization or path rules. Earlier failures remain retained.

The all-package Go race run passes in `2026-10-13-final-go-race.txt`; it predates
the latest planning-read admission changes. Those changes now yield before
catalog work and at bounded source hash reads, with focused race and authenticated
HTTP proof in `2026-10-13-content-observation-traffic-race-final.txt`. Native
coherent-image acceptance of the planning changes remains outstanding. The fresh
private image is `7dd3bb9088ec`, built using the actual CI runtime packaging path.
Both CI image labels now match schema generation seven, and the CI Web package
includes the approved-upgrade/recovery-set operator documents. All 201 Python
source checks and JavaScript smoke checks pass; two platform-specific Python
checks are skipped.

The selected real one-hour cleanup/retirement run did not complete: after
1784.48 seconds an IP-policy SQL lookup exceeded its normal two-second deadline.
No cleanup/retirement success is claimed. Private diagnostics show deadline
errors, not a Redis shutdown. The concurrent isolated MySQL store suite also
lost its server to a Docker-recorded OOM; an unrelated `fc-win11-dev` OOM event
was observed but that container was not modified. Subsequent long-run acceptance
will avoid overlapping database stress. Ordinary security enforcement is not
weakened and product memory limits are not raised.

Full MySQL store-suite isolation exposed older tests retaining local media in
one shared database, which correctly prevented an empty-node retirement. The
fixture now optionally allocates a fresh explicitly prefixed database per call,
matching SQLite. It never adopts an existing database. Successful private test
databases are reclaimed after all assertions/caller cleanup; failures retain
their evidence. The dedicated development helper additionally bounds table
caches within the same 768-MiB/no-swap server budget. Full MySQL race/schema and
10008-object validation now pass in `2026-10-13-mysql-isolated-final/` with the
same 768-MiB/no-swap, one-CPU server and no OOM. The 10008-object admission/commit
case takes 69.04 seconds; 22 heartbeat attempts have no recoverable-busy errors,
and the largest successful-heartbeat gap is 17.07 seconds. Each temporary
database is fresh, and successful test databases are reclaimed after assertions.
Prior failed logs are not passes.

Five old, empty, labeled fixture networks exhausted Docker's default address
pool. Cleanup checked exact names/owner, age over thirty minutes, no project
containers and no driver, and removed only those networks. All data/volumes were
retained; evidence is `2026-10-13-obsolete-empty-network-cleanup.json`.

The goal remains active. Latest complete-source verification, native planning
load behavior, successful real grace cleanup and independent post-migration
retirement, and the final original requirement audit remain required. The browser
driver additionally supports two real handoffs: during a native large-object
copy and after ownership cutover/restart. That new during-copy gate is compiled
but not yet counted as executed acceptance. The latest complete-source race run
has passed in `2026-10-13-final-go-race-preflight.txt` (`go test -race -count=1
-p1 ./...`). A new isolated SQLite Direct-to-Direct acceptance now uses image
`sha256:7dd3bb9088ec61750e9b5e89c5b6b33655d2cbc8671a73c43321ed71dd288338`
and the compiled during/after browser harness with actual MP3 playback and
lyrics, real one-hour cleanup grace, and independent source retirement. Evidence
is being written under `2026-10-13-preflight-native-during-cleanup-retire/`;
this run is pending and must not be counted as a pass. Database stress is not
overlapped with this run.
