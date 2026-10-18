# Authenticated resource migration planning

The Master exposes planning in the independent Node resource migration module
beside Nodes, and through the same Admin HTTPS API used by `foc` (`./fc` in a bundle). A plan observes managed source bytes and target
filesystems before an administrator explicitly starts a durable migration task.
Both peers must explicitly advertise `resource-migration-direct-v1`. A peer without
that declaration produces a blocking plan; legacy capability fallback never
grants migration support.

Migration data is strictly source-to-target, including Direct/Relay mixtures.
The node's Relay type does not permit migration relay through Master. Master
passes only control metadata and a short-lived source-signed grant bound to the
task, lease, immutable object version, source endpoint and target public key.
The target proves its own identity for each bounded chunk; the source checks
the active Master relationship and persistent task again. Chunk responses bind
the target nonce and are signed by the source. Target staging and disk validation
retain the existing restart and publication transactions. The old Master read,
append and cancellation-read endpoints reject requests. No fallback exists.
Cancellation hashes the authoritative bytes on the source's joined local worker,
returning only a fresh observation proof. Unreachable peers must retain both the
source authority and resumable target staging; repair connectivity before retry.

## Scope and authorization

`POST /api/v1/media/admin/nodes/migration-plans` accepts exactly a random
`request_id`, `source_id`, and `target_id`. Existing Admin authentication, HTTPS,
CSRF checks and request bounds apply. Both members must be Storage followers of
the same current Master. Master Local and self-migration are rejected. There are
no caller-supplied paths, URLs, physical-capacity values, hashes or disk proofs.

The caller polls `GET /api/v1/media/admin/nodes/migration-plans/{plan_id}`.
The response contains at most 16 objects and 48 KiB of object metadata. `after`
uses the returned object cursor. Each object identifies its complete immediate
parent ownership unit, native source and target locators, logical identity and
metadata version. Hidden objects are included by the underlying catalog; a
browser listing or visibility filter is never used to select the migration.

The service has one joined planning worker and a single current plan. Its
30-minute observation deadline does not depend on the lifetime of the initiating
HTTP request. New competing observations are rejected while that worker is
active. Same-request retries reuse the current observation without extending its
lifetime. Ready and blocked previews expire after five minutes. A new preview can replace
an inactive preview; a process restart invalidates previews. Started tasks are
stored in SQL and survive both cases. Generation 7 also persists bounded preview
headers and object observations in `migration_plan_headers`,
`migration_plan_bindings`, and `migration_plan_paths`. These observation records
do not reserve capacity, drain a member, change authority or create a task.
Expired observations may be replaced; admitted bindings remain immutable audit
and recovery facts.

## Evidence collected

The Master uses existing HTTPS raw-body HMAC relationship authentication and
nonce protection to request bounded inventories for the actual `data`, `media`
and `recordings` roots. It validates exact member/Master/relationship/scope
bindings, process incarnations, fixed session expiry, page sequences, cumulative
counts, byte counts and rolling transcript hashes. Sessions close on completion
or failure.

Native expected-media and ready-recording pages must agree with the complete
Master roster. Each source object is then hashed by the peer's bounded native
content-observation worker. The Master verifies the exact request, native path,
metadata digest, length and SHA-256 response. Encryption metadata must match the
Master catalog; bytes remain opaque and no media decryption key is sent.
Recording hashes must also agree with their existing complete-recording hash.
Queued or running observations cannot provide a usable content result.

Target scans reject occupied destination paths, non-directory ancestors and
files already occupying selected immediate-parent units, including unmanaged
files. Reports retain at most 64 blocker samples while counting every conflict;
reaching the sample limit never skips the remaining inventory transcript.
A final Master catalog read rechecks identity bindings, object versions,
healthy relationship state, quota and concurrent transaction blockers.

The report lists source backup items and physical residual concerns separately.
They are not silently included in a media migration or declared safe to erase.
Successful migration does not clear backup retention or independent retirement
gates. Unknown physical files can remain a retirement blocker even after all
managed resources have moved.

Capacity uses the minimum observed free space across the actual native roots,
reserves the existing physical safety margin, and accounts for persistent target
reservations and logical allocation. Free values are never added across roots
that may share a filesystem. This is intentionally conservative for separate
filesystems. Read-only observations do not perform write probes; the report
preserves `writable_verified: false`. Actual target admission and publication
still use native storage readiness, quota, filesystem and transaction checks.

## Explicit start and recovery

`POST /api/v1/media/admin/nodes/migration-plans/{plan_id}/start` accepts exactly
`review_sha256`, `confirm_source_id` and `confirm_target_id`. The reviewed digest
is generated by the service from its private plan. Start schedules another full
authenticated source-content and target-inventory observation. A changed source
hash, object roster, identity binding, conflict or insufficient capacity rejects
the start. A same-length change on disk cannot reuse the old metadata version to
get the previous review accepted.

After that revalidation, the existing `StartMigration` transaction persists the
task, source drain, complete-unit scopes, object proofs and target reservation.
The durable task ID equals the plan ID. Fresh observation timestamps and capacity
facts give the stored task its own plan digest; the review digest remains the
identity of the preview the administrator approved. Repeated identical starts
return the same task. A lost start response can be investigated using the normal
migration task status API with the known plan ID.

The existing runner then performs authenticated streaming copy, target-byte
verification, complete-unit publication and ownership commit, grace-period
cleanup, recovery and explicit controls. Planning does not implement a second
copy engine or bypass those transactions.

A target whose first copy admission failed because of quota or configured
writability can still register cancellation-only reconciliation. Its immutable
local peer-plan record contains `cancellation_only: true`; its task reservation
is zero. It cannot be changed back to queued or paused to admit copying. Native
abort must still prove staging absent or safely removed, full object rosters and
both unit/task receipts are required, and unrelated reservations are never
refunded. Actual disk errors or unknown staging bytes remain explicit cleanup
failures. Clearing a diagnostic error does not erase the admission fact.

## Heavy task scheduling and progress

Admitted tasks already form a durable SQL queue, executed by one joined Master
runner. There is no new message broker. The default Nodes view lists nonterminal
queue/attention items oldest first; history remains available separately. Both
lists use bounded sixteen-task pages. A task's `queue_position` uses the actual
dispatch eligibility, so paused work and cleanup whose one-hour grace has not
expired are never counted as runnable ahead of another task.

The Master and both storage peers measure actual business HTTP body reads and
writes during streaming. Internal media/recording reads and upload routes count
as business traffic when they carry Relay business data. Heartbeat, migration,
inventory and migration observation traffic do not create a feedback loop.
Counts contain no request bodies, credentials or path history. Rates cover five
seconds; a one-second burst is also checked. At 256 KiB/s work stops requesting
new chunks. It resumes only after thirty continuously observed seconds at or
below 64 KiB/s. Startup uses the same quiet observation interval. Hysteresis
keeps running work stable between those thresholds.

Plan generation also waits for low Master traffic before catalog work. The
authenticated source-content observer yields before opening a file and between
64-KiB reads, retaining its pinned file and incremental hash while waiting. No
SQL transaction or native mutation lease is held during that wait. Cancellation
joins the worker. Read-only preview/content observations retain their existing
five-minute freshness limits; an expired preview must be regenerated and does
not authorize a task. Admitted migration tasks remain durable independently of
preview expiry.

Traffic waiting retains `queued`/execution phase plus the persistent controlled
code `waiting_business_traffic`. It neither clears the reservation nor changes
the source drain/authority. A manual pause invalidates the runner lease and never
auto-resumes. Polling and peer lease renewal continue during traffic waiting; the
low-traffic interval does not consume execution-stage timeout budgets. Source
and target recheck local load before each new chunk; local integrity scans yield
at bounded reads. Traffic deferral never marks bytes as corrupt. Before resuming
a deferred destructive operation, the Master obtains fresh byte proofs and
reissues its exact-object authorization.

The Admin status API supplements SQL facts with an optional five-second-fresh
`execution` observation: current phase/object, persisted peer byte offset,
current-object size, transfer rate, waiting node and up to three node traffic
views. Those observations grant no commit/resume authority and are rebuilt from
peer checkpoints after process restart. SQL stage totals and identity/ownership
facts remain independently available. Nodes polls at most four visible active
tasks per refresh, and exposes manual refresh plus bounded object pages.

For `NGINX_MEDIA_ACCEL=true`, the gateway's bounded shared counters measure actual
Nginx request-length and sent-byte changes, including HTTP framing. They observe
ongoing HTTP/1.1 and HTTP/2 streams and X-Accel redirects without reading/copying
payloads, changing sendfile flags, or using declared Content-Length as traffic.
One worker timer samples active requests; idle workers have no polling timer.
Classification survives internal redirects, and graceful reload preserves the
shared epoch/counters. No path/credential history is stored. The status handler
rejects TCP and serves only the shared Unix socket. One joined Web poller merges
its rates with Go's observations using a maximum to avoid proxy double counting.

The `traffic_runtime` volume is disposable IPC/counters, not recovery data.
Missing, malformed, stale or unsupported gateway observations retain the task in
the queue. A new gateway epoch restarts the thirty-second quiet interval. Waiting
alone cannot turn missing facts into low traffic, and disabling acceleration is
not an automatic fallback. Full coherent-image fleet and load acceptance remain
required in addition to component tests.

## CLI commands

Credentials enter through stdin; they are not command-line arguments. Use the
same trusted Master origin and optional `--ca-file` for all commands:

```sh
fc node migrate plan --from SOURCE_NODE_ID --to TARGET_NODE_ID \
  --master https://MASTER --credential-stdin --json
fc node migrate plan-status --plan PLAN_ID \
  --master https://MASTER --credential-stdin --json
fc node migrate start --plan PLAN_ID --review-sha256 REVIEW_SHA256 \
  --confirm-source-id SOURCE_NODE_ID --confirm-target-id TARGET_NODE_ID \
  --master https://MASTER --credential-stdin --json
fc node migrate status PLAN_ID --master https://MASTER --credential-stdin --json
```

`plan` and `start` return promptly with observation state. Poll `plan-status`
until `ready`, `blocked`, `failed`, `expired` or `started`; use `--after` to inspect
additional object pages. Exit 0 means a valid response (which may still be an
ongoing observation). Failed plans include a controlled `error_stage` (`catalog`,
`source_inventory`, `source_content`, `target_inventory`, `seal` or `admission`)
without peer URLs or response bodies. Nodes and the CLI display that stage.
Exit 1 means a blocked/failed/expired plan; exit 2 means
invalid input, authentication, transport or response-validation failure.

## Current limits and acceptance boundary

New plans use `frontiercloud-paged-migration-v1`: a small signed-content header
references immutable object rows and streaming catalog/proof digests. Planning,
execution, cancellation, cleanup and peer completion consume keyset pages of at
most 64 objects. Native target path checks use indexed path/parent/ancestor
locators. Unit cutover compares the complete version transcript and updates the
whole unit with a SQL subquery in one transaction; it never turns a page boundary
into an ownership boundary. Unit and task receipts retain the existing wire
digest while hashing sorted rows without building a complete JSON array.
At admission, each new unit stores its complete sorted object/proof digest in
the existing unit record. Shadow cancellation checks the exact object, current
source ownership/version and fresh source-byte proof. A target establishes its
unit digest by inspecting the complete roster once, then uses that durable fact
across process restarts. Both Master and peer terminal receipts still validate
the whole roster; a sealed digest never substitutes for final reconciliation.
Split-directory checks consume one binary-ordered SQL row stream and retain only
the current directory's ancestor stack, avoiding repeated scans of large units.
Content observation checks queued jobs immediately once, then backs off from
25 to 250 milliseconds while work remains pending. Small files do not each incur
the transfer runner's fixed polling interval.

The prior 10,000-object / 16-MiB format remains supported for existing generation-6
tasks and bounded internal compatibility readers. New Admin plans do not use
that format. Generation 7 is additive and requires the matching generation-7
runtime; an older runtime rejects its marker. The schema journal and DDL replay
tests cover upgrades from generations 4, 5 and 6 for SQLite and MySQL.

Observation sessions and jobs retain finite deadlines. A timed-out or changed
plan must be observed again; no partial catalog can be started. The isolated
repository test can enable `FRONTIERCLOUD_TEST_LARGE_MIGRATION=1` to exceed both
legacy limits and inject an admission-transaction fault. That repository test
uses fixture proof facts and does not replace native byte-transfer acceptance.
`FRONTIERCLOUD_TEST_SHADOW_SCALE=1` checks bounded per-object SQL growth for
128/1,024-object units and exercises rollback, fresh repository recovery, stale
actors/proofs and corrupt sibling rejection at terminal reconciliation.
`FRONTIERCLOUD_TEST_LARGE_NATIVE_PLAN=1` exercises 10,008 actual native files
through signed inventory and content-worker calls; it is separate from the
five-node transfer and browser gates.

The development-only `tests/native_migration_acceptance.py` driver also accepts
`--many-small-files`. It uploads 1,024 additional real files into one immediate
parent through normal site-type upload reservations, then migrates the complete
node. That unit spans sixteen object pages. The driver samples its logical owner
during copying, rejects a mixed source/target directory, and verifies every
published target and retained source file against its actual original SHA-256.
The existing large-file, memory, control responsiveness, restart, logical metadata
and browser gates remain enabled. This option is an executable acceptance gate;
its presence or successful compilation is not an executed result. Run SQLite and
MySQL cases separately on the isolated development host. `TMPDIR` may select a
disk-backed private parent for retained fleet data; browser disposable shared
memory is kept separate from that root-only parent.

Planning and cancellation tests cover real native source bytes, target unmanaged
collisions, zero side effects on tasks/drains/reservations during observation,
same-length byte changes before start, lost cancellation receipts and targets
that never admitted copying. Separate TLS/Redis and compiled-CLI tests exercise
the Admin boundary and use the resulting plan to copy and read actual bytes.
Test execution evidence belongs in the audit logs. DOM smoke tests protect the
migration-module integration and safe text rendering; they are not browser or five-node
acceptance evidence. All original SQLite/MySQL, Direct/Relay, browser playback,
fault-window and one-CPU/512-MiB acceptance gates remain necessary before the
capability is advertised.
The multi-page ownership observer uses SELECT-only queries on the exact private
fixture database during copying. Repeated full-directory HTTP observations are
real business traffic and can correctly keep the quiet gate closed; acceptance
does not exempt them or relax traffic thresholds. Final directory and byte reads
still exercise the authenticated business APIs.

Transfer verification and publication remain asynchronous peer jobs. Their
control observation begins with a 50-ms wait and backs off to 100/200/250 ms
while pending, instead of imposing two fixed 250-ms delays on every small file.
Long-running jobs retain the 250-ms polling ceiling. Traffic admission and
durable verification/publication facts remain required before ownership commit.

## Admin entry

Use the independent **Node resource migration** module for plans, the persistent queue, history, checkpoints and task controls. Pairing, capacity, certificates and safe retirement remain in **Node management**, where node summaries are initially compact and details open only on request. Each module has its own refresh and errors; moving this presentation does not change the authenticated API, direct peer transfer or ownership transaction.
