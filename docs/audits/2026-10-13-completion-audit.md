# Operations, migration and retirement completion audit

This is a requirement audit, not a release approval. The complete original
eleven-section specification and the later direct-only/HTTP-traffic scheduling
instructions remain the scope. Branch is `dev`, based on
`0fb4a9a9b9717c2f7892c3cb63465633c62ee7af`; working changes are not yet an
exact-source published release. No production node or retired staging system
was operated. Private fixture image proofs do not establish public availability.

## Evidence scopes

- [Complete Go race run](2026-10-13-final-go-race-preflight.txt):
  `go test -race -count=1 -p1 ./...`. Packages pass; tests requiring explicitly
  selected external services/fleets can skip. This is not a five-node gate.
- [Fresh MySQL store/schema acceptance](2026-10-13-mysql-isolated-final/evidence.json):
  complete repository/schema race tests, including 10,008-object admission and
  commit, on a fresh one-CPU/768-MiB/no-swap MySQL instance. No OOM.
- [Paged recovery fault set](2026-10-12-paged-fault-set-latest.txt): actual
  native files and authenticated in-process HTTP, with publication/checkpoint,
  cancellation, reverse, capacity and recording faults. Transport is routed
  through test HTTP engines; it is not Docker-network fault evidence.
- [CLI/Redis/TLS acceptance](2026-10-12-paged-cli-retirement-tls.txt): real
  compiled operator client, authentication/CSRF and signed peer observation.
- [Operator requirements 1–4](2026-10-12-operator-requirements-audit.md):
  installation, restoration, recovery-set and approved-upgrade evidence, with
  private provenance adapters and explicit inbound/publication limits.
- Five-node cases own one Master, two Direct and two Relay nodes, private TLS,
  Redis, embedded Storage SQLite and SQLite or MySQL Master. Web is limited to
  one CPU/512 MiB/no swap; normal transfers include 50 actual objects, one
  128-MiB object, ciphertext, hidden objects and independent parent directories.
  Native Source/Target byte hashes, logical metadata, restart, Range and
  retirement-blocking assertions are executable checks, not static counts.

## Original requirements and acceptance

| Requirement | Current implementation and authoritative evidence | Remaining scope or limit |
| --- | --- | --- |
| Development/release discipline | `CONTRIBUTING.md`, `dev` checkout, repository/CI policy checks | Final exact-source commit and successful dev CI are still required. Staging is explicitly retired; no merge/publication authorized. |
| One Master, SQLite/MySQL only, Storage resource role | Native five-node SQLite/MySQL cases; architecture and role assertions | No HA, additional runtime, fleet upgrade or Docker socket in business Web. |
| Public-image Master/Direct/Relay install without host compilers | `cmd/fc`, `scripts/get-fc.sh`, Compose/operator bundles; native installation matrix | New artifacts are private fixtures until reviewed main publication; no public availability claim. |
| Latest verified main selection and immutable manifest | Release verification, `.fc-images.json`/deployment receipts and restart binding | First selection resolves once; no independent latest component drift. Actual public proof is outside private fixture evidence. |
| Architecture/platform/digest/pull errors and no build fallback | Registry/release and install subprocess error tests; native pull failure | Failures retain safe categories; no automatic compile. |
| Concise config, old role/environment compatibility | First-install manual, existing Compose/env examples and startup contract checks | Database/role/path changes never mean data migration. |
| `doctor`, `install`, `status`, `logs`, `diagnose` | CLI handlers and native install/readonly guards; operator audit | Inbound 80/443 and write probes remain unverified unless independently proved; status does not invent playback success. |
| Existing database, keys, identity, mount/project/volume protection | Native installation matrix and repeat-install race tests | New install rejects nonempty state, including renamed project/data roots. |
| Diagnostics and evidence privacy | Allowlisted structured diagnostics; prior scoped secret scan | Repeat scan on final deliverable still required. Raw fixture diagnostics remain private. |
| `backup create/verify`, `restore check/apply` | Operator/recovery code, SQLite and MySQL restored business/Range evidence | Archive hashes alone are not restoration proof. Cold SQLite includes WAL; MySQL uses logical export and external-writer attestation. |
| Complete-state inventory and coordinated cluster recovery | Recovery manifest classes, simultaneous native leases and native two-node recovery-set acceptance | One local Docker engine; unknown cross-host/external writers are not silently declared frozen. |
| `upgrade plan/apply`, precheck/backup/failure fence | Actual generation 6→7 SQLite/MySQL upgrade and injected preparation failure | No implicit DDL rollback or automatic reopening. Publication adapters are identified as fixture-only. |
| Storage→Storage four combinations | SQLite/MySQL eight-case matrix below | Latest image repeat and latest during-copy browser checks remain in progress. |
| No migration relay under any circumstances | Source delegate/target pull grants; direct-byte security test; actual isolated-peer refusal in SQLite/MySQL | Unreachable Source→Target safely fails, preserving source owner/checkpoint. Relay node type still governs ordinary business traffic. |
| Same cluster, different members, capacity/health/protocol/writability | Readonly catalog/start tests, target rejection, physical conflict and native plan | MasterLocal migration explicitly rejected. No selective split-unit feature. |
| All managed media, hidden/ciphertext/nested files and recordings | Native media inventory and recording byte/descriptor/footer tests | Backups are inventoried separately and block unsafe retirement; unknown/orphan files are reported. |
| IDs/path/priority/hidden/lyrics/encryption remain stable | Native byte/metadata/Range assertions, actual MP3/lyric browser cases, recording reverse tests | Node identity and decrypt keys do not migrate. Master lyrics remain Master business state. |
| Complete immediate-parent ownership units | Immutable 64-object keyset pages, whole-unit SQL comparison/commit; split/conflict tests | A page boundary is never an ownership boundary. Ciphertext bytes and descriptors are retained without re-encryption. |
| Readonly version-bound plans, logical/physical capacity | Native source-content observation and start recheck; stale-byte/conflict tests | Preview expiration requires a new observation; observing never drains/reserves. |
| Persistent drain/scope and concurrent mutation fencing | Repository migration task/peer tests and native request/volume retirement barriers | Reads/heartbeats remain available; unrelated directories retain admission. No long network SQL transaction. |
| Durable reservations and bounded streams/checkpoints | Atomic target admission/quota tests, 256-KiB direct chunks, persistent prefix/version proofs, native cgroups | Large-file memory is bounded. 10,008 native-file planning is separate from 50-object native transfer. |
| Authorization, expiry, replay and path/range/version checks | Authenticated direct-byte tests and canonical grant parser/nonce ledger | Master sends control metadata only; legacy relay routes refuse. |
| Actual target integrity and failed-copy cleanup | Native Source/Target SHA-256; corrupted prefix, lost receipts, publication/checkpoint tests | Source authority remains until whole-unit commit; temporary copies never count as owners. |
| Atomic metadata/quota commit and distributed reconciliation | SQLite/MySQL transaction tests plus real-file HTTP runner fault tests | Target publication has its own durable journal; there is no claimed cross-host SQL atomicity. |
| New reads resolve target, old reads retain safety | Native post-cutover/restart catalog, Range, browser decryption; read-lease cleanup tests | Physical source copy remains through the real one-hour grace. |
| Exact-version managed source deletion and cleanup failure | Source/target bound cleanup grants, managed delete/quota journals, authenticated file tests; real one-hour native cleanup and independent retirement passed | Source copies were actually absent after completion; no grace clock or SQL edits shortened the wait. |
| Queued/copying/verify/commit/pause/failed/partial/cancel/cleanup/completed | Durable task/unit/object states; AdminGUI/CLI state and revision tests | Transfer 100% alone is not completion. Failed tasks/history remain visible. |
| Pause/resume/cancel/retry and explicit drain release | Same server APIs called by GUI/CLI; mixed-owner cancellation and reverse tests | Manual pause never automatically resumes; committed units are not rolled back by cancellation. |
| Independent retirement check/apply and confirmation | SQL ledger plus native physical/key/journal inventory; actual empty-node retirement/re-pair | Final check repeats under durable barrier. Unique backups, live reads/transactions and offline unknowns block. |
| Old credentials revoked, identity/history retained, containers/volumes untouched | Lost peer receipt/fence/reset tests, native empty-node retirement and native post-migration retirement with terminal history | NodeID/history and containers/data remain; host disk cleanup is a separate operator action. |
| Nodes module, safe target reasons, plan review and detail | Existing `static/js/nodes.js`, DOM smoke and actual Chromium task/retirement evidence | Top-level module order and normal site-type upload semantics remain protected. |
| GUI/CLI shared authentication/CSRF/audit and no SQL bypass | Compiled CLI/TLS/Redis and Admin boundary tests | Credentials use protected files/stdin, not command-line secrets. |
| Traffic-based heavy-work queue and detailed GUI | Actual Go request-body/write byte accounting plus Nginx HTTP/HTTP2/sendfile shared counter; real burst/manual-pause SQLite/MySQL cases | Master remains control-only for migration. Stale/missing edge counter conservatively waits. |
| Quiet resume, peak silence, hash/planning admission | Five-second window, one-second burst, 30-second quiet interval; fresh peer refusal telemetry; content-hash admission regression | Hash worker retains its open descriptor/prefix while waiting; no automatic override of manual pause. |
| Install/upgrade/recovery/native browser/fault/resource acceptance | Evidence scopes above and matrix below | Do not replace missing external gates with package-pass counts or fixture availability with public release proof. |
| Formal schema and operator handover artifacts | Generation-7 SQLite/MySQL assets, 4/5/6 preservation/replay tests; operator/upgrade/recovery/migration/retirement docs | Final changed-file/source manifest, final privacy scan and exact-source CI remain pending. |

## Executed native matrix before the latest planning-admission changes

These are successful cutover/restart cases, not successful real-hour cleanup.

| Master | Pair | Evidence |
| --- | --- | --- |
| SQLite | Direct→Direct | [Traffic, pause and Chromium](2026-10-13-native-traffic-peak-sqlite-dd-second/evidence.json) |
| SQLite | Direct→Relay | [Cutover](2026-10-13-final-native-go-sqlite-dr-cutover/evidence.json) |
| SQLite | Relay→Direct | [Actual MP3/lyrics](2026-10-13-native-audio-sqlite-rd-second/evidence.json) |
| SQLite | Relay→Relay | [Actual MP3/lyrics](2026-10-13-audio-final-go-sqlite-rr-cutover/evidence.json) |
| MySQL | Direct→Direct | [Traffic, pause and Chromium](2026-10-13-final-native-go-mysql-dd-traffic/evidence.json) |
| MySQL | Direct→Relay | [Actual MP3/lyrics](2026-10-13-audio-final-go-mysql-dr-cutover/evidence.json) |
| MySQL | Relay→Direct | [Actual MP3/lyrics](2026-10-13-audio-final-go-mysql-rd-cutover/evidence.json) |
| MySQL | Relay→Relay | [Actual MP3/lyrics](2026-10-13-audio-final-go-mysql-rr-cutover/evidence.json) |

Headless MP3 decoding, continuous playback and service-worker decryption are
verified where selected. Physical audible speaker output is not observed and
is never claimed. A browser private-CA exception does not change product TLS.

## Current acceptance blockers

The latest-image first long case stopped before copying because `/tmp` was a
7.2-GiB tmpfs with only about 237 MiB free, below the product's one-GiB physical
reserve. The correct 409 is not bypassed. Nineteen terminal owned fixture trees
were copied to the development disk and independently SHA-256/mode/inventory
checked before relocation; original paths remain links, all data remain retained,
and no deployed containers were changed. See the
[archive record](2026-10-13-terminal-fixture-disk-archive.json). Host available
memory recovered from about 397 MiB to 4.3 GiB. New drivers honor `TMPDIR`.

The next disk-backed attempt reached the during-copy browser gate but Chromium
closed at authentication. It is a failure, not a wall-clock cleanup pass. A
fresh run retained bounded public error categories and private browser diagnostics.
A minimal canvas/screenshot reproduced a compositor crash: Chromium reported
permission denied creating shared memory in the root-only retained-data parent.
The driver now leaves browser disposable IPC in `/tmp` while binding fixture
reads to the exact fresh disk-backed workspace. The retained credential/data
permissions are unchanged. The corrected case has passed the actual during-copy
browser gate: copying state, blocked retirement, service-worker decryption and
cross-chunk Range, real MP3 decoding/continuation and original lyric relations.
Cutover/restart and the after browser gate have also passed. Actual grace cleanup
and independent migrated-source retirement passed after 3,807.651 seconds
in `2026-10-13-preflight-native-during-cleanup-retire-disk-fourth/`.
The [evidence privacy scan](2026-10-13-evidence-privacy-scan.json) checked 770
private files, 463 distinct secret values and 406 public evidence files without
a matching secret or private-key PEM block. No grace period, product security check, cgroup limit,
host setting or existing deployment is changed to obtain a green result.

That case actually removed every exact source object through managed cleanup,
revoked the old relationship through the separate retirement API, retained
NodeID/history and running containers/data, and passed five consecutive idle
CPU samples below 20% on all five one-CPU Web containers. The earlier failed
long run remains a failure. Remaining delivery gates are the fixed-commit
native matrix, final privacy/source audit and final documentation CI. This goal
is not complete.

## Source checkpoint

Implementation and retained evidence were committed on `dev` as
`9dca64fa1a0b2a3642fbde1ddb6bd08b4066a280`. A follow-up keeps terminal output
readable by normalizing carriage-return progress lines, trailing spaces and
mixed indentation in thirteen repository audit copies. The original captures
remain on the isolated development host; assertions, failures and outcome text
are preserved. No history is rewritten. Hosted dev CI for the resulting source
checkpoint was observed. `c0416cd` source CI passed after correcting the English
operator instructions. `3a174c29665c2ee46e566b7549e236763d0e07b6` additionally
has successful source CI (run 38405225052) and protocol/schema asset CI (run
38405224905). A clean clone of that exact commit produced the Web and Nginx
private acceptance images with matching revision labels; their binary/image
hashes are recorded in `2026-10-13-exact-source-build-provenance.json` and build
logs. One-CPU/one-GiB compiler budgets are separate from product Web budgets.

The new `--many-small-files` native gate uploads and copies 1,024 additional
actual files in one immediate-parent unit across sixteen pages. During-copy
ownership samples reject split directories, and final checks retain logical
metadata and verify every Source/Target byte hash. It is compiled but not yet
an executed pass. The real grace cleanup/retirement prerequisite has passed;
the exact-source matrix now runs SQLite and MySQL cases serially: Direct→Direct
with the many-file gate and the other three combinations with during/after
browser gates. It stops on the first failure. Evidence is
`2026-10-13-exact-source-serial-matrix.json`; no parallel fleet is started.

The first 1,024-file case stopped safely in `queued / waiting_business_traffic`:
its added directory HTTP observer returned 1,024 records every five seconds,
which correctly kept the real business-flow quiet gate closed. This is a failed
fixture run, not a bypassable product capacity/traffic error. The observer now
uses SELECT-only queries against the exact fresh private SQLite/MySQL fixture;
it still asserts one complete 1,024-object source or target owner. Actual upload,
migration execution, final tree/read/Range, encryption and browser operations
remain on real authenticated APIs. No product traffic exclusions or timeouts
are relaxed. A corrected fresh run is required.
