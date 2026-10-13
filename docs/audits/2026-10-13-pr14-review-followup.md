# PR 14 review follow-up

Reviewed baseline: `dce71d7e3eeede4114a8a0f03c1ea4805f90e930`.
This follow-up does not claim that the baseline's native image IDs represent
the changed operator bundle. New exact-source CI/native operator gates are
required before promotion. The prior eight migration cases retain their recorded
source scope; migration transport/state/store and Nginx module logic are unchanged.

| Review item | Resolution | Evidence |
| --- | --- | --- |
| Fixed fifteen-minute CLI timeout cancels large recovery | Backup/restore/upgrade contexts have no fixed deadline; SIGINT/SIGTERM cancellation propagates. Short control commands retain their deadline. | CLI cancellation/deadline regression and operator/recovery race suite |
| Missing archived Web Dockerfile inputs | Both bundled upgrade and recovery-set manuals are in the immutable source archive allowlist. | `2026-10-13-pr14-archive-inputs-second.txt` runs the actual archive helper with an inert Docker tar sink and verifies every local COPY source; the first non-checkout harness failure is retained |
| Security-sensitive Compose drift unbound | Canonical selection hashing includes effective execution/isolation fields and future non-environment Compose fields, while secret environment rotation and image pins retain their separate semantics. | Fourteen execution/isolation drift cases reject before privileged operations; canonical JSON/secret-rotation regression |
| Backup success retains private dump/config scratch | After durable archive creation, only generated deployment/MySQL trees in the pinned scratch root are removed and the parent is synced. Failure retains materials; rebound roots/source links are not recursive deletion targets. | Actual recovery-byte upgrade test, pinned scratch/source-link/rebound regressions |
| Public opening lacks recoverable durable intent | Persist activation and `opening` intent before changing gates; repeat explicit approval restores owned public maintenance, rechecks recovery/identity/business facts and finishes journal/receipt writes. Failed phases and unowned administrator maintenance remain blocked. | `2026-10-13-pr14-opening-recovery-race.txt`: real journal/receipt/marker files at activation, verification, removal and opened-before-receipt boundaries |
| HTTP/2 connection output allegedly counted per active request | The pinned Nginx implementation uses a per-stream fake request connection, not its shared physical connection. Production module logic is retained; a same-physical-TLS-connection concurrent regression verifies the actual byte attribution. | `2026-10-13-pr14-http2-multiplex.json`: two 32-KiB/s business streams transfer 524,288 bytes while an overlapping excluded stream transfers 2,097,152 bytes; measured business peak is 65,666 bytes/s, with exactly one TLS connection |

The pinned [Nginx stream creation](https://github.com/nginx/nginx/blob/release-1.30.4/src/http/v2/ngx_http_v2.c#L2839)
copies a fake connection for each stream and resets its sent counter.
[Frame accounting](https://github.com/nginx/nginx/blob/release-1.30.4/src/http/v2/ngx_http_v2_filter_module.c#L1529)
increments that stream request's counter. The tested module source SHA-256 is
`ceb76ce3cc27ba2d365290d87850bb004431097b0f459a5e83ad6872026fa685`;
the builder's actual source matched the checkout before acceptance. Range,
sendfile, X-Accel, aborted/ongoing requests, HTTP/2, upload, reload and counter
access protection also pass in the same actual Nginx run.

`2026-10-13-pr14-operator-review-race.txt` passes `cmd/fc`, `internal/operator`
and `internal/recovery` under Go race; the added early-activation recovery cases
have their subsequent selected race run. Native SQLite/MySQL generation-6 to 7 upgrade, backup/restore/business and
failure closure pass on `667db01`; see the `pr14-667-native-*-second` records.
They do not cover the subsequent second-review changes.

## Second review and retained production generation

Second reviewed source: `667db01a5c77d88fe8e56761af5b81c2e9630c20`.

- Restore opening now records durable intent and reconciles missing owned public
  maintenance before rechecking identity/schema/business and finishing receipts.
- Recovery-set opening resumes member journals and opens Master last; resumed
  validation failures refence the whole set.
- `fc install resume` finalizes an original prepared installation without latest,
  replacement pulls, initializers or identity regeneration.
- The production registry client returns a 307 response without automatically
  following it. The existing bounded artifact-host validation performs the
  follow-up without the registry bearer; foreign redirect hosts stay blocked.
- Restore preparation records the original source project before rewriting its
  recovered receipt, and same-intent preparation retries preserve that project.
- `fc upgrade resume` reconciles only approved old/target image locks and receipts,
  restores the native fence, verifies the recovery point and target publication,
  and remains closed after preparation.
- CLI retirement readiness includes nonzero expected-resource counts.
- Atomic JSON publication uses unique scratch files, preserving older crash
  evidence without letting its fixed name permanently block future writes.

`pr14-interruption-race`, `pr14-install-resume-race` and
`pr14-redirect-retirement-race` pass. These tests use actual persistent journal,
receipt, archive and marker files with injected Docker runners; they simulate
interruption windows and do not claim real host SIGKILL coverage.

The retained native command additionally admits explicitly confirmed generation
4/5 to 7 behind maintenance. It inspects the actual source generation's required
transaction tables before additive DDL; operator recovery compatibility remains
6/7. Actual prior SQLite DDL 4, 5 and 6 success/refusal cases pass in
`pr14-legacy-generation-race`. The isolated actual public generation-4 runtime
upgrade passes in `pr14-legacy4-native-thirteenth.json`: cold recovery retained,
identity/secret/stable-table digests preserved, generation 7 reached while fenced,
and original media ID/actual HTTP Range verified after opening. Its target binary
is a private working-source override, so this is not public release proof.
Production has only been inventoried read-only; no production upgrade is claimed.

## Final native operator validation

The immutable, clean `1fe1fbe7becc336e611a3833066bae0cb5bd9e6a` clone passes
full Go race (`pr14-1fe1fbe-go-race`) and builds the runtime/operator binaries.
`pr14-1fe1fbe-source-proof.json` records image/binary/module/input hashes.
The first full run's missing-manual Git fixture failure is retained separately;
the corrected fixture passes in the exact clone and selected adapter race run.

Actual final native gates pass:

| Evidence suffix (`2026-10-13-pr14-1fe1fbe-`) | Executed scope |
| --- | --- |
| `native-sqlite-second` / `native-mysql-second` | Actual 6→7 preparation, already-prepared upgrade resume, explicit opening, cold/logical backup, CLI restore, post-removal opening-journal reconciliation, original NodeID/media ID/priority and HTTP Range |
| `native-failure` | Injected target preparation failure after real native backup; recovery retained and native gate closed, no DDL rollback |
| `native-set` | Actual two-node coordinated cold capture/restoration, sealed relationships, original identities/vault keys, managed reads/HTTP Range, Master-last opening and another verified coordinated backup |
| `native-install` | Actual Master SQLite and Direct local-CA installation; prepared receipt finalization preserves identity and performs no replacement pull; recreation preserves identity/key/pins |
| `native-legacy` | Actual public generation-4 source, exact private generation-7 target binary, cold recovery, preserved stable tables/secrets/identity, original media ID and HTTP Range after opening |

These remain isolated private-image/publication adapters; no public target
release or production update is claimed. The native upgrade adapter now maps
unchanged recorded private infrastructure IDs too, because resume verifies all
approved pins. Its first rejection is retained in `native-sqlite.txt`; the
corrected adapter's race tests and both second native runs pass. This adapter
change does not broaden production registry admission.

Latest review's current-generation documentation finding is corrected to 7;
generation 6 is historical, and future generations above 7 are rejected.
Lightweight source discovery passes 202 cases with three explicit environment
skips. The final privacy check finds no private key/retained fixture secret bytes
in 558 remote public evidence files. Prior migration matrix/browser/quiet-queue/
retirement evidence retains its original source scope: these operator fixes do
not claim that the older images contain new operator code.

## Third review: additional durable interruption phases

Review of `df49f73` identified five further interruption windows. The subsequent
fixes admit matching recovery-set `preparing_fenced`/`activating_fenced` retries,
retain staged-inode proof for restore marker creation, reconcile approved upgrade
`backup_pending` archives without discarding partial material, and distinguish
fresh `initializing` installation from initialized `prepared` readiness.
`pr14-third-review-race-second.txt` passes operator/recovery/CLI packages with
persistent-file tests for set/member checkpoints, marker intent/partial stage/
publication/admin replacement and complete/missing/partial backup outputs.
The first marker-helper error regression is retained separately and corrected.
Fresh native validation and exact-head CI/review for these changes are pending
at this checkpoint. Earlier native records remain scoped to `1fe1fbe`; production
is still untouched.

## Fourth review and native checkpoint

On `2cdd92c`, actual native SQLite/MySQL 6→7 upgrade/resume, CLI restoration with
staged marker ownership and HTTP Range, and two-node coordinated recovery pass.
Its first pre-initialization native install attempt fails only because the
private CA-file bind was created as a directory by the early read-only inspector;
the fixture now precreates that regular trust file. The failed record is retained.

Latest fixes admit only known regular metadata atomic-write residue in set
preparation, retain staged inode evidence for upgrade maintenance ownership,
publish the initializing receipt before its image lock, bind complete effective
root Compose definitions, and preserve verified backup success with explicit
scratch-cleanup warning/retention fields. `pr14-fourth-review-race-second` passes
operator/recovery/CLI race, including missing-lock reconstruction, volume driver
and other root-definition drift, administrator marker refusal, retained atomic
residue and actual verified archive survival through cleanup failure. The prior
opening fixture is updated to model its real retained ownership inode. Fresh
native validation and exact-head CI/review remain pending for these changes;
production is still untouched.

## Fifth review checkpoint

`817790e` actual native SQLite/MySQL 6→7 upgrade/resume, CLI restore/Range,
two-node recovery and Master/Direct pre-initialization install resume all pass;
full Go race passes. Subsequent review finds six remaining retry/publication
boundaries. New fixes expose single-deployment `restore prepare`, atomically
publish exclusive JSON, aggregate member cleanup warnings, accept identical
prior upgrade history, block administrator maintenance before activation, and
record/retry plan-specific generated stage cleanup. The affected-package race
passes in `pr14-fifth-review-race-second`; the first compile failure is retained.
The actual native driver now exercises separate CLI preparation on existing
restored material. Fresh native validation and exact-head CI/review for the
latest fixes remain pending. No production changes or public target release
proof are claimed.

## Sixth review checkpoint

`15a8d2d` passes actual native SQLite/MySQL upgrade/resume, separate CLI restore
preparation/activation/opening with HTTP Range, two-node coordinated recovery,
Master/Direct pre-initialization install resume, and full Go race. Three subsequent
findings are corrected: incomplete related-node manifests cannot use single-node
prepare/activate/open; recovery JSON output failure returns nonzero; ready restore
staging cleanup is recorded and retryable without changing administrator manual
maintenance. Pending cleanup blocks another backup so generated staging cannot
become unowned later recovery material. `pr14-sixth-review-race` passes the affected
operator/recovery/CLI packages, including real incomplete archive rejection,
output writer failure and ready cleanup/admin preservation. Latest exact native
and CI/review gates remain pending. Production is still untouched.
