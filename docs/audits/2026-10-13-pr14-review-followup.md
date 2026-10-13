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
