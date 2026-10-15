# PR 22 review corrections and repeated acceptance

Review of `79aa5ee2fdb6f5089112afaedd16b77e2c93d19c` identified two P2 defects:
an otherwise empty stage-cleanup sweep invalidated the catalog cache, and an
already-offline retry reset interruption state before processing queued files.

Stage housekeeping now acquires the same exclusive process/volume fence without
invalidating visible catalog data. Business mutations retain their original
invalidation behavior. Standalone/Master regressions exercise warm reads, empty
sweeps, actual orphan removal and subsequent business-write invalidation.
The browser rejects already-offline selections before resetting interruption
state, preparing ciphertext, reserving capacity or transferring files. Native
JavaScript tests also verify successful explicit retry after reconnection.

The r4 development preview was updated before repeated acceptance. All 767 Go
inputs match the development validation source. Full Go race with isolated real
MySQL/Redis passes 1,384 tests, with 28 gated skips and zero failures. Separate
real five-node TLS fleets pass SQLite and MySQL profiles in 556.50 seconds;
every Web uses 1 CPU/512 MiB and passes five consecutive idle CPU samples below
20% of one core. Complete lightweight source CI passes as well.

Real Chromium again verifies three lyric viewports and node-card layout.
Refresh/offline tests each observe 15,876 partial server bytes, then zero stages
after approximately 0.046/0.102 seconds. An already-offline selection starts zero
encryption and transfer operations for both encrypted and plaintext queues.
Retry succeeds, a duplicate returns 409 without changing original bytes, and
download cancellation is followed by a successful full SHA-256 readback.

RN public HTTPS acceptance again proves browser-only encryption/decryption,
server ciphertext identity, full-file and HTTP 206 Range byte identity, unchanged
500×500 original-cover SHA-256, and zero browser temporary ciphertext files.

| Five alternating fresh-browser rounds per variant | Before median | After median | Improvement |
| --- | ---: | ---: | ---: |
| Development | 117.7 ms | 76.1 ms | 35.3% |
| RN public HTTPS | 3.7368 s | 1.7617 s | 52.9% |

The comparison changes only the browser scheduler on the same r4 backend and
unchanged fixture covers. It measures six visible covers from nine synthetic
ID3 albums, with no throttling. WAN results vary and do not promise production
library latency. Initial actual-ENOSPC evidence remains an initial-version
result; unchanged publication logic is not used to relabel it as an r4 rerun.

RN staging uses independent Compose scope, data, identities and volumes. After
acceptance all staging services are stopped, with Compose/data retained for
future testing. This releases host 80/443; production Relay remains on 8443 and
needs port 80 temporarily for certificate renewal. No production mutation is
part of this acceptance record. A production certificate probe intermittently
reported no serving fingerprint; three independent verified TLS reads retained
the expected fingerprint and the controller recovered to ACTIVE. The warning
is retained in private evidence and is not suppressed in `foc` readiness.

[Machine-readable r4 evidence](2026-10-15-album-review-fixes.json) preserves
source/image identities, repeated results and raw-evidence SHA-256 values.
The initial acceptance report remains historical. Public release, exact-head
review, merge and production `foc` upgrade evidence follow separately.
