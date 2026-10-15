# Album loading, lyric wrapping and upload lifecycle acceptance

The development preview and isolated RN staging accepted the candidate before
its first push. This record describes pre-release acceptance; production release
and upgrade evidence is a separate record. Machine-readable results and private
raw-log SHA-256 values are in
[the acceptance evidence](2026-10-15-album-upload-acceptance.json).
The subsequent review corrections and repeated r4 acceptance are recorded in
[the review-fix addendum](2026-10-15-album-review-fixes.md); the initial results
below retain their original source and image scope.

## Delivered behavior

- Artwork discovery admits three visible cards, rotates fairly between albums,
  reuses at most 32 descriptor lookups for 30 seconds, and bounds a stalled lookup
  to eight seconds. Browser metadata Range reads have a 15-second deadline and
  retain the existing two-job limit. Original image bytes are unchanged; no
  recompression, resizing, transcoding or server-side media decryption was added.
- Long inline and fullscreen lyrics wrap. The font-size calculations are
  unchanged; row height grows with the text and the slide uses actual row height.
- The virtual `auto` member is omitted from node cards and migration selectors.
  Master Local certificates occupy the same resource-card grid as storage-node
  certificates. Standalone/Follower retain their local certificate controls.
- Admin aborts multipart/raw requests on page exit and browser offline, settles
  raw abort promises and stops subsequent queued files. Prepared ciphertext is
  cleaned in `finally`; interrupted queues distinguish unstarted files.
- All roles periodically reclaim managed abandoned upload stages, lease files
  and unpublished journal temporary files without requiring a restart. Active
  OS leases, publication evidence, unrelated paths and symlinks remain protected.

## Measured original-cover loading

Fresh Chromium contexts alternate before/after, five times each. The before
variant loads the approved `da11d10` browser scheduler; both variants use the
same candidate backend, catalog, original cover bytes and network. Completion
uses the browser image-load event clock, not the test driver's polling interval.
No network throttling is applied.

| Measurement | Before median | After median | Improvement |
| --- | ---: | ---: | ---: |
| Development, final serial gate | 116.7 ms | 81.0 ms | 30.6% |
| RN HTTPS, earlier r3 round | 2.1721 s | 1.6947 s | 22.0% |
| RN HTTPS, final serial gate | 5.2255 s | 1.7327 s | 66.8% |

WAN latency varies substantially; these observations are not a fixed latency
guarantee. All rounds preserve original cover SHA-256. The scheduler fixture has
nine synthetic ID3 albums embedding the same unchanged real 500×500 cover; six
visible covers are measured. These synthetic files are not playable-audio
acceptance and this is not a production-wide album benchmark.

An independent RN HTTPS browser case encrypts a fixture locally, uploads it,
proves server ciphertext exactly matches browser ciphertext, and decrypts the
full file and `bytes=3-9` Range back to the original bytes. The rendered browser
blob has the original cover SHA-256 and dimensions. OPFS temporary files are zero
after upload. Public HTTPS verification and the normal CSP remain enabled.

## Failure and recovery coverage

| Situation | Executed coverage and result |
| --- | --- |
| Browser refresh during a partial upload | Real Standalone HTTP server and Chromium; 15,876 partial bytes observed, then removed in approximately 0.05 s; no stage remains. |
| Browser offline during a partial upload | Same real fixture; approximately 0.10 s physical cleanup; no automatic queue restart. |
| Reconnect/retry and same-name conflict | Real retry succeeds; duplicate returns 409; original bytes remain unchanged. |
| Interrupted download | Real browser cancels a streaming read; subsequent full read matches original SHA-256; no upload spool remains. |
| Abandoned stage without restart | Go race regression removes dead stage/lease/temporary journal on Standalone and Master; repeated sweep is safe and live uploads survive. |
| Process crash/publication uncertainty | Publication journal, ambiguous commit and restart regressions preserve identity, audit and quota; pending evidence fences normal cleanup. |
| Direct/Relay refresh, lost finalize, offline storage | Protocol regressions preserve live/unknown bytes, repair completed uploads and defer when remote absence cannot be proved. |
| Expired quota, cancellation races and delayed writers | Repository/protocol regressions prove refunds occur once only after fenced absence; late writes, unsupported legacy abort and wrong receipts cannot authorize deletion/refund. |
| Content/size/path/type conflicts and audit failure | Validation and atomic-publication regressions reject invalid writes and preserve prior data; SQL/audit failures do not certify completion. |
| Actual filesystem full | Disposable Compose Web has a 16 MiB tmpfs; a 32 MiB upload triggers server ENOSPC, leaves zero stages and no catalog entry, then a small same-path retry reads back byte-for-byte. The early rejection may appear as a client broken pipe. |
| Encryption failure and temporary browser ciphertext | Source and browser tests reject plaintext fallback, preserve authenticated Range behavior and clean OPFS; an interrupted encrypted queue does not start its next file. |
| Download identity, rename/delete and corrupt/truncated source | Bounded plan/read-lease, cancellation, digest/size/EOF and authenticated browser crypto regressions prevent treating incomplete or replaced bytes as successful originals. |
| Real node outage and full restart | Two five-node fleets, SQLite and MySQL Masters, exercise Primary/two Direct/two Relay stores, plain/encrypted bytes, offline exclusion, identity/key/session persistence, backups, recordings and deletion convergence. |

Physical cleanup and logical reserved quota are separate. An unavailable remote
node must retain reservation evidence. Default reservation expiry is 30 minutes;
the sweep has a completion-relative 30-second cooldown. Neither elapsed time nor
a failed network request proves remote bytes absent. Active streams survive a
sweep. Hardware power loss, a full production media disk and every possible
external writer are not claimed: the real full-filesystem test uses disposable
tmpfs, while publication/audit failures use controlled fault injection.
Browser disconnect measurements above are Standalone; Direct/Relay abnormal
cases use protocol/repository tests plus real native fleet outage/restart gates.
Browser-owned unfinished download files are the browser's responsibility, not
server-managed upload stages.

## Source, resource and environment proof

Full Go race with isolated real MySQL/Redis passes 1,381 tests; 28 gated tests
skip. The explicit native fleet gate separately passes both database profiles.
There are 51 executed top-level upload/download/recovery regression families.
The bounded source CI and native JavaScript smoke checks pass. Long-lyric layout
passes 390×844, 768×1024 and 1360×768 Chromium viewports with unchanged font rules.
Node UI tests use deterministic API replies and real shipped CSS/JavaScript;
their purpose is rendering/interaction, not a claim of native transfer.

All 767 Go inputs, including tests, match the source used by the development
race/native checks. The private r2 fleet image and final r3 browser image have
the same Go binary SHA-256; r3 adds the final Admin interruption behavior.
Private images inherit base labels and must not be presented as publicly
reviewed releases. The final browser gate runs after native acceptance under the
same host-wide lock. Development and RN Web retain 1 CPU/512 MiB. Each native
fleet Web passes five consecutive one-second idle CPU samples below 20%; the
development preview's final samples are 2.10, 0.31, 0.33, 0.40 and 0.36%.

RN project `fc-rn-preprod` uses independent data, identities, volumes and network
on ports 80/443. It never joins or mounts production, installs global `foc`, or
starts a competing STUN listener. Production Relay remains on 8443. Read-only
production checks retain the prior version, database generation 7 and active
Master relationship; certificate readiness passes on recheck. A transient
certificate warning during staging work was preserved in private evidence and
rechecked without changing production. No production upgrade occurred as part
of these development/staging acceptance runs.
