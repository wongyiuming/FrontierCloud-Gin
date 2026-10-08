# Native repair audit — 2026-10-08

## Scope and delivery state

Base is reviewed gin_main merge 3345782bc318f718b665ba6f61b1551fc5135de3.
gin_dev was fast-forwarded to that merge before implementation. This is a
source repair, not a production deployment or an authorized main/dev merge.
No production SQL, media, identities, Admin Key or sessions were changed.
No new P0 was demonstrated in these targeted checks; this is not a comprehensive
penetration-test or vulnerability-free certification.

Native security and cache changes are local commits 1a8c1b6 and f2ba444.
[The machine-readable receipt](2026-10-08-native-repairs-evidence.json) records
the native-code commit, event counts, exclusions and private raw-evidence hashes.
The nine updated operator pages were published to the separate
[GitHub Wiki](https://github.com/wongyiuming/FrontierCloud/wiki) as
81e37384deef108a10d0e6dac781df6065da7c36; remote master was verified at that SHA.
No Wiki pages were added under the application's Git-tracked docs/wiki path.

## Findings and repairs

| Finding | Repair | Boundary |
|---|---|---|
| P1: captcha answer in SVG text; correct captcha could admit unlimited password attempts | Outline glyphs without answer text; atomic global/IP/account budgets before captcha/password work; one non-queuing password slot; 429 + Retry-After | Captcha is not OCR-resistant. No Admin-Key authentication bypass was demonstrated. |
| P1 conditional: old Go HTTP/2 client DoS | Web/Updater builders and go.mod pinned to Go 1.26.8; x/crypto 0.56.0, x/text 0.41.0, quic-go 0.59.1 | Requires rebuilding/deploying binaries. Malicious trusted peer is the HTTP/2 threat; source changes do not patch running production. |
| Missing catalog-cache performance/invalidation contract | Bounded native memory cache, shared Store generation after changing SQL commits, filesystem-fence invalidation, cloned caller values | 64 entries / 8 MiB accounted bytes / 1 MiB per entry. TTL 300 default, 0 disables. Not Redis or another durable business authority. |
| Five audio-profile tests not selected by unittest | Retain original assertions as discoverable unittest methods | Counts now include these previously dormant source tests; not additional backend business features. |
| Test counts confused discovery with acceptance | Frozen 552-case ledger, current inventory and JSON-event checker rejecting failed/incomplete/missing/skipped required gates | Nine reviewed rows; 543 pending assertion review. Family navigation is not equivalence proof. |
| Stale docs/default-branch assumptions | README, architecture/contribution guidance and actual separate Wiki updated | Historical default main/dev remain unsupported Python refs pending separately authorized consolidation. |

Default Redis now has maxmemory 128 MiB, noeviction and a 256 MiB container cap.
Admission failures close account writes; do not evict security counters or flush
sessions to recover pressure. New MySQL rollback fault injection uses isolated
business fixtures without binary logging, not SUPER privileges or a weakened
production configuration.

## Evidence

The prepared development host ran heavy checks serially under an exclusive
host lock, with at least 4 GiB available before starting. SDK containers had
two CPUs / 3 GiB RAM / GOMAXPROCS=2 / package parallelism one; real HTTP Web
fixtures had one CPU / 512 MiB. Fixtures used fresh namespaces and no production
target URLs. The two retained migration-recovery MySQL containers were untouched.

- Lightweight Python: 95 discoverable unittest cases; 89 executed passes, with
  a class-level skip hiding six real-binary HTTP cases. The latter separately
  executed and passed on SQLite (6) and MySQL (6), without skips.
- Five deterministic JS smoke entry points and all static JS syntax checks
  passed. Local JS smoke/syntax took about four seconds. CI source/policy/assets,
  English comments and three-minute budget checks passed; no hosted CI run for
  this unpublished source is claimed.
- Real MySQL business: 31 pass events, five existing SQLite-only fault-fixture
  skips. The new catalog rollback and generation tests explicitly passed on
  MySQL; their SQLite paths also passed. Redis/auth/native-process selected
  packages had 77 pass events and no skips.
- Final native inventory: 147 Go test files / 317 top-level Test functions.
  Full native unit: 28 passed packages / 605 passed test events / 14 test skips.
  Full race with actual Redis and real Compose: 28 passed packages / 614 passed
  test events / five test skips. No failed or incomplete events; mandatory
  Master cache, real account admission/API and Compose gates explicitly passed.
  Nested pass events are not top-level test-definition counts; totals overlap
  between runs and must not be summed. No-test package skips are separate.
  Remaining race skips are TestCacheCrashHelper (subprocess fixture helper),
  TestRealDockerEngineArchiveHelpersReplacementAndHealth,
  TestRealNativeMatrixFleetControl, TestRealNativeUpdaterUpgradeHandoffRollback,
  and TestRealNativeUpdaterWholeManifestHandoffRollback. Engine/fleet/updater
  acceptance is not certified by this repair.
- Both native Web and Updater binary build information confirmed Go 1.26.8,
  CGO_ENABLED=0. govulncheck v1.8.0 source and binary scans found no reachable
  vulnerabilities and no vulnerable imported packages. One module-only finding,
  GO-2026-5932, remains for unused x/crypto/openpgp; the project uses scrypt,
  not OpenPGP. The advisory has no fixed OpenPGP version, so bumping x/crypto
  cannot remove that unrelated module-wide warning.

Initial acceptance failures were retained as diagnostics, not converted to
passes: the new HTTP test incorrectly read the HTML shell rather than the
JSON catalog; the MySQL rejecting-trigger fixture initially required binary-log
privileges. Both were corrected and the actual scopes rerun successfully.
The added real-Compose memory assertion also initially assumed a JSON integer;
the installed parser emits a numeric string. The checker now accepts either
numeric representation without weakening the exact 256 MiB requirement.
The Master role-change test asserts the existing Follower ErrCategory denial,
not a successful empty catalog; cached entries cannot override that denial.

## Not yet certified for release

This repair did not rerun full five-node business/whole-release upgrade/rollback,
actual native Updater Engine replacement/default bootstrap or real Chromium
acceptance. Prior production/fleet receipts certify their recorded old source,
not this candidate. Finish the current-source external release gates before
authorizing promotion/deployment. Do not deploy historical main Python recipes.

Follow [validation and promotion](../validation-and-promotion.md). Push/PR/merge,
production rollout and branch consolidation are distinct authorized steps.

Security references: [Go HTTP/2](https://pkg.go.dev/vuln/GO-2026-4918),
[os.Root](https://pkg.go.dev/vuln/GO-2026-4970),
[unused, unmaintained OpenPGP](https://pkg.go.dev/vuln/GO-2026-5932).
