# Validation scopes and native promotion

## Source inventory is not executed acceptance

Python `unittest discover -s tests -p 'test_*.py'` discovers only unittest cases,
not all files under tests/ and not Go tests under internal/ or cmd/. JS smoke
scripts and real Chromium scripts have independent entry points. A setUpClass
skip can suppress an entire class while producing one skip record. Inventory,
executed passes, skips and unselected external gates must be reported separately.

On the 2026-10-07 source, discovery found 83 cases, ran 77 successfully, and
skipped the six-case GinHTTPTests class for absent native fixtures. It did NOT
prove backend regression. The source also had 144 Go test files / 304 top-level
test functions plus subtests, five JS smoke scripts and separate browser/fleet
gates. Counts evolve and must not be summed into a fictional pass total.

## Development acceptance

Keep heavyweight work off hosted CI. Use the authorized development host,
isolated fixtures, verified private-CA HTTPS and SQLite/MySQL rounds. Execute
heavy gates serially with a host-wide lock, memory headroom and explicit resource
caps. Do not use production data or target URLs in fixture smoke tests.

Required scopes are:

| Entry point | Scope |
|---|---|
| scripts/test-ci-source.sh | Lightweight policy/source checks and five JS smoke scripts; <= 3 minutes |
| scripts/test-native-api.sh | Python black-box driver against actual Gin binaries, both stores; must execute GinHTTPTests |
| scripts/test-go-business.sh | Actual MySQL/Redis business, auth/API, observation, native drain, Nginx and Go race checks |
| scripts/test-go-deployment.sh | Actual Compose selection, commands, permissions and immutable image identity |
| scripts/test-native-default.sh | Fresh default bootstrap/restart, native processes, persistent identities and upstream address changes |
| scripts/test-go-updater.sh | Actual native upgrade/self-handoff/rollback, both stores |
| scripts/test-native-matrix.sh | Five Go nodes: one Master, two Direct, two Relay; both store combinations |
| scripts/test-native-release.sh | Master-only release/handoff/rollback; storage unchanged |
| tests/browser_ui_regression.py and tests/*browser.mjs | Real Chromium UI, cache, continuous playback and disconnect recovery |

An unconfigured `go test ./...` can skip Redis/Engine/fleet acceptance. Its green
exit is not proof those gates ran. Save JSON test events and classify all skips;
selected mandatory integration tests must have explicit pass events. A nested
table, assertion count or mocked service is not equivalent to a real HTTP or
browser acceptance run. Historical logs are evidence for their recorded source,
not proof of a new candidate.

## Regression retirement discipline

Python application tests were retired in a6d1587; external Python test drivers
remain supported and target Gin. The old main baseline 7e7b53b has 82 Python test
files / 552 test definitions (547 class methods and five module-level pytest
functions). Compared with the original native release,
67 test files / 477 method definitions were removed. That is a deletion count,
not 477 retired business requirements or evidence of equivalent Go coverage.

Keep a frozen legacy-case ledger with original identifiers, replacement test
locations and review status. Family-level mapping is useful navigation but must
not be labeled assertion-equivalence. Distinguish a retired runtime detail from
a retained business invariant. Newly discovered missing invariants require
executable native regressions, not restored runnable FastAPI tests.

[The frozen ledger](legacy-test-ledger.csv) contains all 552 original identifiers,
including retained names. Four cache contracts have reviewed, explicitly adapted
native replacements; five audio-profile rows retain reviewed original assertions.
The remaining 543 rows are pending assertion review, not certified equivalent.
Do not overwrite reviewed rows by regenerating the CSV. Use
`python scripts/test_inventory.py` to inspect current definitions and
`python scripts/test_inventory.py --legacy-csv` only to generate a fresh comparison
outside the maintained ledger. `scripts/check_test_evidence.py` validates Go JSON
events and rejects missing/skipped mandatory `--require package::TestName` gates.

The five former module-level audio-profile tests were absent from unittest
execution despite existing in tests/. They now run as unittest methods with
their original assertions. Those five rows are reviewed separately from the
four adapted cache contracts. This repair has 95 discoverable unittest cases:
89 lightweight passes and six real-binary HTTP cases, which run separately for
each database. No module-level pytest functions remain in the selected suite.
The current native inventory has 147 Go test files / 317 top-level Test functions;
use the inventory script to refresh these definition counts after changes.

The catalog-cache hit/invalidation guarantee is restored by native cache tests
and black-box Gin visibility checks. Account admission, captcha response secrecy
and non-queuing password work have native tests. These targeted repairs do not
alone certify all historical cases as equivalent.

Navigation for reviewing remaining historical assertions (not equivalence proof):

| Retained business family | Native regression entry points |
|---|---|
| Upload lifecycle, cleanup, reservation | internal/media/upload_test.go, master_upload_test.go; internal/store/business/media_upload_test.go |
| Folder rename, stable identity, durable rollback | internal/media/rename_test.go, global_rename_test.go; internal/store/business/media_rename_test.go |
| Priority, playback facts, visibility | internal/store/business/repository_test.go; internal/media/catalog_cache_test.go; tests/test_gin_http.py |
| Lyrics hierarchy, explicit/default relationships, auto-link | internal/media/lyrics_test.go, lyrics_admin_test.go; internal/store/business/lyrics_test.go |
| Account/CSRF, recording/quota and adoption | internal/httpapi/karaoke_accounts_test.go, recordings_account_test.go; internal/recording/*_test.go |
| IP/security and transactions | internal/security/service_test.go; internal/store/business/security_test.go; internal/httpapi/security_test.go |
| Nodes, Direct/Relay transport and relationship control | internal/httpapi/node_cluster_test.go, nodes_admin_test.go; internal/node/*_test.go |
| Backup recovery and schema/data integrity | internal/backup/*_test.go; internal/store/business/*_test.go |
| Master release provenance and rollback | internal/release/verification_test.go, coordinator_test.go, history_test.go; internal/updater/stack_real_test.go |

The new catalog rollback fault test runs on both stores. Disposable MySQL
business fixtures disable binary logging so a database-scoped test user can
create its rejecting audit trigger without SUPER privileges. This is fixture
configuration only; production users/configuration are never weakened for tests.

## Promotion and deployment are separate

1. Work on `dev` in `wongyiuming/FrontierCloud-Gin`. After a prior promotion,
   fast-forward it to the actual `main` merge commit. Never force-push.
2. Validate the fixed source/tree on the development host. Commit coherent fixes
   separately and preserve complete gate evidence, including skips and limits.
3. When authorized, push `dev`. Hosted source CI is lightweight and capped at
   three minutes; use the newest successful push for that exact source SHA.
4. Await event-driven preproduction CD for that tested dev SHA. Verify complete
   updater state, matching live web/updater revisions and the relevant public
   behavior; a delivered wakeup or green CI is not deployment acceptance.
   Only then open the same-repository dev -> main PR, use the configured
   GitHub automatic review within existing quota, and
   merge. The resulting production tree must equal the reviewed source tree;
   exact PR/CI provenance is rechecked after merge. A local commit is not a
   published release, and CI success alone is not full business acceptance.
5. Production deployment requires its own authorization. The native Admin
   Master self-upgrade flow verifies published provenance, current identity,
   maintenance and persistent release journals. It builds immutable allowlisted
   Git archives locally; it never upgrades storage appliances. Storage rebuilds
   are operator-controlled exact-revision deployments. Rebuild binaries to apply
   Go security fixes.
6. Confirm readiness, business transport and actual component runtime SHAs,
   retain recovery evidence, then synchronize `dev` to the release merge.

The new repository has only `main` and `dev`; the old repository's `gin_*`
branches are bootstrap history, not active release profiles. Initial imported
commits are not PR-certified releases. Production rollout is performed by the
operator and is separate from the authorized implementation/PR/merge workflow.

## Security and runtime bounds

Web and Updater builders use Go 1.26.8, including the HTTP/2 and os.Root security
fixes missing from 1.26.0. Dependency upgrades require a new binary build; changing
only an image label or OS package does not replace the embedded standard library.

Karaoke credential admission is atomic in Redis: 60 accepted requests per minute
globally, 20 per IP/action, 10 per normalized account/action, independent of
captcha correctness. Captcha creation allows 200 globally and 20 per IP per
minute. Fixed-window rejected requests neither create keys nor extend TTLs.
Redis errors fail closed. One password calculation may run; a busy slot returns
429 immediately rather than accumulating an unbounded queue. Clients receive
Retry-After. Captcha SVG uses outlines, not answer-bearing text; it is not claimed
to resist OCR and never substitutes for hard admission budgets.

Default Redis uses 128 MiB maxmemory, noeviction and a 256 MiB container cap.
Noeviction preserves security counters/session validity instead of silently
evicting them to admit more guesses; write refusal fails closed. Do not flush
sessions, rotate keys or purge data to remediate resource pressure.

Primary security references: [Go HTTP/2 advisory](https://pkg.go.dev/vuln/GO-2026-4918)
and [os.Root advisory](https://pkg.go.dev/vuln/GO-2026-4970).
