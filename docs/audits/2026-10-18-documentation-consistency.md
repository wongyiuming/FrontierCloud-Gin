# Documentation and historical-residue review

Date: 2026-10-18, Asia/Shanghai. Source baseline:
`1ce61b545727a19059a7ba82eb8bd45a9c93aa14`; origin/dev and origin/main both
matched at inspection. Work uses the existing attached checkout; the owner's
primary checkout is unchanged.

This is a source/configuration/test-entry/documentation consistency review,
not a complete security audit, production inspection or new full acceptance.
A file inventory and keyword/dependency scan do not prove every function correct.

## Corrected current guidance

| Finding | Implementation checked | Correction |
| --- | --- | --- |
| Daily foc guide still required copied SHA and separate self-update | `cmd/fc/upgrade_automatic.go`, `upgrade_simple.go` | Use `foc upgrade` and one confirmation; separate old-tool bootstrap, deliberate selection and recovery. |
| Default Compose was described as installing global foc automatically | Default business/storage YAML lacks `foc-host-init`; registration requires it and its marker | README, architecture, manual, overview and Wiki now disclose the gap; separate installer remains supported. |
| Migration guidance still located tasks inside Nodes | `static/js/nodes.js`, `node-migrations.js`, `admin.js` | Independent migration module; retirement remains in expanded node details. |
| Schema introduction was confused with current generation | `migrations/schema.go`; recording/admission uses `migrations.Generation` | Current 7 versus historical introductions; document 6-to-7 paged plans. |
| Low-level 4/5-to-7 preparation could imply foc support | `cmd/frontiercloud/release.go` versus `internal/recovery/generation.go` | Operator archive/upgrade source generations remain 6/7. |
| RN was both permanently retired and reauthorized in different guides | CONTRIBUTING records 2026-10-11 and 10-15 | Old CD stays retired; temporary isolated staging normally stops and yields 80 for Relay HTTP-01; no new executed acceptance claim. |
| Cache wording could imply encrypted-cover persistence across restart | `docs/music-metadata.md`, `static/js/media-crypto-sw.js`, `player.js` | Distinguish HTTP cache, page memory and worker ciphertext cache; no restart download guarantee. |
| Delivery prose implied source-build fallback or mandatory explicit upgrade SHA | Current operator and public image workflows | Automatic selection followed by exact pins; production failures stop without compiling. |
| Wiki repeated PR15 as current and mixed updater/CD history with instructions | Old Wiki versus current source | Rewrite 13 current explanations; retain originals in separate historical snapshots; scope-label 3 historical pages. |
| Stale counts, old repository links, missing anchor, Bash invocation of Python | Test entry points and actual files/headings | Date old counts, correct links and Python invocation; check current local links. |

## Code follow-ups identified, not silently declared fixed

No runtime code, tests or publication workflows changed in this documentation pass.

1. **Connect global foc installation to default Compose.** Installer/registration
   support exists but the default YAML lacks its service. The opt-in
   `TestNativeDefaultComposeRegistersGlobalFoc` skips without
   `FC_COMPOSE_REGISTRATION_SPEC`; its existence does not prove default hookup.
   A separate implementation needs real fresh-node Compose installation acceptance.
2. **Remove the unused old branch-policy alternative.** `Policy.Valid()` in
   `internal/release/verification.go` still accepts `gin_main/gin_dev`, while
   `scripts/check_release_policy.py` requires that text. The current CLI passes
   only `DefaultPolicy()`. Remove policy and matching checks/tests together;
   no exposed CLI bypass was established by this review.
3. **Retire the PR5-only bootstrap execution entry.**
   `.github/workflows/bootstrap-images.yml` and `scripts/bootstrap_native_publish.py`
   serve the historical one-time PR5 authorization, not normal publication.
   Remove dedicated gates/tests together; preserve historical proof and OCI
   validation reused by the normal publisher.

## Material that must remain

- `cmd/fc` and bundle `fc`: actual backend/distribution contract; global `foc`
  avoids the Bash collision.
- Persisted `Follower` and `only_stroge`: protocol/configuration/relationship compatibility.
- Historical schemas, migration checksums, recovery journals, ownership and key/nonce
  tombstones: recovery and duplicate-admission evidence.
- Updater/conversion absence regressions: prevent retired services, images, UI
  and Docker authority from returning.
- Python scripts/tests and test-only FFmpeg: fixture/driver tooling, not a product
  conversion runtime.
- Explicitly refusing legacy operator entries: prevent accidental legacy deployment.
- Dated audits and the 552-row legacy assertion ledger: preserve original evidence
  and unresolved equivalence review instead of manufacturing complete coverage.

Keyword/entry scanning found no updater or format-conversion product implementation
or publication service. This does not establish elimination of every unused symbol,
remote deployment artifact or third-party dependency.

## Changes and verification scope

Only Markdown changes in the source repository. Wiki has a separate local checkout,
never tracked docs/wiki. Current explanations are separated from history; existing
docs/audits originals are unchanged. See the [machine record](2026-10-18-documentation-consistency.json)
for executed checks and explicit skips.

No production access, development deployment, native database, Go race, browser or
five-node acceptance was performed. Runtime behavior is unchanged. No repository
push, PR, merge or Wiki publication occurred; these local documentation changes
are independently reviewable without unrelated feature work.
