# Contributing to FrontierCloud

FrontierCloud uses one authorized two-branch provenance pair and one deployable runtime (Gin/Go). These rules are architectural constraints, not suggestions.

## Repository topology — MUST NOT violate

- `dev` is the **only development branch**; `main` is the release branch in FrontierCloud-Gin.
- **Do not create any new branch** outside these two refs.
- Only same-repository `dev -> main` PRs promote code; never force-push or rewrite canonical branches.
- Do not commit implementation directly to `main`.
- After merge, fast-forward `dev` to the release merge commit.
- Old `gin_dev`/`gin_main` refs belong to the original repository, not this repository's release topology. Python is never deployable.

The repository can fail an invalid PR topology, but repository-local code cannot reliably prevent somebody with GitHub ref permission from creating a branch. The **no-new-branch rule therefore remains an explicit human/automation invariant** and should also be mirrored in the GitHub Wiki and repository ruleset/branch-protection settings.

## Change discipline

1. Read `ARCHITECTURE.md` before changing a cross-cutting subsystem.
2. Start from the selected profile's development HEAD. Synchronize it with a just-promoted release first as described above.
3. Change the smallest coherent surface. Do not revive retired compatibility/product features to make a test pass.
4. Add or strengthen regression coverage for every bug fix and every new invariant.
5. Run the bounded source CI checks and native acceptance on the development host. A narrow unit test is not release evidence; heavyweight acceptance must never be added to hosted CI.
6. Await successful dev CI, event-triggered preproduction CD completion, matching live revisions and relevant staging behavior before opening the authorized release PR. Use the fixed dev-to-main promotion pair and configured GitHub automatic review within existing quota. Merge requires owner authorization and successful exact-source validation; production upgrade is a separate maintainer action.

## Documentation ownership

Keep top-level documentation intentionally separated:

- `README.md` is the concise product entry point, shortest startup path, and documentation map.
- `ARCHITECTURE.md` owns cross-cutting invariants and prohibited design drift.
- `CONTRIBUTING.md` owns repository, testing, review, and release procedure.
- The separate [GitHub Wiki](https://github.com/wongyiuming/FrontierCloud-Gin/wiki) owns operator/subsystem guidance; docs/wiki must not be Git-tracked. docs/ holds focused engineering contracts and audit evidence.

Do not copy a full architecture or operations manual back into the README. When behavior changes, update the narrowest authoritative document and link to it from the entry point only when discovery would otherwise suffer.

## Regression policy

Prefer executable protection over prose:

- Business invariants belong in unit/runtime tests.
- Browser behavior and Admin layout belong in Chromium acceptance tests when practical.
- Master/storage behavior belongs in federation tests when it crosses node boundaries.
- Nginx/Compose/release assumptions belong in source/deployment contract tests.
- A rule that cannot be reliably asserted from the repository (for example, **never create a new Git branch**) must be documented here and in the Wiki instead of being implied by convention.

Never weaken an existing regression merely to make a new implementation pass. If an invariant genuinely changes, update the architecture documentation and the test in the same change and explain why.

## Non-negotiable architecture boundaries

- A cluster has one business Master. storage nodes are resource nodes, not independent business authorities.
- Master-owned business state (lyrics, lyric relations, playback/business facts, users, audit facts) must not silently migrate to storage nodes.
- One managed media object is complete and belongs to exactly one storage member. Do not split one logical object across storage members.
- Compute Worker is retired. Do not add worker slots, compute scheduling, worker UI, or worker product configuration back without an explicit architecture decision.
- Product runtime changes that add burst or sustained high-load computation are rejected. Do not add transcoding, compression, inference, bulk transformation, process execution, executor offload, or compute-heavy runtime dependencies. This is a one-core service boundary, not a tunable CPU budget.
- Development-host acceptance runs the Web container with one CPU. A compute-caused test timeout fails the build; failure handling stops the Web fixture before cleanup. After business tests, CPU must fall below 20% of one core for five consecutive one-second samples within 30 seconds. The threshold detects failure to recover and does not authorize compute-heavy work below it.
- Heartbeat health is independent from Backup work. Backup failure must never mark a healthy node offline.
- Backup is a recovery artifact, not online replication, HA, or automatic failover.
- Managed paths are changed only through FrontierCloud transactions. Do not rename/move/delete managed files directly on disk as a substitute for metadata updates.
- Folder rename is a rename inside the same parent, not a general move API. Cross-member rename must remain rollback-capable. Master rename is the exclusive path mutation; upload reservation, delete, hide/unhide, and priority changes must participate in the same mutation-fence protocol.
- Lyrics support at most two directory levels below `lyrics`: `lyrics/<category>/<subdir>/<file>.lrc`. Every upload, catalog, tree, search, download, and delete surface must enforce the same boundary.
- `lyrics/default.lrc` is an internal playback fallback. It is not user content and must not appear in Admin lists/counts/search or be exposed as a normal mutable object.
- Same-name lyric auto-link is manual fallback automation: only the explicit Admin control may trigger it. Upload/refresh paths must not invoke it; it may replace missing/default fallback state but **must never overwrite an explicit user-managed lyric relation**, even if that selected lyric file is temporarily unavailable.
- Admin module order is intentional and protected by regression tests. Do not reorder modules incidentally while changing a module.

## Validation workflow

Hosted **test CI** is restricted to lightweight source/policy/JavaScript smoke checks and three-minute parallel jobs; scripts/check_ci_budget.py rejects heavyweight acceptance and serial test-job chains. Do not raise this budget or use background jobs to evade it. The normal delivery exception is the separate default-main `publish-images.yml`: a completed successful exact-source CI event gates its trusted plan, parallel compilation without package-write credentials (ten minutes per component job) and isolated trusted publication (three minutes per component job), followed by a three-minute signed CD notification. Only these explicit delivery dependencies are allowed, not serial test chains. No tests/fleet/databases/browser acceptance belong in compilation workflows. Normal credential-bearing jobs never execute candidate code. See [image delivery](docs/public-image-delivery.md).

The owner separately authorized one first-activation exception:
`bootstrap-images.yml` for **PR #5 only**, triggered by an owner-applied
`bootstrap:<full dev SHA>` label after development acceptance/source CI success.
Its fixed PR workflow code is an explicitly authorized snapshot, not main code.
The plan verifies current refs, source run/attempt and first authorization claim;
read-only compilation exports OCI data to an isolated automatic-token publisher.
There is no signing secret, Environment or deployment job. Plan/publication
remain three minutes, compilation ten minutes per component. Relabel-triggered
duplicate runs and future PRs cannot use it. Staging acceptance remains a merge
gate even though PR #5 must exist before this first label-triggered publication.

Only exact publish jobs and main-only alias promotion receive automatic `GITHUB_TOKEN` `packages: write`; plan,
compile and notify jobs do not. Public packages must grant `FrontierCloud-Gin`
Actions Write while anonymous image pulls require no credentials. Personal PATs
and a publisher Environment are not required; old unreferenced ones may remain
without being used or triggering deployments. Repository workflow writers are
trusted to request package write permissions in other workflows: do not present
this model as preventing every dev-authored workflow from replacing old tags.
The CD signing secret remains exclusively in `staging-cd-main`, restricted to the
exact main Branch rule, with no dev-accessible repository/organization copy.
External permissions must be verified separately from source tests. Record
actual bootstrap CI completion and public image proofs before claiming initial
activation; do not direct-write main or merge before staging acceptance to
sidestep that bootstrap boundary.

Run native unit/race, actual SQLite/MySQL business/API, deployment and updater tests on the development host. Python remains a test/script language, but application tests target Gin HTTP/native source; importing app, main, FastAPI or SQLAlchemy in tests is prohibited. Reference app/ and updater/server.py are illustrative only and must not be deployed. Keep syntax examples aligned when relevant; runnable Python compatibility is not a product requirement.

The fleet is exactly five Go nodes: one Master, two Direct, two Relay. scripts/test-native-matrix.sh covers both database combinations; Master-only upgrade/rollback must leave storage versions and identities unchanged; whole-fleet release synchronization is retired. These and real browser tests are development-host-only. Legacy data/token golden vectors are retained independently of Python runtime support.

## Release evidence

Report discovered, executed, passed and skipped tests separately. A class-level
skip can hide several HTTP cases; a successful Go unit run may omit external
Redis/Engine/fleet gates. Preserve legacy-case replacement ledgers and never
claim assertion-equivalence from matching total counts. See
[validation scopes and promotion](docs/validation-and-promotion.md).

A release is valid only when the exact development commit has successful CI and the production tree is identical to the reviewed source tree. The new repository uses only `dev -> main`. Post-merge proof is an additional guard, not a replacement for review. A local tested commit is not an already-published production release.

The complete local baseline and CI composition are maintained in the separate [Engineering and CI Wiki](https://github.com/wongyiuming/FrontierCloud-Gin/wiki/Engineering-and-CI). Deployment, rollback, and migration procedures are maintained in the [Release and Database Migrations Wiki](https://github.com/wongyiuming/FrontierCloud-Gin/wiki/Release-and-Database-Migrations).

### Startup-default regression gate

Preserve the five-value HTTPS fresh-start baseline in ARCHITECTURE.md. Render
real Compose with only those five values and also with empty optional values;
verify default public latest images, no builds, SQLite, persistent initialization,
ports and project identity. Run a fresh HTTPS startup on the development host
with one CPU and isolated ports/volumes; fixture image aliases may stand in for
unreleased main/latest bytes, but that is not evidence that remote latest exists.
Verify trusted latest promotion rejects dev, stale main, incomplete publisher
jobs, digest drift and partial proof before writes. Only main publication after
an authorized merge activates the new default aliases; do not create them by
an ad-hoc dev push or treat the source checkout HEAD as a published release.
