# FrontierCloud Architecture Boundaries

This document records invariants that must survive feature work. It is intentionally stricter than a feature list: contributors should understand **what FrontierCloud is allowed to become** before changing cross-cutting code.

## 1. Roles and authority

FrontierCloud runs as one of three roles:

- **Standalone** — one node owns business state and local media.
- **Master** — the only business authority in a cluster. Public pages and business APIs are served by the Master.
- **storage node** — a resource node paired to a Master. A storage node provides authenticated health, storage/data-plane, backup, and node-control capabilities; it is not a second business authority.

A cluster has exactly one business Master. Do not introduce multi-Master, implicit leader election, automatic Master failover, or peer-to-peer business writes under an unrelated feature change.

Fixed Master/storage node roles require certificate-verified HTTPS. Loss of the TLS requirement must fail closed rather than silently downgrading a fixed role.

## 2. Business state versus resource state

The Master owns business truth, including lyrics and lyric relations, playback/business facts, karaoke users/recording business state, Admin audit facts, and the global media catalog.

storage nodes own only the resource state required to serve their assigned data and maintain the authenticated relationship with the Master. A storage node must not become an alternate source of truth for Master business records.

## 3. Storage model

The Master exposes one logical storage pool containing Master Local plus enabled storage nodes.

- One logical media path identifies one complete media object.
- One complete object belongs to exactly one storage member at a time.
- Placement is transparent to playback/download: Local, Direct, and Relay are transport choices, not different business objects.
- Storage allocation is FrontierCloud logical capacity. Physical disk capacity is observed separately.
- Admin Storage wording is intentionally split into `physical used / all` and `used / allocated`; do not conflate filesystem free space with FrontierCloud quota.

### Upload site types

Admin media upload chooses a **site type**, never a concrete storage member. The selector starts empty and media upload does not begin until a type is explicitly selected.

The only supported site types are:

- `primary` — the Master Local placement (`member_kind=MasterLocal`, transport `Local`);
- `direct` — storage node placements whose current transport is `Direct`;
- `relay` — storage node placements whose current transport is `Relay`.

For Direct and Relay uploads, the user must not name a specific member. The first live object/reservation in an immediate parent folder selects an eligible member by lowest `(used + reserved) / allocated` pressure, then more available bytes. Subsequent direct children bind to that same owner; a child folder is a separate affinity unit. An offline, non-writable or full bound owner causes refusal, never silent spill to another member. Historical split-owner folders fail closed. Member selection plus durable reservation is serialized by the storage write lock so concurrent Admin sessions see current `reserved_bytes`.

Historical media requires **no migration** for this feature. Existing `storage_member_id`, `member_kind`, and `transport` remain the source of truth; Admin derives the visible site type from those fields. A missing transport in a local/Standalone media tree is treated as primary/local. Changing this presentation must not rewrite historical ownership.

Site-type colors in Admin are observation aids only: local/primary uses a muted green marker, Direct a muted amber marker, and Relay a muted red marker. They must remain low-saturation badges rather than full-row alert colors.

Compute Worker is **retired**. Worker slots, leased compute scheduling, worker UI, or product-level Compute configuration must not be reintroduced accidentally through compatibility code.

## 4. Heartbeat and Backup

### Browser encryption boundary

Every upload selection explicitly chooses plaintext or encrypted storage; neither
remembered choices nor crypto-error fallback can silently choose plaintext.
Browser AES-GCM chunks preserve bounded Range playback and one complete object
per storage owner. The Master owns durable encryption metadata and permissions
and wraps small file keys through session-scoped asymmetric handshakes; ordinary
media encryption/decryption runs only in the browser. Fixed authorization expiry
covers multiple files without per-request ECDH. Obfuscation does not replace
standard cryptography or prevent authorized users retaining keys or plaintext.
Premaster recovery is independent of storage-node business backups. See the
[browser encryption contract](docs/browser-media-encryption.md).

Heartbeat is node-health control traffic. Backup is asynchronous recovery work. They are independent failure domains:

- a successful heartbeat stays successful even if Backup subsequently fails;
- Backup work must not block the heartbeat loop;
- full Backup construction is serialized to avoid multiple large in-memory business backups being built concurrently;
- interrupted receiving generations are explicitly aborted/cleaned when supported.

Backup artifacts are bounded business-recovery packages. They are **not** online replicas, HA storage, or automatic failover.

## 5. Managed media mutation

Managed filesystem paths and database metadata form one business object lifecycle. Direct filesystem changes are not a supported substitute for FrontierCloud mutations.

Deletion uses the recovery journal/quarantine transaction path. Rename must update both bytes and metadata or roll back.

### Folder rename

Folder rename is deliberately narrower than a general move API:

- only supported managed `music`/`vido` folders are rename targets;
- the parent directory does not change;
- target collisions are rejected;
- active uploads and pending deletion state block rename;
- a Master coordinates all storage members containing that logical folder;
- if a later member or Master metadata commit fails, already moved members are rolled back in reverse order;
- offline storage nodes block a rename that cannot be completed safely.

All Master path mutations participate in one process-local reader/writer fence. Cross-member folder rename owns the exclusive fence from preflight through commit/rollback. Upload-session reservation, global delete, hide/unhide, and priority mutations enter through a shared fence; upload reservations and `pending_delete` then remain durable database fences after that short shared section ends. A new path-mutation entry point must join this protocol instead of creating an independent race window.

### Process model for mutation safety

The production Web service must remain a single native Go process. Media mutation fences and recovery OS leases do not authorize horizontally replicated Web services or multiple independent business authorities. Python application sources are non-executable syntax references, not a supported deployment profile.

Do not add multiple Web workers as a performance tweak. Multi-process or horizontally scaled Web execution requires replacing the process-local media mutation fence with a database-backed or distributed lock, plus new cross-process concurrency regressions, before deployment topology changes are allowed.

Do not turn folder rename into an arbitrary cross-parent move without a new transaction design and federation regression coverage.

## 6. Directory priority

Folders are first-class sorting objects. Directory priority is distinct from media-file priority and uses the same bounded preference range.

Public category/subcategory ordering is `directory priority descending -> name`. Priority state is stored as managed metadata and must migrate with a successful folder rename.

Catalog ordering is cached server-side. A cache hit must not cause a new MySQL sort query; changing priority or a directory name must invalidate the catalog generation.

## 7. Lyrics

Lyrics are Master-owned business content even when media bytes are stored on storage nodes.

The supported hierarchy is intentionally bounded:

```text
lyrics/<file>.lrc
lyrics/<category>/<file>.lrc
lyrics/<category>/<subdir>/<file>.lrc
```

Two directories below `lyrics` is the maximum. Upload, validation, Admin tree, scoped search, download/delete collection, lyric catalog, and relation management **must all enforce the same hierarchy**. It is forbidden for one surface to accept a path that another surface cannot manage.

`lyrics/default.lrc` is an internal, automatically maintained playback fallback:

- it is not user lyric content;
- it is excluded from Admin lyric counts and relation counts;
- it is excluded from Admin media-tree/search presentation;
- it cannot be selected as a normal delete/download target;
- a fallback relation does not make a track appear to have a user-managed lyric in Admin.

Same-name auto-link is fallback automation, not an authority over user decisions. It runs only after an administrator explicitly clicks the Admin auto-link control; lyric upload and catalog refresh must never trigger it. It may fill a missing relation or replace `lyrics/default.lrc`, but it **must never overwrite an explicit user-managed lyric relation**, even when that selected lyric file is temporarily unavailable. The current-relation check and replacement happen under the same database row lock so a concurrent manual link cannot be overwritten. Auto-link must scan only the supported media and lyric hierarchy; historical orphan files outside that hierarchy cannot re-enter business state through automation.

An accepted lyric upload is successful only after the file and its managed-object registration are durable together. A failed registration/audit transaction removes the newly published file. A later cache-invalidation failure must never delete an already committed lyric.

## 8. Catalog and cache consistency

Bounded process-local catalog generations cache expensive scans/catalog queries. Browser/API cache headers must not make mutable directory structure remain stale after a successful Admin mutation.

For mutable catalog APIs, the HTTP client revalidates while a single-process cache avoids repeated catalog work. All domain handles from one selected Store share a SQL commit generation; successful writes conservatively invalidate it, rolled-back writes do not. Managed filesystem mutation fences also clear the cache, including ambiguous/failing mutations. A fill racing a commit is not published. Scope keys separate role, media type, path and hidden visibility; caller-specific ordering is applied to copied results rather than creating per-session entries. Cache hits never bypass readiness, role checks or stream authorization.

`MEDIA_CATALOG_CACHE_TTL` defaults to 300 seconds, accepts 0 to disable, and is bounded by 86400. Admission is capped at 64 entries / 8 MiB accounted payload; entries above 1 MiB bypass caching. Errors are not cached, waiting readers honor cancellation, and restart drops all cache state. Stores without an invalidation contract bypass caching. This is not cross-process cache coherence: maintenance/offline writers must close the native runtime fence first; live direct SQL or filesystem edits remain prohibited.

## 9. Playback continuity

Compatible MP3 playback is one continuous browser media session: one audio element, one `MediaSource`, and one `audio/mpeg` `SourceBuffer` in sequence mode. A track boundary updates business metadata and accounting; it must not recreate the player, switch `src`, call `load()`, or introduce a second standby element.

The browser keeps a bounded playback window rather than downloading an album into an unbounded SourceBuffer. Appends are backpressured by the playback clock, old ranges are pruned after a boundary, and `QuotaExceededError` retries the same bytes silently without marking a track as failed.

All SourceBuffer appendBuffer and remove operations share one serialized queue. A network/body read interruption retries the same track at the exact byte offset, with bounded backoff and cancellation on a deliberate user switch. A waiting reader never completes a segment, skips a track, adds a runtime yellow warning, or starts a replacement player. Decoder/identity errors remain distinct and hold the current session for diagnosis; they are not mislabeled as a successful truncated read.

The player exposes stable track-local duration and time over the global MSE timeline. A seek inside the current buffer moves that timeline directly. A seek outside it restarts the same logical track with an open-ended HTTP Range request near the requested byte position, preserves playing/paused state, and resumes a transiently interrupted range from the explicit base plus delivered bytes. It must not clamp the request to the buffered edge or show a playlist failure notice for a recoverable read.

The initial continuous profile is MP3-only. Other accepted audio formats remain manually playable through the single-track fallback and are visibly skipped by automatic continuation. Video remains outside this architecture.

The complete browser and release contract is documented in [`docs/audio-continuous-stream.md`](docs/audio-continuous-stream.md) and [`docs/wiki/Playback-Continuity.md`](https://github.com/wongyiuming/FrontierCloud-Gin/wiki/Playback-Continuity).

## 10. Admin GUI contract

The Admin console order is an intentional product contract and is tested in both source and real Chromium layout:

1. Media management
2. Media sorting policy
3. Lyric relations
4. Karaoke users
5. IP security
6. WebRTC network relations
7. Nodes
8. Site access state
9. System release management
10. Admin Key
11. Brand Logo

Dynamic modules must join this same final DOM/visual order. Reordering code must be idempotent; DOM mutation observers must not create self-triggering reorder loops.

## 11. Release topology

The independent `wongyiuming/FrontierCloud-Gin` repository inherits the old
`gin_dev` development and `gin_main` release history as `dev` and `main`.
The old repository is not renamed or rewritten. Only Gin artifacts deploy.

Absolute repository policy:

- **Do not create any new branch** outside `dev` and `main`.
- implementation goes to `dev`, never directly to `main`;
- only same-repository `dev -> main` promotion PRs are valid;
- after promotion, fast-forward `dev` to the release merge commit;
- never force-rewrite a canonical branch. Database selection does not change the release profile.

Release management upgrades only the Master itself. Storage has no updater,
release synchronization, cluster convergence or remote upgrade API. Historical
local manifest parsing exists solely for durable updater recovery. See
[Master-only version management](docs/master-self-release.md).

GitHub-side ref creation cannot be fully prevented by a unit test. The repository-policy workflow detects non-canonical branch creation after the event, while true pre-creation prevention requires GitHub repository ruleset/administrative enforcement. The no-new-branch invariant must remain documented here, in `CONTRIBUTING.md`, and in the Wiki/ruleset configuration.

## 12. Supported runtime and validation

Only Gin/Go may serve business APIs or run the updater. Default deployment is Gin + SQLite; the sole database alternative is Gin + MySQL. Changing DB_TYPE is not a database migration. Preserve historical keys, IDs, passwords, tokens, node relationships and backup serialization when adopting existing data; preserving data formats does not authorize a Python runtime.

Python application sources remain explicitly non-executable examples for comparing syntax. Python is supported only as a test/script driver; tests call real Gin HTTP endpoints or inspect native source contracts, never import FastAPI/application services. No Python application, tests or scripts are packaged into the production Web build context.

Karaoke password work has one non-queuing slot. Atomic Redis admission budgets
apply before captcha/password validation and cannot be bypassed by correct
captcha answers. Rejections return 429 with Retry-After; unavailable admission
fails closed. Captcha SVG outlines must not contain answer-bearing text/metadata;
OCR resistance is not assumed. Redis noeviction protects security counters and
sessions under a bounded memory limit. See docs/validation-and-promotion.md for
the complete contract. Public HTML has a fresh script CSP nonce bound to trusted
template source before user substitutions. Inline event attributes and eval are
forbidden; player DOM listeners, HTTPS direct storage, blob playback and
same-origin karaoke microphone access remain supported. Nginx preserves one CSP
and protects maintenance/errors; direct Go storage has its own restrictive
headers. TLS servers share a TLS 1.2/1.3 AEAD policy and negotiate HTTP/2.
See docs/public-security-baseline.md for verified scope, explicit compatibility
exceptions and manual DNS/no-mail tasks. These changes are not a penetration-test
certification. See docs/validation-and-promotion.md for
the exact budgets and release-scoped security evidence.

Heavy acceptance runs only on the prepared development host: five native nodes (one Master, two Direct storage nodes, two Relay storage nodes), repeated for SQLite/MySQL on the Master; all storage appliances use embedded SQLite. No mixed Python/Go fleet or Python application acceptance remains. Hosted test CI has an explicit three-minute hard limit per parallel job, no serial test-job chains, Docker builds, fleet, real database, or real-browser jobs. A timeout is a failure, not permission to extend the limit. A separate exact-test-success-gated compilation workflow publishes public exact-SHA Web/Updater/Nginx runtime images, with parallel ten-minute jobs and no acceptance work. CD notification waits for every public image. Deployers pin manifest digests and validate runtime/schema/source/platform before use; only confirmed absent versions/platforms permit bounded immutable-source compilation. Auth/network/proof failures stop, rather than fall back.

Wiki operations guidance is maintained in the separate GitHub Wiki repository. Do not track docs/wiki in this repository.

Publication is a default-main `workflow_run` consumer of completed successful
source CI, not a dev-defined credentialed push workflow. Compile jobs are
free of package-write credentials; a separate immutable-main publisher validates bounded OCI data
and writes only the verified source SHA tag. It must not run candidate scripts,
Dockerfiles, containers or archive-extracted executables with write credentials.
Only the publisher receives automatic `GITHUB_TOKEN` `packages: write`; plan,
compile and notify jobs do not. The public packages must grant
`FrontierCloud-Gin` Actions Write; public pulls remain anonymous. Repository
workflow writers are explicitly trusted to request package writes in other
workflows, so this is not an ACL preventing dev writers from replacing tags.
No personal package PAT or publisher Environment is required; previously
created unreferenced credentials/settings are not consumed or deployment triggers.
The separate staging signing key still belongs only to `staging-cd-main` with
an exact main Branch rule, never a dev-accessible repository/organization secret.
These external settings are not properties proved by source tests. The owner
authorized one image-only bootstrap exception for same-repository PR #5: an
owner-applied full-SHA label, fixed PR workflow snapshot, exact successful source
CI and current refs gate bounded compilation and verified OCI publication.
This explicitly authorized candidate snapshot is not immutable-main code. Its
publisher is the only package writer; it reads no signing secret or Environment
and cannot deploy. Only the first matching run/latest owner retry may claim
that label. No future PR inherits this exception. Actual staging acceptance
still precedes merging; the normal main-only signing boundary is unchanged.
Delivery dependencies are allowed only in these isolated publication workflows;
hosted test job chains and their three-minute limit remain unchanged.

The dedicated RN preproduction Master at `www4399.sbs` has separate data,
identity, secrets and updater control from any production storage appliance on
the same host. Its local CD follows the newest successful exact `dev` push,
never substitutes that evidence for reviewed production `main` publication.
Native immutable image builds are bounded to one CPU and 1 GiB with no extra
swap allowance. Production migration artifacts are built on the development
host before the cutover. See `docs/staging-cd.md`.

## 13. Regression rule

When an invariant can be encoded as a test, encode it. When it cannot be reliably observed from repository code (for example, who is allowed to create a Git ref), document it explicitly and enforce it with GitHub repository settings where available.

A regression may not be weakened merely to accommodate a new feature. Architectural changes require an explicit architecture update and corresponding test changes in the same development cycle.

## 14. Storage appliance deployment

`DEPLOYMENT_MODE=only_stroge` runs a single resident Go HTTPS/file/control
container. Initializers exit; no Nginx, Redis, MySQL, updater, coturn, Admin GUI
or player is deployed on storage. SQL payload backups are files, not online
replicas or SQL BLOB copies. Master controls transport and allocations.
Ports 80/443 are prohibited; the default explicit HTTPS port is 8443.

The persisted role discriminator `Follower` remains in protocol-v2/SQL to
preserve node IDs, references and transactional recovery. It is not a supported
independent business deployment or another business authority. Do not globally
rewrite persisted roles or reinitialize an owned disk to rename the product.
See [storage appliance operations](docs/storage-appliance.md).

RN's production storage and preproduction Master (`www4399.sbs`) are
separate security/data/Compose projects. Only the staging Master uses 80/443.
No production operation is automated in this change.
