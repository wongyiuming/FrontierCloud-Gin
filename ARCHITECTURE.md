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

The production Web service must remain a single native Go process. Media mutation fences and recovery OS leases do not authorize horizontally replicated Web services or multiple independent business authorities. Python application and display references are removed; Python is restricted to script and test drivers.

Do not add multiple Web workers as a performance tweak. Multi-process or horizontally scaled Web execution requires replacing the process-local media mutation fence with a database-backed or distributed lock, plus new cross-process concurrency regressions, before deployment topology changes are allowed.

Do not turn folder rename into an arbitrary cross-parent move without a new transaction design and federation regression coverage.

## 6. Directory priority

Folders are first-class sorting objects. Directory priority is distinct from media-file priority and uses the same bounded preference range.

The preference range is **-7 through 500000**, inclusive. Existing persisted
values retain their exact meaning; there is no reset, scaling or rank migration.
Admin dragging changes only same-parent, same-kind siblings. The Master reads the
complete scope (including hidden and off-page peers), checks a content revision,
then plans and audits a bounded integer batch in one transaction. Equal-value
ties still use the public directory/media comparators. Collisions expand a
contiguous adjustment window; peers outside it keep their values and order.
Uploads, pending deletions and renames fence unsafe scopes. Stale pages receive
409, and an unrepresentable bounded order receives 422 with no partial writes.
Slider and exact numeric entry use this same range and retain existing APIs.

Public category/subcategory ordering is `directory priority descending -> name`. Priority state is stored as managed metadata and must migrate with a successful folder rename.

Media catalog ordering is `file priority descending -> managed path -> stable media ID`.
Equal priorities must keep the same order across page loads, playback sessions,
Local/Master catalogs and cache hits. Session IDs never seed a shuffle.

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

For mutable catalog APIs, the HTTP client revalidates while a single-process cache avoids repeated catalog work. All domain handles from one selected Store share a SQL commit generation; successful writes conservatively invalidate it, rolled-back writes do not. Managed filesystem mutation fences also clear the cache, including ambiguous/failing mutations. A fill racing a commit is not published. Scope keys separate role, media type, path and hidden visibility; deterministic ordering is applied to copied results without per-session entries. Cache hits never bypass readiness, role checks or stream authorization.

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
9. Admin Key
10. Brand Logo

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

Online upgrade/rollback controls are retired for all roles. Admin has no release
status/history/upgrade/rollback API, polling UI or upgrade module. Default business
Compose launches no updater and mounts no Docker/control socket or legacy updater
maintenance volume. Manual site maintenance works independently; its GUI cannot
reopen the native offline migration fence. Reviewed releases are deployed by the
operator with Compose after compatible database backup/migration checks. The update controller implementation, image and retired CD entry points are removed. Only explicit host-side operator commands manage upgrades. See
[operator release procedure](docs/master-self-release.md).

Application upgrade recovery and ordinary operator backups default to state-only
archives: database state, deployment configuration, identity keys, certificates
and native control state. Media, lyric and recording files remain in their
original mounts and are excluded. Upgrade approval binds this scope and cannot
select a full media archive. These recovery points cannot claim fresh-machine
business restoration; explicit complete disaster-recovery archives and sets
retain a separate opt-in contract. See [upgrade recovery scope](docs/operator-upgrade.md).

The normal `foc upgrade --revision SHA` entry owns its plan and recovery paths.
One explicit confirmation approves preparation and subsequent verified opening;
the existing identity, provenance, capacity, freeze and image checks still apply.
Recorded resumable stages reuse their original recovery point. Failed phases and
database restoration remain explicit and never authorize automatic reopening.

GitHub-side ref creation cannot be fully prevented by a unit test. The repository-policy workflow detects non-canonical branch creation after the event, while true pre-creation prevention requires GitHub repository ruleset/administrative enforcement. The no-new-branch invariant must remain documented here, in `CONTRIBUTING.md`, and in the Wiki/ruleset configuration.

## 12. Supported runtime and validation

### Frontend baseline — HTML, CSS and native JavaScript

All frontend development MUST use HTML, CSS and native JavaScript. This applies
to public pages, players, Admin GUI, new views and subsequent UI changes.

Use browser-native DOM, CSS, Canvas, SVG and Web APIs for rendering, interaction
and animation. Do not introduce frontend frameworks or framework runtimes,
including React, Vue, Angular, Svelte, Solid, Next.js or Nuxt. Do not add JSX/TSX,
framework-specific component files, virtual-DOM rendering, or framework-based UI
component systems. Do not replace native browser rendering with an engine such
as Three.js.

Build-only tooling, such as the existing JavaScript obfuscator, and test-only
browser automation do not change this baseline. They must not introduce a
frontend framework into shipped browser code. A new UI feature, dependency or
visual redesign is not authorization to change this architecture boundary.

### Operator installation boundary

The short-lived `fc` host client is distributed inside the public Web image's
operator bundle, alongside the canonical Compose files and environment examples.
It is not a resident service or a Web request handler. Docker subprocess access
exists only in `cmd/fc`, never in a linked Web service package. No business
container receives a Docker socket. Storage ordinary installation pulls the same
public Web component as Master; source compilation is a separate developer path.

Fresh installation verifies one reviewed main revision and all selected runtime
manifest/config digests, persists every service digest and a project/role/mount/
database binding before startup, and refuses existing identity/data/volumes.
Installation pull failure never authorizes compilation. Restart uses only those
fixed images and rejects changed deployment selection. Doctor does not create
directories/locks, initialize a database, bind ports, pull or execute images;
registry/DNS observations do not establish public inbound reachability or write
permission. Diagnostics use allowlisted facts, excluding arbitrary raw peer
summaries, errors, credentials, pairing envelopes and signed URLs.

Only Gin/Go may serve business APIs or provide operator CLI commands. Default deployment is Gin + SQLite; the sole database alternative is Gin + MySQL. Changing DB_TYPE is not a database migration. Preserve historical keys, IDs, passwords, tokens, node relationships and backup serialization when adopting existing data; preserving data formats does not authorize a Python runtime.

No Python application or illustrative application source is retained. Python is supported only as a test/script driver; tests call real Gin HTTP endpoints or inspect native source contracts, never import FastAPI/application services. No Python application, tests or scripts are packaged into the production Web build context.

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

Heavy acceptance runs only on the prepared development host: five native nodes (one Master, two Direct storage nodes, two Relay storage nodes), repeated for SQLite/MySQL on the Master; all storage appliances use embedded SQLite. No mixed Python/Go fleet or Python application acceptance remains. Hosted test CI has an explicit three-minute hard limit per parallel job, no serial test-job chains, Docker builds, fleet, real database, or real-browser jobs. A timeout is a failure, not permission to extend the limit. A separate exact-test-success-gated compilation workflow publishes public exact-SHA Web/Nginx runtime images, with parallel ten-minute jobs and no acceptance work. Fresh-install alias promotion waits for both public images. Deployers pin manifest digests and validate runtime/schema/source/platform before use; only confirmed absent versions/platforms permit bounded immutable-source compilation. Auth/network/proof failures stop, rather than fall back.

Wiki operations guidance is maintained in the separate GitHub Wiki repository. Do not track docs/wiki in this repository.

Publication is a default-main `workflow_run` consumer of completed successful
source CI, not a dev-defined credentialed push workflow. Compile jobs are
free of package-write credentials; a separate immutable-main publisher validates bounded OCI data
and writes only the verified source SHA tag. It must not run candidate scripts,
Dockerfiles, containers or archive-extracted executables with write credentials.
Only exact publishers and main-only alias promotion receive automatic `GITHUB_TOKEN` `packages: write`; plan,
compile jobs do not. The public packages must grant
`FrontierCloud-Gin` Actions Write; public pulls remain anonymous. Repository
workflow writers are explicitly trusted to request package writes in other
workflows, so this is not an ACL preventing dev writers from replacing tags.
No personal package PAT or publisher Environment is required; previously
created unreferenced credentials/settings are not consumed or deployment triggers.
No current publication workflow uses a staging signing key or notification
Environment. External package permissions are not proved by source tests. The
owner historically authorized one image-only bootstrap exception for PR #5: an
owner-applied full-SHA label, fixed PR workflow snapshot, exact successful source
CI and current refs gate bounded compilation and verified OCI publication.
This explicitly authorized candidate snapshot is not immutable-main code. Its
publisher is the only package writer; it reads no signing secret or Environment
and cannot deploy. Only the first matching run/latest owner retry may claim
that label. No future PR inherits this exception. PR #5 required actual staging
acceptance before merge. Current promotions follow the retired-staging exception
below; that historical requirement is not an unavailable live merge gate.
Delivery dependencies are allowed only in these isolated publication workflows;
hosted test job chains and their three-minute limit remain unchanged.

The owner retired RN preproduction and its external CD on 2026-10-11.
There is no staging notification or update receiver, and no replacement
preproduction environment has been provisioned. No live staging proof can be claimed.
Exact-source development-host acceptance, successful source CI, automatic review
and owner authorization remain required; document the missing staging gate.
The exception does not by itself authorize a merge or production upgrade.
Production storage retains its own state, identity, secrets and media.
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
Business public HTTP is fixed at 80 and HTTPS at 443. HTTP_PORT and HTTPS_PORT
are retired and nonstandard business origins are rejected before startup.
Storage has an explicit deployment profile, STORAGE_TRANSPORT=direct|relay.
Direct defaults to and requires HTTPS 443 for browser media/Range and Master
traffic. Relay uses an authenticated communication high port (default 8443),
without idle 80/443 listeners. HTTP-01 temporarily binds host 80 during
validation and releases it after success, failure or cancellation. Changing
profile requires a fenced endpoint transition; it cannot be a GUI mode toggle.
 UDP STUN defaults to 3478 and runs inside the
existing Go process: one packet loop, a 513-byte receive buffer, a small kernel
queue, at most ten datagrams/second including malformed requests. Binding only;
no TURN, relay forwarding or per-packet goroutines. Diagnostic failure must not
stop or degrade the successful HTTPS/media/heartbeat service.

Master supplies its own STUN address and every active, paired downstream storage
hostname, with custom UDP ports from signed heartbeat facts (legacy default
3478). Browser ICE diagnostics are strictly serial: one node/one live peer at a
time, close before advancing, three-second timeout, 250 ms inter-node yield,
and a cooldown of at least 30 seconds after the complete round. Same-origin
tabs share a non-queued Web Lock where supported; older browsers serialize per
page. No fan-out, overlapping timers, four-node truncation or parallel probe
workers. Reports retain the existing maximum eight observed addresses.

All product components are built and run through Docker/Compose. Do not install
host executables, users, systemd units or invoke systemctl for product services.
The owner explicitly authorized a limited global-operator exception: the one-shot
`compose.foc.yaml` installer and the same bounded `foc-host-init` stage in normal
Compose startup may write `/usr/local/bin/foc`, a private backend
under `/usr/local/lib/frontiercloud/foc`, and `/etc/frontiercloud/foc-deployments`.
The operator process may run briefly on the host; it is not a resident service
and does not grant Docker access, create users/systemd units or invoke systemctl.
It discovers recorded deployments and invokes existing manual operator workflows.
Normal startup registers automatic discovery; first use verifies the marked
standard project's running public images and provenance before recording its
receipt and immutable image lock. This installation completion writes only
operator metadata, never business data, DDL, permissions or service state.
Unrelated Compose projects are not adopted. Host installation state is excluded
from business recovery archives and is reproducible from the published bundle.
Business and certificate processes remain Compose services. The installer has
three writable install binds plus read-only deployment and `/usr`/`/etc` parent views;
no host-root/runtime-directory bind, Docker socket or network is attached.
See `docs/operator-manual.md`.

Enabling TLS requires automatic certificate control in a Compose container using the same Go image,
a five-percent CPU/128 MiB/no-swap limit, read-only rootfs and dropped capabilities.
Its exiting initializer touches only explicit volume mount roots. No host PID,
privileged mode, service-manager access, Docker socket or arbitrary commands exist.
The default Linux temporary mode uses host networking and only NET_BIND_SERVICE: no Docker 80 publication persists after
the Go listener closes. Host networking shares only the network namespace; it
does not authorize host process/filesystem/service management. Business uses a private bridge challenge service, reached through Nginx on
public 80. No user-managed webroot or optional manual certificate mode exists.
User-owned external CI/CD integration is outside the business product boundary
and may use systemd; the business GUI does not manage those host services.
Certificate TLS/control state uses project-scoped persistent Docker volumes;
container recreation must not replace the volume directory mounted by Web.
Container UID 0/GID 10001 can publish TLS for the Web's read-only group mount;
ACME account and job journal remain root-private. It is not a storage business
service. Hostname/approved CA and public paths are fixed in local Compose.
The active upstream Master observes certificate lifecycle state through existing
relationship authentication. AdminGUI provides status and authenticated,
audited certificate/key downloads; it cannot upload, configure paths, request
renewal or disable automatic renewal. Storage key exports are encrypted to the
requesting browser so Master can relay opaque data without reading the key.
Certificate accounts remain private to their originating node. Renewal uses a
mature ACME library's scheduling, retries, storage locks and ARI when available.
Published complete generations occupy a separate volume from private account
state. Edge reload performs fixed local validation and reload only; no business
process receives host service control or Docker access. First issuance failure
keeps a diagnosable controller running without plaintext business fallback.
Storage HTTP-01 binds public 80 only during validation; an occupied port produces
a clear failure without displacing another application. Relay retains its
high-port communication endpoint; Direct retains public HTTPS 443.
See [automatic TLS audit and replacement contract](docs/automatic-tls-audit.md).

The persisted role discriminator `Follower` remains in protocol-v2/SQL to
preserve node IDs, references and transactional recovery. It is not a supported
independent business deployment or another business authority. Do not globally
rewrite persisted roles or reinitialize an owned disk to rename the product.
See [storage appliance operations](docs/storage-appliance.md).

RN's preproduction and external CD are decommissioned at the owner's request
on 2026-10-11. Production storage retains its own identity and high-port HTTPS.
A future isolated preproduction IP does not inherit the retired deployment.

## Fresh-start configuration baseline

A fresh HTTPS business deployment requires only `TLS_ENABLED` and `SERVER_NAME`.
Certificate paths and ACME webroot are not operator configuration. Every other operator setting
has a usable default. Plain `docker compose up -d` pulls public GHCR `latest`
Web/Nginx images; it must not require a user-supplied source SHA or run
local builds. Empty optional values retain their defaults. HTTP without `.env`
also remains supported. Public DNS and reachable standard validation/listening
ports are prerequisites. Fresh installations never require prepared certificates.
Go obtains, validates and renews certificates; bootstrap exposes no plaintext
business while waiting for issuance. Published HTTPS must be verified before
reporting TLS ready or generating a five-minute storage pairing package.

Only immutable-main workflow code, after successful current-main source CI and
all verified exact-SHA publication jobs (including the retained legacy tool artifact), may advance `latest`. Candidate
dev code cannot advance it. Alias promotion executes no candidate code and uses
one repository-wide serialization lock with current-head/attempt checks before
each write. Registry tags are not atomic across components: installs overlapping
promotion should retry after publication completes or pin the exact SHA.
Reviewed upgrades, CD, rollback, schema and provenance checks still use exact
source/digest evidence. Defaults must not permit pull failure to trigger a build,
change database identity, migrate existing data or replace generated secrets.


### Native resource observations

Internal retirement inventory uses fixed `data`, `media` and `recordings` namespaces. The latter two borrow the actual rooted handles of the native services, so configurable mounts are not replaced by defaults under DataRoot. A default child is omitted from the data walk only when its inode matches that native root; its pinned identity is checked before/after scan pages. Unused default subtrees remain visible as unmanaged residual data. A single scanner slot, bounded pages/depth/path lengths, exact relationship binding, process incarnation and five-minute expiry apply across all three scopes. Every request uses the existing HTTPS/raw-HMAC/nonce control authentication and requires the active upstream Master.

Expected managed presence resolves at native roots. The Master independently checks every scope transcript and combines it with fresh SQL retirement ledgers; missing native-scope support yields an incomplete check. Per-scope filesystem total/free values are observations, may share one filesystem and must not be added into a capacity promise. No write probe or reservation is inferred. Observations do not freeze concurrent writers and are never migration-start, managed-delete or final node-revocation grants. Native workers/scanners must be cancelled and joined before the services close their borrowed roots. Independent retire apply still requires a final durable fence and reconciliation; a completed diagnostic report cannot substitute for it.


Retained native-state inventory exceptions require native observations: known zero-byte coordination inodes must pass an exclusive nonwaiting OS lease probe with inode/size/mtime checks, and the built-in default lyric must match its canonical bytes. Deleted-recording lease candidates require the local member's SQL tombstone and version digest plus the native idle probe; SQL classification is repeated after the probe and a changed candidate invalidates the session. Unknown, active, nonempty, foreign or malformed material stays blocking. Retained entries remain in physical observation totals and are reported separately. Probes release their leases before returning, so these facts do not replace the durable, held fence required by final retirement.


Terminal peer migration ledgers reconcile scalar task/unit/object rosters and role-specific journal outcomes. Cleaned committed units retain source deleted and target published-or-later-deleted history; cancelled uncommitted units retain source receiving and target aborted/deleted history. A terminal task cannot hide missing bindings/units, mismatched counts/bytes, incomplete grace or active runner leases. Resource ownership, reservations, scopes, reads, physical material and recovery retention are independent gates. These readonly diagnostic queries do not substitute for archived binding integrity validation or a final durable revocation fence.

### Paged migration plans and explicit protocol support

Generation 7 stores plan headers, immutable admitted object bindings and target
path observations separately. Preview records do not drain members, reserve
capacity or change ownership. Native inventories, content proofs and keyset SQL
pages bind the complete source catalog to an incremental digest; a page boundary
must never become an ownership boundary. Start rechecks identity and catalog
facts, then admits the task with its source drain, scopes and reservation in one
transaction. Runtime operations page through the same bound roster. Ownership
still changes for an entire immediate-parent unit in a short commit transaction;
copying never holds that transaction open. The bounded legacy task representation
remains readable for already recorded tasks.

Current nodes explicitly advertise `resource-migration-direct-v1`. Missing optional
capability fields retain only the historical protocol-v2 baseline. Compatibility
fallback must never grant a newly added migration, release or restore feature.

Master computation and data traffic must be avoided wherever business work can
run on storage peers. An administrator-selected Relay deployment remains a
business transport choice; it never authorizes migration data relay. Migration
bytes travel directly from source Storage to target Storage for every Direct/Relay
combination. Master only coordinates tasks, public identity grants, progress and
ownership commits. Neither administrator approval nor connectivity failure can
enable a Master migration relay. Unreachable peers retain source authority and
durable target checkpoints until connectivity is repaired. Source cancellation
proofs hash bytes locally and return only version-bound proof metadata.

Heavy migration work is queued durably and must yield to external business HTTP
traffic on Master and both peers. Automatic traffic waiting must retain task
intent and checkpoints separately from an administrator's manual pause. Resume
requires a sustained low-traffic interval with hysteresis; migration/control
traffic must not count as external business traffic or prevent its own resume.
Admin observation must expose the queue, waiting reason, measured rates, stage,
objects, byte progress and failures. The HTTP process counts actual request-body
reads and response writes incrementally, including storage business data routes
used by Relay. Migration/control and its Admin observation traffic are excluded.
Five-second rates plus a one-second burst observation pause new chunks at
256 KiB/s; resumption requires rates at or below 64 KiB/s for thirty continuously
observed seconds. Startup waits for that low interval too. The persisted task
remains runnable with `waiting_business_traffic`; manual pause remains a separate
state and invalidates its runner lease. Local disk scans yield at bounded reads,
without marking traffic deferral as corruption. Deferred destructive operations
obtain fresh proofs again before applying their grants. Nginx's bounded native
counter module measures actual request-length/sent-byte deltas without changing
sendfile or HTTP/2 delivery. A read-only Unix socket shares aggregate rates with
Web; missing/stale observations fail closed and a new gateway epoch restarts the
quiet interval. The IPC volume is reconstructible and is not recovery state.
Full native fleet and load assertions still require coherent-image acceptance.

### Final retirement admission

Retirement first records a persistent `retiring` relationship and denies normal
work using that relationship. An independent per-data-root OS request lease joins
already authenticated internal HTTP requests and asynchronous migration workers.
Final peer completion holds its exclusive request lease and both native resource
mutation barriers while rechecking the SQL ledger and native filesystem. A
previous successful preflight is never accepted as the final proof. Pending
transactions, reads, sole recovery points and unknown material remain blocking.

Only the narrowly authenticated retirement receipt channel remains usable after
revocation, so a lost acknowledgement can reconcile the same tombstone without
restoring normal credentials. Identity reset cannot bypass an unfinished fence.
Completed history, identities and recovery materials remain retained; business
retirement never stops containers or removes volumes, certificates or disks.
