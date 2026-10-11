# FrontierCloud

FrontierCloud is a self-hosted media browsing, continuous-audio playback, karaoke, cluster-storage, backup, and administration system. Go (Gin) provides the default business/control plane with SQLite; MySQL is the only database alternative. Python application sources are non-executable syntax references; Python remains available for test/script drivers only. Browser JavaScript, Nginx, Redis and coturn retain their existing roles.

The core product model is deliberately small: one business Master owns business truth, storage nodes provide Storage and/or Backup resources, and every managed media object has one complete physical owner.

This independent repository is `FrontierCloud-Gin`, with Go-only `dev` and
`main` branches inherited from the old native reconstruction. Default startup uses the latest published main release; reviewed upgrades still
require exact-source proof. Bootstrap history alone is not release proof.

## Current capabilities

- Music and video catalogs backed by managed media storage.
- MP3 continuous playback through one browser `MediaSource` / `SourceBuffer` session.
- Bounded playback-clock buffering, silent interrupted-read recovery, and HTTP Range repositioning for seeks beyond the current buffer.
- Bounded catalog caching with SQL-commit and managed-file mutation invalidation.
- Synchronized/fullscreen lyrics, explicit lyric relations, and non-destructive same-name auto-link.
- Karaoke entry from media playback, guest preview, account recordings, and storage quota.
- Master/storage storage placement using Local, Direct, or Relay transport.
- Transactional upload, visibility, priority, same-parent folder rename, and recovery-aware deletion.
- [Browser media encryption](docs/browser-media-encryption.md), explicit per-selection
  storage modes, session-scoped key envelopes and authenticated streaming decryption.
- [Abandoned-upload recovery](docs/upload-lifecycle.md): expiry triggers physical
  reconciliation, never blind deletion; live streams and complete files are protected.
- Asynchronous bounded Backup artifacts, node health/control, Admin audit facts, and reviewed Master-only releases.

## Quick start

For a fresh HTTPS node, create `.env` with only these five host-specific values
(use your own hostname and existing certificate paths):

```dotenv
TLS_ENABLED=true
SERVER_NAME=ml.520mall.cc
SSL_CERT_PATH=/etc/letsencrypt/live/ml.520mall.cc/fullchain.pem
SSL_KEY_PATH=/etc/letsencrypt/live/ml.520mall.cc/privkey.pem
ACME_WEBROOT=/root/FrontierCloud/certs/acme
```

```bash
docker compose up -d --wait
```

All other settings have defaults: public GHCR `latest` images from the newest
successfully published **main** release, SQLite, `./data`, generated persistent
secrets, the `frontiercloud-gin` project and ports 80/443/3478. No source SHA,
host Python, local image preparation or compilation is required. With no `.env`,
the same command starts HTTP at `http://localhost`. Existing certificate files
and free ports remain host prerequisites; on a shared host, optional port and
project/data overrides avoid collisions. Startup does not migrate an old store.

Compiled images are available in the repository's [public Packages](https://github.com/wongyiuming/FrontierCloud-Gin/packages).
Advanced deployments may set `FRONTIERCLOUD_REVISION` to an exact published SHA.
See [image delivery](docs/public-image-delivery.md) for immutable digest checks,
local development builds and release gates. The default stack has no build
instructions; failed image pulls stop startup. The initializer creates
`data/media` and persistent runtime secrets automatically.

For first Admin access, read the existing key from the running deployment:

```bash
# Run in this deployment's Compose directory.
docker compose exec -T web cat /run/frontiercloud-secrets/admin_key
```

For preproduction, this works from any directory:
`docker exec frontiercloud-staging-web-1 cat /run/frontiercloud-secrets/admin_key`.
See [existing keys and exact staging Compose commands](https://github.com/wongyiuming/FrontierCloud-Gin/wiki/Deployment-and-Configuration#%E6%9F%A5%E7%9C%8B%E7%8E%B0%E6%9C%89%E5%AF%86%E9%92%A5%E5%90%AB%E9%A2%84%E5%8F%91%E5%B8%83)
for the metrics token, persistent recovery keys and their separate purposes.

The two supported `.env` deployment selections are documented in
[Native deployment](protocol/v2/native-deployment.md). Changing the runtime or
database selection does not migrate existing state. Historical Python cluster
volumes remain fenced until a separately verified offline adoption/migration;
do not apply this quick start to an existing cluster.

Preserving an existing storage identity and media requires the separate
[offline storage handover](docs/storage-appliance.md), not
reinitialization or re-pairing. Existing native MySQL Masters use the
[separate SQLite conversion](docs/offline-master-to-sqlite.md).

For HTTPS, copy the relevant switches from `.env.example`, enable TLS, set `SERVER_NAME`, and provide `certs/fullchain.pem` plus `certs/privkey.pem`. Fixed Master/Follower roles require certificate-verified HTTPS and fail closed when that contract is missing.

Fresh storage deployments use `.env.storage.example` and `docker-compose.storage.yaml` alone. Run `bash scripts/deploy-storage.sh`; one Go HTTPS container remains running and prints a five-minute pairing package. Ports 80/443, business GUIs, database containers and storage updaters are absent. Master controls Direct/Relay and allocations. See [storage appliance operations](docs/storage-appliance.md) before touching an existing owned disk.

Detailed configuration, generated-secret recovery, first Admin access, role initialization, and persistent-volume guidance live in [Deployment and Configuration](https://github.com/wongyiuming/FrontierCloud-Gin/wiki/Deployment-and-Configuration).

RN preproduction at `www4399.sbs` is a separate Master with its own state.
Its [bounded local CD controller](docs/staging-cd.md) receives signed wakeups only
from a default-`main` trusted workflow after successful exact-`dev` test CI and
all three public image proofs. Publication itself also executes immutable main
code: candidate compilation has no package-write credentials, and the isolated
publisher consumes verified OCI data without running candidate code. Only the
exact publishers and main-only alias promotion receive automatic `GITHUB_TOKEN` `packages: write`; plan, compilation
and notification do not. Each public package grants `FrontierCloud-Gin` Actions
Write access. Repository workflow writers are trusted to request package write
permissions; this model does not isolate them from publishing package versions.
The signing secret belongs only to the
`staging-cd-main` Environment restricted to the `main` branch, not to repository
secrets or dev compilation jobs. Initial activation uses an explicitly
owner-authorized, exact-SHA label on PR #5 for image-only CI compilation and
publication, followed by a separately verified operator staging wakeup. This
one-time PR workflow reads no deployment secret and cannot deploy production.
The normal workflow becomes active after promotion to default main; no polling
timer or direct main write substitutes for `dev -> main` promotion. Production
remains manual. See the first-activation gates in [staging CD](docs/staging-cd.md).

The [public security baseline](docs/public-security-baseline.md) documents
nonce-based CSP, TLS/HTTP/2, crawler privacy, real reporting contacts and
manual DNS/no-mail hardening. Its real browser/TLS checks run on the development
host, not in the three-minute GitHub CI.

## Documentation map

The three top-level documents have separate jobs:

- **README.md** — product entry point, capability summary, shortest startup path, and navigation.
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — authority, storage, mutation, playback, security, and release invariants that implementation must preserve.
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — repository topology, change discipline, required checks, and promotion procedure.

Operational and subsystem detail belongs in the separate GitHub Wiki (not tracked in this repository):

- [Wiki home](https://github.com/wongyiuming/FrontierCloud-Gin/wiki/Home)
- [Deployment and configuration](https://github.com/wongyiuming/FrontierCloud-Gin/wiki/Deployment-and-Configuration)
- [Operations and troubleshooting](https://github.com/wongyiuming/FrontierCloud-Gin/wiki/Operations-and-Troubleshooting)
- [Cluster and resource model](https://github.com/wongyiuming/FrontierCloud-Gin/wiki/Cluster-and-Resource-Model)
- [Media and storage](https://github.com/wongyiuming/FrontierCloud-Gin/wiki/Media-and-Storage)
- [Playback continuity](https://github.com/wongyiuming/FrontierCloud-Gin/wiki/Playback-Continuity)
- [Engineering and CI](https://github.com/wongyiuming/FrontierCloud-Gin/wiki/Engineering-and-CI)
- [Release and database migrations](https://github.com/wongyiuming/FrontierCloud-Gin/wiki/Release-and-Database-Migrations)
- [Command reference](https://github.com/wongyiuming/FrontierCloud-Gin/wiki/Command-Reference)
- [Audit and validation](https://github.com/wongyiuming/FrontierCloud-Gin/wiki/Audit-and-Validation)

The published GitHub Wiki is available at [github.com/wongyiuming/FrontierCloud-Gin/wiki](https://github.com/wongyiuming/FrontierCloud-Gin/wiki).

Development-host acceptance uses five Go nodes (one Master, two Direct, two Relay), repeated for SQLite and MySQL. Hosted test CI stays within three minutes. A separate, success-gated image compilation workflow has ten-minute parallel component jobs; neither workflow runs fleet, database or browser acceptance.

## Repository delivery

The only promotion path is same-repository `dev -> main` in FrontierCloud-Gin. Only Go artifacts are deployable. Do not create additional branches. Each promotion must
be same-repository, reviewed and backed by exact source CI; synchronize its
implementation branch after merge. Database selection never changes release profile.

Read [ARCHITECTURE.md](ARCHITECTURE.md) and [CONTRIBUTING.md](CONTRIBUTING.md) before changing cross-cutting behavior.

See [validation scopes and promotion](docs/validation-and-promotion.md) for the
distinction between source CI, executable regression and production deployment.
The [2026-10-08 repair audit](docs/audits/2026-10-08-native-repairs.md) records
security/cache fixes, actual verification and remaining release gates.
