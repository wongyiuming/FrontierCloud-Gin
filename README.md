# FrontierCloud

FrontierCloud is a self-hosted media browsing, continuous-audio playback, karaoke, cluster-storage, backup, and administration system. Go (Gin) provides the default business/control plane with SQLite; MySQL is the only database alternative. Python application sources are non-executable syntax references; Python remains available for test/script drivers only. Browser JavaScript, Nginx, Redis and coturn retain their existing roles.

The core product model is deliberately small: one business Master owns business truth, storage nodes provide Storage and/or Backup resources, and every managed media object has one complete physical owner.

This independent repository is `FrontierCloud-Gin`, with Go-only `dev` and
`main` branches inherited from the old native reconstruction. Deployment must
use an exact reviewed release; bootstrap history alone is not release proof.

## Current capabilities

- Music and video catalogs backed by managed media storage.
- MP3 continuous playback through one browser `MediaSource` / `SourceBuffer` session.
- Bounded playback-clock buffering, silent interrupted-read recovery, and HTTP Range repositioning for seeks beyond the current buffer.
- Bounded catalog caching with SQL-commit and managed-file mutation invalidation.
- Synchronized/fullscreen lyrics, explicit lyric relations, and non-destructive same-name auto-link.
- Karaoke entry from media playback, guest preview, account recordings, and storage quota.
- Master/storage storage placement using Local, Direct, or Relay transport.
- Transactional upload, visibility, priority, same-parent folder rename, and recovery-aware deletion.
- Asynchronous bounded Backup artifacts, node health/control, Admin audit facts, and reviewed Master-only releases.

## Quick start

For a fresh HTTP Standalone node, prepare images for the exact committed native
source: pull verified public GHCR images first, compile locally only for confirmed
missing versions/platforms. No Python application or MySQL service is required
(the host-side image resolver uses Python 3):

```bash
export FRONTIERCLOUD_REVISION="$(git rev-parse HEAD)"
bash scripts/build-native-images.sh "$FRONTIERCLOUD_REVISION"
docker compose up -d --no-build --wait
```

Compiled images are visible in the repository's [public Packages](https://github.com/wongyiuming/FrontierCloud-Gin/packages).
See [image delivery](docs/public-image-delivery.md) for exact-SHA/digest checks,
fallback rules and the independent compilation workflow. Do not use `--build`
for the normal image-first deployment path.

Open `http://localhost`. The startup initializer creates the managed media tree under `data/media` and the persistent runtime secrets required by the stack.

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

EVOXT preproduction at `ml.520mall.cc` is a separate Master with its own state.
Its [bounded local CD controller](docs/staging-cd.md) is triggered by each completed
successful `dev` push test CI **and public image publication**, never by a polling timer; production follows reviewed
`dev -> main` releases only.

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
