# FrontierCloud

FrontierCloud is a self-hosted media browsing, continuous-audio playback, karaoke, cluster-storage, backup, and administration system. Go (Gin) provides the default business/control plane with SQLite; MySQL is the only database alternative. Python is used only for test and operational scripts; the retired application and display references have been removed. Browser JavaScript, Nginx, Redis and coturn retain their existing roles.

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
- Asynchronous bounded Backup artifacts, node health/control, Admin audit facts, and reviewed operator-managed releases.
- Compact node summaries and an independent Storage-to-Storage migration module;
  migration bytes never relay through Master and retirement remains separate.

## Quick start

Already have a registered global `foc` deployment? Use the separate
[daily foc guide](docs/foc-quickstart.md) for status and the one-command `foc upgrade`
path; installation and advanced recovery remain in the complete manual.

For the guarded installation path without a source checkout, use the public
[operator bundle](docs/operator-manual.md): download `scripts/get-fc.sh`, extract
one published main release, configure the domain and run `./fc doctor` followed
by `./fc install master` (or `storage`). Its receipt pins all component digests
and rejects existing state. Default business and storage Compose also install
the mandatory global `foc` entry before their application initializers run.

For a fresh HTTPS node, point public DNS at this host and create `.env` with
only these two values (replace the example hostname):

```dotenv
TLS_ENABLED=true
SERVER_NAME=4399.com
```

```bash
docker compose up -d --wait
```

All other settings have defaults: public GHCR `latest` images from the newest
successfully published **main** release, SQLite, `./data`, generated persistent
secrets, the `frontiercloud-gin` project and ports 80/443/3478. No source SHA,
host Python, local image preparation or compilation is required. With no `.env`,
the same command starts HTTP at `http://localhost`. Public TCP 80/443 must be
reachable and available. Go obtains, validates and renews certificates; no
prepared certificate or Certbot is required. Public HTTP/HTTPS ports are fixed
at 80/443. Startup does not migrate an old store.

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

Use this deployment's own Compose directory and persistent secrets.

The two supported `.env` deployment selections are documented in
[Native deployment](protocol/v2/native-deployment.md). Changing the runtime or
database selection does not migrate existing state. Historical Python cluster
volumes remain fenced until a separately verified offline adoption/migration;
do not apply this quick start to an existing cluster.

Preserving an existing storage identity and media requires the separate
[offline storage handover](docs/storage-appliance.md), not
reinitialization or re-pairing. Existing native MySQL Masters use the
[separate SQLite conversion](docs/offline-master-to-sqlite.md).

TLS_ENABLED=true always enables automatic certificate management. Nginx
remains the business HTTPS entry; Storage uses Go HTTPS directly. Failed first
issuance exposes no plaintext business. Admin shows certificate lifecycle facts
and offers authenticated, audited downloads of each node's certificate/key pair;
there are no upload, path, manual renewal or automatic-renewal toggle controls.
Storage exports are encrypted to a fresh browser key before crossing the Master.

Fresh storage deployments use `.env.storage.example` and
`docker-compose.storage.yaml` alone. Use `./fc install storage` from the public
operator bundle; the repository's `scripts/deploy-storage.sh` delegates to it.
`STORAGE_TRANSPORT=direct` uses public HTTPS 443. Relay deployments explicitly set
`STORAGE_TRANSPORT=relay`, `STORAGE_PORT=8443` and the corresponding HTTPS endpoint;
8443 carries authenticated Master communication without idle listeners on 80/443.
Both storage types temporarily bind 80 for HTTP-01 and release it after validation.
The fresh pairing package is generated only after verified HTTPS is ready.
Storage STUN uses UDP 3478 by default; browser probes visit all paired storage
nodes serially. See [storage appliance operations](docs/storage-appliance.md)
before touching an existing owned disk.

Detailed configuration, generated-secret recovery, first Admin access, role initialization, and persistent-volume guidance live in [Deployment and Configuration](https://github.com/wongyiuming/FrontierCloud-Gin/wiki/Deployment-and-Configuration).

On registered hosts, `foc upgrade` selects a verified published release, refreshes
the tool when needed, captures state recovery material and verifies the deployment
before opening. Run it independently on each host. AdminGUI has no upgrade or
rollback API. See [operator release procedure](docs/master-self-release.md).

The [public security baseline](docs/public-security-baseline.md) documents
nonce-based CSP, TLS/HTTP/2, crawler privacy, real reporting contacts and
manual DNS/no-mail hardening. Its real browser/TLS checks run on the development
host, not in the three-minute GitHub CI.

## Documentation map

The three top-level documents have separate jobs:

- **README.md** — product entry point, capability summary, shortest startup path, and navigation.
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — authority, storage, mutation, playback, security, and release invariants that implementation must preserve.
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — repository topology, change discipline, required checks, and promotion procedure.

Start with the [current capability and boundary overview](docs/current-capabilities.md).
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

Maintainers use the separate [image delivery](docs/public-image-delivery.md)
and [staging status](docs/staging-cd.md) for publication permissions,
exact-source CI and the staging boundary. The external CD receiver remains
retired. Isolated RN staging was reauthorized on 2026-10-15 and must normally be
stopped so production Relay can temporarily use port 80 for certificate renewal.
An authorization or retained Compose file is not evidence of a running staging
environment or successful acceptance. Production upgrades remain separate actions.

See [validation scopes and promotion](docs/validation-and-promotion.md) for the
distinction between source CI, executable regression and production deployment.
The [2026-10-08 repair audit](docs/audits/2026-10-08-native-repairs.md) records
security/cache fixes, actual verification and remaining release gates.
