# Public native image delivery

The original `docker.yml` test/promotion CI keeps its three-minute hard limit.
Heavyweight acceptance still runs serially on the development host. Compilation
is a **separate** `Publish native images` workflow (`publish-images.yml`), not a
longer test CI or a background test workaround.

## Gates and budgets

1. Push a development-host-accepted exact commit to `dev`.
2. Compilation first waits for the newest successful same-repository **push**
   `docker.yml` run for that exact SHA and branch. No checkout, compilation or
   package publication happens before success. Failed/pending/wrong-source runs
   cannot authorize compilation. The bounded wait does not extend test CI.
3. Three parallel compilation/publication jobs (Web, Updater, Nginx), each with
   a ten-minute hard deadline, publish `linux/amd64` images. Web/Updater compile
   on the GitHub runner (Go 1.26.8, CGO off, four compiler workers, 2 GiB Go memory
   limit). Runtime Dockerfiles copy those binaries, not source/compiler/tests.
   No `go test`, databases, fleet or browser acceptance runs in compilation CI.
4. All three packages must be anonymously readable with verified manifests.
   Only then the isolated, one-minute notification job signs a CD wakeup. It
   does not check out source or expose the CD secret to compilation jobs.
5. The receiver keeps the **original test CI** run identity for replay ordering.
   EVOXT independently verifies exact current dev HEAD/test CI, performs native
   deployment and must pass live acceptance before opening/merging dev -> main.
6. A main merge verifies identical reviewed source tree/provenance, passes its
   source CI and publishes its own exact-merge-SHA images. Production remains a
   separate operator-controlled upgrade. Storage is never auto-upgraded.

The workflow is push-triggered with an explicit exact test-CI gate rather than
only `workflow_run`: this lets its first dev candidate be tested end-to-end
before the workflow exists on default main. This does not permit premature
compilation. The old source-success-only staging notification is retired and
must be disabled on GitHub during the transition, not left racing image builds.

## Public artifacts and deployment

The repository's Packages page links to:

| Component | Public registry repository |
|---|---|
| Web (Master and storage appliance) | `ghcr.io/wongyiuming/frontiercloud-gin-web` |
| Master updater | `ghcr.io/wongyiuming/frontiercloud-gin-updater` |
| Master Nginx | `ghcr.io/wongyiuming/frontiercloud-gin-nginx` |

Tags are full 40-character commit SHAs, not `latest`. A deployer resolves the
manifest/index, checks its SHA-256 and unique matching platform, then pulls the
**digest**. It verifies component, Go runtime, revision, schema generation,
canonical repository, OS/architecture and release contract before tagging the
local Compose/native-updater alias. A SHA tag alone is not provenance proof.
Public images contain no production data, `.env`, keys, Python backend or tests.
First GHCR packages are private by default: an owner must make these three
packages public; anonymous validation deliberately fails until that is done.

Normal fresh deployment remains:

```bash
export FRONTIERCLOUD_REVISION="$(git rev-parse HEAD)"
bash scripts/build-native-images.sh "$FRONTIERCLOUD_REVISION"
docker compose up -d --no-build --wait
```

Storage uses the same image-first resolver through `deploy-storage.sh`, then
starts only its Web appliance. Compose consumes prepared exact-version aliases;
it does not compile in this path. Host-side Python 3 is a script driver, not a
runtime dependency inside Web. Compose build definitions remain available for
explicit development/confirmed-missing-image fallback, not normal publication.

## Fallback and recovery

Only a valid `404 MANIFEST_UNKNOWN` for the exact SHA or an index confirming no
image for this platform permits bounded local compilation from an allowlisted
immutable Git archive. A generic 404, private/auth-denied package, HTTP 5xx,
network error, invalid manifest/digest, failed pull or wrong labels/platform
**stops** deployment. Never interpret these as missing images. Other supported
architectures can use this confirmed-platform-missing fallback; initial CI
publication covers the current amd64 fleet only.

The native updater uses the same public-image preference and can reuse a
validated project-scoped local cache for recovery. It never accepts an arbitrary
registry or runtime credential. Cleanup removes only exact obsolete project
aliases, retaining current/previous images and shared registry tags/digests;
it never force-deletes images, prunes globally, changes data or updates storage.

One bridge upgrade is unavoidable for an old updater whose binary predates this
feature: it still uses its previous local build implementation to install the
new updater. Subsequent upgrades use public images. Historical release SHAs
without published images retain the proven-absence local-build fallback.
`FRONTIERCLOUD_IMAGE_SOURCE=local` is reserved for isolated development fixtures
whose private synthetic history has no public artifacts; it is not a production
workaround for a failed registry check.

Compilation or publication timeout/failure does not trigger CD. Rerun the exact
workflow after fixing the cause; do not increase test CI's budget, switch to
`latest`, weaken image verification or silently resume a failed deployment.
