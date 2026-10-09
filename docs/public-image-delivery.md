# Public native image delivery

The original `docker.yml` test/promotion CI keeps its three-minute hard limit.
Heavyweight acceptance runs on the development host with bounded parallelism,
not inside hosted test CI. Compilation
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
4. All three packages must be anonymously readable with verified manifests and
   image configurations. A separate default-`main` `workflow_run` workflow then
   handles the CD wakeup with its own three-minute limit. It executes only the
   trusted default-branch code, not candidate code; its secret is restricted to
   the `staging-cd-main` Environment with a main-only Branch deployment rule and
   is never exposed to compilation jobs. A repository/organization secret copy
   must not remain available to dev workflows.
5. The receiver keeps the **original test CI** run identity for replay ordering.
   EVOXT independently verifies exact current dev HEAD/test CI, performs native
   deployment and must pass live acceptance before opening/merging dev -> main.
6. A main merge verifies identical reviewed source tree/provenance, passes its
   source CI and publishes its own exact-merge-SHA images. Production remains a
   separate operator-controlled upgrade. Storage is never auto-upgraded.

The compilation workflow is push-triggered with an explicit exact test-CI gate;
the secret-bearing CD notification uses the default-branch trust boundary.
Before the new notification workflow exists on default main, its first dev
candidate requires an explicitly authorized one-time operator bootstrap rather
than running candidate code with a CD secret. That bootstrap is not implied by
CI success. See [staging CD](staging-cd.md) for the transition and receiver gates.
The old source-success-only staging notification must remain retired, not race
image publication.

## Public artifacts and deployment

Development MySQL fixtures use one CPU and an explicit 768 MiB no-swap cgroup,
a 64 MiB InnoDB buffer pool, 64 connections and disabled Performance Schema.
This bounds test-server instrumentation without changing transactions or
production settings. A 2026-10-09 run proved a 512 MiB fixture was OOM-killed
during business tests; that failed run is retained, not counted as acceptance.
Fixture failures now print scoped exit/OOM diagnostics before cleanup. Hosted
test CI still runs no database and keeps its three-minute deadline.

Business/race test containers also cap compilation explicitly: two package
workers, `GOMAXPROCS=2`, a 512 MiB Go managed-heap target per process, `GOGC=25`
and an aggregate 3 GiB no-swap cgroup. The heap target is not an RSS hard cap.
A separate 2 GiB fixture OOM killed two compiler processes during HTTPAPI
dependency compilation; those failed results are not acceptance. These limits
retain parallel compilation without assuming that limiting CPU automatically
limits aggregate compiler memory. They do not change production runtime limits.

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

## Write-once publication discipline

Before setting up Go/Buildx, compiling or logging in, every matrix job
anonymously checks **all three exact-SHA components**. It verifies the index and
selected manifest SHA-256, config descriptor size and SHA-256, a unique
`linux/amd64` runtime, canonical source/revision/component labels, Go/schema
generation and the Web/Updater release contract. Existing verified bytes are
reused by digest: rerunning a SHA or promoting the identical SHA from dev to
main skips compilation and push. A valid partial release resumes only its
missing components; existing ones are never rebuilt.

Only one canonical `404 MANIFEST_UNKNOWN` for the **SHA tag itself** authorizes
new publication. Generic 404, private/permission failures, network/5xx errors,
unsupported existing platform, missing child/config or wrong provenance stop
publication rather than granting a rebuild. GHCR's config-blob redirect is
restricted to HTTPS `pkg-containers.githubusercontent.com`; a fresh request
does not forward registry authorization, and returned bytes are hash-checked.

Trusted publication jobs share a repository + SHA + component concurrency key
across dev/main, with `cancel-in-progress: false`. The publisher rechecks the
tag before pushing and verifies its final digest against Buildx's generated
metadata. A previously verified digest that drifts or disappears is an error,
not permission to replace it. These are **workflow-level** write-once controls,
not registry atomic compare-and-swap or intrinsically immutable SHA tags. Every
trusted writer must use that shared lock; external package administrators can
still modify tags. Deployment therefore remains digest-pinned and fail-closed.

On 2026-10-10 the new publisher was exercised twice against the already public
SHA `05617629dc8f1bbb6cf029d24724d6f6b142d3b0`, anonymously checking its real
three-component manifests/configurations. Both invocations reused identical
digests with **zero build/push calls and no registry writes** (21.11 seconds
total). This is a real existing-SHA reuse test, not a new GitHub workflow rerun
or proof of registry CAS. The verified `linux/amd64` runtime digests were:

| Component | Runtime digest |
|---|---|
| Web | `sha256:34d40ba6b751cb0b94075fe0215fcfe55cc9fc61af0f0c948801486431202ab2` |
| Updater | `sha256:6f0edad01b75449b73a387a3d9bb21ee5d042b460db91da9d5a7b08f8916f624` |
| Nginx | `sha256:f1c76d52389fa6fd43dd4b730ded3a1ffd3d6429189292480c52eddd4d66f60c` |

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

An old updater whose binary predates this feature needs a controlled bridge.
Do not force its cold local compilation on a low-memory production host.
A development-only real fixture has verified preserving the old business,
identity/data and native idle journal while replacing only the control runtime
with a verified public updater. Production use still requires explicit operator
authorization and full acceptance of the final main release; never edit a
journal to claim idle/success or bypass AdminGUI release policy. Subsequent
upgrades use public images. Historical release SHAs
without published images retain the proven-absence local-build fallback.
`FRONTIERCLOUD_IMAGE_SOURCE=local` is reserved for isolated development fixtures
whose private synthetic history has no public artifacts; it is not a production
workaround for a failed registry check.

Compilation or publication timeout/failure does not trigger CD. Rerun the exact
workflow after fixing the cause; do not increase test CI's budget, switch to
`latest`, weaken image verification or silently resume a failed deployment.
