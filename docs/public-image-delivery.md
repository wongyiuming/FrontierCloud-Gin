# Public native image delivery

The original `docker.yml` test/promotion CI keeps its three-minute hard limit.
Heavyweight acceptance runs on the development host with bounded parallelism,
not inside hosted test CI. Compilation
is a **separate** `Publish native images` workflow (`publish-images.yml`), not a
longer test CI or a background test workaround.

## Gates and budgets

1. Push a development-host-accepted exact commit to `dev`.
2. A **completed** `docker.yml` event starts `publish-images.yml` on default main.
   Its read-only trusted plan validates the real newest successful
   same-repository push for the exact source SHA/branch and the current HEAD.
   No candidate checkout or compilation precedes that proof. There is no
   195-second polling race against a separately queued source workflow.
3. Three parallel compilation jobs without package-write credentials (Web,
   Updater, Nginx), each
   with a ten-minute hard deadline, produce bounded OCI archives. Web/Updater compile
   on the GitHub runner (Go 1.26.8, CGO off, four compiler workers, 2 GiB Go memory
   limit). Runtime Dockerfiles copy those binaries, not source/compiler/tests.
   No `go test`, databases, fleet or browser acceptance runs in compilation CI.
4. Separate publication jobs use immutable default-main code and the automatic
   `GITHUB_TOKEN`, with `packages: write` granted only to these publisher jobs.
   Plan, compilation and notification have no package-write permission. The
   trusted publisher reads OCI data without extraction, executing a Dockerfile,
   loading/running a container or invoking candidate scripts. It binds the
   archive, source CI, current workflow attempt, component, platform, labels and
   SHA256 bytes, then writes only that verified source SHA tag. Existing accepted
   bytes are reused, never replaced. All three packages must remain public and
   independently pass anonymous manifest/configuration verification.
5. Only then a separate `notify-staging` job in the same trusted publication run
   handles the signed CD wakeup (three-minute limit). It verifies the trusted plan,
   the three completed publication jobs and anonymous image proofs, not an
   attacker-supplied publication receipt. It does not read candidate artifacts
   or execute candidate code. The signing key is restricted to `staging-cd-main`,
   with its own main-only Branch rule, and is never shared with compilation.
6. The receiver keeps the **original test CI** run identity for replay ordering.
   EVOXT independently verifies exact current dev HEAD/test CI, performs native
   deployment and must pass live acceptance before opening/merging dev -> main.
7. A main merge verifies identical reviewed source tree/provenance, passes its
   source CI and publishes its own exact-merge-SHA images. Production remains a
   separate operator-controlled upgrade. Storage is never auto-upgraded.

Both credential-bearing jobs use only immutable default-main code. Their
dependency chain is an isolated delivery exception, not a relaxation of test CI.
The REST uploader accepts the registry's returned upload location in both
GHCR's singular `/blobs/upload/` and distribution's `/blobs/uploads/` forms.
It retains the opaque upload identifier and query state, while requiring the
same fixed repository and verified `https://ghcr.io` origin (or a local absolute
path). Foreign hosts, credentials, insecure schemes, fragments, traversal and
pre-existing digest parameters fail closed. It streams only hash-verified OCI
blob bytes; publication still requires the exact revision manifest and digest.
The [OCI distribution specification](https://github.com/opencontainers/distribution-spec/blob/main/spec.md)
describes upload locations returned by the registry, not a client-constructed
UUID endpoint. This transfer compatibility does not broaden the package scope.

No personal package PAT or publisher Environment is required. For each public
Web/Updater/Nginx package, grant repository **`FrontierCloud-Gin` Write** under
**Manage Actions access**; do not revoke that grant as a prerequisite. Public
image reads remain anonymous and require no runtime registry credentials.
Source code cannot apply or certify these external package settings.

This is an explicitly accepted repository-writer trust model: a contributor
able to change repository workflows can add another job requesting
`packages: write`. Default read permissions are not a ceiling, and package
write-once checks in our trusted publisher do not prevent a different authorized
workflow or package administrator from changing old tags. Immutable-main code
and job isolation keep candidate execution out of this publisher's credentials;
they are not an ACL denying all dev-authored workflows package writes. Deployment
still independently verifies exact-SHA provenance and pins content digests.
See GitHub's [package Actions access](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility).

The separate **CD signing secret** still belongs only to `staging-cd-main` with
its exact main Branch deployment rule; no repository/organization signing-key
copy may remain available to dev. Any previously created package PAT secret or
publisher Environment may remain unreferenced; this workflow does not consume
them, their presence does not trigger deployment, and their cleanup is a
separate administrator choice.

Before this workflow exists on default main, the owner has explicitly authorized
one initial publication exception: `bootstrap-images.yml`, restricted to the
existing same-repository **PR #5, dev -> main**. Only an owner-applied
`bootstrap:<full 40-character dev SHA>` label starts its proof job. This is an
authorized PR workflow snapshot, **not immutable-main code**. It independently
checks owner actor/sender, current PR/head/base/merge snapshot and the newest
successful exact-source push CI before compiling. The first matching run claims
that label; only its newest owner-triggered attempt may recover. Removing and
reapplying the label cannot grant a second run the same authorization.

The exception retains three-minute plan/publication and ten-minute parallel
compilation limits. Only its isolated REST publisher gets automatic package
write; it verifies run/attempt-bound OCI data and never runs build/container code.
It has **no signing secret, Environment, PAT or deployment job**. It must not
spoof a default-main workflow identity, prematurely merge main, or re-enable the
retired source-only notifier. PR source-head metadata and the workflow's PR
merge snapshot are separate proof fields, not interchangeable SHAs.

After actual public image verification, a separately authorized operator wakeup
must preserve the EVOXT receiver's HMAC/replay/current-source/image gates and
live acceptance before merging PR #5. The label does not deploy staging or
production. Once PR #5 closes/merges, this entry cannot run for another PR.
Source tests alone are not evidence that this first CI publication has succeeded;
record the real run and all three public digests before claiming activation.
See [staging CD](staging-cd.md) for first activation and receiver gates.

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

`scripts/test-publication-oci.sh` runs only on the development host. It exports
a tiny real Buildx OCI format fixture through a disposable 512 MiB/one-CPU
no-swap builder, pins the pulled official BuildKit digest for that run, validates
the tar through the trusted publisher and removes only its own builder. It does
not compile a second application, authenticate to GHCR, publish a package,
load/run the output or certify the credentialed publication path. Keep its
archive/budget/digest evidence distinct from real application-image delivery.

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
