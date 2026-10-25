# Public native image delivery

Public releases comprise `ghcr.io/wongyiuming/frontiercloud-gin-web` and
`ghcr.io/wongyiuming/frontiercloud-gin-nginx`, built from the same explicit main
commit. Web contains the native application, `fc` and certificate controller.
No update-daemon image is built, published or required by installation or upgrade.
The optional `operator` profile installs global foc from a separately pinned,
already published Web bundle. Ordinary Compose startup does not run or depend on
this installer. Its image is independent of the selected application release and
is not silently replaced during business upgrades.

## Reviewed source and CI

The authorized provenance pair is dev -> main in this repository. Release proof
requires exact-source successful CI and equality of reviewed and merged Git trees.
The immutable-main publication workflow runs only after successful source CI.
The trusted plan verifies the source run number/attempt, current main head and
anonymous exact-version registry evidence. Candidate code never executes with
package-write credentials.

Compilation uses parallel jobs with ten-minute hard limits, no acceptance work,
no registry credentials and no writable shared build cache. Go builders are
patch-pinned. The separate three-minute publishers validate bounded OCI archives,
platform/config/source/schema labels and descriptors before publishing. Existing
verified exact-version bytes are reused; only proven manifest absence admits
creation. Network, authentication and integrity failures stop publication.

Only exact publish and main-alias jobs receive automatic `GITHUB_TOKEN`
`packages: write`. Each package must grant this repository Actions Write and
allow anonymous pulls. Personal PATs and a publisher Environment are unnecessary.
Repository workflow writers remain trusted; this is not protection against an
authorized workflow writer replacing registry tags.

## Immutable selection and aliases

Exact 40-character commit tags are discovery references. Deployments pin manifest
digests after verifying image/config digests, Linux platform, source revision,
database generation and Web release contract. Tag text alone is not proof.

The `publish-latest` job validates both successful exact component publication
jobs in the current workflow attempt, rechecks reviewed main proof and public
image bytes, then promotes those verified manifests to fresh-install aliases.
It never builds or runs candidate code. `foc upgrade` may select a verified
published release automatically, then pins its exact revision and digests.
An explicit revision is optional; restart never re-resolves `latest`.

The PR5-only bootstrap workflow and driver are removed; their historical
authorization cannot authorize a new publication. External CD is retired; isolated staging is manual.
Publishing images does not
authorize source promotion, production deployment or database migration.

## Development and production

`scripts/build-native-images.sh` prepares only Web/Nginx. Local compilation is
explicitly selected for isolated acceptance; production upgrades use public images
without host compilation. [Operator upgrades](operator-upgrade.md) keep original
identity/configuration, verify backups and prepare behind a closed fence before
separately opening services. [Installation](operator-manual.md) documents initial
selection. [Staging status](staging-cd.md) records the temporary RN staging constraints.

Historical public image and deployment evidence under `docs/audits` remains
unchanged; it does not describe the current component set.
