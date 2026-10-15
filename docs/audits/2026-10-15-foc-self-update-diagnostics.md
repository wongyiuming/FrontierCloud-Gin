# foc self-update diagnostics acceptance

The previous self-update discarded the installer process failure. This change
separates verified image download from Compose installation, preserves an
allowlisted failure category and exit status, and identifies release/image
verification failures without disclosing arbitrary stderr or signed URLs.
Compose installation uses the already verified local image with pulling disabled.
No business upgrade, installer ownership check or lock is bypassed.

## Development acceptance

The exact implementation, test and manual inputs listed in the companion
JSON passed focused Go race tests and the bounded source CI script on
192.168.6.201. A disposable Docker-in-Docker daemon performed a real anonymous
GHCR cold download and global Compose installation of published revision
c438232d16a8c95baa94fa81289e9afed980c881. Modified host-command and active-lock
refusals retained compose_install and exit_code=2; restoring fixture-owned
conditions allowed a successful retry. The business receipt stayed unchanged.
Publication evidence was fixed inside this test binary only; actual registry
proof, image download, Docker runner, Compose and host installer were exercised.
This is operator acceptance, not a new business fleet or database migration test.

Review follow-ups extend real TLS cancellation and context/client timeout tests
through both response-header and partial-body reads for GitHub verification and
the registry, public-token, authenticated-retry and fixed-host config redirect
paths. The self-update image stage preserves these causes. Storage/permission
failures take precedence over secondary lock messages, unavailable images retain
their specific category, and an active backoff always reports a positive rounded
wait. Each follow-up's native/race/source evidence is retained separately in JSON.

## Historical Direct failure

Read-only Docker/containerd logs around the original 2026-10-15T13:43:14Z
self-update show canceled image-layer writes and subsequent missing-snapshot
cleanup errors. No retained installer container or kernel OOM event was found.
The original initiating stderr was discarded by the old client and cannot be
reconstructed. These observations do not establish disk exhaustion, a registry
fault or snapshot corruption as the initiating cause. The original implementation
also succeeded in an isolated cold-download baseline; the historical interruption
was not deterministically reproduced. The five diagnostic input scripts and
validation input are preserved in the companion JSON, separately from production
mutation records. No production deployment was changed during development
acceptance.
