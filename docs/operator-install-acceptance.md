# Isolated installation acceptance

`tests/operator_install_acceptance.py` exercises installation in two distinct
ways. Its result never claims that an unpublished revision passed public release
verification.

The first group executes the shipping compiled `fc` against a real local Docker
engine. It checks a missing DNS name, an occupied TCP listener, existing database
and identity files, a changed data mount, a stopped old Compose project in the
same working directory, and an existing named volume. File hashes and Docker
resource inventories must remain unchanged after `doctor` and the rejected
`install`. The subprocess PATH contains only Docker. Go, Node, Python and C
compilers are unavailable to both `fc` and the compiled installation driver.

Registry availability may prevent the shipping CLI from reaching its final
installation admission. The result therefore also records the complete doctor
report and independently tests the existing-data guard through the real
`Deployment.Install` implementation with controlled release evidence. It does
not mistake a registry rejection for proof that a later guard executed.

The second group uses the opt-in `TestOperatorInstallComposeAcceptance` test
binary. It supplies synthetic reviewed-release evidence and maps immutable
publication proofs to already built private image IDs. Docker Compose and all
native initialization, database, identity and certificate processes are real.
The private certificate test controller runs the existing ACME client against a
local CA. No production CLI trust override is introduced. The test network has
no published service ports, and the CA is started before its trust file is
mounted into the consumers.

The success cases cover Master SQLite, Master MySQL, Direct Storage and Relay
Storage. Each starts from empty native data, requires fresh certificate issuance
and matching serving bytes, then recreates serving containers and verifies the
same NodeID, database generation, native vault key and version receipt. Master
also retains its media premaster; Storage must not create a media decryption
key. The configured Master deployment initially retains its ordinary Standalone native identity;
promotion remains the existing explicit Admin operation.

The failure cases execute a real Docker pull against an unavailable loopback
registry and a real local-CA rejection. A failed pull must not initialize the
deployment. A failed certificate installation must retain its prepared receipt,
must retain its initialized vault key, must not report ready, and must refuse
fresh reinitialization over that state without starting another pull or service.

Installation verifies the native certificate status after Compose starts. The
configured hostname and TLS setting must match; enabled TLS requires actual
HTTPS readiness and identical managed and serving fingerprints. The native
`certificate-ready` command must then pass before the receipt becomes `ready`.
Compose startup and these checks share the existing ten-minute startup deadline.
Controller liveness alone does not satisfy installation readiness.

The [2026-10-12 evidence matrix](audits/2026-10-12-installation-acceptance-matrix.json)
links the verified cases and hashes of their original reports:

| Acceptance | Recorded evidence |
| --- | --- |
| Seven compiled-`fc` protection cases; existing bytes/resources unchanged | The `guards` section of the [third run](audits/2026-10-12-installation-native-third.json) |
| Master SQLite/MySQL, Direct/Relay, actual pull failure | Five completed cases in the [fifth run](audits/2026-10-12-installation-native-fifth.json) |
| Actual CA rejection; prepared receipt/vault key preserved; repeated install refused before pull/up | The [sixth run](audits/2026-10-12-installation-native-sixth.json) |
| Readiness mismatch, stale observation, pending CA rejection, retained failure state | [Final operator race suite](audits/2026-10-12-installation-readiness-race-final.txt) |

These are per-case results. The third run stopped at an incorrect Storage-key
test assumption, subsequently corrected. The fifth run's old CA-wait case was
explicitly stopped when the controller returned `PENDING` with a recorded
permanent rejection; its [cleanup record](audits/2026-10-12-installation-obsolete-case-cleanup.json)
retains the cause and owned-resource evidence. The corrected sixth run verifies
that rejection directly. Neither partial run is claimed as a complete passing run.

Build `fc`, `internal/operator` and `internal/certmanager` test binaries in the
isolated build environment first, then run on the isolated Linux Docker host:

```sh
python3 tests/operator_install_acceptance.py \
  --binary /path/to/fc \
  --operator-test-binary /path/to/operator.test \
  --certificate-test-binary /path/to/certificate.test \
  --image private-web-image --edge-image private-nginx-image \
  --workspace /path/to/isolated-workspace --output /path/to/evidence.json
```

`--guards-only` runs the first group independently. `--skip-guards` and
`--private-cases direct relay pull-failure certificate-failure` can resume only
unfinished cases in a fresh isolated directory. The harness stops only its own
started Compose fixtures, records their image IDs and exit states, then removes
those stopped containers and empty networks after validating project labels.
It retains named volumes, data, receipts and test logs for review. It never runs
a global prune, data wipe or volume deletion. Its per-case test logs identify
startup failures without printing Docker command
output that might contain credentials.

Public release first-installation acceptance still requires an approved
published bundle and the corresponding public DNS and CA entrance. Private
installation-protocol evidence does not replace that release boundary.
