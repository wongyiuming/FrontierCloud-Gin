# Automatic certificate timeout and classification acceptance

Development acceptance completed on `192.168.6.201`, before any production
mutation for this fix. Machine-readable input records, runtime hashes and raw-log
hashes are in [the acceptance record](2026-10-15-certificate-fix-development.json).
The [original diagnosis](2026-10-15-certificate-probe-diagnosis.md) remains a
historical account of the unfixed implementation.

## Behavior change

Local cache/metadata work retains a three-second context. Online DNS/TCP/TLS
probing starts with an independent eight-second budget, bounded by controller
shutdown. Timeout, DNS, connection, TLS verification and handshake failures have
distinct safe codes. Fingerprint mismatch requires an actually verified different
certificate. No TLS trust, hostname, validity or cache-integrity checks were
removed. Successful probes clear only prior probe errors, preserving failed
renewal/cache evidence and in-flight issuance/renewal state. CA transport timeouts
also map to `ca_timeout` rather than generic CA errors.

`foc status` and installation status reads now execute the existing status client
in Web, using its existing read-only Unix socket mount. The 0.05 CPU agent still
owns automatic management and its healthcheck. No new host service, socket
permission, Docker mount, CPU allocation or Compose configuration is required.
Admin GUI and foc display the new safe categories.

## Executed development gates

- Race tests: `internal/certmanager`, `internal/operator`, `cmd/fc` and
  `cmd/frontiercloud`; the certificate protocol package was included and has no
  standalone tests. Slow metadata work exceeding the old shared deadline still
  produced fresh matching TLS proof. Real trusted-different and untrusted TLS
  identities, stalled TLS deadline, recovery, renewal-error preservation and
  safe operator diagnostics have regressions.
- Source CI: bounded repository checks, Python contracts, JavaScript syntax,
  crypto/build and native UI smoke checks passed.
- Real isolated Compose lifecycle: Business, Direct and Relay each completed
  real CertMagic/acmez account/order/HTTP-01/CSR/issuance and forced fixture
  renewal against a local CA. No public CA request was made.
- Restart scope: the Go manager and its Unix server were shut down and reopened
  over the same persistent state, retaining the account without extra issuance.
  Actual Web/Nginx containers were force-recreated; serving identity recovered.
- Each profile retained the actual 0.05 CPU agent quota. At both initial issuance
  and post-restart renewal, three concurrent real Web certificate-status clients
  and an agent healthcheck ran in three rounds spanning the five-second observer
  ticker: 72 submitted CLI commands overall, including 54 status reads. Every
  status read returned ACTIVE, verified HTTPS, matching fingerprints and no error.
  Status latency was 0.058-0.250 seconds. These are component status calls through
  the same socket path used by foc, not 72 complete host-level foc invocations.
- Five consecutive Web CPU samples per profile were all below 1 percent; the
  development user preview was also updated and exact nodes.js bytes verified.

The first deliberate concurrent-agent stress run failed to start a process under
the controller's small PID quota. This was retained as failed evidence and led to
the Web-side query change. An early preview verification used the wrong host
port; Compose had already updated successfully, and a separate successful check
used the existing loopback port 18080. Neither is relabeled as a passing run.

The final 889 runtime/build inputs match the local source byte-for-byte after
Git text line-ending normalization. Private candidate images were compiled from
this overlay on base `6588b7403db2bef9025046cb0d4b74f6a62d5306`; their local base-SHA
image tags do not claim a public release. Public release/production updates must
follow exact-source review and successful main publication. Database generation
remains 7; no database DDL is introduced.
