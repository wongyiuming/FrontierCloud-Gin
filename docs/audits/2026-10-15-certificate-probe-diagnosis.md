# Historical RN automatic certificate probe diagnosis

This read-only investigation observed production `rnlsj.520mall.cc:8443` at
revision `6588b7403db2bef9025046cb0d4b74f6a62d5306`. It changed no CPU quota,
Compose selection, certificate, key, trust configuration or container state, and
forced no public issuance or renewal. This document describes the original bug,
not a later fixed or deployed version.

## Confirmed defect

The Go manager's `refresh` in `internal/certmanager/manager.go` shared one
three-second context between local cache/key/chain validation, metadata reads
and the final online TLS probe. Local work could exhaust the probe's budget.
Every probe failure could become `serving_certificate_mismatch`, conflating
an unavailable trusted observation with a proven fingerprint difference.
Refusing readiness without proof was correct; the reported cause was incorrect.
`foc` read these facts through `certificate-status` in `internal/operator/doctor.go`;
it did not originate the manager's error code.

## Development reproduction

An isolated diagnostic copy used the existing local test CA and a real Go TLS
server. After obtaining a valid identity and stopping manager background loops,
the diagnostic metadata wrapper delayed a successful load by 3.1 seconds. The
original implementation then reported mismatch with an empty serving fingerprint.
A fresh three-second independent probe returned the original matching fingerprint.
The observation interval was about 3.169 seconds, including the independent probe.
`TestDiagnosticSharedRefreshDeadlineMislabelsHealthyTLS` passed under race: that
means successful reproduction of the old bug, not a product fix.

The original `manager.go` SHA-256 was
`24fd34bdce9398dad20d3d78cce7bac020e7a07eb8f112135d27287fd0334df5`.
No production certificate/trust material was copied into the fixture. Injected
local delay is not a trace of a particular production request's underlying error.

## Production observations, 2026-10-15 20:37-20:39 UTC+08:00

- Agent quota was `5000/100000`, or 0.05 CPU, matching Compose.
- Six direct reads of the existing Unix status socket, without starting another
  agent process, returned ACTIVE. Independent trusted TLS handshakes all matched
  `aae8e868cc372646963ea5fc045a6bae07df8665af16d62e060ac63c2d7233bb`.
- The cgroup recorded 120 quota periods, 93 throttled, and about 9.845 seconds of
  accumulated throttling. That is not individual request or refresh latency.
- Three actual `foc status` calls returned certificate pass/blocked/blocked and
  took about 6.01/14.97/11.38 seconds. The original tool launched the full Web
  binary inside the agent, sharing its quota with the controller and healthcheck.
- Independent TLS still returned the same valid certificate. In one interval,
  the Unix view recovered to ACTIVE after `foc` had already received blocked.

These observations support CPU throttling/query contention as a production
trigger, but do not prove it caused every warning. The original implementation
retained neither individual probe error types nor per-stage timings. DNS and
network delays could enter the same branch.

## Automatic management implications

This defect belongs to Go automatic certificate management. It is not merely
operator wording. Observations did not establish an expired certificate, changed
key, replacement certificate or failed ACME issuance. Approximately 86.9 days of
validity and `auto_renew=true` do not validate a future renewal.

CertMagic/acmez scheduling and its three-minute issuance budget are distinct from
the original three-second observation budget. Probe state affects operational
readiness and actions requiring a verified serving identity. Current HTTPS
availability alone does not validate the complete renewal lifecycle.
RN staging remained stopped, preserving temporary host port 80 for production
HTTP-01 renewal.

Required follow-up: independent probe deadlines, distinct timeout/DNS/connection/
TLS-verification/mismatch codes, actual low-quota concurrent status validation,
and isolated issuance/renewal/restart/recovery acceptance. The accompanying JSON
preserves the original observations and private-record hashes.
