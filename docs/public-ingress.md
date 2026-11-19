# Public ingress and native resource transport

## Decision and current stage

The public browser may be unable to reach the Master even when the Master and
its authenticated node relationships are healthy. The Master remains the only
business authority and writer, and keeps the media premaster, catalog, resource
ownership, permissions, audit and Admin services. Public ingress is a separate
responsibility, selected explicitly by the administrator through the Master.
It is not Master migration, election, failover or a second business database.
Resource migration, backup, recovery and safe retirement remain independent
capabilities.

The ingress configuration and native transport policy model are separate from
the existing placement fields. Prepared Linux SQLite Master startup installs
the authenticated Owner and encrypted tree prerequisite. The Admin candidate
check verifies the signed proxy and encrypted media paths, and selection
repeats those checks before committing the new ingress generation. Each
deployment must establish that its own TLS, peers and resource paths are ready.

The development paths include authenticated Local, Direct and Relay reads,
plaintext and encrypted native objects, bounded browser grants and distinct
random aliases for the encrypted-tree transition. Master-owned lyric Direct
and Relay paths are also being integrated against the encrypted tree. Existing
legacy paths remain subject to their own contracts and are not automatically
migrated or used as a fallback when a new path is unavailable.

Activation requires all supported new-format uploads, public and Admin reads,
owner grant revocation and backup/recovery to pass together. The Master uses
the same encrypted content and physical object format as every other owner.
The ingress changes the route to an object and leaves its format intact. Use
the normal download and reupload workflow for old media. Real-browser
acceptance must cover Master Local, Direct and Relay playback, lyrics, karaoke
and downloads with independently controlled network links.

Four facts are independent:

| Fact | Meaning |
| --- | --- |
| Master | The only authority that commits business facts and authorizes access. |
| Active ingress | The one node accepting new public sessions and grants. Master is the default. |
| Resource owner | The native member that holds the object; switching ingress or policy does not move it. |
| Native policy | The administrator's Direct or Relay choice for the owner when it is not ingress. |

`Local` is an effective access classification, never a third configured
policy. It means that the resource owner is the active ingress. Otherwise the
effective native transport is that owner's applied Direct or Relay policy.
A missing or unavailable policy cannot authorize a new non-local path.
There is no special case for Master identity. In particular, a Master still
configured as Direct remains Direct after leaving ingress, even if a particular
browser cannot reach it. A failure is reported, not converted into Relay.
The ingress node keeps its non-ingress policy while its effective access is
Local, so it can resume that policy after a later explicit ingress change.
S3 is an independent adapter and retains its existing contract.

Existing `MasterLocal`, member `transport`, and relationship `mode` fields
have placement and legacy protocol meanings. The ingress model retains them and
introduces separate `public_ingress_config` and `native_transport_policy`
state; it does not reinterpret or rewrite historical ownership. A historical
Follower's existing relationship mode preserves its current applied behavior
and is marked legacy for administrator confirmation. It records the old
Master-side routing behavior, not proof that the peer's public capability is
ready. A missing Master policy is unconfirmed; neither the old `Local` value nor
its role implies Direct or Relay. Confirming a policy is independent of
selecting an ingress. Versioned peer acknowledgments distinguish a saved policy
from a node confirmation, but the runtime readiness verifier is unset by
default and the legacy route remains in use. A peer acknowledgment does not
establish browser reachability. Revision checks reject stale changes. No automatic
retry or route switch follows from saving the desired policy.

Once the prerequisite lease is installed, Master Direct can be checked against
its explicitly configured resource origin while Master remains ingress. Its
application proof is process-local, expires, and is bound to the current
ingress generation and saved policy revision. A
Relay proof requires a selected peer's authenticated proxy path; restarting the
process discards either proof. These checks do not establish client reachability.

The legacy relationship-mode API accepts an idempotent request for the current
mode, but rejects a different mode until a versioned peer application and
acknowledgment protocol is available. Its old Admin selector is removed so it
cannot bypass the policy panel. Rejection does not modify the relationship,
health, ownership or current route. A successful heartbeat remains independent
of the missing transport application capability.

## Address purposes

| Address | Purpose | Effect of selecting another ingress |
| --- | --- | --- |
| Admin origin | Master Admin GUI, management session and APIs | Remains the Master management domain. |
| Public origin | Public page, session, business and key entry point | Chosen with ingress configuration; it may remain the same if that origin reaches the new ingress. |
| Node control endpoint | Pairing, authenticated heartbeat and node control | Does not change. |
| Resource public origin | Direct browser access to a native owner | Remains that owner's validated deployment address. |

Configured, validated origins are authoritative; arbitrary request `Host`,
forwarded headers and browser-supplied proxy destinations are not. Direct URLs
may legitimately name the Master or another resource node, while Admin URLs
remain on the Master. Do not globally rewrite domains in responses, overwrite a
control endpoint, recreate an identity or re-pair to select ingress.
When the selected peer is unavailable, the recovery UI can use the Master's
existing TLS name if it differs from the persisted peer origin. Recovery admits
only the dedicated management routes while the peer is unavailable. The
Master retries the exact persisted peer, origin and generation with a fresh
heartbeat and signed edge and storage readiness proofs. When that peer
recovers, business service resumes without a selection write. An operator
can still restore ingress to the Master from the recovery UI.
`MASTER_RESOURCE_ORIGIN` is an optional, explicit HTTPS resource address; an
empty value disables the Master Direct reader and never falls back to the
control endpoint. The implemented reader currently covers encrypted objects
and plaintext Master-owned media and lyrics, and requires a verified applied
Direct policy, a live browser session, and a current authenticated ingress
admission. `FOLLOWER_RESOURCE_ORIGIN` and `FOLLOWER_INGRESS_ORIGIN` are
independent optional Follower addresses for resource Direct and public ingress
candidate checks. Configuring an address alone neither applies a policy nor
selects an ingress; the runtime selection gate remains closed until the full
encrypted-tree and resource-serving prerequisites are verified.

## Target routing matrix

The following is the required behavior. Some paths have isolated implementations,
while production activation remains gated as described above. `I` is the explicitly active ingress;
all resource grants remain subject to Master authorization.

| Resource owner | Applied policy | Effective access | Browser data path |
| --- | --- | --- | --- |
| `I` | Direct or Relay | Local | Browser → `I` local resource service |
| Any other native owner | Direct | Direct | Browser → owner |
| Master, when `I` is not Master | Relay | Relay | Browser → `I` → Master |
| Another native owner | Relay | Relay | Browser → `I` → Master → owner |

The last row reuses the existing trusted Master-to-node path; it does not copy
all long-term node credentials to ingress or require direct ingress-to-owner
connectivity. Owner `I` must never loop through Master back to `I` for its
bytes. A Relay target is determined by resource identity, ownership and the
authorization result, never by a browser-supplied URL. Public metadata and
permission decisions go to Master; lyric relationships are business facts,
while lyric body bytes follow their owner's resource path. A Service Worker
virtual URL does not change the underlying effective transport.

The browser's session and file-key envelope go through ingress to Master.
Master checks the session, identity, visibility and permission, then creates
the envelope for that browser session. The ingress does not receive the media
premaster or unwrap, re-encrypt or downgrade encrypted media. Explicitly
plaintext objects retain their semantics. An ingress is nevertheless trusted
to serve the page and its browser code; this design does not defend against a
fully malicious ingress or erase keys and plaintext already obtained by users.

## Selection, application and continuity requirements

The eventual selection flow explicitly checks an eligible paired native node's
identity, protocol and public HTTPS/proxy capability, and authenticated Master
connectivity. Master commits one monotonically increasing ingress version;
prepared candidates cannot issue new public grants, and an old ingress cannot
issue new grants once superseded. Existing short-lived authorizations and
in-flight reads need a bounded drain/expiry rule. No health, reachability or
latency observation elects an ingress or changes a policy. Master failure is
reported; ingress must not become an offline business writer.

Policy configuration needs separate desired, applied and effective states with
versioned, idempotent acknowledgement. A rejection or stale acknowledgement
must not mark a healthy control relationship offline or overwrite a newer
choice. Direct requires validated public HTTPS and an operational authorized
resource interface; it is not a guarantee that every client network can reach
the node. Relay selection does not close a public listener. Switching policy
must not provision ports, certificates or firewall rules, change control
addresses, migrate resources or re-pair nodes. Deployment of new code and any
missing public capability remains a separate operator action.

Network retries may retry the same path, but cannot request another policy
without an administrator's intervening change. After a confirmed change, a new
plan may resume only the same resource identity, object version, encryption
descriptor and correct Range position. Authentication, integrity and decryption
failures must not be bypassed through another route. Uploads and recordings
retain their existing reservation, idempotency, commit and recovery boundaries;
an entry or policy change cannot duplicate an intent or change ownership.

The current Master Direct reader, Master Relay reader and peer Relay proxy each
bound an individual admitted byte response to 30 minutes, even if bytes are
still flowing. This is an absolute drain deadline, not an inactivity timeout
or a guarantee that a longer playback will continue. A browser may make
multiple requests for a video, so total video duration alone does not establish
whether this deadline interrupts it. Before peer ingress activation, acceptance
must cover a continuously flowing response that exceeds the bound, the actual
supported browser's Range and authorization behavior, and an ingress/policy
change while a response is in flight. Any replacement must preserve a finite
old-grant drain and must not silently switch the selected transport or owner.
This is an open compatibility issue; it does not authorize a new automatic
stall-recovery feature.

Karaoke is public business functionality. Its page, named static assets and
three brand logos have exact proxy routes; the account routes forward only the
Karaoke session and CSRF cookies and the signed Karaoke CSRF header. The
encrypted-tree transition adapter can describe a currently visible native
background track and its linked lyric under the same ingress/tree lease, and
the browser requests their bytes through the corresponding native source
plan. The legacy Karaoke byte stream is unavailable when the tree is active.
Prepared Master startup installs the sealed tree, Local lyric reader and
authenticated recording controls. The account response lists eligible Direct
storage nodes and reports read and cleanup availability separately. New sealed
recordings require an explicitly selected Direct storage node. The browser
transfers ciphertext to that node and receives the storage receipt there. The
Master verifies that receipt before marking the recording ready. Only bounded
account, reservation, recovery, cleanup and key requests cross the ingress
proxy. Playback and download use a short-lived account-authorized grant for the
same opaque ciphertext on the storage node. An interrupted cleanup remains
visible in the account until verified storage cleanup releases its allocation.
The Local reader and cleanup remain available for sealed recordings already
stored on the Master.
In sealed mode, account deletion requires the account's recordings and pending
uploads to be cleared first. The Master commits account removal and its audit
together, retains the recording tombstones, and invalidates the account's
sessions. The same check applies to personal and Admin GUI deletion.
An isolated authenticated framing primitive exists for a future Relay upload:
it validates fixed-size blocks and withholds the final block until the terminal
authenticator and EOF succeed. It has no HTTP route or runtime key exchange.
Integration must bind a fresh key, request and reserved size to authenticated
peer state, propagate deadlines and cancellation, verify even early idempotent
responses, and retain the existing owner and recovery fences.
The existing default lyric is an internal fallback, not a user-manageable lyric
association. Until migration can preserve that distinction without replacing
an explicit user association, missing encrypted-tree fallback facts fail closed;
that temporary rejection is not the final Karaoke behavior.

## Security and management boundaries

Public proxying requires an explicit route and method allowlist. It must not
proxy Admin or internal control APIs, accept arbitrary targets, or trust public
clients to supply ingress identity, client IP, origin or authorization context.
Master accepts only authenticated, current-version ingress context for
forwarded business requests. Bind resource grants to the relevant identity,
operation, lifetime and ingress context; preserve existing visibility and
revocation checks. Streaming uses bounded buffers, backpressure, cancellation
and Range handling, without starving control or key traffic. Sensitive session
values, key envelopes and reusable resource URLs stay out of shared caches,
ordinary logs and diagnostic exports.

New ingress-local media grants use `X-Media-Capability`, never a URL query.
Existing v2 grants retain their prior short lifetime and query contract. For
the repository's Nginx, legacy media, storage, recording, relay and protected-file
locations suppress detailed error logs that may contain a bearer request line;
the structured access log records a fixed route category and failure status,
without client path components or queries. Application request logs likewise
record registered route templates, and error and panic events omit raw error
text and request dumps. Historical logs and audit records require separate
handling before an encrypted-tree migration.
An independently managed proxy must provide equivalent redaction.
The access event includes the HTTP and upstream status, completion and timing,
so accepted requests with 4xx/5xx responses can still be counted without URI
or bearer text. A TLS handshake or connection failure before an HTTP request
does not create such an event: suppressing request-level Nginx error text loses
that diagnostic visibility and is not equivalent to the previous error log.
Deployments that need those counts must obtain aggregate TLS/connection telemetry
from their trusted edge without recording request targets or credentials.

Follower plaintext grants use a distinct v4 token containing the authorized
content digest; older v3 readers reject the token. Before issuing a Local,
Direct or Relay source, Master requires a paired, TLS-authenticated synthetic
v4 reader probes at the relevant origin, including its actual node media URL.
Their tokens cannot authorize a user media read and do not inspect user files.
Each verifies the actual chunk reader with synthetic bytes and a separately
signed challenge; neither is evidence of encrypted-tree health or reachability
from a browser. The first read of a content version
checks its full SHA-256 and creates bounded in-memory chunk proofs; later reads
verify each requested chunk before returning its bytes. Proofs do not depend on
mtime, are discarded on restart, and contain no filenames. Native plaintext
reads remain on the leased Go reader rather than X-Accel.

The Master runtime mounts a dedicated peer verifier path behind its trusted
HTTPS edge. The peer runtime can prepare a narrowly allowlisted proxy from an
authenticated, monotonic heartbeat observation; this observation expires after
90 seconds without refresh, is not selection authority, is lost on restart, and each request still needs the
Master's current lease. An administrator can run a fixed authenticated
candidate identity and proxy-chain check; the separate selection transaction
rechecks evidence and generation under an exclusive lease. Selection binds the
specific paired relationship, including its credential identity and control
address; replacing that relationship fails admission until an administrator
performs a fresh check and explicit selection. Returning public ingress to the
Master clears the binding. Its runtime gate
continues to reject non-Master activation until the remaining storage, resource
and public paths are complete.
TLS termination on either side requires an explicitly configured
`PUBLIC_INGRESS_TRUSTED_PROXY_NETWORKS` CIDR for that trusted edge. The default
is empty and rejects forwarded HTTPS assertions. The general proxy trust list
does not grant this separate authority. Direct TLS needs no forwarded assertion.
The verifier buffers complete session/key responses before
committing the shared ingress lease and publishing them. MySQL commits the same
transaction that acquired the row lock; a failed or ambiguous commit discards
the response. Catalog and metadata responses follow the same rule because they
can contain signed handles. The current implementation permits 64 KiB for key
responses and 8 MiB for catalog, metadata, page and allowlisted asset responses, with four buffered requests
per class across verifier instances; larger responses fail with 503. This is an explicit
current limit, not a catalog-size guarantee. Resource-byte streams are not in
this allowlist and require a separately reviewed authorization and drain
boundary before they can be enabled.

Playback and session revocation commit admission before their handlers run;
they may finish after a selection as already admitted operations. Playback uses
the existing session/media deduplication, and revocation is idempotent. A
failed or canceled buffered response does not undo arbitrary work a handler
already did. Newly created crypto sessions register an abort callback so that
failed admission revokes the undisclosed session. Local Master session, key,
catalog and metadata responses also hold the ingress lease until their bounded
responses commit; an authenticated peer already holds the verifier's lease.
Other public routes still require review before peer activation. Requests use the
existing 30-second context and response deadline, without promising immediate
revocation of earlier grants.

Admin continues to connect directly to Master. `ADMIN_ORIGIN` is independently
configured from the Master server name and TLS settings and is not inferred
from request Host or the active public origin. The Master-side handoff starts
on that origin with a host-only HttpOnly cookie and a separately generated
challenge. An authenticated current ingress may submit the registered
challenge and Admin Key for Master validation. A 60-second, single-use ticket
is bound to that cookie, target and ingress generation; only direct same-origin
redemption on Master creates the browser's Admin cookies. Pending session
secrets exist only in bounded process memory, and failed proxy admission
discards them. The public proxy and browser integration must explicitly enable
only that authorization endpoint before this is a usable cross-origin flow;
the management API itself is not proxied. No long-lived credential is put in
a URL. A TLS-terminating management edge must be covered by the separate
`PUBLIC_INGRESS_TRUSTED_PROXY_NETWORKS` setting; general proxy trust alone does
not authorize the handoff. If public origin changes, cookies, browser
workers and crypto sessions follow the new origin and may require a fresh
authorization. No cross-origin seamless-session guarantee is implied.

## Schema, upgrade and recovery

The new state is additive and Master-owned. SQLite and MySQL must advance under
the same reviewed schema generation and journal, preserving historical schema
snapshots and testing upgrade, incomplete-DDL recovery and future-generation
refusal. The migration must not infer the Master's Direct/Relay choice or
rewrite resource ownership, IDs, object versions, paths, encryption metadata,
node identity or control endpoints. Runtime upgrades and rollback continue to
follow the existing exact-source, backup and operator procedures; policy hot
application is not an upgrade mechanism.

Full deployment recovery must retain the ingress and policy state with the
matching Master database and identity material. Business backup is a separate
bounded recovery artifact and does not contain node credentials or establish
live relationships. Any export of the new state must preserve old artifact
readability, validate configuration and references, and require explicit
identity/relationship reconciliation before activation. A restored or stale
record alone cannot promote a node or grant ingress authority. Until backup
format support and recovery tests are completed, do not claim that a business
snapshot independently restores these settings or a live ingress.

Acceptance of later stages must independently control browser-to-Master,
ingress-to-Master and Master-to-owner connectivity, verify Direct failure stays
Direct, manual Relay use, local ingress bytes, encrypted and plaintext resource
identity, stale-ingress rejection, in-flight recovery, Admin separation, and
actual supported browser behavior. A page loading or a unit routing calculation
is not evidence of the complete public path.
