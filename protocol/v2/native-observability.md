# Native observation contracts

The Admin nodes observation API reads fresh identity, storage membership and
heartbeat facts from SQL. Desired settings are not evidence of effective remote
settings. An absent observation is awaiting; mismatched settings are syncing;
offline relationships are offline. Only the exact current membership relationship
can supply remote facts. Reads do not initiate network probes or expose sealed
credentials/public signing keys. Non-Master roles do not expose a stale Master
pool. Backup health retains disabled/running/failed/first/stale/healthy precedence.

The storage display exposes physical total/free, current allocation and project
usage alongside existing reservation/availability fields. The synthetic Auto
entry does not inflate aggregate capacity. Display calculations grant no write
reservation: the SQL placement transaction retains its own physical/logical
ceiling and native uploads supply current disk capacity.

Playback continuity diagnostics preserve the deliberately temporary reference
contract: 24 reports, five-minute TTL, process memory only and mandatory retirement
at 2026-10-15T00:00:00Z. They are not stored in SQL, Redis or files. Sanitization
limits strings, nesting, dictionary slots and timeline length and strips sensitive
keys recursively. Follower reports use a 2.5-second bounded signed upstream relay;
failure falls back locally. Only an authenticated active downstream relationship
can relay into a Master. Admin snapshot/clear uses existing session/CSRF rules.
Restart destroys reports; they are not authoritative cross-worker business state.

`/metrics` preserves case-sensitive Bearer authentication against the current
metrics token file and hides missing/invalid credentials with 404. Rotation is
observed without restart. Native collectors expose real HTTP counts, histograms,
in-progress requests, recovered exceptions and readiness dependencies, plus Go/
process facts. Route templates and bounded method labels prevent arbitrary path,
query, identity or method cardinality. No database backend label changes the
public dependency contract.

Master Nginx access logs use JSON escaping and include the supplied `user_agent`,
HTTP/TLS protocol, total request duration and upstream connect/header/response
durations. Upstream durations are strings: `-` means no upstream measurement,
and multi-hop/retry values retain Nginx's sequence instead of becoming invalid
JSON numbers. A large total duration with small upstream timings can indicate
client transfer delay; a large upstream header duration can indicate time spent
waiting for the application. These measurements do not include requests that
never reach HTTP (DNS, TCP/TLS failure), and an access entry appears at request
completion, not initial connection. UA is client-supplied, not proof of a Tesla
device or mobile carrier; do not infer either without corroborating evidence.

Access paths still exclude query strings and mask internal relay capability
paths. Authorization, cookies, Referer and forwarded client-supplied addresses
are not logged. UA remains an untrusted escaped string; do not render it as HTML
or execute it. Successful health/metrics checks remain quiet. Source contracts
run in lightweight CI; `scripts/test-nginx-access-log.sh` verifies real Nginx
JSON escaping, upstream timings and query-token exclusion on the development
host, without host port bindings or deployment mutations.

`/docs`, `/redoc` and `/openapi.json` require the existing Admin session. The schema
is a reviewed language-neutral JSON artifact embedded in the binary; a development
oracle compares it to the effective reference schema. Runtime startup, request
handling and schema serving do not invoke Python. Interface coverage and behavior
acceptance remain independent of schema registration.
