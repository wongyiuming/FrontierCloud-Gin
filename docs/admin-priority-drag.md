# Admin priority ordering

Directories and media retain the same integer preference field, descending
priority and existing public tie comparators. Values now accept -7..500000.
Existing values, IDs, playback scores and timestamps survive schema 3 -> 4;
there is no reset or scaling. See [physical migration](../migrations/README.md).

For a:100, b:100, c:101, the initial order is c, a, b. Moving c between a and b
can produce a:101, c:101, b:100: their canonical name/path tie resolves a before
c. A neighbouring 99 group stays in place. At a bound or another collision,
the server expands an adjustment window until the requested order fits, while
retaining values outside that window. It does not invent fractional ranks or
replace the public sorting rule. A mathematically unrepresentable bounded
order fails with 422 and commits nothing.

Authenticated GET `/api/v1/media/admin/priority-order?scope=music/album&kind=media`
returns the complete sibling scope and a SHA256 content revision. `directory`
scopes use the same endpoint. Hidden and off-page siblings are included; a
Master derives virtual siblings from its own placement ledger across Local,
Direct and Relay members. Storage nodes do not compute or store business ranks.

CSRF-protected POST to that endpoint accepts `scope`, `kind`, `revision`, `path`,
`before` and `after`. Anchors must be adjacent after removing the moved item,
belong to that exact parent/kind, and describe both sides of the insertion.
An empty anchor represents the scope boundary. A stale revision yields 409.
The shared path fence plus database transaction protects rename and concurrent
Admin adjustments; reserved uploads, pending deletion/rename scopes reject
unsafe mutations. Preference writes, bounded complete audit batches and catalog
generation invalidation commit together. Failed audit rolls back every change.

The UI offers pointer/touch handles, keyboard arrows, Escape cancellation,
time-based edge scrolling, FLIP animations, reduced-motion support and live
save/error announcements. Numeric entry is exact across the full range. Search
does not permit dragging across unrelated parents; navigate into that folder.
Pagination exposes only current-page targets but validates the complete scope.
Request failure restores the displayed sequence and asks for a refresh, because
a lost response may follow a committed transaction.

The UI refresh includes desktop module navigation and a small-screen menu,
responsive priority controls and consistent spacing. Canonical module order,
upload, certificate and security operations retain their contracts. Online
upgrade/rollback APIs and their UI are retired; site maintenance is independent.

Development-host checks: Go unit/race tests, actual MySQL migration/transaction
tests, authenticated API/CSRF checks and `scripts/test-admin-priority.sh` using
a one-CPU Compose Web fixture with real Chromium desktop/touch input. Hosted CI
retains its lightweight source-only budget. This fixture uses loopback HTTP and
does not expose insecure Admin outside the development host. No public ACME is
needed for this UI test.

First release needs generation-4 image proofs and an operator-managed Compose
transition. There is no Admin upgrade API. Historical generation-3 updater tooling
must not mislabel the new images as schema 3 or bypass proof checks. Back up the database,
close the maintenance fence, start reviewed generation-4 containers and verify
the migration before reopening service. Old binaries refuse the new database;
rollback requires restoring its independent database backup. This development
change does not authorize a production upgrade. The browser fixture binds only
the private Go API on loopback port 8000, without publishing an HTTP service on
an alternative public port. Production public entry points remain 80/443.
