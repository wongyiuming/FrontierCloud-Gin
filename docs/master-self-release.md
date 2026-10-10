# Master-only version management

Release management controls only the Master's local native updater. Storage
versions do not participate in permission, progress, completion or rollback.
There are no signed `/internal/v1/cluster-update/*` routes, release-distribution
CLI commands or per-storage upgrade jobs.

The new repository has only `dev` and `main`. Work is pushed to `dev`; a
same-repository `dev -> main` PR promotes the reviewed exact tree. Hosted CI
test jobs remain lightweight and capped at three minutes. A separate exact-CI-success-gated
compilation workflow publishes public images with ten-minute parallel jobs; native unit/race, real
database, Docker/updater, five-node and browser gates run on the development
host. After merge, fast-forward development to the release merge commit;
never force-rewrite it. Bootstrap history alone is not publishable release
proof. Native releases pull and validate exact-SHA public images pinned by digest;
only confirmed missing images/platforms allow bounded local immutable-source
builds. Auth/network/proof failures stop. See [image delivery](public-image-delivery.md).

Admin lists up to ten recently merged release PRs, including the merge SHA,
title, description, date and PR link. History discovery is cached for five
minutes and obeys API rate-limit backoff. PR text is rendered as text, never
HTML. Listing a version is not authorization to deploy it.

Upgrade targets the verified release HEAD. An explicitly selected historical
rollback must be listed and independently pass the exact merged PR, source
tree, newest source push CI and branch-policy checks. The updater additionally
checks Git ancestry. Local previous-version rollback remains available without
GitHub access when its durable local release state is valid.

Rollback changes code, not database contents or media. Schema compatibility
must be checked separately; an older version is not automatically safe for a
newer database. The local maintenance, crash-recovery journal, immutable image
checks and failed-upgrade restore remain enforced. Historical manifest parsing
is retained only for reading/recovering existing local updater state; no new
HTTP whole-cluster manifest publication is supported.

## Browser encryption and schema generation 3

Browser media encryption descriptors introduce schema generation 3. Current
Web, Updater and Nginx image labels, release manifests and
`prepare-release --confirm-generation 3` must agree. Historical schema-2
manifest bytes and canonical digests remain preserved but cannot prove a
current-schema release. Protocol 2 does not imply cross-generation rollback.

A compiled schema-2 updater cannot admit schema-3 images; the first switch is
operator-managed. Before development or staging migration, verify independent
database, media metadata and key backups, close maintenance and stop all
database/filesystem writers, then use the new native runtime's supported
`Initialize` 2-to-3 migration. Preserve identities, relationships, tokens, file
IDs and historical plaintext media. Production Master operations remain manual,
and storage appliances continue to require independent manual upgrades.
The [first-switch review plan](schema3-first-switch.md) records the separate
publisher/updater admission boundaries and a scoped staging operation order;
it does not authorize a gate exception or claim a completed deployment.

After migration, do not start an old schema-2 image against a schema-3 database.
Automated publication and failed-upgrade recovery accept only the current
compatible generation; reverse DDL is not implemented. Offline MySQL inventory
also requires the source and tool to use the same generation; schema-2 evidence
cannot prove a schema-3 database unchanged. Recovery across that boundary needs
the independent maintenance-time recovery material and a reviewed procedure.

These are code and deployment boundaries, not proof that staging or production
was upgraded. Record executed, passed, skipped and undeployed work separately in
the current validation evidence.
