# Master-only version management

Release management controls only the Master's local native updater. Storage
versions do not participate in permission, progress, completion or rollback.
There are no signed `/internal/v1/cluster-update/*` routes, release-distribution
CLI commands or per-storage upgrade jobs.

The new repository has only `dev` and `main`. Work is pushed to `dev`; a
same-repository `dev -> main` PR promotes the reviewed exact tree. Hosted CI
remains lightweight and capped at three minutes; native unit/race, real
database, Docker/updater, five-node and browser gates run on the development
host. After merge, fast-forward development to the release merge commit;
never force-rewrite it. Bootstrap history alone is not publishable release
proof.

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
