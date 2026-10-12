# Operator-managed releases

Online release management was retired at the owner's request. Business and
storage deployments expose no release status/history/upgrade/rollback HTTP API.
AdminGUI has no upgrade buttons, release module or release polling. Default
business Compose no longer launches an updater, shares its control socket with
Web, mounts Docker authority or reads its maintenance volume. Site maintenance
remains authenticated and audited, independent of updater availability; the
native offline fence cannot be reopened by Admin.

The repository still promotes only reviewed same-repository dev -> main PRs.
Owner merge authorization, successful exact-source CI and native acceptance
remain mandatory. Public immutable images and trusted latest promotion remain
the delivery mechanism. Historical updater code/artifacts and external CD
scripts remain operator-owned tooling, outside the normal business deployment.
Removing the GUI does not authorize automatic source promotion or production
deployment. No new branch or direct main implementation is permitted.

## Existing deployment transition

1. Identify the actual Compose project, overrides, data roots and image digests.
   Render the combined configuration: old production overrides can reintroduce
   an updater even after it is removed from the repository default.
2. Pull and verify the reviewed published Web/Nginx images before maintenance.
   Record the currently running source/image proofs and compatible restore plan.
3. Close public maintenance and stop database/filesystem writers, including any
   legacy updater. Enter the native offline fence before making a cold backup.
4. Make an independent consistent database backup, including every business
   table. Verify integrity and preserve node identities, relationships, media
   metadata, encryption descriptors and exact priorities. Preserve runtime secrets,
   media premaster and ACME volumes; a database alone is not encrypted-media
   recovery material. An already verified independent media backup need not be
   recopied for this metadata-only migration.
5. Use the reviewed new runtime's supported offline migration commands. Do not
   manually edit a schema marker or start an old binary against a newer database.
   Generation 3 -> 4 preserves priorities and widens their range to -7..500000;
   see [physical migration](../migrations/README.md).
6. Keep data/secrets/certificate volume identities and project names. Recreate
   the reviewed services with Compose, then verify database generation, facts,
   HTTPS, pairing/heartbeat, Local/Direct/Relay playback, Range and Admin behavior
   before reopening traffic. Remove only the precisely identified legacy updater
   container and its obsolete configuration; do not delete its recovery journal
   or use down -v/global volume pruning against an existing deployment.

Manual maintenance uses the shared data flag. The legacy force-open flag no
longer overrides manual maintenance; an explicit authenticated maintenance
change validates/removes recognized legacy bytes. The native offline marker
still gates public and Admin traffic and cannot be overridden in the GUI.

Code rollback does not reverse database DDL. A cross-generation rollback needs
the maintenance-time independent database backup and matching old containers;
new writes after reopening must be reconciled before restoring older facts.
Keep old images and recovery material until the new release is verified.
Use containers/Compose for product services, never host systemctl components.

RN preproduction and external CD are currently retired. Their scripts describe
historical user-owned integrations and are not a working default CD deployment.
Native development acceptance and current source CI remain required; no live
staging or production upgrade is claimed by this document.
