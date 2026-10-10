# First schema-3 switch review

This is an operator review plan, not an executed deployment or permission to
replace a live runtime. Normal release gates remain in
[CONTRIBUTING](../CONTRIBUTING.md). Production Master upgrades remain manual.

## Two independent admission boundaries

The schema-2 updater cannot admit schema-3 images or reverse the migration.
Its release operation closes public maintenance before preparing the target;
running that operation is not a safe first-generation bootstrap.

The current default-main trusted publisher validates generation 2. Candidate
generation-3 compilation does not change its credential-bearing verifier.
Successful source CI and compilation therefore do not imply image publication
or event-triggered preproduction CD. Do not change image labels, manifests,
journals or schema markers to make incompatible artifacts pass.

If the owner chooses a first-switch exception, approve its exact source and
isolated image provenance, its maintenance-time migration, and any proposed
replacement of the normal event-CD promotion gate separately. A manual staging
acceptance is reported as manual; it cannot be recorded as an event CD success.
No implementation is committed directly to `main`, and merge still requires
owner authorization.

## Observed staging scope

The inspected staging deployment is project `frontiercloud-staging`, using
`/opt/frontiercloud-staging/repo/docker-compose.yaml`, environment file
`/opt/frontiercloud-staging/.env`, and data
`/opt/frontiercloud-staging/data`. Its independent volumes are
`frontiercloud-staging_runtime_secrets`, `frontiercloud-staging_updater_control`,
`frontiercloud-staging_maintenance_state` and
`frontiercloud-staging_redis_data`. Re-inspect these labels and resolved paths
before any action; observations do not authorize using stale configuration.

This host also runs production storage project `frontiercloud-storage` and
other applications. A staging operation must preserve their containers, data,
credentials, networks and versions. Never run host-wide pruning or a compose
command without the explicit staging project and environment file. Clean only
verified task-owned temporary resources and package caches before disconnecting.

## Reviewable operation order

1. Record the exact tested `dev` SHA, newest successful source CI, source tree,
   image IDs, platform, component/revision/schema/manifest labels, binary hashes
   and exported artifact hashes. If an owner authorizes isolated offline staging
   import, verify all three components without package credentials. Keep that
   evidence separate from public-registry provenance.
2. Recheck live image labels, native readiness, schema generation, identities,
   relationships, media/recording inventory, pending mutations, updater state and
   trigger state. Tagged image names and an updater's claimed SHA alone do not
   prove the actual running revision. Acquire the staging CD lock and stop its
   dedicated event path and any active staging CD operation.
3. Close the staging Nginx maintenance flag and verify public HTTP 503. Stop the
   staging Web and Updater writers, drain the native data-root lease, and inspect
   the native maintenance state. Other applications and production storage stay
   running. Abort on an active or unknown operation rather than discarding it.
4. Make a complete independent recovery copy while writers are stopped: SQLite
   plus any WAL/SHM, all managed media and recording files, native lifecycle
   markers, signing identities and relationship credentials, runtime secrets,
   environment/configuration/certificates, Redis persistence and the complete
   updater control/maintenance state. Verify its hashes and copy it off this
   disk before migration. A business metadata backup alone is insufficient.
5. Validate the actual old database copy with the exact new runtime. Compare old
   table rows, columns, constraints, indexes and foreign-key results; then run
   the supported idempotent generation-2-to-3 migration. The new runtime's
   `prepare-release --confirm-generation 3` requires the native gate closed and
   uses `OpenExisting` plus `Initialize`; it must not create a missing store.
6. Preserve the old updater control journal as recovery evidence. After proving
   the old updater is stopped and its state is terminal, archive its real
   `status.json` outside the active control directory. Do not rewrite it or
   invent a successful schema-3 release. A new updater may create an honest idle
   state for its actual runtime; no schema-2 previous version is offered as a
   code-only rollback. Abort if a handoff or replacement journal is present.
7. Install only the verified staging source and schema-3 images. Keep the Nginx
   maintenance flag closed while resuming the native gate and starting the new
   Web. That startup creates or verifies the Master premaster and SQL verifier.
   Back up `media-keys/media-premaster.key` into private off-host recovery material
   before allowing encrypted writes or reopening public traffic. Never print
   key bytes or put them in business backups sent to storage.
8. Prove actual Web/Updater/Nginx source labels and native runtime revision,
   schema checksum, readiness, preserved identity/relationships/plain files,
   and key verifier. Open staging traffic only after these checks. Perform
   encrypted/plain upload, browser Range/seek/continuous playback, downloads,
   rename/delete/recovery, opaque recording snapshots, and abandoned-upload
   recovery acceptance. Storage nodes need their own manually authorized
   compatible upgrade before testing new remote storage behavior.
9. After any separately authorized promotion exception and owner merge, verify
   the default-main schema-3 publisher and normal exact-source public image/CD
   flow. Restore the dedicated staging CD event path only with a compatible
   updater, terminal control state and reviewed pending event state. Record
   manual acceptance and later normal event-CD proof independently.

Failure retains maintenance. Before migration, restore the unchanged runtime
only after validating its state. After migration, recovery to generation 2
requires the complete maintenance-time database/files/key/control backup, not
just old images or reverse DDL. Do not overwrite a database containing new
writes without an owner-reviewed recovery decision.
