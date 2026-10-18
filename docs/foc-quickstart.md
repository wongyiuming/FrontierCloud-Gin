# Daily foc operation

For a Linux Docker host with global `foc` installed and a registered deployment.
Run from any directory; no version-directory change or container shell is needed.
Use `foc`, preserving Bash's existing `fc` builtin.

## Check status

```sh
foc status
```

`foc version` reports the tool version; `foc status` reports the deployment version.
Multiple deployments require `foc --directory /absolute/deployment status`.

## Update this node

```sh
foc upgrade
```

Check the displayed target, database-generation transition and state-backup
capacity, then enter `y`. The tool selects a reviewed main release with successful
CI and public publication, refreshes its backend when needed, and manages the
plan, approval digest, NodeID and recovery path. No copied revision or file is
required. Run independently on Master, Direct and Relay; there is no fleet rollout.

If newest main is still in CI, compilation or publication, the command explains
the stage and tries the last verified published release. If already installed,
it reports no upgrade. Network, permission, provenance and integrity failures
stop; they are not treated as an unpublished version. Implicit downgrade is refused.

The operation verifies images, fences writes, captures state recovery material,
prepares the target, verifies managed reads and opens service. Archives exclude
media, lyrics and recording content: retain the original business mounts.
Code rollback does not reverse DDL. MySQL confirmation also requires that external
writers really have stopped.

After interruption, repeat the command to inspect and continue its original
resumable target. Failed fenced operations require [controlled recovery](operator-upgrade.md),
not forced opening or automatic database restoration.

## Optional inputs

| Input | Purpose |
| --- | --- |
| `foc upgrade --revision FULL_PUBLISHED_MAIN_SHA` | Deliberately select an exact published release. |
| `foc self-update --revision FULL_PUBLISHED_MAIN_SHA` | Tool-only refresh; unnecessary before ordinary upgrade. |
| `foc diagnose` / `foc logs` | Sanitized diagnostics and bounded logs. |
| `foc restart` | Restart pinned images without resolving latest. |
| `upgrade plan/apply/resume/open` | Deliberately staged operation or recovery, not daily parameter copying. |

Older tools lacking parameterless upgrade need one explicit verified self-update
to acquire it. Noninteractive upgrade may use `--yes`; MySQL additionally needs
`--confirm-external-writers-stopped`, which cannot substitute for stopping writers.

## Status and limits

Read-only `status` leaves `business_read=unverified` and may return exit code 3;
it has not read actual media and is not reporting playback failure. Blocking
checks return 2. Upgrade-managed read verification is recorded separately.

The default Compose files **do not yet contain the global foc installation stage**.
A new host does not acquire foc merely by starting the business stack. First
installation and existing-deployment hookup use the separate
[Compose installer](operator-manual.md#global-host-command).

Upgrade changes images within the recorded Compose selection. New services,
mounts, environment configuration, host relocation and database conversion need
separate procedures. The tool centralizes release proof, fencing, state recovery
and verified opening; it does not cover arbitrary deployment changes.
