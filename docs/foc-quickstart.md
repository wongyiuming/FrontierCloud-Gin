# Daily foc operation

For a host with global `foc` already installed and its deployment registered.
Log in and run commands directly; no version-directory change or agent shell is
needed. Use `foc`; Bash already has an unrelated `fc` builtin.

## Check status

```sh
foc status
```

`foc version` reports the tool version; `foc status` reports the deployment
version. With one registered deployment it is selected automatically. If several
exist, resolve the ambiguity explicitly with `foc --directory /absolute/path status`.

## Update an existing deployment: two commands

Choose a successful run of
[Publish native images](https://github.com/wongyiuming/FrontierCloud-Gin/actions/workflows/publish-images.yml)
and copy its associated full 40-character main commit SHA. A merged PR or passing
source CI alone does not prove public images are available. Replace `RELEASE_SHA`
with that same published SHA in both commands:

```sh
foc self-update --revision RELEASE_SHA
foc upgrade --revision RELEASE_SHA
```

The first updates the tool; the second updates this host's deployment. Check the
shown target, database generation and state-backup capacity, then answer `y`.
These remain two commands; the tool does not automatically select the latest
release. An already authorized noninteractive run may add `--yes` to the second.

No manually supplied plan file, approval hash, NodeID, backup path or image digest
is required for a normal upgrade. The tool verifies public release provenance and
pinned images, generates the plan, fences writes, backs up state, prepares the
target, verifies managed reads and opens service. Upgrade-state backups exclude
media, lyrics and recordings; retain the existing business mounts.

Noninteractive MySQL upgrades additionally require
`--confirm-external-writers-stopped`, and external writers really must be stopped.
All three current production nodes use SQLite.

Run the pair separately on each host. There is no fleet-wide update command.
A compatible installed tool may update the deployment alone; updating the tool
first provides a consistent routine.

The [six actual PR22 mutation inputs](audits/2026-10-15-foc-update-inputs.txt)
and [complete input inventory](audits/2026-10-15-foc-production-inputs.json)
were extracted from submitted invocation records, without embedding outputs.
The additional 22 read-only checks are audit work, not 22 required upgrade steps.
Historical input evidence is not a source of future release identifiers.

## Optional or recovery inputs

| Input | Purpose |
| --- | --- |
| `upgrade plan/apply/resume/open`, approval SHA and NodeID | Deliberately split stages or recover a recorded interruption; ordinary `upgrade` manages these. |
| `backup verify --file ... --sha256 ...` | Additional archive audit, with parameters extracted from the result; not a normal upgrade prerequisite. |
| `--json` | Machine-readable reporting; not required to upgrade. |
| Repeated `status`, `diagnose`, `version` | Operational checks, not extra upgrade stages. |

## Understand abnormal status

Read the check item, not only the exit code. `certificate=blocked` is a failure.
`business_read=unverified` in read-only status means that command did not play or
read actual media; it may return exit code 3. Certificate blockage returns 2.
The upgrade result separately records `managed_read_verified` for actual reads.

On failure, retain generated plans, logs and recovery material. `upgrade open`
is not a general bypass for warnings. Do not recreate volumes or overwrite new
business writes with an old database.

## Current limits

- First installation remains separate: see [Compose installation and global entry](operator-manual.md#global-host-command). An arbitrary new host does not already have `foc`.
- Upgrade updates component images within the existing Compose selection. New services, mounts or environment settings require a separate release-configuration procedure; these two commands cannot deploy every possible project change.
- Its value is enforcing release proof, write fencing, state backup, identity/generation checks and managed reads. It has not eliminated version selection or replaced every Docker operation with fewer commands.

See the [operator manual](operator-manual.md) and
[upgrade/recovery contract](operator-upgrade.md) for recovery, migration and retirement.
