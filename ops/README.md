# Native development operations

Python operator drivers live in scripts/ops, never inside Web. They target the
five-node Gin inventory only (one Master, two Direct, two Relay); old ten-node
inventories fail closed. Provision with SQLite or MySQL and verified native
image seeds. Heavy acceptance remains on the development host, not hosted CI.

Changing these repository files does not modify an installed timer, service or
existing host inventory. Retire/rebuild an old development topology only as a
separate explicitly scoped operation. Do not run chaos/import/reconcile against
production or reuse its data. Operator dependencies belong to the host driver,
not the native Web image.

Install host-only operator dependencies with `pip install '.[operator]'`.
The Gin HTTP test driver uses only the Python standard library.

The former `frontiercloud-dev-cd.service` and timer are retired and are no
longer distributed. `dev_control.py` direct invocation fails explicitly. On a
host that still has these units installed, disable/remove those units during
its separately reviewed development-host retirement; deleting repository files
does not uninstall existing systemd units. Upgrade current deployments with
the `foc upgrade` workflow on each registered host; staged commands remain
available for controlled recovery. See [daily operation](../docs/foc-quickstart.md).
