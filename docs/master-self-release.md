# Operator-managed releases

Online release management and its update controller have been removed. Business
and Storage expose no release status/history/upgrade/rollback HTTP API. Admin has
no upgrade module or polling. Default Compose retains the certificate controller,
but no Docker socket, release control socket or release daemon.

Only reviewed same-repository dev-to-main promotion is allowed. Public delivery
publishes Web and Nginx exact-SHA images and promotes verified main aliases for
fresh installation. Publication never deploys production.

Use [operator upgrades](operator-upgrade.md) for explicit plan, apply and open.
Retain existing Compose/project/mount selection, identities, keys, databases and
recovery material. The native offline fence cannot be reopened through Admin.
Preserve historical deployment recovery journals as data; current code does not
execute historical update controllers or automatically interpret them.

Code rollback does not reverse DDL. New writes after opening must be preserved
before any explicitly approved restoration. RN preproduction remains retired;
isolated development acceptance does not claim a live staging gate.
