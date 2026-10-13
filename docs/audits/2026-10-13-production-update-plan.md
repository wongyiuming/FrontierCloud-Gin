# Production update plan — awaiting exact-head PR review

Owner authorization: update production after PR 14 passes. No production writes
have occurred at this checkpoint; the following inventory is read-only.

| Deployment | Current revision | Actual schema | Managed objects |
| --- | --- | --- | --- |
| Master (`frontiercloud`, 520mall.cc) | a6f8e3a5ec960578bc0d08b070afbddc2370243f | 4 | 2180 |
| Direct Storage (`frontiercloud-storage`, ml.520mall.cc) | 80bcfcc7dc2ce1f13e9519fdaeab2cad76e10118 | 4 | 17 |
| Relay Storage (`frontiercloud-storage`, rnlsj.520mall.cc) | 80bcfcc7dc2ce1f13e9519fdaeab2cad76e10118 | 4 | 10 |

The SSH host keys are pinned. Each source uses SQLite and persistent original
identity/secrets/data/certificate mounts. Master has about 3.9 GiB free, Direct
about 5.3 GiB, Relay about 13.7 GiB; this is a timestamped observation, not a
reservation. Recovery archives will be streamed uncompressed to protected
operator storage. Checksums and archive verification will run off the Master.

1. Require successful exact-source CI, resolved review findings, relevant native
   acceptance and canonical dev-to-main merge. Verify the released main tree
   matches the reviewed tree and the normal publisher succeeds.
2. Verify anonymous immutable public Web/Nginx/updater manifests, platform,
   revision and generation. Pin those digests; never build on production.
3. Recheck current configuration/identity/schema/maintenance and disk capacity.
   Preserve current Compose/project, mounts, environment and resource budgets.
4. Close public admission, stop the selected writers, establish each old runtime's
   native maintenance proof, and capture complete cold data/secrets/certificate/
   deployment recovery material. Keep original images/configuration for recovery.
5. Use the explicitly admitted generation-4 to 7 maintainer preparation with the
   original NodeID and verified recovery SHA, while all selected writers remain
   stopped. Do not use fresh initialization or edit schema markers by SQL.
6. Verify identities, retained secret bytes, stable business tables, generation,
   idle transaction state and representative managed reads before opening.
   Update the retained services with immutable pins; preserve source project and
   mount names and add only required runtime observation state.
7. Verify HTTPS, certificate serving, existing relationships, catalog/media ID,
   representative local/Direct/Relay Range reads, node status and idle resource
   behavior. Failures retain maintenance and recovery materials; image rollback
   is never described as DDL rollback.

The retired RN staging gate remains unavailable under the owner's explicit
exception. Development-host evidence does not claim staging or public release
proof. Production completion will be recorded separately after actual execution.
