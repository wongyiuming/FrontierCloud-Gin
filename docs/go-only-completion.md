# Go-only runtime and validation

## Supported combinations

Only Gin/Go serves the backend and certificate controller. The default is Gin + SQLite; the
only database alternative is Gin + MySQL. .env selects DB_TYPE and the MySQL
Compose overlay; it does not migrate existing data. Python deployment is
prohibited. The retired application tree app/, main.py, updater/server.py and
updater/release_evidence.py, including illustrative code, are removed. The unused
Python migration package marker is removed; Go migration code and schema assets
are preserved. Production runtime excludes Python tests/drivers and their dependencies;
the allowlisted POSIX foc launcher/installer scripts remain in its operator bundle.
Tests/scripts may use Python to drive real Gin or inspect native contracts.

Preserving existing serialized keys, tokens, password hashes, media IDs,
backup data and node relationships is mandatory. Go legacy-data vectors are
not Python application interoperability acceptance.

## Replacement coverage

Retired Python/FastAPI component tests and mixed-runtime drivers are replaced
by native Go package coverage, Python-driven Gin HTTP and the five-node matrix:

The table is family-level navigation, not proof that every retired assertion has
an equivalent native test. The frozen baseline has 552 Python definitions; the
[case ledger](legacy-test-ledger.csv) distinguishes nine reviewed replacements
from 543 cases pending assertion review. Some native gates skip unless explicitly
configured, and five formerly module-level audio-profile tests were not selected
by unittest until the 2026-10-08 repair. See [execution scopes and promotion](validation-and-promotion.md)
and the [dated repair audit](audits/2026-10-08-native-repairs.md).

| Retired target area | Native behavior coverage |
| --- | --- |
| Database/schema/transactions/audit | internal/store/business, internal/store/sqlite, migrations |
| Admin key/auth/session/CSRF/security | internal/admin, internal/security, internal/httpapi |
| Media upload/delete/rename/visibility/priority | internal/media, internal/store/business, internal/httpapi |
| Lyrics/manual/auto link/default fallback | internal/media/lyrics*, internal/httpapi/lyrics_admin* |
| Catalog/playback/Range/download/brand | internal/media, internal/brand, internal/httpapi |
| Karaoke users/quota/recording lifecycle | internal/recording, internal/store/business, internal/httpapi |
| Pair/role/heartbeat/resource transport | internal/node, five-node native matrix |
| Backup/protocol/token/capabilities | internal/backup, internal/protocol, protocol/v2/vectors |
| Release proof/manual upgrade/recovery | internal/release, internal/operator, native operator acceptance |
| HTTP black-box in Python | tests/test_gin_http.py, both SQLite/MySQL real native processes |
| Browser/UI/continuous audio | retained Python UI contracts, JS smoke, isolated real Chromium |

The HTTP driver starts its own native binary, fresh temporary data/secrets and
loopback listener. It accepts no production target URL. scripts/test-native-api.sh
owns disposable Redis/MySQL containers and runs it for both database choices.
Full Go tests include transaction rollback, media mutation races, persisted
identity, security and transport failures rather than substituting source-string
assertions for runtime behavior.

## Development-host gates

```bash
bash scripts/test-native-api.sh
bash scripts/test-go-deployment.sh
bash scripts/test-go-business.sh
bash scripts/test-native-default.sh
bash scripts/test-native-matrix.sh
python3 tests/operator_recovery_acceptance.py --help
```

Fleet acceptance uses exactly five native nodes: one Master, two Direct, two
Relay, repeated with SQLite and MySQL Master selection. All storage appliances
use embedded SQLite; MySQL is a Master/business deployment alternative. Fixtures use private CA
HTTPS, exact private source artifacts, disposable namespaces and independent
data. They never reuse or stop a deployed node and never globally prune Docker.
The release matrix retains manual upgrades and explicit recovery, business/data
transport, backup and restart assertions at the smaller fleet size.

Hosted test CI only runs scripts/test-ci-source.sh and bounded metadata promotion
checks, with parallel jobs capped at three minutes and no serial dependency
chain. It does not build Docker, run a database/fleet/browser/race acceptance,
install FastAPI, or evade limits through background work.
The separately authorized image compilation workflow waits for exact test CI
success and publishes public runtime images, with ten-minute parallel jobs and
no acceptance tests. See [image delivery](public-image-delivery.md).

## Documentation and release scope

Wiki guidance is maintained in the separate
[GitHub Wiki](https://github.com/wongyiuming/FrontierCloud-Gin/wiki); docs/wiki is
untracked/ignored. The prior reconstruction evidence is retained as an explicitly
[historical audit](audits/go-reconstruction-through-2026-10-05.md), not current
operator instructions.

Only same-repository dev-to-main promotion is current. Old gin_dev/gin_main
names describe inherited history, not additional supported branches. No new
branch or production deployment is implied by this policy. A local/private test artifact is not published CI
proof or authorization to replace production.
