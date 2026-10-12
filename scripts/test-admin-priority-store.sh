#!/usr/bin/env bash
# Real-driver priority migration and authenticated API checks on disposable stores.
set -euo pipefail
cd "$(dirname "$0")/.."
binary=$(realpath "${1:?compiled candidate binary required}")
work=$(mktemp -d /tmp/fc-admin-priority-mysql-XXXXXXXX)
mysql="fc-admin-priority-mysql-$(cat /proc/sys/kernel/random/uuid)"
redis="${mysql}-redis"
cleanup() {
  docker rm -fv "$mysql" "$redis" >/dev/null 2>&1 || true
  case "$work" in /tmp/fc-admin-priority-mysql-*) rm -rf -- "$work/secrets" "$work/data" "$work/race-cache" ;; *) exit 1 ;; esac
}
trap cleanup EXIT
DATA_ROOT="$work/data" SECRETS_DIR="$work/secrets" "$binary" init-secrets > "$work/init.log"
docker run -d --name "$mysql" --cpus=1 --memory=768m --memory-swap=768m -p 127.0.0.1::3306 \
  -e MYSQL_DATABASE=fc_priority -e MYSQL_USER=media_admin \
  -e MYSQL_PASSWORD_FILE=/run/frontiercloud-secrets/mysql_password \
  -e MYSQL_ROOT_PASSWORD_FILE=/run/frontiercloud-secrets/mysql_root_password \
  -v "$work/secrets:/run/frontiercloud-secrets:ro" mysql:8.4.11 \
  --skip-log-bin --innodb-buffer-pool-size=64M --performance-schema=OFF --max-connections=64 >/dev/null
docker run -d --name "$redis" --cpus=1 --memory=128m -p 127.0.0.1::6379 redis:7.4.11-alpine >/dev/null
port=$(docker inspect --format '{{(index (index .NetworkSettings.Ports "3306/tcp") 0).HostPort}}' "$mysql")
redis_port=$(docker inspect --format '{{(index (index .NetworkSettings.Ports "6379/tcp") 0).HostPort}}' "$redis")
for _ in $(seq 1 90); do
  if docker exec "$mysql" sh -c 'MYSQL_PWD=$(cat /run/frontiercloud-secrets/mysql_password) mysql -h 127.0.0.1 -u media_admin -e "SELECT 1" fc_priority' >/dev/null 2>&1; then break; fi
  sleep 1
done
python3 tests/priority_mysql_migration.py --container "$mysql" --binary "$binary" --secrets "$work/secrets" --port "$port"
export FRONTIERCLOUD_TEST_MYSQL_HOST=127.0.0.1 FRONTIERCLOUD_TEST_MYSQL_PORT="$port"
export FRONTIERCLOUD_TEST_MYSQL_DATABASE=fc_priority FRONTIERCLOUD_TEST_MYSQL_USER=media_admin
export FRONTIERCLOUD_TEST_MYSQL_PASSWORD_FILE="$work/secrets/mysql_password"
export FRONTIERCLOUD_TEST_REDIS_URL="redis://127.0.0.1:$redis_port/0"
GOMAXPROCS=2 GOMEMLIMIT=800MiB CGO_ENABLED=0 go test -p=1 ./internal/store/business ./internal/httpapi
# These suites use deterministic Redis fixture identities. The next suite
# needs a fresh cache, owned solely by this runner, not retained auth sessions.
docker exec "$redis" redis-cli FLUSHALL >/dev/null
unset FRONTIERCLOUD_TEST_MYSQL_HOST FRONTIERCLOUD_TEST_MYSQL_PORT FRONTIERCLOUD_TEST_MYSQL_DATABASE FRONTIERCLOUD_TEST_MYSQL_USER FRONTIERCLOUD_TEST_MYSQL_PASSWORD_FILE
docker run --rm --cpus=2 --memory=3g --memory-swap=3g --network host \
  -e GOMAXPROCS=2 -e GOMEMLIMIT=800MiB -e CGO_ENABLED=1 -e FRONTIERCLOUD_TEST_REDIS_URL \
  -v "$PWD:/src:ro" -v "$(go env GOPATH)/pkg/mod:/go/pkg/mod" \
  -v "$(go env GOCACHE):/root/.cache/go-build" -w /src golang:1.26.8-bookworm \
  go test -race -p=1 ./internal/store/business ./internal/media ./internal/httpapi
printf '%s\n' 'PASS: MySQL migration/transactions, Redis auth API, SQLite race suite'
