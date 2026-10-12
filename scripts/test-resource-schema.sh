#!/usr/bin/env bash
# Real isolated schema migration faults; never run in hosted CI or production.
set -euo pipefail
cd "$(dirname "$0")/.."
source_root="$PWD"
run="fc-schema-$(date +%s)-$$"
prefix="fc_schema_$$_"
network="$run-network"
mysql="$run-mysql"
secret_dir=$(mktemp -d /tmp/fc-schema-secrets-XXXXXXXX)
chmod 700 "$secret_dir"
head -c 32 /dev/urandom | base64 > "$secret_dir/mysql_root_password"
chmod 600 "$secret_dir/mysql_root_password"
cleanup() {
    result=$?
    if [ "$result" -ne 0 ]; then
        printf 'Schema acceptance failed; isolated fixture retained: %s, private material %s\n' "$mysql" "$secret_dir" >&2
        return
    fi
    docker rm -fv "$mysql" >/dev/null 2>&1 || true
    docker network rm "$network" >/dev/null 2>&1 || true
    rm -- "$secret_dir/mysql_root_password"
    rmdir -- "$secret_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
docker network create --label "frontiercloud.test.run=$run" "$network" >/dev/null
docker run -d --name "$mysql" --network "$network" --network-alias mysql \
    --label "frontiercloud.test.run=$run" --cpus=1 --memory=768m --memory-swap=768m \
    -e MYSQL_ROOT_PASSWORD_FILE=/run/frontiercloud-secrets/mysql_root_password \
    -v "$secret_dir:/run/frontiercloud-secrets:ro" mysql:8.4.11 \
    --skip-log-bin --innodb-buffer-pool-size=64M --performance-schema=OFF --max-connections=64 >/dev/null
ready=false
for _ in $(seq 1 90); do
    if docker exec "$mysql" sh -c 'MYSQL_PWD=$(cat /run/frontiercloud-secrets/mysql_root_password) mysqladmin ping -h 127.0.0.1 -u root --silent' >/dev/null 2>&1; then ready=true; break; fi
    sleep 1
done
[ "$ready" = true ] || { printf 'Isolated MySQL did not become ready\n' >&2; exit 1; }
printf 'CREATE DATABASE `%spreserve`; CREATE DATABASE `%sinterrupted`; CREATE DATABASE `%sbusiness`;\n' "$prefix" "$prefix" "$prefix" | \
    docker exec -i "$mysql" sh -c 'MYSQL_PWD=$(cat /run/frontiercloud-secrets/mysql_root_password) exec mysql -u root'
# Optional reusable caches affect compiler speed only, never database facts.
cache=()
if [ -n "${FC_GO_MOD_CACHE:-}" ]; then cache+=(-v "$FC_GO_MOD_CACHE:/go/pkg/mod"); fi
if [ -n "${FC_GO_BUILD_CACHE:-}" ]; then cache+=(-v "$FC_GO_BUILD_CACHE:/root/.cache/go-build"); fi
docker run --rm --name "$run-go" --network "$network" --label "frontiercloud.test.run=$run" \
    --cpus=2 --memory=3g --memory-swap=3g -e GOMAXPROCS=2 -e GOMEMLIMIT=512MiB -e GOGC=25 \
    -e FRONTIERCLOUD_SCHEMA_TEST_MYSQL_HOST=mysql \
    -e "FRONTIERCLOUD_SCHEMA_TEST_MYSQL_DATABASE_PREFIX=$prefix" \
    -e FRONTIERCLOUD_SCHEMA_TEST_MYSQL_USER=root \
    -e FRONTIERCLOUD_SCHEMA_TEST_MYSQL_PASSWORD_FILE=/run/frontiercloud-secrets/mysql_root_password \
    -e FRONTIERCLOUD_TEST_MYSQL_HOST=mysql -e "FRONTIERCLOUD_TEST_MYSQL_DATABASE=${prefix}business" \
    -e FRONTIERCLOUD_TEST_MYSQL_USER=root \
    -e FRONTIERCLOUD_TEST_MYSQL_PASSWORD_FILE=/run/frontiercloud-secrets/mysql_root_password \
    -v "$secret_dir:/run/frontiercloud-secrets:ro" -v "$source_root:/src:ro" \
    "${cache[@]}" -w /src golang:1.26.8-bookworm \
    sh -c 'go test -p=2 -count=1 -race -v ./internal/store/schema && go test -p=2 -count=1 -race -v ./internal/store/business -run TestMigrationFacts'
printf 'PASS: SQLite/MySQL generation-4 preservation, migration journal failure, DDL recovery, idempotency, future-generation refusal and MySQL migration backup guards\n'
