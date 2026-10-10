#!/usr/bin/env bash
# Isolated real-driver tests. This script must never use a deployed database.
set -euo pipefail
cd "$(dirname "$0")/.."
prefix="fc-go-business-$(date +%s)-$$"
network="$prefix-network"
secrets="$prefix-secrets"
mysql="$prefix-mysql"
redis="$prefix-redis"
build_image="frontiercloud-go:business-test"
runtime_image="frontiercloud-gin:business-test"
test_started_at=$(date -u +%FT%TZ)
# Keep two compiler workers, but cap each compiler's managed heap and the
# aggregate cgroup. Go package parallelism must not inherit all host cores.
go_test_budget=(--cpus=2 --memory=3g --memory-swap=3g
    -e GOMAXPROCS=2 -e GOMEMLIMIT=512MiB -e GOGC=25
    --label "frontiercloud.test.run=$prefix")
cleanup() {
    test_status=$?
    if [ "$test_status" -ne 0 ]; then
        docker inspect --format 'MySQL fixture status={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} memory={{.HostConfig.Memory}}' "$mysql" 2>/dev/null || true
        docker logs --tail 30 "$mysql" 2>/dev/null || true
        docker events --since "$test_started_at" --until "$(date -u +%FT%TZ)" \
            --filter type=container --filter event=oom --filter "label=frontiercloud.test.run=$prefix" \
            --format 'Test compiler OOM: {{.Actor.ID}}' 2>/dev/null || true
    fi
    docker rm -fv "$mysql" "$redis" >/dev/null 2>&1 || true
    docker volume rm "$secrets" >/dev/null 2>&1 || true
    docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
DOCKER_BUILDKIT=0 docker build --memory=3g --memory-swap=3g --cpu-period=100000 --cpu-quota=200000 -f Dockerfile.gin --target build -t "$build_image" .
DOCKER_BUILDKIT=0 docker build --memory=3g --memory-swap=3g --cpu-period=100000 --cpu-quota=200000 -f Dockerfile.gin -t "$runtime_image" .
docker network create "$network" >/dev/null
docker volume create "$secrets" >/dev/null
docker run --rm --user 0:0 -v "$secrets:/run/frontiercloud-secrets" "$runtime_image" init-secrets
# Bound MySQL itself; default instrumentation can exceed a 512 MiB cgroup.
docker run -d --memory=768m --memory-swap=768m --cpus=1 --name "$mysql" --network "$network" --network-alias mysql \
    -e MYSQL_DATABASE=fc_business -e MYSQL_USER=media_admin \
    -e MYSQL_PASSWORD_FILE=/run/frontiercloud-secrets/mysql_password \
    -e MYSQL_ROOT_PASSWORD_FILE=/run/frontiercloud-secrets/mysql_root_password \
    -v "$secrets:/run/frontiercloud-secrets:ro" mysql:8.4.11 --skip-log-bin \
    --innodb-buffer-pool-size=64M --performance-schema=OFF --max-connections=64 >/dev/null
docker run -d --memory=128m --cpus=1 --name "$redis" --network "$network" --network-alias redis redis:7.4.11-alpine >/dev/null
ready=false
for _ in $(seq 1 90); do
    if docker exec "$mysql" sh -c 'MYSQL_PWD=$(cat /run/frontiercloud-secrets/mysql_password) mysql -h 127.0.0.1 -u media_admin -e "SELECT 1" fc_business' >/dev/null 2>&1; then
        ready=true
        break
    fi
    sleep 1
done
if [ "$ready" != true ]; then docker logs --tail 40 "$mysql"; exit 1; fi
docker run --rm "${go_test_budget[@]}" --network "$network" -v "$secrets:/run/frontiercloud-secrets:ro" \
    -e FRONTIERCLOUD_TEST_MYSQL_HOST=mysql -e FRONTIERCLOUD_TEST_MYSQL_DATABASE=fc_business \
    -e FRONTIERCLOUD_TEST_MYSQL_USER=media_admin \
    -e FRONTIERCLOUD_TEST_MYSQL_PASSWORD_FILE=/run/frontiercloud-secrets/mysql_password \
    "$build_image" go test -p=2 -count=1 -v ./internal/store/business
docker run --rm "${go_test_budget[@]}" --network "$network" -e FRONTIERCLOUD_TEST_REDIS_URL=redis://redis:6379/1 \
    "$build_image" go test -p=2 -count=1 -v ./internal/admin
docker run --rm "${go_test_budget[@]}" --network "$network" -e FRONTIERCLOUD_TEST_REDIS_URL=redis://redis:6379/2 \
    "$build_image" go test -p=2 -count=1 -v ./internal/httpapi
docker run --rm "${go_test_budget[@]}" --network "$network" -e FRONTIERCLOUD_TEST_REDIS_URL=redis://redis:6379/3 \
    "$build_image" go test -p=2 -count=1 -v ./internal/observation
docker run --rm "${go_test_budget[@]}" --network "$network" -e FRONTIERCLOUD_TEST_REDIS_URL=redis://redis:6379/5 \
    "$build_image" go test -p=2 -count=1 -v ./internal/karaoke
docker run --rm "${go_test_budget[@]}" --network "$network" -e FRONTIERCLOUD_TEST_REDIS_URL=redis://redis:6379/4 \
    "$build_image" go test -p=2 -race -count=1 -v ./cmd/frontiercloud
docker run --rm "${go_test_budget[@]}" "$build_image" go test -p=2 -race -count=1 ./...
bash scripts/test-nginx-maintenance.sh
bash scripts/test-nginx-response-headers.sh
printf '%s\n' 'PASS: real MySQL, Redis, native process drain, Nginx maintenance and Go race checks'
