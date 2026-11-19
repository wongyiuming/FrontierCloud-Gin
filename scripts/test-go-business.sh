#!/usr/bin/env bash
# Isolated real-driver tests. This script must never use a deployed database.
set -euo pipefail
cd "$(dirname "$0")/.."
prefix="fc-go-business-$(date +%s)-$$"
network="$prefix-network"
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
        docker events --since "$test_started_at" --until "$(date -u +%FT%TZ)" \
            --filter type=container --filter event=oom --filter "label=frontiercloud.test.run=$prefix" \
            --format 'Test compiler OOM: {{.Actor.ID}}' 2>/dev/null || true
    fi
    docker rm -fv "$redis" >/dev/null 2>&1 || true
    docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
DOCKER_BUILDKIT=0 docker build --memory=3g --memory-swap=3g --cpu-period=100000 --cpu-quota=200000 -f Dockerfile.gin --target build -t "$build_image" .
DOCKER_BUILDKIT=0 docker build --memory=3g --memory-swap=3g --cpu-period=100000 --cpu-quota=200000 -f Dockerfile.gin -t "$runtime_image" .
docker network create "$network" >/dev/null
docker run -d --memory=128m --cpus=1 --name "$redis" --network "$network" --network-alias redis redis:7.4.11-alpine >/dev/null
docker run --rm "${go_test_budget[@]}" \
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
printf '%s\n' 'PASS: real SQLite, Redis, native process drain, Nginx maintenance and Go race checks'
