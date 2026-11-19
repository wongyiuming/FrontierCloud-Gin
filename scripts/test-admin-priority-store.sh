#!/usr/bin/env bash
# Real-driver priority migration and authenticated API checks on disposable stores.
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d /tmp/fc-admin-priority-XXXXXXXX)
redis="fc-admin-priority-$(cat /proc/sys/kernel/random/uuid)-redis"
cleanup() {
  docker rm -fv "$redis" >/dev/null 2>&1 || true
  case "$work" in /tmp/fc-admin-priority-*) rm -rf -- "$work/secrets" "$work/data" "$work/race-cache" ;; *) exit 1 ;; esac
}
trap cleanup EXIT
docker run -d --name "$redis" --cpus=1 --memory=128m -p 127.0.0.1::6379 redis:7.4.11-alpine >/dev/null
redis_port=$(docker inspect --format '{{(index (index .NetworkSettings.Ports "6379/tcp") 0).HostPort}}' "$redis")
export FRONTIERCLOUD_TEST_REDIS_URL="redis://127.0.0.1:$redis_port/0"
GOMAXPROCS=2 GOMEMLIMIT=800MiB CGO_ENABLED=0 go test -p=1 ./internal/store/business ./internal/httpapi
# These suites use deterministic Redis fixture identities. The next suite
# needs a fresh cache, owned solely by this runner, not retained auth sessions.
docker exec "$redis" redis-cli FLUSHALL >/dev/null
docker run --rm --cpus=2 --memory=3g --memory-swap=3g --network host \
  -e GOMAXPROCS=2 -e GOMEMLIMIT=800MiB -e CGO_ENABLED=1 -e FRONTIERCLOUD_TEST_REDIS_URL \
  -v "$PWD:/src:ro" -v "$(go env GOPATH)/pkg/mod:/go/pkg/mod" \
  -v "$(go env GOCACHE):/root/.cache/go-build" -w /src golang:1.26.8-bookworm \
  go test -race -p=1 ./internal/store/business ./internal/media ./internal/httpapi
printf '%s\n' 'PASS: SQLite priority transactions, Redis auth API, SQLite race suite'
