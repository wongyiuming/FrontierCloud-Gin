#!/usr/bin/env bash
# Disposable real Gin HTTP fixtures; Python is only the external test driver.
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d /tmp/fc-native-api-XXXXXXXX)
prefix="fc-native-api-$(cat /proc/sys/kernel/random/uuid)"
image="$prefix-web"
redis="$prefix-redis"
cleanup() {
  docker rm -f "$redis" "$prefix-copy" >/dev/null 2>&1 || true
  # Keep the private evidence directory and image; no global prune.
}
trap cleanup EXIT
DOCKER_BUILDKIT=0 docker build --memory=3g --memory-swap=3g --cpu-period=100000 --cpu-quota=200000 -f Dockerfile.gin -t "$image" .
docker create --name "$prefix-copy" "$image" >/dev/null
docker cp "$prefix-copy:/app/frontiercloud" "$work/frontiercloud"
docker rm "$prefix-copy" >/dev/null
chmod 0700 "$work/frontiercloud"
docker run -d --memory=256m --cpus=1 --name "$redis" -p 127.0.0.1::6379 redis:7.4.11-alpine \
  redis-server --maxmemory 128mb --maxmemory-policy noeviction >/dev/null
redis_port=$(docker inspect --format '{{(index (index .NetworkSettings.Ports "6379/tcp") 0).HostPort}}' "$redis")
python3 tests/test_gin_http.py --binary "$work/frontiercloud" --database sqlite \
  --redis-url "redis://127.0.0.1:$redis_port/0"
printf '%s\n' 'PASS: Python black-box driver tested real Gin/SQLite'
