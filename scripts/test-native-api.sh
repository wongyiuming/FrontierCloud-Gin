#!/usr/bin/env bash
# Disposable real Gin HTTP fixtures; Python is only the external test driver.
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d /tmp/fc-native-api-XXXXXXXX)
prefix="fc-native-api-$(cat /proc/sys/kernel/random/uuid)"
image="$prefix-web"
mysql="$prefix-mysql"
redis="$prefix-redis"
cleanup() {
  test_status=$?
  if [ "$test_status" -ne 0 ]; then
    docker inspect --format 'MySQL fixture status={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} memory={{.HostConfig.Memory}}' "$mysql" 2>/dev/null || true
    docker logs --tail 30 "$mysql" 2>/dev/null || true
  fi
  docker rm -f "$mysql" "$redis" "$prefix-copy" >/dev/null 2>&1 || true
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
DATA_ROOT="$work/data" SECRETS_DIR="$work/secrets" "$work/frontiercloud" init-secrets
docker run -d --memory=768m --memory-swap=768m --cpus=1 --name "$mysql" -p 127.0.0.1::3306 \
  -e MYSQL_DATABASE=fc_gin_http -e MYSQL_USER=media_admin \
  -e MYSQL_PASSWORD_FILE=/run/frontiercloud-secrets/mysql_password \
  -e MYSQL_ROOT_PASSWORD_FILE=/run/frontiercloud-secrets/mysql_root_password \
  -v "$work/secrets:/run/frontiercloud-secrets:ro" mysql:8.4.11 \
  --innodb-buffer-pool-size=64M --performance-schema=OFF --max-connections=64 >/dev/null
mysql_port=$(docker inspect --format '{{(index (index .NetworkSettings.Ports "3306/tcp") 0).HostPort}}' "$mysql")
ready=false
for _ in $(seq 1 90); do
  if docker exec "$mysql" sh -c 'MYSQL_PWD=$(cat /run/frontiercloud-secrets/mysql_password) mysql -h 127.0.0.1 -u media_admin -e "SELECT 1" fc_gin_http' >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
test "$ready" = true
for database in sqlite mysql; do
  python3 tests/test_gin_http.py --binary "$work/frontiercloud" --database "$database" \
    --redis-url "redis://127.0.0.1:$redis_port/0" --mysql-port "$mysql_port" \
    --mysql-password-file "$work/secrets/mysql_password"
done
printf '%s\n' 'PASS: Python black-box driver tested real Gin/SQLite and Gin/MySQL'
