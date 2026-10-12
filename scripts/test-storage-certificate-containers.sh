#!/usr/bin/env bash
# Development-host only: real Compose volumes, recreation, TLS and temporary 80.
set -euo pipefail
cd "$(dirname "$0")/.."
test "$(id -u)" = 0
revision="${FRONTIERCLOUD_REVISION:-$(git rev-parse HEAD)}"
test "$(git rev-parse HEAD)" = "$revision"
test -z "$(git status --porcelain)"
test "$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)" -ge 3145728
test "$(df -Pk /tmp | awk 'NR==2 {print $4}')" -ge 262144
FRONTIERCLOUD_IMAGE_SOURCE=local bash scripts/build-native-images.sh "$revision" all
identity=fc-certificate-$(cat /proc/sys/kernel/random/uuid)
work=$(mktemp -d /tmp/fc-certificate-XXXXXXXX)
driver=frontiercloud-certificate-driver-test:$identity
cleanup() {
  docker rm -f "$identity-compiler" >/dev/null 2>&1 || true
  if [[ -e "$work/resources.json" ]]; then
    python3 tests/storage_certificate_containers.py cleanup "$work"
  fi
  if docker image inspect "$driver" >/dev/null 2>&1; then
    docker image rm "$driver" >/dev/null
  fi
  case "$work" in /tmp/fc-certificate-????????)
    test "$(readlink -f "$work")" = "$work"
    rm -rf -- "$work" ;;
  *) return 1;; esac
}
trap cleanup EXIT
paths=(Dockerfile Dockerfile.gin go.mod go.sum cmd internal migrations protocol static nginx updater/Dockerfile updater/Dockerfile.gin docker-compose.yaml docker-compose.gin-mysql.yaml docker-compose.storage.yaml .env.example .env.storage.example docs/operator-manual.md)
git archive --format=tar "$revision" -- "${paths[@]}" | DOCKER_BUILDKIT=0 docker build --memory=1g --memory-swap=1g --cpu-period=100000 --cpu-quota=100000 -f Dockerfile.gin --target build -t "$driver" -
docker run --rm --name "$identity-compiler" --cpus=1 --memory=1g --memory-swap=1g -e GOMAXPROCS=1 -e GOMEMLIMIT=600MiB -e CGO_ENABLED=0 -v "$work:/out" "$driver" /usr/local/go/bin/go test -c -p=1 -o /out/certificate.test ./internal/certmanager
chmod 755 "$work/certificate.test"
python3 tests/storage_certificate_containers.py run "$work" "$identity" "$revision"
test "$(git rev-parse HEAD)" = "$revision"
test -z "$(git status --porcelain)"
