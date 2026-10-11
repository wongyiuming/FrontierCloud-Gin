#!/usr/bin/env bash
# Real parser + fresh TLS startup; isolated development host only, one CPU.
set -euo pipefail
cd "$(dirname "$0")/.."
root="$PWD"
work=$(mktemp -d /tmp/fc-five-parameter-XXXXXXXX)
project="fc-five-parameter-$(cat /proc/sys/kernel/random/uuid)"
declare -A old_aliases=()
compose() { env -i PATH="$PATH" HOME="$HOME" docker compose --project-directory "$work" --env-file "$work/five.env" -p "$project" -f "$root/docker-compose.yaml" -f "$work/fixture.yaml" "$@"; }
cleanup() {
  compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  for component in web updater nginx; do
    alias="ghcr.io/wongyiuming/frontiercloud-gin-$component:latest"
    if [[ -n "${old_aliases[$component]:-}" ]]; then
      docker tag "${old_aliases[$component]}" "$alias"
    else
      docker image rm "$alias" >/dev/null 2>&1 || true
    fi
  done
  if [[ "$work" == /tmp/fc-five-parameter-* && ! -L "$work" ]]; then rm -r -- "$work"; fi
}
trap cleanup EXIT
trap 'compose stop web >/dev/null 2>&1 || true; compose logs --no-color --tail 12 web nginx updater >&2 || true' ERR
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$work/acme"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
  -addext subjectAltName=DNS:localhost -keyout "$work/key.pem" -out "$work/cert.pem" >/dev/null 2>&1
cat > "$work/five.env" <<EOF
TLS_ENABLED=true
SERVER_NAME=localhost
SSL_CERT_PATH=$work/cert.pem
SSL_KEY_PATH=$work/key.pem
ACME_WEBROOT=$work/acme
EOF
# No application variable override: only private fixture ports/project/CPU.
cat > "$work/fixture.yaml" <<'EOF'
services:
  web:
    cpus: 1
  nginx:
    ports: !override
      - target: 80
        published: "0"
        host_ip: 127.0.0.1
      - target: 443
        published: "0"
        host_ip: 127.0.0.1
  stun:
    ports: !override
      - target: 3478
        published: "0"
        host_ip: 127.0.0.1
        protocol: udp
      - target: 3478
        published: "0"
        host_ip: 127.0.0.1
        protocol: tcp
EOF
# Use the actual Compose parser with a clean environment and no fixture overlay.
for mode in http five empty pinned; do
  cp "$work/five.env" "$work/parse.env"
  if [[ "$mode" == http ]]; then : > "$work/parse.env"; fi
  if [[ "$mode" == empty ]]; then
    printf '%s\n' 'FRONTIERCLOUD_REVISION=' 'DB_TYPE=' 'COMPOSE_PROJECT_NAME=' 'HTTP_PORT=' 'HTTPS_PORT=' 'WEBRTC_STUN_PORT=' 'DATA_DIRECTORY=' > "$work/optional.env"
    cat "$work/optional.env" >> "$work/parse.env"
  fi
  if [[ "$mode" == pinned ]]; then printf 'FRONTIERCLOUD_REVISION=%s\n' "${FRONTIERCLOUD_TEST_IMAGE_REVISION:?Provide only the fixture image revision}" >> "$work/parse.env"; fi
  env -i PATH="$PATH" HOME="$HOME" docker compose --project-directory "$work" --env-file "$work/parse.env" -f "$root/docker-compose.yaml" config --format json > "$work/$mode.json"
done
python3 - "$work" "${FRONTIERCLOUD_TEST_IMAGE_REVISION:?}" <<'PY'
import json, pathlib, sys
root=pathlib.Path(sys.argv[1])
for mode in ('http','five','empty','pinned'):
    config=json.loads((root/(mode+'.json')).read_text())
    assert config['name']=='frontiercloud-gin'
    services=config['services']
    assert 'mysql' not in services
    for name, service in services.items():
        assert 'build' not in service, (mode,name)
    for name in ('web','secrets-init','media-init','updater','nginx'):
        component='web' if name.endswith('-init') else name
        tag=sys.argv[2] if mode=='pinned' else 'latest'
        assert services[name]['image']=='ghcr.io/wongyiuming/frontiercloud-gin-'+component+':'+tag
    web=services['web']['environment']
    assert web['DB_TYPE']=='sqlite' and web['SQLITE_PATH']=='/app/data/frontiercloud.db'
    assert web['RELEASE_BRANCH']=='main' and web['RELEASE_SOURCE_BRANCH']=='dev'
    assert web['TLS_ENABLED']==('false' if mode=='http' else 'true')
    assert {(p['target'],p['published']) for p in services['nginx']['ports']}=={(80,'80'),(443,'443')}
    assert all(p['published']=='3478' for p in services['stun']['ports'])
    assert any(v.get('source')==str(root/'data') and v['target']=='/app/data' for v in services['web']['volumes'])
print('PASS: real Compose HTTP, five TLS values, empty defaults and exact-SHA pin; no builds')
PY
# Main/latest is not published until merge. Test the unchanged runtime startup
# using explicitly selected, verified exact-version fixture bytes; restore tags.
for component in web updater nginx; do
  alias="ghcr.io/wongyiuming/frontiercloud-gin-$component:latest"
  old_aliases[$component]=$(docker image inspect --format '{{.Id}}' "$alias" 2>/dev/null || true)
  source="frontiercloud-go-$component:$FRONTIERCLOUD_TEST_IMAGE_REVISION"
  test "$(docker image inspect --format '{{index .Config.Labels "frontiercloud.revision"}}' "$source")" = "$FRONTIERCLOUD_TEST_IMAGE_REVISION"
  test "$(docker image inspect --format '{{index .Config.Labels "frontiercloud.schema-generation"}}' "$source")" = 3
  docker tag "$source" "$alias"
done
compose up -d --pull never --wait --wait-timeout 180
cid=$(compose ps -q web)
test "$(docker inspect --format '{{.HostConfig.NanoCpus}}' "$cid")" = 1000000000
address=$(compose port nginx 443)
port=${address##*:}
curl --fail --silent --show-error --cacert "$work/cert.pem" "https://localhost:$port/health/ready" >/dev/null
curl --fail --silent --show-error --cacert "$work/cert.pem" "https://localhost:$port/" | grep -q '前沿娱乐'
compose exec -T web sh -c 'test "$(id -u)" = 10001; test -s /run/frontiercloud-secrets/admin_key; ! command -v python; ! command -v go'
test -d "$work/data/media"
test -f "$work/data/frontiercloud.db"
receipt=$(sha256sum "$work/data/.native-runtime" | cut -d' ' -f1)
compose restart web
curl --fail --silent --show-error --retry 10 --retry-all-errors --retry-delay 1 --max-time 5 --cacert "$work/cert.pem" "https://localhost:$port/health/ready" >/dev/null
test "$(sha256sum "$work/data/.native-runtime" | cut -d' ' -f1)" = "$receipt"
python3 scripts/check_cpu_quiescence.py "$cid" --timeout 30
printf '%s\n' 'PASS: fresh five-value HTTPS, initialized SQLite/media/secrets, persistent restart, one CPU; fixture latest aliases, not remote publication'
