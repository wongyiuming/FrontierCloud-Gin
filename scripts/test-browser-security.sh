#!/usr/bin/env bash
# Real TLS/browser checks on a fresh isolated project; never target a live node.
set -euo pipefail
cd "$(dirname "$0")/.."
revision=${FRONTIERCLOUD_REVISION:?Exact locally committed candidate SHA required}
[[ "$revision" =~ ^[0-9a-f]{40}$ ]]
work=$(mktemp -d /tmp/fc-browser-security-XXXXXXXX)
project="fc-browser-security-$(cat /proc/sys/kernel/random/uuid)"
cleanup() {
  if [[ "$project" == fc-browser-security-* && "$work" == /tmp/fc-browser-security-* ]]; then
    compose down --volumes --remove-orphans >/dev/null || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
export COMPOSE_PROJECT_NAME="$project" FRONTIERCLOUD_REVISION="$revision"
export DATA_DIRECTORY="$work/data" DB_TYPE=sqlite TLS_ENABLED=true SERVER_NAME=127.0.0.1
export PUBLIC_BIND_ADDRESS=127.0.0.1 HTTP_PORT=0 HTTPS_PORT=0 WEBRTC_STUN_PORT=0
export SSL_CERT_PATH="$work/cert.pem" SSL_KEY_PATH="$work/key.pem" ACME_WEBROOT="$work/acme"
export SECURITY_CONTACT=https://reports.example.test/security
export PUBLIC_ORIGIN=
export RELEASE_BRANCH=main RELEASE_SOURCE_BRANCH=dev STAGING_CD=false
mkdir -p "$work/acme" "$work/data/media/music/security-fixture"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
  -keyout "$SSL_KEY_PATH" -out "$SSL_CERT_PATH" -subj /CN=127.0.0.1 -addext subjectAltName=IP:127.0.0.1 >/dev/null 2>&1
chmod 600 "$SSL_KEY_PATH"
python3 - "$work/data/media/music/security-fixture" <<'PY'
import math,pathlib,struct,sys,wave
root=pathlib.Path(sys.argv[1])
data=b''.join(struct.pack('<h',round(2000*math.sin(i*440*2*math.pi/16000))) for i in range(16000*20))
for name in ('01-first.wav','02-second.wav'):
    with wave.open(str(root/name),'wb') as out:
        out.setnchannels(1);out.setsampwidth(2);out.setframerate(16000);out.writeframes(data)
PY
compose() { docker compose --env-file /dev/null -p "$project" -f docker-compose.yaml -f tests/native-loopback.compose.yaml "$@"; }
FRONTIERCLOUD_IMAGE_SOURCE=local bash scripts/build-native-images.sh "$revision"
compose up -d --no-build --wait --wait-timeout 180
compose exec -T nginx nginx -t
address=$(compose port nginx 443)
base="https://$address"
# Docker allocated the public port after Web initialization. Configure its
# canonical origin explicitly, then test the actual discovery documents too.
export PUBLIC_ORIGIN="$base"
compose up -d --no-build --no-deps --wait --wait-timeout 90 web
curl --fail --silent --show-error --cacert "$SSL_CERT_PATH" "$base/health/ready" >/dev/null
for protocol in 1.2 1.3; do
  curl --fail --silent --show-error --cacert "$SSL_CERT_PATH" --tlsv1."${protocol#1.}" --tls-max "$protocol" "$base/health/ready" >/dev/null
done
for old in tls1 tls1_1; do
  timeout 10 openssl s_client -connect "$address" -servername 127.0.0.1 -"$old" -cipher 'ALL:@SECLEVEL=0' </dev/null > "$work/$old.log" 2>&1 || true
  grep -q 'alert protocol version' "$work/$old.log"
done
curl --silent --show-error --cacert "$SSL_CERT_PATH" --http2 -D "$work/headers" -o /dev/null "$base/api/v1/media"
grep -q '^HTTP/2 200' "$work/headers"
! grep -qi 'server: nginx/' "$work/headers"
test "$(grep -ci '^content-security-policy:' "$work/headers")" = 1
for route in /api/v1/media/music /api/v1/media/video /karaoke/; do
  curl --fail --silent --show-error --cacert "$SSL_CERT_PATH" -D "$work/public-headers" -o /dev/null "$base$route"
  for header in content-security-policy x-content-type-options x-frame-options referrer-policy permissions-policy strict-transport-security; do
    test "$(grep -ci "^$header:" "$work/public-headers")" = 1
  done
done
curl --fail --silent --show-error --cacert "$SSL_CERT_PATH" -H 'Range: bytes=0-43' -D "$work/range-headers" \
  "$base/api/v1/media/stream?file_path=music%2Fsecurity-fixture%2F01-first.wav" -o "$work/range-body"
grep -q ' 206' "$work/range-headers"
test "$(wc -c < "$work/range-body")" = 44
python3 -m venv "$work/tools"
"$work/tools/bin/pip" -q install 'playwright>=1.55,<2'
# Reuse an installed Chromium; do not download another browser per test.
browser=${PLAYWRIGHT_CHROMIUM_EXECUTABLE:-}
if [[ -z "$browser" ]]; then
  browser=$(find /root/.cache/ms-playwright -maxdepth 4 -type f -name chrome-headless-shell -print | sort | tail -1)
fi
test -x "$browser"
export PLAYWRIGHT_CHROMIUM_EXECUTABLE="$browser"
ADMIN_KEY=$(compose exec -T web sh -c 'cat /run/frontiercloud-secrets/admin_key')
export ADMIN_KEY
"$work/tools/bin/python" tests/browser_security_smoke.py --base-url "$base"
unset ADMIN_KEY
volume="${project}_maintenance_state"
test "$(docker volume inspect --format '{{index .Labels "com.docker.compose.project"}}' "$volume")" = "$project"
gate=$(docker volume inspect --format '{{.Mountpoint}}' "$volume")
test "$gate" = "/var/lib/docker/volumes/$volume/_data"
touch "$gate/enabled"
"$work/tools/bin/python" tests/browser_security_smoke.py --base-url "$base" --maintenance-only
rm -- "$gate/enabled"
curl --fail --silent --show-error --cacert "$SSL_CERT_PATH" "$base/health/ready" >/dev/null
printf '%s\n' 'PASS: real TLS 1.2/1.3, HTTP/2, old TLS rejected, single CSP, no version banner, Range and maintenance recovery'
