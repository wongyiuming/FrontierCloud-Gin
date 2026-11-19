#!/usr/bin/env bash
# Exercise the production log format in one isolated, bounded Nginx container.
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d /tmp/fc-nginx-access-log-XXXXXXXX)
container="fc-nginx-access-log-$(date +%s)-$$"
cleanup() {
    docker rm -fv "$container" >/dev/null 2>&1 || true
    if [[ "$work" == /tmp/fc-nginx-access-log-* && ! -L "$work" && -d "$work" ]]; then
        rm -r -- "$work"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
{
    printf '%s\n' 'worker_processes 1;' 'events { worker_connections 32; }' 'http {'
    # Preserve the production request-error policy: upstream failures can
    # otherwise log the original URI, including its query string.
    tr -d '\r' < nginx/nginx.conf | awk '/^http \{/ { inside=1; next }
         inside && !found && /^    error_log \/dev\/null crit;$/ { print; found=1 }
         END { if (!found) exit 1 }'
    # Extract, do not duplicate the production path redaction and log format.
    tr -d '\r' < nginx/nginx.conf | awk '/^    map \$request_uri \$logged_path \{/ { emitting=1 }
         emitting { print }
         emitting && /^    }/ { emitting=0 }
         /^    log_format structured escape=json/ { formatting=1 }
         formatting { print }
         formatting && /;$/ { formatting=0 }' |
        sed 's/${INSTANCE_NAME}/nginx-log-fixture/g'
    printf '%s\n' \
        'upstream frontiercloud_web { server 127.0.0.1:8081; }' \
        'server { listen 8081; access_log off; location / { return 200 "upstream fixture\n"; } }' \
        'server { listen 8080;' \
        'set $trace_id ""; set $parent_request_id "";' \
        'set $media_resource_id ""; set $media_owner_id ""; set $media_object_id "";' \
        'set $security_blocked 0; set $logged_upstream_addr "fixture";' \
        'set $frontiercloud_csp "default-src none"; set $frontiercloud_hsts "";' \
        'access_log /dev/stdout structured;' \
        'location = /fixture-ready { return 200 "ready\n"; }' \
        'location ^~ /api/v1/media/master-local/ { return 403; }' \
        'location ^~ /api/v1/media/master-local-lyric/ { proxy_pass http://127.0.0.1:18089; }'
    # Exercise the exact production observation and generic signed-edge
    # locations, including their separate body limits.
    tr -d '\r' < nginx/nginx.conf | awk '
        /^        location = \/_fc_public_proxy\/api\/v1\/media\/network-observation \{/ { emitting=1; found++ }
        /^        location \^~ \/_fc_public_proxy\/ \{/ { emitting=1; found++ }
        emitting { print }
        emitting && /^        }/ { emitting=0 }
        END { if (found != 2) exit 1 }'
    printf '%s\n' \
        'location / { proxy_pass http://127.0.0.1:8081; }' \
        '}' '}'
} > "$work/nginx.conf"
head -c 16384 /dev/zero | tr '\0' x > "$work/observation-exact"
head -c 16385 /dev/zero | tr '\0' x > "$work/observation-over"
head -c 8193 /dev/zero | tr '\0' x > "$work/other-over"
docker run -d --name "$container" --cpus=0.5 --memory=64m --memory-swap=64m \
    --pids-limit=64 --entrypoint nginx \
    -v "$work/nginx.conf:/etc/nginx/nginx.conf:ro" \
    -v "$PWD/nginx/security-headers.conf:/etc/nginx/security-headers.conf:ro" \
    -v "$work:/fixtures:ro" \
    nginx:1.30.4-alpine -g 'daemon off;' >/dev/null
if ! docker exec "$container" nginx -t; then
    # A container can exit immediately on invalid configuration. Preserve the
    # reason before the fixture cleanup removes it.
    docker logs "$container" >&2 || true
    exit 1
fi
ready=false
for _ in $(seq 1 20); do
    if docker exec "$container" wget -q -O /dev/null http://127.0.0.1:8080/fixture-ready; then
        ready=true
        break
    fi
    sleep 1
done
if [[ "$ready" != true ]]; then docker logs --tail 20 "$container"; exit 1; fi
docker exec "$container" wget -q -O /dev/null \
    -U 'Tesla Browser "quote" \slash' \
    'http://127.0.0.1:8080/api/v1/media/music/category?path=music&token=SECRET_QUERY_TOKEN'
# Exercise both an application-style rejection and an upstream connection
# failure. The identifiers and tokens here are inert synthetic values.
docker exec "$container" wget -q -O /dev/null \
    'http://127.0.0.1:8080/api/v1/media/master-local/1111111111111111111111111111111111111111111111111111111111111111?token=INERT_LOCAL_TOKEN' || true
docker exec "$container" wget -q -O /dev/null \
    'http://127.0.0.1:8080/api/v1/media/master-local-lyric/2222222222222222222222222222222222222222222222222222222222222222?token=INERT_LYRIC_TOKEN' || true
docker exec "$container" wget -q -O /dev/null -U fc-observation-exact --post-file=/fixtures/observation-exact \
    'http://127.0.0.1:8080/_fc_public_proxy/api/v1/media/network-observation' || true
docker exec "$container" wget -q -O /dev/null -U fc-observation-over --post-file=/fixtures/observation-over \
    'http://127.0.0.1:8080/_fc_public_proxy/api/v1/media/network-observation' || true
docker exec "$container" wget -q -O /dev/null -U fc-other-over --post-file=/fixtures/other-over \
    'http://127.0.0.1:8080/_fc_public_proxy/api/v1/media/crypto/session' || true
# Stop flushes the log before collection, without touching any deployed Nginx.
docker stop --time 5 "$container" >/dev/null
docker logs "$container" > "$work/access.log" 2>&1
FRONTIERCLOUD_NGINX_LOG_CAPTURE="$work/access.log" \
    python3 -m unittest discover -s tests -p test_nginx_access_log_contract.py
printf '%s\n' 'PASS: real Nginx UA escaping, upstream timing and query-token redaction'
