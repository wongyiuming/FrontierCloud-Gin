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
    # Extract, do not duplicate the production path redaction and log format.
    awk '/^    map \$request_uri \$logged_path \{/ { emitting=1 }
         emitting { print }
         emitting && /^    }/ { emitting=0 }
         /^    log_format structured escape=json/ { formatting=1 }
         formatting { print }
         formatting && /;$/ { formatting=0 }' nginx/nginx.conf |
        sed 's/${INSTANCE_NAME}/nginx-log-fixture/g'
    printf '%s\n' \
        'server { listen 8081; access_log off; location / { return 200 "upstream fixture\n"; } }' \
        'server { listen 8080;' \
        'set $trace_id ""; set $parent_request_id "";' \
        'set $media_resource_id ""; set $media_owner_id ""; set $media_object_id "";' \
        'set $security_blocked 0; set $logged_upstream_addr "fixture";' \
        'access_log /dev/stdout structured;' \
        'location = /fixture-ready { return 200 "ready\n"; }' \
        'location / { proxy_pass http://127.0.0.1:8081; }' \
        '}' '}'
} > "$work/nginx.conf"
docker run -d --name "$container" --cpus=0.5 --memory=64m --memory-swap=64m \
    --pids-limit=64 --entrypoint nginx \
    -v "$work/nginx.conf:/etc/nginx/nginx.conf:ro" \
    nginx:1.30.4-alpine -g 'daemon off;' >/dev/null
docker exec "$container" nginx -t
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
# Stop flushes the log before collection, without touching any deployed Nginx.
docker stop --time 5 "$container" >/dev/null
docker logs "$container" > "$work/access.log" 2>&1
FRONTIERCLOUD_NGINX_LOG_CAPTURE="$work/access.log" \
    python3 -m unittest discover -s tests -p test_nginx_access_log_contract.py
printf '%s\n' 'PASS: real Nginx UA escaping, upstream timing and query-token redaction'
