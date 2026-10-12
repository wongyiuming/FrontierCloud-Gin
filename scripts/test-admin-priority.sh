#!/usr/bin/env bash
# Disposable Compose UI acceptance. Never select a live project/data directory.
set -euo pipefail
cd "$(dirname "$0")/.."
binary=$(realpath "${1:?compiled candidate binary required}")
test -x "$binary"
python_bin="${FRONTIERCLOUD_TEST_PYTHON:?Playwright test Python required}"
work=$(mktemp -d /tmp/fc-admin-priority-XXXXXXXX)
project="fc-admin-priority-$(cat /proc/sys/kernel/random/uuid)"
compose="$work/compose.json"
cleanup() {
  code=$?
  if [ "$code" -ne 0 ]; then
    docker compose -p "$project" -f "$compose" logs --no-color --tail 25 web > "$work/web.log" 2>&1 || true
    docker compose -p "$project" -f "$compose" stop web >/dev/null 2>&1 || true
  fi
  docker compose -p "$project" -f "$compose" down --volumes --remove-orphans >/dev/null 2>&1 || true
  # Keep the small acceptance evidence, never credentials or disposable data.
  case "$work" in /tmp/fc-admin-priority-*) rm -rf -- "$work/data" "$work/secrets" ;; *) exit 1 ;; esac
}
trap cleanup EXIT
mkdir "$work/data" "$work/secrets"
chown -R 10001:10001 "$work/data" "$work/secrets"
python3 - "$work" "$binary" "$PWD" <<'PY'
import json,pathlib,socket,sys
work,binary,source=sys.argv[1:]
with socket.socket() as sock:
    sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]
image='ghcr.io/wongyiuming/frontiercloud-gin-web:latest'
document={'services':{
 'redis':{'image':'redis:7.4.11-alpine','network_mode':'host','cpus':1,'mem_limit':'128m','command':['redis-server','--bind','127.0.0.1','--port',str(port),'--save','','--appendonly','no']},
 'web':{'image':image,'network_mode':'host','cpus':1,'mem_limit':'1g','user':'10001:10001',
  'volumes':[binary+':/app/frontiercloud:ro',source+'/static:/app/static:ro',work+'/data:/app/data',work+'/secrets:/run/frontiercloud-secrets'],
  'environment':{'HTTP_ADDR':'127.0.0.60:8000','TLS_ENABLED':'false','SERVER_NAME':'localhost','PUBLIC_ORIGIN':'http://localhost',
   'DATA_ROOT':'/app/data','SQLITE_PATH':'/app/data/frontiercloud.db','DB_TYPE':'sqlite','SECRETS_DIR':'/run/frontiercloud-secrets',
   'REDIS_URL':f'redis://127.0.0.1:{port}/0','NGINX_MEDIA_ACCEL':'false'},'depends_on':['redis']}}}
pathlib.Path(work,'compose.json').write_text(json.dumps(document))
PY
docker compose -p "$project" -f "$compose" up -d redis >/dev/null
for command in init-secrets init-media migrate; do
  docker compose -p "$project" -f "$compose" run --rm --no-deps web "$command" > "$work/$command.log" 2>&1
done
python3 - "$work/data/media" <<'PY'
import os,pathlib,sys
root=pathlib.Path(sys.argv[1])
for folder,names in [('drag',['a.mp3','b.mp3','c.mp3','d.mp3']),('pages',[f'{i:04d}.mp3' for i in range(205)]),('aa-folder',['one.mp3']),('zz-folder',['one.mp3'])]:
    directory=root/'music'/folder;directory.mkdir(parents=True,exist_ok=True)
    for name in names:(directory/name).write_bytes(b'ID3payload')
for p in root.rglob('*'):os.chown(p,10001,10001)
PY
docker compose -p "$project" -f "$compose" up -d web >/dev/null
for _ in $(seq 1 60); do if curl -fsS --noproxy '*' http://127.0.0.60:8000/health >/dev/null 2>&1; then break; fi; sleep 1; done
curl -fsS --noproxy '*' http://127.0.0.60:8000/health >/dev/null
"$python_bin" tests/admin_priority_browser.py --base-url http://127.0.0.60:8000 --key-file "$work/secrets/admin_key" --output "$work/evidence"
web=$(docker compose -p "$project" -f "$compose" ps -q web)
python3 scripts/check_cpu_quiescence.py "$web" --timeout 30
printf 'PASS: Compose/Chromium priority acceptance; evidence=%s/evidence\n' "$work"
