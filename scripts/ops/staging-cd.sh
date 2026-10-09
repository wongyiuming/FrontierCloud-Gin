#!/usr/bin/env bash
# Local preproduction CD. Never run this controller on the production Master.
set -euo pipefail
root=/opt/frontiercloud-staging
test "$(readlink -f "$root")" = "$root"
test -f "$root/.env"
exec 9>"$root/cd.lock"
flock -w 300 9
cd "$root/repo"
test "$(git remote get-url origin)" = https://github.com/wongyiuming/FrontierCloud-Gin.git
export COMPOSE_PROJECT_NAME=frontiercloud-staging
export STAGING_CD=true SERVER_NAME=ml.520mall.cc TLS_ENABLED=true
export DATA_DIRECTORY="$root/data"
# The stable active project's existing image is used to request a verified
# update. Source is fetched/archived by the native updater, never reset by CD.
test -f "$root/current-revision"
revision=$(<"$root/current-revision")
[[ "$revision" =~ ^[0-9a-f]{40}$ ]]
export FRONTIERCLOUD_REVISION="$revision"
compose=(docker compose --env-file "$root/.env" -p frontiercloud-staging -f docker-compose.yaml)
web=$("${compose[@]}" ps -q web)
test -n "$web"
test "$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$web")" = frontiercloud-staging
test "$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/app/data"}}{{.Source}}{{end}}{{end}}' "$web")" = "$root/data"
# Wait only for an earlier accepted local deployment, never poll GitHub.
# A CI event arriving during that deployment must not be silently discarded.
deadline=$((SECONDS + 300))
while true; do
  status=$("${compose[@]}" exec -T web /app/frontiercloud updater-status < /dev/null)
  state=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["state"])' <<< "$status")
  case "$state" in
    idle|success) break ;;
    failed|unavailable) printf '%s\n' 'Staging updater requires operator attention.' >&2; exit 1 ;;
    running|restarting) ;;
    *) printf '%s\n' 'Unknown staging updater state.' >&2; exit 1 ;;
  esac
  (( SECONDS < deadline )) || { printf '%s\n' 'Previous staging deployment is still busy.' >&2; exit 1; }
  sleep 2
done
"${compose[@]}" exec -T web /app/frontiercloud staging-release < /dev/null
