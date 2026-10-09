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
# Wait only for an earlier accepted local deployment, never poll GitHub.
# A CI event arriving during that deployment must not be silently discarded.
volume=frontiercloud-staging_updater_control
test "$(docker volume inspect --format '{{index .Labels "com.docker.compose.project"}}' "$volume")" = frontiercloud-staging
test "$(docker volume inspect --format '{{index .Labels "com.docker.compose.volume"}}' "$volume")" = updater_control
control=$(docker volume inspect --format '{{.Mountpoint}}' "$volume")
test "$control" = /var/lib/docker/volumes/frontiercloud-staging_updater_control/_data
# The persisted journal remains readable while web/updater containers are
# replaced. Cover the updater's 45-minute build plus eight-minute recovery.
deadline=$((SECONDS + 3300))
while true; do
  state=$(python3 "$root/staging_updater_state.py" "$control/status.json")
  case "$state" in
    idle|success) break ;;
    failed|unavailable) printf '%s\n' 'Staging updater requires operator attention.' >&2; exit 1 ;;
    queued|running|distributing|restarting) ;;
    *) printf '%s\n' 'Unknown staging updater state.' >&2; exit 1 ;;
  esac
  (( SECONDS < deadline )) || { printf '%s\n' 'Previous staging deployment is still busy.' >&2; exit 1; }
  sleep 5
done
web=$("${compose[@]}" ps -q web)
test -n "$web"
test "$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$web")" = frontiercloud-staging
test "$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/app/data"}}{{.Source}}{{end}}{{end}}' "$web")" = "$root/data"
"${compose[@]}" exec -T web /app/frontiercloud staging-release < /dev/null
