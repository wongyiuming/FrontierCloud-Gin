#!/usr/bin/env bash
# Local preproduction CD. Never run this controller on the production Master.
set -euo pipefail
root=/opt/frontiercloud-staging
test "$(readlink -f "$root")" = "$root"
test -f "$root/.env"
exec 9>"$root/cd.lock"
flock -n 9 || exit 0
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
"${compose[@]}" exec -T web /app/frontiercloud staging-release < /dev/null
