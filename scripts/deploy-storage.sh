#!/usr/bin/env bash
# Storage only; never selects the business Compose stack or production data.
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose -f docker-compose.storage.yaml config --quiet
# Compose resolves the operator's .env. Read only the non-sensitive image SHA,
# then build that exact Git archive rather than relabeling a mutable checkout.
revision="$(docker compose -f docker-compose.storage.yaml config --images | sort -u)"
revision="${revision#frontiercloud-go-web:}"
if ! [[ "$revision" =~ ^[0-9a-f]{40}$ ]]; then
  printf '%s\n' 'Storage requires one exact committed native image SHA' >&2
  exit 1
fi
bash scripts/build-native-images.sh "$revision" web-only
docker compose -f docker-compose.storage.yaml up -d --no-build --wait --wait-timeout 120
printf '%s\n' 'Storage ready. Import the following one-use package on the Master within five minutes.'
docker compose -f docker-compose.storage.yaml exec -T web /app/frontiercloud storage-pair < /dev/null
