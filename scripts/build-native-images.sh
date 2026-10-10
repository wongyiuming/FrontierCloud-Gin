#!/usr/bin/env bash
# Pull public exact-SHA images; only confirmed absence compiles immutable source.
set -euo pipefail
cd "$(dirname "$0")/.."
revision="${1:-${FRONTIERCLOUD_REVISION:-}}"
selection="${2:-all}"
if [[ "${FRONTIERCLOUD_IMAGE_SOURCE:-auto}" != auto && "${FRONTIERCLOUD_IMAGE_SOURCE:-auto}" != local ]]; then
  printf '%s\n' 'Image source must be auto, or local for isolated acceptance.' >&2
  exit 1
fi
if [[ $# -gt 2 || ! "$revision" =~ ^[0-9a-f]{40}$ || ( "$selection" != all && "$selection" != web-only ) ]]; then
  printf '%s\n' 'Provide one exact committed native source SHA' >&2
  exit 1
fi
test "$(git rev-parse --verify "$revision^{commit}")" = "$revision"
git cat-file -e "$revision:Dockerfile.gin"
git cat-file -e "$revision:updater/Dockerfile.gin"
# Never send .env, data, keys, untracked files, .git or mutable source changes.
paths=(Dockerfile Dockerfile.gin go.mod go.sum cmd internal migrations protocol static nginx updater/Dockerfile updater/Dockerfile.gin)
components=(web updater nginx)
if [[ "$selection" == web-only ]]; then components=(web); fi
for component in "${components[@]}"; do
  if [[ "${FRONTIERCLOUD_IMAGE_SOURCE:-auto}" != local ]]; then
    code=0
    python3 scripts/registry_images.py --ensure "$revision" "$component" || code=$?
    if (( code == 0 )); then continue; fi
    if (( code != 3 )); then exit "$code"; fi
  fi
  case "$component" in
    web) dockerfile=Dockerfile.gin ;;
    updater) dockerfile=updater/Dockerfile.gin ;;
    nginx) dockerfile=nginx/Dockerfile ;;
  esac
  args=(--build-arg "REVISION=$revision")
  if [[ "$component" == nginx ]]; then args+=(--build-arg FRONTIERCLOUD_RUNTIME=go); fi
  git archive --format=tar "$revision" -- "${paths[@]}" |
    DOCKER_BUILDKIT=0 docker --host unix:///var/run/docker.sock build --memory=1g --memory-swap=1g --cpu-period=100000 --cpu-quota=100000 -f "$dockerfile" "${args[@]}" \
      -t "frontiercloud-go-$component:$revision" -
done
printf 'Prepared verified native images at %s; no services were replaced.\n' "$revision"
printf '%s\n' 'Production publication still requires reviewed source/CI proof.'
