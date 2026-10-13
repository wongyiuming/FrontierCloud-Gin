#!/usr/bin/env sh
# Extract the operator bundle from one public runtime digest, without running it.
# Requires only a POSIX shell and Docker; no Git, Go, Node or Python on the host.
set -eu
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo 'Usage: sh get-fc.sh EMPTY_DIRECTORY [published-main-SHA]' >&2
  exit 2
fi
destination=$1
case "$destination" in -*) echo 'Destination must not start with a dash' >&2; exit 2 ;; esac
revision=${2:-latest}
case "$revision" in
  latest) ;;
  *[!a-f0-9]*|'') echo 'Use latest or one full published main SHA' >&2; exit 2 ;;
  *) [ "${#revision}" -eq 40 ] || exit 2 ;;
esac
# Refuse an existing directory even if it looks empty: bootstrap never takes over.
[ ! -e "$destination" ] && [ ! -L "$destination" ] || { echo 'Destination exists; choose a new bundle directory' >&2; exit 2; }
repository=ghcr.io/wongyiuming/frontiercloud-gin-web
docker pull "$repository:$revision" || { echo 'Public image pull failed; no local build fallback' >&2; exit 2; }
image=$(docker image inspect --format '{{index .RepoDigests 0}}' "$repository:$revision")
case "$image" in
  "$repository"@sha256:*) ;;
  *) echo 'Public image has no matching immutable digest' >&2; exit 2 ;;
esac
digest=${image#"$repository"@sha256:}
case "$digest" in *[!a-f0-9]*|'') echo 'Invalid image digest' >&2; exit 2 ;; esac
[ "${#digest}" -eq 64 ] || exit 2
source=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.source"}}' "$image")
runtime=$(docker image inspect --format '{{index .Config.Labels "frontiercloud.runtime"}}' "$image")
component=$(docker image inspect --format '{{index .Config.Labels "frontiercloud.component"}}' "$image")
actual=$(docker image inspect --format '{{index .Config.Labels "frontiercloud.revision"}}' "$image")
oci_revision=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$image")
[ "$source" = 'https://github.com/wongyiuming/FrontierCloud-Gin' ] && [ "$runtime" = go ] && [ "$component" = web ] && [ "$actual" = "$oci_revision" ] || { echo 'Image provenance mismatch' >&2; exit 2; }
case "$actual" in *[!a-f0-9]*|'') exit 2 ;; esac
[ "${#actual}" -eq 40 ] || exit 2
[ "$revision" = latest ] || [ "$revision" = "$actual" ] || exit 2
container=''
cleanup() { [ -z "$container" ] || docker rm "$container" >/dev/null; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# This disposable container is never started and has no host data/socket mounts.
container=$(docker create --entrypoint /bin/true "$image")
mkdir "$destination"
docker cp "$container:/app/operator/." "$destination/" || { echo 'Release has no operator bundle; preserve the directory and select a supported release' >&2; exit 2; }
[ "$("$destination/fc" version)" = "$actual" ] || { echo 'Operator bundle revision mismatch' >&2; exit 2; }
printf 'Operator bundle extracted: %s (%s). Configure .env, then run ./fc doctor and ./fc install.\n' "$actual" "$image"
