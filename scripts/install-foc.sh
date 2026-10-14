#!/bin/sh
# Run only by the isolated Compose installer, never a resident product service.
set -eu
[ "${FOC_COMPOSE_INSTALL:-}" = 1 ] || { echo 'Use the Compose foc installation service' >&2; exit 2; }
[ "$#" -eq 1 ] || { echo 'Usage: sh install-foc.sh EXISTING_DEPLOYMENT_DIRECTORY' >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo 'Host command installation requires root' >&2; exit 2; }
source=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
deployment=$1
automatic=false
if [ "$deployment" = auto ] && [ "${FOC_AUTOMATIC_PROJECT:-}" = 1 ]; then
  automatic=true
  deployment=@compose
fi
if [ "$automatic" = false ]; then
case "$deployment" in /*) ;; *) echo 'Absolute host deployment path required' >&2; exit 2 ;; esac
receipt_directory=/deployment
case "$deployment" in *'
'*) echo 'Deployment path must not contain newlines' >&2; exit 2 ;; esac
[ -f "$receipt_directory/.fc-deployment.json" ] && [ ! -L "$receipt_directory/.fc-deployment.json" ] || {
  echo 'Existing native deployment receipt required; this does not initialize deployments' >&2; exit 2;
}
fi
[ -f "$source/fc" ] && [ ! -L "$source/fc" ] && [ -x "$source/fc" ] && [ -f "$source/foc" ] && [ ! -L "$source/foc" ] || {
  echo 'Run this installer from an extracted operator bundle containing fc and foc' >&2; exit 2;
}
revision=$("$source/fc" version)
case "$revision" in *[!a-f0-9]*|'') echo 'Invalid operator bundle revision' >&2; exit 2 ;; esac
[ "${#revision}" -eq 40 ] || exit 2
expected=${FOC_OPERATOR_REVISION:-}
if [ "$automatic" = true ] && [ -z "$expected" ]; then expected=$revision; fi
[ "$revision" = "$expected" ] || { echo 'Selected operator revision mismatch' >&2; exit 2; }
# Inspect the unmasked host hierarchy: writable binds may resolve host symlinks.
host_root=/host
[ -d "$host_root/usr" ] && [ -d "$host_root/etc" ] || { echo 'Read-only host parent views required' >&2; exit 2; }
for directory in /usr/local /usr/local/bin /usr/local/lib /usr/local/lib/frontiercloud /usr/local/lib/frontiercloud/foc /etc/frontiercloud; do
  [ ! -L "$host_root$directory" ] || { echo 'Refusing symlinked host installation path' >&2; exit 2; }
done
home=/usr/local/lib/frontiercloud/foc
fresh=false
if [ -e /usr/local/bin/foc ] || [ -L /usr/local/bin/foc ] || [ -e "$home" ]; then
  [ -f "$home/.managed" ] && [ ! -L "$home/.managed" ] || {
    echo 'Existing unmanaged foc installation; refusing replacement' >&2; exit 2;
  }
  [ "$(cat "$home/.managed")" = frontiercloud-foc-v2 ] || { echo 'Unknown foc ownership marker' >&2; exit 2; }
else
  fresh=true
fi
locked=false
cleanup() {
  rm -f "$home/fc.new.$$" "$home/marker.new.$$" "$home/identity.new.$$" /usr/local/bin/foc.new.$$ /etc/frontiercloud/foc-deployments.new.$$
  if [ "$locked" = true ]; then rmdir "$home/.install-lock"; fi
  if [ "$fresh" = true ] && [ ! -e "$home/.managed" ] && [ -d "$home" ]; then rmdir "$home"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p /usr/local/bin "$home" /etc/frontiercloud
mkdir "$home/.install-lock" || { echo 'Another host installation is active or interrupted' >&2; exit 2; }
locked=true
umask 022
if [ "$fresh" = true ]; then
  printf 'frontiercloud-foc-v2\n' > "$home/marker.new.$$"
  chmod 644 "$home/marker.new.$$"
  mv -f "$home/marker.new.$$" "$home/.managed"
fi
for identity in "$home/launcher.current" "$home/launcher.pending"; do
  [ ! -L "$identity" ] || { echo 'Unsafe launcher identity' >&2; exit 2; }
  if [ -e "$identity" ]; then [ -f "$identity" ] || exit 2; fi
done
if [ -e /usr/local/bin/foc ] || [ -L /usr/local/bin/foc ]; then
  [ -f /usr/local/bin/foc ] && [ ! -L /usr/local/bin/foc ] || { echo 'Unsafe global foc command' >&2; exit 2; }
  cmp -s /usr/local/bin/foc "$home/launcher.current" || cmp -s /usr/local/bin/foc "$home/launcher.pending" || {
    echo 'Global foc command differs from managed identity; refusing replacement' >&2; exit 2;
  }
fi
registry=/etc/frontiercloud/foc-deployments
[ ! -L "$registry" ] || { echo 'Refusing symlinked deployment registry' >&2; exit 2; }
if [ -e "$registry" ]; then [ -f "$registry" ] || exit 2; fi
umask 022
{ if [ -f "$registry" ]; then cat "$registry"; fi; printf '%s\n' "$deployment"; } |
  LC_ALL=C sort -u > "$registry.new.$$"
chmod 644 "$registry.new.$$"
if [ "$automatic" = true ] && [ -f "$home/fc" ]; then
  current_revision=$("$home/fc" version)
  if [ "$current_revision" != "$revision" ]; then
    "$home/fc" operator-generation >/dev/null 2>&1 || { echo 'Existing legacy foc must be refreshed through the verified operator workflow before automatic registration' >&2; exit 2; }
    mv -f "$registry.new.$$" "$registry"
    printf 'Registered Compose deployment; retained the existing different foc backend. Use verified self-update to replace it.\n'
    exit 0
  fi
fi
install -m 755 "$source/fc" "$home/fc.new.$$"
install -m 755 "$source/foc" /usr/local/bin/foc.new.$$
# Keep the candidate identity across interruption after global command publication.
install -m 644 "$source/foc" "$home/identity.new.$$"
mv -f "$home/identity.new.$$" "$home/launcher.pending"
mv -f "$home/fc.new.$$" "$home/fc"
mv -f /usr/local/bin/foc.new.$$ /usr/local/bin/foc
mv -f "$registry.new.$$" "$registry"
mv -f "$home/launcher.pending" "$home/launcher.current"
printf 'Installed foc (%s); registered %s. Run foc status from any directory. Docker permissions are still required.\n' "$revision" "$deployment"
