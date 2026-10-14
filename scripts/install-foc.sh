#!/bin/sh
# Run only by the isolated Compose installer, never a resident product service.
set -eu
[ "${FOC_COMPOSE_INSTALL:-}" = 1 ] || { echo 'Use the Compose foc installation service' >&2; exit 2; }
[ "$#" -eq 1 ] || { echo 'Usage: sh install-foc.sh EXISTING_DEPLOYMENT_DIRECTORY' >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo 'Host command installation requires root' >&2; exit 2; }
source=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
deployment=$1
case "$deployment" in /*) ;; *) echo 'Absolute host deployment path required' >&2; exit 2 ;; esac
receipt_directory=/deployment
case "$deployment" in *'
'*) echo 'Deployment path must not contain newlines' >&2; exit 2 ;; esac
[ -f "$receipt_directory/.fc-deployment.json" ] && [ ! -L "$receipt_directory/.fc-deployment.json" ] || {
  echo 'Existing native deployment receipt required; this does not initialize deployments' >&2; exit 2;
}
[ -f "$source/fc" ] && [ ! -L "$source/fc" ] && [ -x "$source/fc" ] && [ -f "$source/foc" ] && [ ! -L "$source/foc" ] || {
  echo 'Run this installer from an extracted operator bundle containing fc and foc' >&2; exit 2;
}
revision=$("$source/fc" version)
case "$revision" in *[!a-f0-9]*|'') echo 'Invalid operator bundle revision' >&2; exit 2 ;; esac
[ "${#revision}" -eq 40 ] || exit 2
[ "$revision" = "${FOC_OPERATOR_REVISION:-}" ] || { echo 'Selected operator revision mismatch' >&2; exit 2; }
for directory in /usr/local /usr/local/bin /usr/local/lib /usr/local/lib/frontiercloud /usr/local/lib/frontiercloud/foc /etc/frontiercloud; do
  [ ! -L "$directory" ] || { echo 'Refusing symlinked installation path' >&2; exit 2; }
done
home=/usr/local/lib/frontiercloud/foc
if [ -e /usr/local/bin/foc ] || [ -L /usr/local/bin/foc ] || [ -e "$home" ]; then
  [ -f "$home/.managed" ] && [ ! -L "$home/.managed" ] && [ ! -L /usr/local/bin/foc ] || {
    echo 'Existing unmanaged foc installation; refusing replacement' >&2; exit 2;
  }
  [ "$(cat "$home/.managed")" = frontiercloud-foc-v1 ] || { echo 'Unknown foc ownership marker' >&2; exit 2; }
fi
mkdir -p /usr/local/bin "$home" /etc/frontiercloud
mkdir "$home/.install-lock" || { echo 'Another host installation is active or interrupted' >&2; exit 2; }
trap 'rm -f "$home/fc.new.$$" /usr/local/bin/foc.new.$$ /etc/frontiercloud/foc-deployments.new.$$; rmdir "$home/.install-lock"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
registry=/etc/frontiercloud/foc-deployments
[ ! -L "$registry" ] || { echo 'Refusing symlinked deployment registry' >&2; exit 2; }
if [ -e "$registry" ]; then [ -f "$registry" ] || exit 2; fi
umask 022
{ if [ -f "$registry" ]; then cat "$registry"; fi; printf '%s\n' "$deployment"; } |
  LC_ALL=C sort -u > "$registry.new.$$"
chmod 644 "$registry.new.$$"
install -m 755 "$source/fc" "$home/fc.new.$$"
install -m 755 "$source/foc" /usr/local/bin/foc.new.$$
mv -f "$home/fc.new.$$" "$home/fc"
mv -f /usr/local/bin/foc.new.$$ /usr/local/bin/foc
mv -f "$registry.new.$$" "$registry"
printf 'frontiercloud-foc-v1\n' > "$home/.managed"
chmod 644 "$home/.managed"
printf 'Installed foc (%s); registered %s. Run foc status from any directory. Docker permissions are still required.\n' "$revision" "$deployment"
