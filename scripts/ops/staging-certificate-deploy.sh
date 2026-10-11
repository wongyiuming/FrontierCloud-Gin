#!/usr/bin/env bash
# RN staging-only Certbot hook; do not install this on the production Master.
set -euo pipefail
lineage=/etc/letsencrypt/live/www4399.sbs
[[ "${RENEWED_LINEAGE:-}" = "$lineage" ]] || exit 0
test "$(hostname)" = racknerd-2ee08ce
openssl x509 -in "$lineage/fullchain.pem" -noout -checkend 86400
cmp <(openssl x509 -in "$lineage/fullchain.pem" -pubkey -noout) \
    <(openssl pkey -in "$lineage/privkey.pem" -pubout)
# Retain existing file-bind mount inodes. Reload only after both files are copied.
for directory in /opt/frontiercloud-staging/certs /etc/frontiercloud-staging-trigger; do
  test -d "$directory"
  cp -- "$lineage/fullchain.pem" "$directory/fullchain.pem"
  case "$directory" in
    /etc/frontiercloud-staging-trigger)
      cp -- "$lineage/privkey.pem" "$directory/privkey.pem"
      chown root:frontiercloud-staging-trigger "$directory/fullchain.pem" "$directory/privkey.pem"
      chmod 0640 "$directory/fullchain.pem" "$directory/privkey.pem"
      ;;
    *)
      cp -- "$lineage/privkey.pem" "$directory/privkey.pem"
      chmod 0644 "$directory/fullchain.pem"
      chmod 0600 "$directory/privkey.pem"
      ;;
  esac
done
docker exec frontiercloud-staging-nginx-1 nginx -t
docker exec frontiercloud-staging-nginx-1 nginx -s reload
systemctl restart frontiercloud-staging-trigger.service
