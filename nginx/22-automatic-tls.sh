#!/bin/sh
set -eu
# Environment substitution has finished. Select verified managed material or
# ACME-only bootstrap before the first Nginx config validation and launch.
/usr/local/bin/frontiercloud-tls-edge initialize
