#!/bin/sh
set -eu
# The helper is confined to this container's files and Nginx master process.
/usr/local/bin/frontiercloud-tls-edge watch &
