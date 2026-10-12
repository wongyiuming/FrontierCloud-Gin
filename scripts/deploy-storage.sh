#!/usr/bin/env bash
# Storage only; never selects the business Compose stack or production data.
set -euo pipefail
cd "$(dirname "$0")/.."
client="${FC_OPERATOR_CLIENT:-./fc}"
if [[ ! -x "$client" ]]; then
  printf '%s\n' 'Download the public operator bundle with scripts/get-fc.sh; an installed fc client is required. No local compilation fallback.' >&2
  exit 2
fi
exec "$client" install storage
