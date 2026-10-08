#!/usr/bin/env bash
# Master-only upgrade/handoff/rollback. Storage has no release agent.
set -euo pipefail
cd "$(dirname "$0")/.."
exec bash scripts/test-go-updater.sh
