#!/usr/bin/env bash
# Real isolated schema migration faults; never run in hosted CI or production.
set -euo pipefail
cd "$(dirname "$0")/.."
source_root="$PWD"
run="fc-schema-$(date +%s)-$$"
# Optional reusable caches affect compiler speed only, never database facts.
cache=()
if [ -n "${FC_GO_MOD_CACHE:-}" ]; then cache+=(-v "$FC_GO_MOD_CACHE:/go/pkg/mod"); fi
if [ -n "${FC_GO_BUILD_CACHE:-}" ]; then cache+=(-v "$FC_GO_BUILD_CACHE:/root/.cache/go-build"); fi
docker run --rm --name "$run-go" --label "frontiercloud.test.run=$run" \
    --cpus=2 --memory=3g --memory-swap=3g -e GOMAXPROCS=2 -e GOMEMLIMIT=512MiB -e GOGC=25 \
    -e FRONTIERCLOUD_TEST_LARGE_MIGRATION="${FRONTIERCLOUD_TEST_LARGE_MIGRATION:-}" \
    -v "$source_root:/src:ro" "${cache[@]}" -w /src golang:1.26.8-bookworm \
    sh -c 'go test -p=2 -count=1 -race -v ./internal/store/schema && go test -p=2 -count=1 -race -v ./internal/store/business -run "TestMigrationFacts|TestResourceMigration|TestPeerMigration|TestPeerPhysicalInventory|TestPeerExpectedPhysicalInventory|TestPeerRetirement|TestPeerBackupObservation"'
printf 'PASS: SQLite schema recovery, task/reservation/lease transactions and migration backup guards; byte transport remains separate acceptance\n'
