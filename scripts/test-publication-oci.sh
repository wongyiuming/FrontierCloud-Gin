#!/usr/bin/env bash
# Development-only real Buildx export compatibility, not authenticated delivery.
# Never logs in, pushes, loads/runs the output, or touches production services.
set -euo pipefail
cd "$(dirname "$0")/.."
revision=$(git rev-parse HEAD)
[[ "$revision" =~ ^[0-9a-f]{40}$ ]]
test -z "$(git status --porcelain)"
work=$(mktemp -d /var/tmp/fc-publication-oci.XXXXXXXX)
builder="fc-oci-format-${work##*.}"
created=false
cleanup() {
  result=$?
  if test "$created" = true; then
    docker buildx rm "$builder" > "$work/builder-cleanup.log" 2>&1 || result=1
  fi
  printf 'OCI_FORMAT_FIXTURE_EVIDENCE %s RESULT %s\n' "$work" "$result"
  exit "$result"
}
trap cleanup EXIT
docker pull moby/buildkit:buildx-stable-1 > "$work/buildkit-pull.log" 2>&1
buildkit=$(docker image inspect moby/buildkit:buildx-stable-1 --format '{{index .RepoDigests 0}}')
[[ "$buildkit" =~ ^moby/buildkit@sha256:[0-9a-f]{64}$ ]]
printf 'OCI_FORMAT_SOURCE %s BUILDKIT %s\n' "$revision" "$buildkit"
docker buildx create --name "$builder" --driver docker-container \
  --driver-opt "image=$buildkit,memory=512m,memory-swap=512m,cpu-period=100000,cpu-quota=100000,restart-policy=no" \
  > "$work/builder-create.log" 2>&1
created=true
docker buildx build --builder "$builder" --platform linux/amd64 \
  --file tests/publication-oci.Dockerfile --build-arg "REVISION=$revision" \
  --provenance=false --sbom=false --output "type=oci,dest=$work/web.oci.tar" . \
  > "$work/export.log" 2>&1
docker inspect "buildx_buildkit_${builder}0" \
  --format 'memory={{.HostConfig.Memory}} swap={{.HostConfig.MemorySwap}} cpu={{.HostConfig.CpuQuota}}/{{.HostConfig.CpuPeriod}} oom={{.State.OOMKilled}}' \
  > "$work/builder-budget.log"
python3 - "$work/web.oci.tar" "$revision" <<'PY' > "$work/verification.json"
import json, sys
from scripts.trusted_native_publish import verify_oci
verified = verify_oci(sys.argv[1], sys.argv[2], 'web')
print(json.dumps({'source': sys.argv[2], 'manifest_digest': verified['digest'],
                  'blob_count': len(verified['blobs']), 'format_fixture_only': True}, sort_keys=True))
PY
cat "$work/builder-budget.log" "$work/verification.json"
printf 'REAL BUILDX OCI FORMAT VERIFICATION PASSED; NO IMAGE PUBLICATION PERFORMED\n'
