#!/usr/bin/env bash
# Real proxy semantics with a synthetic upstream; no ports or external network.
set -euo pipefail
cd "$(dirname "$0")/.."
container="fc-nginx-headers-$(cat /proc/sys/kernel/random/uuid)"
cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
docker run -d --name "$container" --network none --cpus=.5 --memory=64m --memory-swap=64m --pids-limit=64 \
  -v "$PWD/tests/nginx-response-headers.conf:/etc/nginx/nginx.conf:ro" \
  -v "$PWD/nginx/proxy-response-headers.conf:/etc/nginx/proxy-response-headers.conf:ro" \
  -v "$PWD/nginx/security-headers.conf:/etc/nginx/security-headers.conf:ro" nginx:1.30.4-alpine >/dev/null
docker exec "$container" nginx -t
python3 - "$container" <<'PY'
import re, subprocess, sys, time
container = sys.argv[1]
for route in ('cache', 'relay'):
    for attempt in range(20):
        result = subprocess.run(['docker', 'exec', container, 'wget', '-S', '-O', '-',
                                 f'http://127.0.0.1:8080/{route}'], capture_output=True, text=True)
        if result.returncode == 0:
            break
        time.sleep(.2)
    assert result.returncode == 0, result.stderr
    assert result.stdout == 'synthetic-body', (route, result.stdout)
    headers = re.findall(r'^\s+([\w-]+):\s*(.*?)\s*$', result.stderr, re.M)
    for name, value in {
        'Content-Security-Policy': "default-src 'none'",
        'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'same-origin',
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    }.items():
        assert [v for n, v in headers if n.lower() == name.lower()] == [value], (route, name, headers)
    private = ('strict-transport-security', 'x-media-resource-id', 'x-media-owner-id',
               'x-media-object-id', 'x-media-parent-request-id', 'x-audit-trace-id')
    assert not any(n.lower() in private for n, _ in headers), (route, headers)
    if route == 'relay':
        assert not any(n.lower() in ('set-cookie', 'x-accel-redirect') for n, _ in headers), headers
print('PASS: child proxy filters preserve canonical headers, hide audit IDs/cookies and ignore internal redirects')
PY
