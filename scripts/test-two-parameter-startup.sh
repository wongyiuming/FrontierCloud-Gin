#!/usr/bin/env bash
# Real Compose defaults plus first issuance on private fixed-port networks.
set -euo pipefail
cd "$(dirname "$0")/.."
revision=${FRONTIERCLOUD_REVISION:-$(git rev-parse HEAD)}
[[ "$revision" =~ ^[a-f0-9]{40}$ ]]
work=$(mktemp -d /tmp/fc-two-parameter-XXXXXXXX)
cleanup() {
  test "$(readlink -f "$work")" = "$work"
  [[ "$work" =~ ^/tmp/fc-two-parameter-[a-zA-Z0-9]{8}$ ]]
  rm -rf -- "$work"
}
trap cleanup EXIT
for mode in http tls empty pinned; do
  : > "$work/$mode.env"
  if [[ "$mode" != http ]]; then
    printf '%s\n' 'TLS_ENABLED=true' 'SERVER_NAME=business.fixture.test' > "$work/$mode.env"
  fi
  if [[ "$mode" == empty ]]; then
    printf '%s\n' 'FRONTIERCLOUD_REVISION=' 'DB_TYPE=' 'COMPOSE_PROJECT_NAME=' 'WEBRTC_STUN_PORT=' 'DATA_DIRECTORY=' >> "$work/$mode.env"
  fi
  if [[ "$mode" == pinned ]]; then printf 'FRONTIERCLOUD_REVISION=%s\n' "$revision" >> "$work/$mode.env"; fi
  env -i PATH="$PATH" HOME="$HOME" docker compose --project-directory "$work" --env-file "$work/$mode.env" -f "$PWD/docker-compose.yaml" config --format json > "$work/$mode.json"
done
python3 - "$work" "$revision" <<'PY'
import json, pathlib, sys
root=pathlib.Path(sys.argv[1])
for mode in ('http','tls','empty','pinned'):
    config=json.loads((root/(mode+'.json')).read_text())
    assert config['name']=='frontiercloud-gin'
    services=config['services']
    assert 'mysql' not in services
    assert all('build' not in service for service in services.values())
    for name in ('web','secrets-init','media-init','certificate-init','certificate-agent','nginx'):
        component='web' if name.endswith('-init') or name=='certificate-agent' else name
        tag=sys.argv[2] if mode=='pinned' else 'latest'
        assert services[name]['image']=='ghcr.io/wongyiuming/frontiercloud-gin-'+component+':'+tag
    web=services['web']['environment']
    assert web['DB_TYPE']=='sqlite' and web['SQLITE_PATH']=='/app/data/frontiercloud.db'
    assert not {'RELEASE_BRANCH','RELEASE_SOURCE_BRANCH','GITHUB_API_TOKEN','STAGING_CD'} & web.keys()
    assert web['TLS_ENABLED']==('false' if mode=='http' else 'true')
    assert services['nginx']['healthcheck']['test']==['CMD','/usr/local/bin/frontiercloud-tls-edge','ready']
    assert {(p['target'],p['published']) for p in services['nginx']['ports']}=={(80,'80'),(443,'443')}
    assert all(p['published']=='3478' for p in services['stun']['ports'])
    assert any(v.get('source')==str(root/'data') and v['target']=='/app/data' for v in services['web']['volumes'])
    for service in services.values():
        assert not {'SSL_CERT_PATH','SSL_KEY_PATH','STORAGE_TLS_CERT','STORAGE_TLS_KEY','ACME_WEBROOT','HTTP_PORT','HTTPS_PORT'} & service.get('environment',{}).keys()
print('PASS: real Compose HTTP, two TLS values, empty defaults and exact-SHA pin; fixed ports and no builds')
PY
# Actual first issuance/recreation/renewal uses production Compose on private
# networks, a local CA in a test binary and no host-port remapping.
bash scripts/test-storage-certificate-containers.sh
