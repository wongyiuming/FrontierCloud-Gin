"""Actual local-engine SQLite recovery using private fixtures, never a live target.

The receipt is test-generated for private images, so this is not public delivery,
fresh HTTPS installation, MySQL or five-node acceptance. Source data/volumes stay
private and stopped after capture. Failed fixtures retain their recovery material.
"""
import argparse
import hashlib
import http.cookiejar
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import uuid


REVISION = '0' * 40  # Explicitly synthetic private-fixture identity.
ENV_KEYS = ('DEPLOYMENT_MODE', 'DB_TYPE', 'SQLITE_PATH', 'DATA_ROOT', 'SECRETS_DIR',
            'MYSQL_HOST', 'MYSQL_PORT', 'MYSQL_DATABASE', 'SERVER_NAME', 'TLS_ENABLED',
            'STORAGE_TRANSPORT', 'STORAGE_ENDPOINT', 'STORAGE_PORT')


def command(args, directory=None, timeout=180):
    result = subprocess.run(args, cwd=directory, capture_output=True, timeout=timeout)
    if result.returncode:
        # A failed initializer or server may log credentials. Never dump it here.
        raise RuntimeError('private fixture command failed: ' + args[0])
    return result.stdout


def compose(directory, *args):
    files = ['docker-compose.yaml']
    if (directory / 'docker-compose.gin-mysql.yaml').exists():
        files.append('docker-compose.gin-mysql.yaml')
    receipt_file = directory / '.fc-deployment.json'
    if receipt_file.exists():
        receipt = json.loads(receipt_file.read_text())
        files = receipt['compose_files']
    command_args = ['docker', 'compose', '--project-directory', str(directory)]
    if receipt_file.exists() and receipt.get('recovered'):
        command_args += ['--project-name', receipt['project']]
    for filename in files:
        command_args += ['-f', str(directory / filename)]
    return command(command_args + ['-f', str(directory / '.fc-images.json'), *args], timeout=700)


def fingerprint(configuration):
    def canonical(value):
        if isinstance(value, dict):
            return {key: canonical(value[key]) for key in sorted(value)}
        if isinstance(value, list):
            return [canonical(item) for item in value]
        if isinstance(value, float) and value.is_integer():
            return int(value)
        return value

    def redis_location(value):
        value = value or 'redis://redis:6379/0'
        parsed = urllib.parse.urlsplit(value)
        if not parsed.hostname or parsed.scheme not in ('redis', 'rediss'):
            return 'invalid:' + hashlib.sha256(value.encode()).hexdigest()
        host = parsed.hostname.lower()
        if ':' in host:
            host = '[' + host + ']'
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        query = sorted((key, value) for key, value in query if key not in ('username', 'password', 'token'))
        return urllib.parse.urlunsplit((parsed.scheme, host + ':' + str(parsed.port or 6379), parsed.path or '/0', urllib.parse.urlencode(query), parsed.fragment))

    def listen_location(environment):
        port = '8000'
        if environment.get('DEPLOYMENT_MODE') == 'only_stroge':
            port = environment.get('STORAGE_PORT') or ('8443' if environment.get('STORAGE_TRANSPORT') == 'relay' else '443')
        value = environment.get('HTTP_ADDR') or ':' + port
        if value.startswith('[') and ']:' in value:
            host, port = value[1:].split(']:', 1)
            host = '[' + host + ']'
        elif value.count(':') == 1:
            host, port = value.split(':', 1)
        else:
            return 'invalid:' + hashlib.sha256(value.encode()).hexdigest()
        return host + ':' + port

    def trust_networks(value, defaults, skip_empty):
        value = value or defaults
        try:
            prefixes = []
            for raw in value.split(','):
                raw = raw.strip()
                if not raw and skip_empty:
                    continue
                if '/' not in raw or '%' in raw:
                    raise ValueError('invalid prefix')
                prefix = ipaddress.ip_network(raw, strict=False)
                if prefix.version == 6 and prefix.network_address.ipv4_mapped:
                    prefixes.append('::ffff:' + str(prefix.network_address.ipv4_mapped) + '/' + str(prefix.prefixlen))
                else:
                    prefixes.append(str(prefix))
        except ValueError:
            return 'invalid:' + hashlib.sha256(value.encode()).hexdigest()
        return ','.join(sorted(set(prefixes)))

    services = {}
    for name in sorted(configuration['services']):
        service = configuration['services'][name]
        mounts = None
        if service.get('volumes'):
            mounts = [{key: item.get(key, False if key == 'read_only' else '')
                       for key in ('type', 'source', 'target', 'read_only')} for item in service['volumes']]
        ports = None
        if service.get('ports'):
            ports = [{key: item.get(key, 0 if key == 'target' else '')
                      for key in ('target', 'published', 'host_ip', 'protocol')} for item in service['ports']]
        services[name] = {'environment': {key: service['environment'][key]
                                          for key in sorted(service.get('environment', {})) if key in ENV_KEYS},
                          'execution': canonical({key: value for key, value in service.items()
                                                  if key not in ('image', 'environment', 'volumes', 'ports', 'build')}),
                          'mounts': mounts, 'ports': ports}
    for name in services:
        services[name]['environment']['REDIS_URL'] = redis_location(configuration['services'][name].get('environment', {}).get('REDIS_URL', ''))
        services[name]['environment']['HTTP_ADDR'] = listen_location(configuration['services'][name].get('environment', {}))
        services[name]['environment']['SECURITY_EXEMPT_NETWORKS'] = trust_networks(configuration['services'][name].get('environment', {}).get('SECURITY_EXEMPT_NETWORKS', ''), '127.0.0.0/8,::1/128', False)
        services[name]['environment']['TRUSTED_PROXY_NETWORKS'] = trust_networks(configuration['services'][name].get('environment', {}).get('TRUSTED_PROXY_NETWORKS', ''), '172.16.0.0/12', True)
        services[name]['environment'] = dict(sorted(services[name]['environment'].items()))
    volumes = {name: {'name': value['name'], 'external': value.get('external', False)}
               for name in sorted(configuration.get('volumes', {}))
               for value in [configuration['volumes'][name]]}
    # Go sorts map keys, but retains declared struct-field order for mounts,
    # ports and volumes. This fixture reproduces those bytes exactly.
    definitions = canonical({key: value for key, value in configuration.items()
                             if key not in ('name', 'services') and not key.startswith('x-')})
    value = {'definitions': definitions, 'project': configuration['name'], 'services': services, 'volumes': volumes}
    encoded = json.dumps(value, separators=(',', ':'), ensure_ascii=False)
    # encoding/json escapes HTML characters and the two JavaScript separators.
    for character, escaped in [('&', r'\u0026'), ('<', r'\u003c'), ('>', r'\u003e'),
                               ('\u2028', r'\u2028'), ('\u2029', r'\u2029')]:
        encoded = encoded.replace(character, escaped)
    return hashlib.sha256(encoded.encode()).hexdigest()


def wait_ready(base, host=None):
    for _ in range(150):
        try:
            with urllib.request.urlopen(urllib.request.Request(base + '/health/ready', headers={'Host': host} if host else {}), timeout=2) as response:
                if response.status == 200:
                    return
        except OSError:
            pass
        time.sleep(.2)
    raise AssertionError('private fixture never became ready')


def idle_cpu(container):
    samples = []
    consecutive = 0
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        percent = float(command(['docker', 'stats', '--no-stream', '--format', '{{.CPUPerc}}', container]).decode().strip().rstrip('%'))
        samples.append(percent)
        consecutive = consecutive + 1 if percent < 20 else 0
        if consecutive == 5:
            return samples
        time.sleep(1)
    raise AssertionError('fixture Web failed the existing post-business CPU recovery gate')


def api(base, host=None):
    jar = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    def request(method, route, body=None, fields=None):
        headers = dict(fields or {})
        if host:
            headers['Host'] = host
        if isinstance(body, dict):
            body = json.dumps(body).encode()
            headers['Content-Type'] = 'application/json'
        with client.open(urllib.request.Request(base + route, data=body, headers=headers, method=method), timeout=10) as response:
            return response.status, response.headers, response.read()
    return jar, request


def login(request, jar, key):
    status, _, _ = request('POST', '/api/v1/media/admin/elevate',
                           urllib.parse.urlencode({'token': key}).encode(),
                           {'Content-Type': 'application/x-www-form-urlencoded'})
    assert status == 200
    _, _, body = request('GET', '/api/v1/media/admin/status')
    csrf_name = json.loads(body)['csrf_cookie_name']
    return next(cookie.value for cookie in jar if cookie.name == csrf_name)


def probe(request, payload):
    status, _, body = request('GET', '/api/v1/media/catalog/media?media_type=music&path=music%2Ffixture'
                                    '&playback_session_id=20512c3b-5340-4185-b76d-20402279482a')
    assert status == 200
    entries = json.loads(body)['entries']
    assert len(entries) == 1
    status, headers, body = request('GET', '/api/v1/media/stream?file_path=music%2Ffixture%2Fsong.mp3',
                                    fields={'Range': 'bytes=3-9'})
    assert status == 206 and body == payload[3:10]
    assert headers['Content-Range'] == f'bytes 3-9/{len(payload)}'
    return entries[0]['media_id']


def run(args):
    source = Path(__file__).resolve().parents[1]
    client_image = 'python:3.14-alpine'
    try:
        command(['docker', 'image', 'inspect', client_image])
    except RuntimeError:
        command(['docker', 'pull', client_image])
    client_image = json.loads(command(['docker', 'image', 'inspect', client_image]))[0]['Id']
    def admin_probe(location, action):
        container = compose(location, 'ps', '--quiet', 'web').decode().strip()
        assert container
        return json.loads(command(['docker', 'run', '--rm', '--cpus=1', '--memory=128m', '--memory-swap=128m',
                                  '--network', 'container:' + container, '--volumes-from', container + ':ro',
                                  '-v', str(source / 'tests/operator_recovery_admin_probe.py') + ':/probe.py:ro',
                                  client_image, 'python', '/probe.py', action]))
    prefix = 'fc-ops-recovery-' + uuid.uuid4().hex[:16]
    directory = Path(tempfile.mkdtemp(prefix=prefix + '-', dir=args.workspace))
    project = prefix
    data = directory / 'data'
    folder = data / 'media/music/fixture'
    folder.mkdir(parents=True)
    payload = b'ID3' + bytes(range(128))
    (folder / 'song.mp3').write_bytes(payload)
    os.chown(data, 10001, 10001)
    for path in (data / 'media', data / 'media/music', folder, folder / 'song.mp3'):
        os.chown(path, 10001, 10001)
    shutil.copyfile(source / 'docker-compose.yaml', directory / 'docker-compose.yaml')
    # These scenarios recover an existing deployment whose public source image
    # predates automatic foc installation. Fresh-node bootstrap has its own
    # actual Compose acceptance; retain the historical service graph here.
    compose_file = directory / 'docker-compose.yaml'
    legacy = compose_file.read_text()
    if '\n  foc-host-init:\n' in legacy:
        before, after = legacy.split('\n  foc-host-init:\n', 1)
        legacy = before + '\n  secrets-init:\n' + after.split('\n  secrets-init:\n', 1)[1]
        legacy = legacy.replace('    depends_on:\n      foc-host-init: {condition: service_completed_successfully}\n', '', 1)
        compose_file.write_text(legacy)
    if args.database == 'mysql':
        shutil.copyfile(source / 'docker-compose.gin-mysql.yaml', directory / 'docker-compose.gin-mysql.yaml')
    # Use an isolated loopback address and the canonical stack. No global host
    # interface, firewall, SELinux or IPv6 setting is changed.
    address = '127.0.0.27'
    for port in (80, 443):
        with socket.socket() as check:
            check.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            check.bind((address, port))
    (directory / '.env').write_text(f'COMPOSE_PROJECT_NAME={project}\nTLS_ENABLED=false\nSERVER_NAME=localhost\nPUBLIC_BIND_ADDRESS={address}\nDB_TYPE={args.database}\nMYSQL_DATABASE={prefix.replace("-", "_")}\n')
    web_image = json.loads(command(['docker', 'image', 'inspect', args.image]))[0]['Id']
    edge_image = json.loads(command(['docker', 'image', 'inspect', args.edge_image]))[0]['Id']
    raw = command(['docker', 'compose', '--project-directory', str(directory), '-f',
                   str(directory / 'docker-compose.yaml'),
                   *(['-f', str(directory / 'docker-compose.gin-mysql.yaml')] if args.database == 'mysql' else []),
                   'config', '--format', 'json'])
    configuration = json.loads(raw)
    overrides = {}
    for name, service in configuration['services'].items():
        image = service['image']
        if 'frontiercloud-gin-web' in image:
            image = web_image
        elif 'frontiercloud-gin-nginx' in image:
            image = edge_image
        else:
            try:
                command(['docker', 'image', 'inspect', image])
            except RuntimeError:
                command(['docker', 'pull', image])
            image = json.loads(command(['docker', 'image', 'inspect', image]))[0]['Id']
        overrides[name] = {'image': image}
        if name == 'mysql':
            overrides[name].update(cpus=1, mem_limit='768m', memswap_limit='768m',
                                  command=['--skip-log-bin', '--innodb-buffer-pool-size=64M', '--performance-schema=OFF', '--max-connections=64'])
        if name == 'nginx':
            # Host loopback publication is a test boundary. Nginx itself must
            # listen on its container interface, as the production contract
            # deliberately rejects a loopback PUBLIC_BIND_ADDRESS internally.
            overrides[name]['environment'] = {'PUBLIC_BIND_ADDRESS': '0.0.0.0'}
        if name == 'web':
            overrides[name].update(cpus=1, mem_limit='512m', memswap_limit='512m')
    (directory / '.fc-images.json').write_text(json.dumps({'services': overrides}))
    receipt = {'configuration_version': 1, 'role': 'master', 'project': project,
               'database': args.database, 'revision': REVISION, 'reviewed_source_sha': REVISION,
               'created_at': '2026-10-12T00:00:00Z', 'selection_sha256': fingerprint(configuration),
               'images': {}, 'service_images': {name: value['image'] for name, value in overrides.items()},
               'compose_files': ['docker-compose.yaml'] + (['docker-compose.gin-mysql.yaml'] if args.database == 'mysql' else []), 'state': 'ready'}
    (directory / '.fc-deployment.json').write_text(json.dumps(receipt))
    if args.state_restore:
        effective = json.loads(compose(directory, 'config', '--format', 'json'))
        receipt['selection_sha256'] = fingerprint(effective)
        (directory / '.fc-deployment.json').write_text(json.dumps(receipt))
    os.chmod(directory / '.fc-deployment.json', 0o600)
    restored_project = project + '-restore'
    restored_started = False
    success = False
    result = {'scope': 'actual private-Compose deployment backup, CLI restoration and gated activation',
              'public_installation_proof': False, 'synthetic_revision': REVISION,
              'fixture_directory': str(directory), 'database': args.database}
    try:
        compose(directory, 'up', '-d', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', '120')
        base = 'http://' + address
        wait_ready(base)
        jar, request = api(base)
        key = compose(directory, 'exec', '-T', 'web', 'cat', '/run/frontiercloud-secrets/admin_key').decode().strip()
        media_id = probe(request, payload)
        assert admin_probe(directory, 'set')['priority'] == 77
        before_fact = json.loads(compose(directory, 'exec', '-T', 'web', '/app/frontiercloud', 'operator-status'))
        if args.upgrade_test_binary:
            # This adapter exercises actual native processes, Compose, archives
            # and writes. Only public-release proof is mapped to private image
            # IDs by the opt-in Go test; no production command has that bypass.
            target_image = json.loads(command(['docker', 'image', 'inspect', args.upgrade_image]))[0]['Id']
            assert target_image != web_image, 'upgrade acceptance requires a distinct target image'
            spec = directory / 'upgrade-fixture.json'
            spec.write_text(json.dumps({'directory': str(directory), 'web_image_id': web_image,
                                        'target_web_image_id': target_image, 'edge_image_id': edge_image,
                                        'fail_prepare': args.upgrade_failure,
                                        'recover_failure': args.upgrade_recover,
                                        'expected_source_generation': args.expected_source_generation}))
            completed = subprocess.run([str(args.upgrade_test_binary), '-test.run',
                                        '^TestOperatorUpgradeComposeAcceptance$', '-test.v'],
                                       env={**os.environ, 'FRONTIERCLOUD_TEST_OPERATOR_UPGRADE': str(spec)},
                                       capture_output=True, timeout=800)
            transcript = directory / 'upgrade-test.log'
            transcript.write_bytes(completed.stdout + completed.stderr)
            os.chmod(transcript, 0o600)
            if completed.returncode:
                raise AssertionError('native upgrade failed; private transcript retained at ' + str(transcript))
            upgrade = json.loads((directory / 'upgrade-evidence.json').read_text())
            result['upgrade'] = upgrade
            if args.upgrade_failure and not args.upgrade_recover:
                assert upgrade['phase'] == 'failed_fenced'
                assert (data / '.frontiercloud-native-maintenance').exists()
                checked = json.loads(command([str(args.binary), 'backup', 'verify', '--file',
                                              str(directory / 'pre-upgrade-recovery.tar'),
                                              '--sha256', upgrade['backup_sha256']], timeout=700))
                assert checked['integrity_verified']
                state_output = compose(directory, 'ps', '--all', '--format', 'json').decode()
                try:
                    states = json.loads(state_output)
                except json.JSONDecodeError:
                    states = [json.loads(line) for line in state_output.splitlines() if line.strip()]
                if isinstance(states, dict):
                    states = [states]
                assert all(item['State'] in ('exited', 'created', 'dead')
                           for item in states if item['Service'] != 'mysql')
                result.update(status='passed', scope='actual native upgrade preparation failure and retained recovery point',
                              no_production_operation=True, database=args.database)
                success = True
                return result
            assert upgrade['phase'] == 'opened' and upgrade['native_managed_business_reads']
            wait_ready(base)
            upgraded_fact = json.loads(compose(directory, 'exec', '-T', 'web', '/app/frontiercloud', 'operator-status'))
            assert upgraded_fact['node_id'] == before_fact['node_id']
            assert probe(request, payload) == media_id
            assert admin_probe(directory, 'verify')['priority'] == 77
            upgraded_web = compose(directory, 'ps', '--quiet', 'web').decode().strip()
            actual = json.loads(command(['docker', 'inspect', upgraded_web]))[0]
            assert actual['Image'] == (web_image if args.upgrade_recover else target_image)
            assert actual['HostConfig']['NanoCpus'] == 1000000000
            assert actual['HostConfig']['Memory'] == 512 * 1024 * 1024
            assert actual['HostConfig']['MemorySwap'] == 512 * 1024 * 1024
            upgrade['actual_image_switch'] = True
            upgrade['http_range_and_identity_preserved'] = True
            upgrade['post_business_cpu_samples'] = idle_cpu(upgraded_web)
            if args.upgrade_recover:
                result.update(status='passed', scope='actual failed-DDL recovery with original business mounts and managed Range reads',
                              no_production_operation=True, database=args.database)
                success = True
                return result
        if args.state_restore:
            secrets_volume = configuration['volumes']['runtime_secrets']['name']
            secrets_root = Path(json.loads(command(['docker', 'volume', 'inspect', secrets_volume]))[0]['Mountpoint'])
            directory_probe = secrets_root / 'state-directory-proof'
            directory_probe.mkdir(mode=0o750)
            os.chown(directory_probe, 10001, 10001)
            (directory_probe / 'probe').write_text('captured-directory-state')
            os.chown(directory_probe / 'probe', 10001, 10001)
            os.chmod(directory_probe / 'probe', 0o600)
        state_archive = directory / 'default-state.tar'
        state_report = json.loads(command([str(args.binary), '--directory', str(directory), 'backup', 'create',
                                           '--freeze', '--output', str(state_archive),
                                           *(['--confirm-external-writers-stopped'] if args.database == 'mysql' else [])], timeout=700))
        assert state_report['integrity_verified']
        assert state_report['manifest']['scope'] == 'upgrade-state'
        assert not state_report['manifest']['complete_cluster']
        assert all(not item['path'].startswith(('data/media/', 'data/lyrics/', 'data/recordings/'))
                   for item in state_report['manifest']['files'])
        if args.state_restore:
            shutil.rmtree(directory_probe)
            for receipt_name in ('.native-store', '.native-runtime'):
                (data / receipt_name).unlink()
            if args.database == 'sqlite':
                sqlite_path = configuration['services']['web']['environment']['SQLITE_PATH']
                (data / Path(sqlite_path).relative_to('/app/data')).unlink()
            else:
                compose(directory, 'exec', '-T', 'mysql', 'sh', '-c',
                        'MYSQL_PWD=$(cat /run/frontiercloud-secrets/mysql_root_password) exec mysql -u root -e "DROP DATABASE $MYSQL_DATABASE"')
            recovery_directory = directory.parent / ('ordinary-state-' + directory.name)
            state = json.loads(command([str(args.binary), '--directory', str(directory), 'restore', 'state',
                                        '--file', str(state_archive), '--sha256', state_report['sha256'],
                                        '--confirm-node-id', before_fact['node_id'],
                                        '--recovery-directory', str(recovery_directory),
                                        '--confirm-source-offline', '--confirm-state-loss',
                                        *(['--confirm-external-writers-stopped'] if args.database == 'mysql' else [])], timeout=800))
            assert state['phase'] == 'prepared_fenced'
            opened = json.loads(command([str(args.binary), '--directory', str(directory), 'restore', 'state-open',
                                         '--approve-plan-sha256', state['plan']['plan_sha256'],
                                         '--confirm-node-id', before_fact['node_id']], timeout=800))
            assert opened['phase'] == 'opened' and opened['business_verified']
            assert directory_probe.stat().st_uid == 10001
            assert directory_probe.stat().st_gid == 10001
            assert directory_probe.stat().st_mode & 0o777 == 0o750
            assert (directory_probe / 'probe').read_text() == 'captured-directory-state'
            assert all((data / name).is_file() for name in ('.native-store', '.native-runtime'))
            wait_ready(base)
            assert probe(request, payload) == media_id
            assert admin_probe(directory, 'verify')['priority'] == 77
            result.update(status='passed', scope='ordinary default state backup restored lost database in retained mounts without an upgrade journal',
                          original_business_mounts_retained=True, actual_http_range_verified=True,
                          no_production_operation=True)
            success = True
            return result
        archive = directory / 'recovery.tar'
        report = json.loads(command([str(args.binary), '--directory', str(directory), 'backup', 'create',
                                     '--freeze', '--include-business-files', '--output', str(archive),
                                     *(['--confirm-external-writers-stopped'] if args.database == 'mysql' else [])], timeout=700))
        assert report['integrity_verified'] and not report['restored_business_verified']
        assert report['manifest']['node_id'] == before_fact['node_id']
        assert (data / '.frontiercloud-native-maintenance').exists()
        target = directory / 'restoration'
        command([str(args.binary), 'restore', 'check', '--file', str(archive), '--target', str(target),
                 '--sha256', report['sha256']])
        assert not target.exists(), 'restore check created a target'
        command([str(args.binary), 'restore', 'apply', '--file', str(archive), '--target', str(target),
                 '--sha256', report['sha256'], '--confirm-node-id', before_fact['node_id'],
                 ])
        command([str(args.binary), 'restore', 'prepare', '--file', str(archive), '--target', str(target),
                 '--sha256', report['sha256'], '--confirm-node-id', before_fact['node_id'], '--project', restored_project])
        assert (target / 'data/.frontiercloud-native-maintenance').exists()
        assert (target / 'runtime_secrets/admin_key').read_text().strip() == key
        restore_dir = target / 'deployment'
        activated = json.loads(command([str(args.binary), '--directory', str(restore_dir),
                                       'restore', 'activate', '--confirm-node-id', before_fact['node_id'],
                                       '--confirm-source-offline'], timeout=700))
        assert activated['phase'] == 'verified'
        assert activated['recovery']['restored_business_verified']
        assert (target / 'data/.frontiercloud-maintenance').exists()
        # Model process loss after durable opening intent and public removal;
        # actual CLI must restore maintenance, recheck native facts and finish.
        restore_journal = restore_dir / '.fc-restore.json'
        opening = json.loads(restore_journal.read_text())
        opening['phase'] = 'opening'
        restore_journal.write_text(json.dumps(opening))
        restore_journal.chmod(0o600)
        (target / 'data/.frontiercloud-maintenance').unlink()
        command([str(args.binary), '--directory', str(restore_dir), 'restore', 'open',
                 '--confirm-node-id', before_fact['node_id']])
        restored_started = True
        wait_ready(base)
        restored_jar, restored_request = api(base)
        assert probe(restored_request, payload) == media_id
        assert admin_probe(restore_dir, 'verify')['priority'] == 77
        restored_web = compose(restore_dir, 'ps', '--quiet', 'web').decode().strip()
        host = json.loads(command(['docker', 'inspect', restored_web]))[0]['HostConfig']
        assert host['NanoCpus'] == 1000000000
        cpu = idle_cpu(restored_web)
        result.update(status='passed', archive_sha256=report['sha256'], node_identity_preserved=True,
                      media_id_preserved=True, priority_preserved=True, actual_http_range_verified=True,
                      restore_check_read_only=True, offline_fence_preserved_on_apply=True,
                      operator_activation_verified=True, interrupted_restore_open_reconciled=True, no_production_operation=True,
                      web_cpu_limit=host['NanoCpus'], web_memory=host['Memory'], web_memory_swap=host['MemorySwap'],
                      post_business_cpu_samples=cpu, web_image_id=web_image, edge_image_id=edge_image,
                      test_http_client_image_id=client_image)
        success = True
        return result
    finally:
        # Stop only projects born in this driver. Keep volumes and recovery
        # material on failure; no global pruning or volume deletion is used.
        for location in (directory / 'restoration/deployment', directory):
            if (location / '.fc-images.json').exists():
                try:
                    compose(location, 'stop')
                    compose(location, 'rm', '-f')
                except RuntimeError:
                    pass
        # Only detach empty networks bearing the exact born-project label.
        # Keep every volume, archive, and bind directory on either outcome.
        for born_project in (project, restored_project):
            if not born_project.startswith('fc-ops-recovery-'):
                continue
            try:
                networks = command(['docker', 'network', 'ls', '--quiet', '--filter',
                                    'label=com.docker.compose.project=' + born_project]).decode().split()
                for network in networks:
                    detail = json.loads(command(['docker', 'network', 'inspect', network]))[0]
                    if (detail.get('Labels', {}).get('com.docker.compose.project') == born_project
                            and not detail.get('Containers')):
                        command(['docker', 'network', 'rm', network])
            except RuntimeError:
                pass
        if not success:
            print('FAILED: private recovery material retained at ' + str(directory))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', choices=('sqlite', 'mysql'), default='sqlite')
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--edge-image', required=True)
    parser.add_argument('--upgrade-test-binary', type=Path)
    parser.add_argument('--upgrade-image', help='distinct private target image for optional native upgrade acceptance')
    parser.add_argument('--expected-source-generation', type=int, default=0, help='require this actual source runtime schema for explicit cross-generation acceptance')
    parser.add_argument('--upgrade-failure', action='store_true', help='inject failure at target preparation after real native backup')
    parser.add_argument('--upgrade-recover', action='store_true', help='restore failed database state in original business mounts and reopen source')
    parser.add_argument('--state-restore', action='store_true', help='restore an ordinary default state backup after database loss')
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    if (options.upgrade_test_binary is None) != (options.upgrade_image is None):
        parser.error('--upgrade-test-binary and --upgrade-image must be supplied together')
    if options.upgrade_failure and options.upgrade_test_binary is None:
        parser.error('--upgrade-failure requires the native upgrade adapter')
    if options.upgrade_recover and not options.upgrade_failure:
        parser.error('--upgrade-recover requires --upgrade-failure')
    options.workspace.mkdir(parents=True, exist_ok=True)
    evidence = run(options)
    options.output.write_text(json.dumps(evidence, indent=2) + '\n')
    print('PASS: actual Compose backup, CLI restore/activation and HTTP Range validation')
