"""Actual local-engine SQLite recovery using private fixtures, never a live target.

The receipt is test-generated for private images, so this is not public delivery,
fresh HTTPS installation, MySQL or five-node acceptance. Source data/volumes stay
private and stopped after capture. Failed fixtures retain their recovery material.
"""
import argparse
import hashlib
import http.cookiejar
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
    return command(['docker', 'compose', '--project-directory', str(directory), '-f',
                    str(directory / 'docker-compose.yaml'), '-f', str(directory / '.fc-images.json'),
                    *args], timeout=700)


def fingerprint(configuration):
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
                          'mounts': mounts, 'ports': ports}
    volumes = {name: {'name': value['name'], 'external': value.get('external', False)}
               for name in sorted(configuration.get('volumes', {}))
               for value in [configuration['volumes'][name]]}
    # Go sorts map keys, but retains declared struct-field order for mounts,
    # ports and volumes. This fixture reproduces those bytes exactly.
    value = {'project': configuration['name'], 'services': services, 'volumes': volumes}
    return hashlib.sha256(json.dumps(value, separators=(',', ':')).encode()).hexdigest()


def wait_ready(base):
    for _ in range(150):
        try:
            with urllib.request.urlopen(base + '/health/ready', timeout=2) as response:
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


def api(base):
    jar = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    def request(method, route, body=None, fields=None):
        headers = dict(fields or {})
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
    # Use an isolated loopback address and the canonical stack. No global host
    # interface, firewall, SELinux or IPv6 setting is changed.
    address = '127.0.0.27'
    for port in (80, 443):
        with socket.socket() as check:
            check.bind((address, port))
    (directory / '.env').write_text(f'COMPOSE_PROJECT_NAME={project}\nTLS_ENABLED=false\nSERVER_NAME=localhost\nPUBLIC_BIND_ADDRESS={address}\n')
    web_image = json.loads(command(['docker', 'image', 'inspect', args.image]))[0]['Id']
    edge_image = json.loads(command(['docker', 'image', 'inspect', args.edge_image]))[0]['Id']
    raw = command(['docker', 'compose', '--project-directory', str(directory), '-f',
                   str(directory / 'docker-compose.yaml'), 'config', '--format', 'json'])
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
        if name == 'nginx':
            # Host loopback publication is a test boundary. Nginx itself must
            # listen on its container interface, as the production contract
            # deliberately rejects a loopback PUBLIC_BIND_ADDRESS internally.
            overrides[name]['environment'] = {'PUBLIC_BIND_ADDRESS': '0.0.0.0'}
        if name == 'web':
            overrides[name].update(cpus=1, mem_limit='512m', memswap_limit='512m')
    (directory / '.fc-images.json').write_text(json.dumps({'services': overrides}))
    receipt = {'configuration_version': 1, 'role': 'master', 'project': project,
               'database': 'sqlite', 'revision': REVISION, 'reviewed_source_sha': REVISION,
               'created_at': '2026-10-12T00:00:00Z', 'selection_sha256': fingerprint(configuration),
               'images': {}, 'service_images': {name: value['image'] for name, value in overrides.items()},
               'compose_files': ['docker-compose.yaml'], 'state': 'ready'}
    (directory / '.fc-deployment.json').write_text(json.dumps(receipt))
    os.chmod(directory / '.fc-deployment.json', 0o600)
    restored_project = project + '-restore'
    restored_started = False
    success = False
    result = {'scope': 'actual private-Compose SQLite deployment backup and offline material restoration',
              'public_installation_proof': False, 'synthetic_revision': REVISION,
              'fixture_directory': str(directory), 'database': 'sqlite'}
    try:
        compose(directory, 'up', '-d', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', '120')
        base = 'http://' + address
        wait_ready(base)
        jar, request = api(base)
        key = compose(directory, 'exec', '-T', 'web', 'cat', '/run/frontiercloud-secrets/admin_key').decode().strip()
        media_id = probe(request, payload)
        assert admin_probe(directory, 'set')['priority'] == 77
        before_fact = json.loads(compose(directory, 'exec', '-T', 'web', '/app/frontiercloud', 'operator-status'))
        archive = directory / 'recovery.tar'
        report = json.loads(command([str(args.binary), '--directory', str(directory), 'backup', 'create',
                                     '--freeze', '--output', str(archive)], timeout=700))
        assert report['integrity_verified'] and not report['restored_business_verified']
        assert report['manifest']['node_id'] == before_fact['node_id']
        assert (data / '.frontiercloud-native-maintenance').exists()
        target = directory / 'restoration'
        command([str(args.binary), 'restore', 'check', '--file', str(archive), '--target', str(target),
                 '--sha256', report['sha256']])
        assert not target.exists(), 'restore check created a target'
        command([str(args.binary), 'restore', 'apply', '--file', str(archive), '--target', str(target),
                 '--sha256', report['sha256'], '--confirm-node-id', before_fact['node_id']])
        assert (target / 'data/.frontiercloud-native-maintenance').exists(), 'restore reopened the native fence'
        assert (target / 'runtime_secrets/admin_key').read_text().strip() == key
        # First validate restored SQL/identity while the source and restored
        # generation both remain offline. Activation is an explicit TEST step.
        env = ['-e', 'DB_TYPE=sqlite', '-e', 'SQLITE_PATH=/app/data/frontiercloud.db',
               '-e', 'DATA_ROOT=/app/data', '-e', 'SECRETS_DIR=/run/frontiercloud-secrets',
               '-e', 'TLS_ENABLED=false', '-e', 'SERVER_NAME=localhost']
        mounts = ['-v', str(target / 'data') + ':/app/data', '-v',
                  str(target / 'runtime_secrets') + ':/run/frontiercloud-secrets']
        restored_fact = json.loads(command(['docker', 'run', '--rm', '--cpus=1', '--memory=512m',
                                             '--memory-swap=512m', *env, *mounts, web_image, 'operator-status']))
        assert restored_fact['node_id'] == before_fact['node_id']
        assert restored_fact['database']['schema_generation'] == before_fact['database']['schema_generation']
        command(['docker', 'run', '--rm', '--cpus=1', '--memory=512m', '--memory-swap=512m',
                 *env, *mounts, web_image, 'maintenance', 'resume'])
        # Restore the canonical stack's state classes through test-only bind
        # overrides, preserving identities and secret bytes; never run a fresh
        # initializer against recovery material.
        restore_dir = directory / 'restored-compose'
        restore_dir.mkdir()
        shutil.copyfile(source / 'docker-compose.yaml', restore_dir / 'docker-compose.yaml')
        (restore_dir / '.env').write_text(f'COMPOSE_PROJECT_NAME={restored_project}\nTLS_ENABLED=false\nSERVER_NAME=localhost\nPUBLIC_BIND_ADDRESS={address}\nDATA_DIRECTORY={target / "data"}\n')
        restored_overrides = json.loads(json.dumps(overrides))
        for service in ('web',):
            restored_overrides[service]['volumes'] = [
                {'type': 'bind', 'source': str(target / 'runtime_secrets'), 'target': '/run/frontiercloud-secrets'}]
            restored_overrides[service]['depends_on'] = {'redis': {'condition': 'service_healthy'}}
        restored_overrides['redis']['volumes'] = [{'type': 'bind', 'source': str(target / 'redis_data'), 'target': '/data'}]
        restored_overrides['certificate-agent']['volumes'] = [
            {'type': 'bind', 'source': str(target / 'certificate_state'), 'target': '/var/lib/frontiercloud-certificate'},
            {'type': 'bind', 'source': str(target / 'certificate_published'), 'target': '/run/frontiercloud-tls'}]
        # certificate-runtime is regenerated independently; its initializer is
        # safe because it receives only fresh certificate-runtime/state mounts.
        (restore_dir / '.fc-images.json').write_text(json.dumps({'services': restored_overrides}))
        compose(restore_dir, 'up', '-d', '--no-build', '--pull', 'never', '--no-deps', 'redis', 'certificate-init')
        compose(restore_dir, 'up', '-d', '--no-build', '--pull', 'never', '--no-deps', 'certificate-agent', 'web', 'nginx')
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
                      test_activation_separate_from_restore_apply=True, no_production_operation=True,
                      web_cpu_limit=host['NanoCpus'], web_memory=host['Memory'], web_memory_swap=host['MemorySwap'],
                      post_business_cpu_samples=cpu, web_image_id=web_image, edge_image_id=edge_image,
                      test_http_client_image_id=client_image)
        success = True
        return result
    finally:
        # Stop only projects born in this driver. Keep volumes and recovery
        # material on failure; no global pruning or volume deletion is used.
        for location in (directory / 'restored-compose', directory):
            if (location / '.fc-images.json').exists():
                try:
                    compose(location, 'stop')
                    compose(location, 'rm', '-f')
                except RuntimeError:
                    pass
        if not success:
            print('FAILED: private recovery material retained at ' + str(directory))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--edge-image', required=True)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    options.workspace.mkdir(parents=True, exist_ok=True)
    evidence = run(options)
    options.output.write_text(json.dumps(evidence, indent=2) + '\n')
    print('PASS: actual Compose SQLite backup, material restore and separately activated HTTP Range validation')
