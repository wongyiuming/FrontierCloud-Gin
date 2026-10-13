"""Real private two-node Compose recovery-set acceptance (SQLite).

The fresh fixture completes real native startup, then is paired through native store APIs. It tests native writers,
archives, original identities, sealed relationship credentials, managed media
references and gated set restoration. It does not assert public release proofs,
network pairing/reconnect, automatic certificate issuance, or five-node coverage.
No production resource or host network/DNS configuration is modified.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import uuid

from operator_recovery_acceptance import command, compose, fingerprint, probe, api, idle_cpu

REVISION = '0' * 40


def own_tree(root):
    os.chown(root, 10001, 10001)
    for directory, dirs, files in os.walk(root):
        for name in dirs + files:
            os.chown(Path(directory) / name, 10001, 10001)


def volume_path(project, logical):
    found = json.loads(command(['docker', 'volume', 'inspect', project + '_' + logical]))[0]
    assert found['Labels']['com.docker.compose.project'] == project
    return Path(found['Mountpoint'])


def run(args):
    project = 'fc-ops-set-' + uuid.uuid4().hex[:12]
    root = Path(tempfile.mkdtemp(prefix=project + '-', dir=args.workspace))
    image = json.loads(command(['docker', 'image', 'inspect', args.image]))[0]['Id']
    redis = 'redis:7.4.11-alpine'
    try:
        command(['docker', 'image', 'inspect', redis])
    except RuntimeError:
        command(['docker', 'pull', redis])
    redis = json.loads(command(['docker', 'image', 'inspect', redis]))[0]['Id']
    master_address = '127.0.0.31'
    with socket.socket() as check:
        check.bind((master_address, 80))
    ca = root / 'ca.pem'
    key = root / 'leaf.key'
    command(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
             '-noenc', '-keyout', str(key), '-out', str(ca), '-days', '2', '-subj', '/CN=storage.fixture.test',
             '-addext', 'subjectAltName=DNS:storage.fixture.test', '-addext', 'basicConstraints=critical,CA:TRUE'])
    os.chmod(key, 0o600)
    locations = []
    projects = []
    specs = []
    success = False
    payload = b'ID3' + bytes(range(128))
    result = {'fixture_directory': str(root), 'database': 'sqlite', 'nodes': 2,
              'public_installation_proof': False, 'transport_pairing_reconnect_proof': False,
              'automatic_certificate_issuance_proof': False}
    fc_calls = 0

    def fc_command(argv, timeout=700):
        nonlocal fc_calls
        fc_calls += 1
        completed = subprocess.run(argv, capture_output=True, timeout=timeout)
        if completed.returncode:
            diagnostic = root / ('private-fc-command-%02d.log' % fc_calls)
            with os.fdopen(os.open(diagnostic, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as log:
                log.write(completed.stdout + completed.stderr)
            raise RuntimeError('native fc command failed; private diagnostic retained')
        return completed.stdout

    try:
        for kind in ('master', 'storage'):
            directory = root / kind
            directory.mkdir(mode=0o700)
            locations.append(directory)
            member_project = project + '-' + kind
            projects.append(member_project)
            data = directory / 'data'
            data.mkdir()
            env = {'DB_TYPE': 'sqlite', 'SQLITE_PATH': '/app/data/frontiercloud.db', 'DATA_ROOT': '/app/data',
                   'SECRETS_DIR': '/run/frontiercloud-secrets', 'TLS_ENABLED': 'true',
                   'SERVER_NAME': kind + '.fixture.test', 'SSL_CERT_FILE': '/run/frontiercloud-tls/ca.pem',
                   'GOMAXPROCS': '1', 'GOMEMLIMIT': '384MiB', 'NGINX_MEDIA_ACCEL': 'false',
                   'TRUSTED_PROXY_NETWORKS': '192.0.2.1/32'}
            if kind == 'master':
                env.update(HTTP_ADDR=':8000', REDIS_URL='redis://redis:6379/0')
            else:
                env.update(DEPLOYMENT_MODE='only_stroge', STORAGE_TRANSPORT='relay', STORAGE_PORT='8443',
                           HTTP_ADDR=':8443', STORAGE_ENDPOINT='https://storage.fixture.test:8443')
            mounts = [{'type': 'bind', 'source': str(data), 'target': '/app/data'},
                      {'type': 'volume', 'source': 'runtime_secrets', 'target': '/run/frontiercloud-secrets'},
                      {'type': 'volume', 'source': 'certificate_published', 'target': '/run/frontiercloud-tls', 'read_only': True}]
            common = {'image': image, 'environment': env, 'volumes': mounts, 'read_only': True,
                      'security_opt': ['no-new-privileges:true'], 'tmpfs': ['/tmp:size=67108864'],
                      'cpus': 1, 'mem_limit': '512m', 'memswap_limit': '512m'}
            web = dict(common, user='10001:10001', command=['serve'], cap_drop=['ALL'],
                       healthcheck={'test': ['CMD', '/app/frontiercloud', 'healthcheck'],
                                    'interval': '1s', 'timeout': '5s', 'retries': 90})
            if kind == 'master':
                web['ports'] = [{'target': 8000, 'published': '80', 'host_ip': master_address, 'protocol': 'tcp'}]
            services = {'web': web}
            for init in ('secrets', 'media'):
                services[init + '-init'] = dict(common, user='0:0', command=['init-' + init], restart='no')
            volumes = {'runtime_secrets': {}, 'certificate_published': {}}
            if kind == 'master':
                services['redis'] = {'image': redis, 'volumes': ['redis_data:/data'],
                                     'cpus': .25, 'mem_limit': '128m', 'memswap_limit': '128m'}
                volumes['redis_data'] = {}
            filename = 'docker-compose.yaml' if kind == 'master' else 'docker-compose.storage.yaml'
            (directory / filename).write_text(json.dumps({'name': member_project, 'services': services, 'volumes': volumes}))
            (directory / '.env').write_text('COMPOSE_PROJECT_NAME=' + member_project + '\n')
            overrides = {name: {'image': value['image']} for name, value in services.items()}
            (directory / '.fc-images.json').write_text(json.dumps({'services': overrides}))
            configuration = json.loads(command(['docker', 'compose', '--project-directory', str(directory),
                                                 '-f', str(directory / filename), 'config', '--format', 'json']))
            receipt = {'configuration_version': 1, 'role': kind, 'project': member_project,
                       'database': 'sqlite', 'revision': REVISION, 'reviewed_source_sha': REVISION,
                       'created_at': '2026-10-12T00:00:00Z', 'selection_sha256': fingerprint(configuration),
                       'images': {}, 'service_images': {name: value['image'] for name, value in services.items()},
                       'compose_files': [filename], 'state': 'ready'}
            (directory / '.fc-deployment.json').write_text(json.dumps(receipt))
            os.chmod(directory / '.fc-deployment.json', 0o600)
            for init in ('secrets', 'media'):
                compose(directory, 'run', '--rm', '--no-deps', '-T', init + '-init')
            published = volume_path(member_project, 'certificate_published')
            generation = 'c' * 32
            (published / generation).mkdir(mode=0o750)
            shutil.copyfile(ca, published / generation / 'fullchain.pem')
            shutil.copyfile(key, published / generation / 'privkey.pem')
            shutil.copyfile(ca, published / 'ca.pem')
            (published / 'current.json').write_text(json.dumps({'generation': generation}))
            own_tree(published)
            if kind == 'master':
                folder = data / 'media/music/fixture'
                folder.mkdir(parents=True, exist_ok=True)
                (folder / 'song.mp3').write_bytes(payload)
            specs.append({'Directory': str(directory), 'Secrets': str(volume_path(member_project, 'runtime_secrets')),
                          'Endpoint': 'https://' + kind + '.fixture.test' + (':8443' if kind == 'storage' else ''),
                          'Role': 'Master' if kind == 'master' else 'Follower'})
        # Complete native admission through the production server before any
        # fixture promotion. Never forge a runtime receipt for an offline seed.
        for i, directory in enumerate(locations):
            own_tree(directory / 'data')
            compose(directory, 'up', '-d', '--no-build', '--pull', 'never', '--no-deps', '--wait',
                    '--wait-timeout', '120', *(['redis', 'web'] if i == 0 else ['web']))
            compose(directory, 'stop', 'web')
        specfile = root / 'seed.json'
        specfile.write_text(json.dumps(specs))
        completed = subprocess.run([str(args.operator_test_binary), '-test.run', '^TestOperatorRecoverySetNativeSeed$', '-test.v'],
                                   env={**os.environ, 'FRONTIERCLOUD_TEST_RECOVERY_SET_SEED': str(specfile)},
                                   capture_output=True, timeout=120)
        (root / 'seed.log').write_bytes(completed.stdout + completed.stderr)
        os.chmod(root / 'seed.log', 0o600)
        if completed.returncode:
            raise AssertionError('native seed failed; private log retained')
        seed = json.loads((root / 'seed-evidence.json').read_text())
        vault_hashes = {}
        for i, directory in enumerate(locations):
            own_tree(directory / 'data')
            own_tree(Path(specs[i]['Secrets']))
            vault_hashes[seed['master_id' if i == 0 else 'storage_id']] = hashlib.sha256(
                (Path(specs[i]['Secrets']) / 'node-vault.key').read_bytes()).hexdigest()
            compose(directory, 'up', '-d', '--no-build', '--pull', 'never', '--no-deps', '--wait',
                    '--wait-timeout', '120', *(['redis', 'web'] if i == 0 else ['web']))
        before = [json.loads(compose(d, 'exec', '-T', 'web', '/app/frontiercloud', 'operator-status')) for d in locations]
        assert before[0]['node_id'] == seed['master_id'] and before[1]['node_id'] == seed['storage_id']
        base = 'http://' + master_address
        _, request = api(base)
        media_id = probe(request, payload)
        # Omitting the known Storage must reject before any native fence exists.
        incomplete = root / 'incomplete'
        rejected = subprocess.run([str(args.binary), 'backup', 'set-create', '--deployment', str(locations[0]),
                                   '--confirm-master-id', seed['master_id'], '--freeze-all', '--output', str(incomplete)],
                                  capture_output=True, timeout=90)
        assert rejected.returncode and not incomplete.exists()
        assert all(not (d / 'data/.frontiercloud-native-maintenance').exists() for d in locations)
        archives = root / 'archives'
        report = json.loads(fc_command([str(args.binary), 'backup', 'set-create',
                                     '--deployment', str(locations[0]), '--deployment', str(locations[1]),
                                     '--confirm-master-id', seed['master_id'], '--freeze-all', '--output', str(archives)], timeout=700))
        assert report['complete_cluster'] and report['integrity_verified'] and not report['restored_business_verified']
        target = root / 'restored'
        common = ['--file', str(archives), '--target', str(target), '--sha256', report['sha256'],
                  '--confirm-master-id', seed['master_id']]
        fc_command([str(args.binary), 'restore', 'set-check', *common], timeout=700)
        assert not target.exists()
        fc_command([str(args.binary), 'restore', 'set-apply', *common], timeout=700)
        prefix = project + '-r'
        prepared = json.loads(fc_command([str(args.binary), 'restore', 'set-prepare', *common,
                                       '--project-prefix', prefix], timeout=700))
        assert prepared['phase'] == 'prepared_fenced'
        for member in report['manifest']['members']:
            projects.append(prefix + '-' + member['node_id'])
            locations.append(target / member['node_id'] / 'deployment')
            assert hashlib.sha256((target / member['node_id'] / 'runtime_secrets/node-vault.key').read_bytes()).hexdigest() == vault_hashes[member['node_id']]
        approval = ['--target', str(target), '--sha256', report['sha256'], '--confirm-master-id', seed['master_id']]
        activated = json.loads(fc_command([str(args.binary), 'restore', 'set-activate', *approval,
                                        '--confirm-all-sources-offline'], timeout=700))
        assert activated['phase'] == 'verified_fenced' and activated['recovery_set']['restored_business_verified']
        for member in report['manifest']['members']:
            assert (target / member['node_id'] / 'data/.frontiercloud-maintenance').exists()
        opened = json.loads(fc_command([str(args.binary), 'restore', 'set-open', *approval], timeout=700))
        assert opened['phase'] == 'opened'
        _, request = api(base)
        assert probe(request, payload) == media_id
        for member in report['manifest']['members']:
            location = target / member['node_id'] / 'deployment'
            fact = json.loads(compose(location, 'exec', '-T', 'web', '/app/frontiercloud', 'operator-status'))
            assert fact['node_id'] == member['node_id'] and fact['role'] == member['role']
            assert not (location / '.fc-recovery-set.json').exists()
            web = compose(location, 'ps', '--quiet', 'web').decode().strip()
            host = json.loads(command(['docker', 'inspect', web]))[0]['HostConfig']
            assert host['NanoCpus'] == 1000000000 and host['Memory'] == host['MemorySwap'] == 512 * 1024 * 1024
        verifyfile = root / 'verify.json'
        verifyfile.write_text(json.dumps({'Target': str(target), 'Master': seed['master_id'], 'Storage': seed['storage_id']}))
        checked = subprocess.run([str(args.operator_test_binary), '-test.run', '^TestOperatorRecoverySetNativeVerify$', '-test.v'],
                                 env={**os.environ, 'FRONTIERCLOUD_TEST_RECOVERY_SET_VERIFY': str(verifyfile)},
                                 capture_output=True, timeout=90)
        (root / 'verify.log').write_bytes(checked.stdout + checked.stderr)
        os.chmod(root / 'verify.log', 0o600)
        if checked.returncode:
            raise AssertionError('restored sealed native identity/pair verification failed; private log retained')
        samples = idle_cpu(compose(target / seed['master_id'] / 'deployment', 'ps', '--quiet', 'web').decode().strip())
        # A restored deployment uses classified bind roots for former named
        # volumes. The next complete capture must include these live bytes.
        second_archives = root / 'second-archives'
        second = json.loads(fc_command([str(args.binary), 'backup', 'set-create',
                                     '--deployment', str(target / seed['master_id'] / 'deployment'),
                                     '--deployment', str(target / seed['storage_id'] / 'deployment'),
                                     '--confirm-master-id', seed['master_id'], '--freeze-all',
                                     '--output', str(second_archives)], timeout=700))
        assert second['complete_cluster'] and second['integrity_verified']
        fc_command([str(args.binary), 'backup', 'set-verify', '--file', str(second_archives),
                 '--sha256', second['sha256']], timeout=700)
        assert second['manifest']['set_id'] != report['manifest']['set_id']
        result.update(status='passed', sealed_identity_and_relationship_credentials_decrypted=True,
                      set_sha256=report['sha256'], native_store_seed=seed['seed'],
                      original_identities_and_vault_keys_preserved=True, actual_http_range_and_media_id_preserved=True,
                      missing_member_rejected_before_freeze=True, prepared_and_activated_publicly_fenced=True,
                      all_members_opened=True, source_data_and_archives_retained=True,
                      restored_set_rebacked_up_and_integrity_verified=True, second_set_sha256=second['sha256'],
                      master_post_business_cpu_samples=samples)
        success = True
        return result
    finally:
        for location in reversed(locations):
            if (location / '.fc-deployment.json').exists():
                try:
                    if not success:
                        try:
                            diagnostic = location / 'private-fixture-compose.log'
                            with os.fdopen(os.open(diagnostic, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'wb') as log:
                                log.write(compose(location, 'logs', '--no-color', '--tail', '80'))
                        except (RuntimeError, OSError):
                            pass
                    compose(location, 'stop')
                    compose(location, 'rm', '-f')
                except RuntimeError:
                    pass
        for born in projects:
            assert born.startswith('fc-ops-set-')
            try:
                networks = command(['docker', 'network', 'ls', '--quiet', '--filter',
                                    'label=com.docker.compose.project=' + born]).decode().split()
                for network in networks:
                    info = json.loads(command(['docker', 'network', 'inspect', network]))[0]
                    if info.get('Labels', {}).get('com.docker.compose.project') == born and not info.get('Containers'):
                        command(['docker', 'network', 'rm', network])
            except RuntimeError:
                pass
        if not success:
            print('FAILED: private recovery-set material retained at ' + str(root))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--operator-test-binary', type=Path, required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    options.workspace.mkdir(parents=True, exist_ok=True)
    evidence = run(options)
    options.output.write_text(json.dumps(evidence, indent=2) + '\n')
    print('PASS: actual two-node Compose recovery set, native identity/resource verification and HTTP Range')
