"""Actual isolated generation-4 native runtime -> gated generation-7 preparation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tarfile
import tempfile
import uuid

from operator_recovery_acceptance import api, command, idle_cpu, probe, wait_ready


def table_digest(database):
    connection = sqlite3.connect(f'file:{database}?mode=ro', uri=True)
    try:
        tables = ['node_identity', 'node_relationships', 'media_objects',
                  'media_playback_stats', 'media_encryption', 'media_crypto_keys']
        result = {}
        for table in tables:
            rows = connection.execute('SELECT * FROM ' + table).fetchall()
            encoded = json.dumps([[v.hex() if isinstance(v, bytes) else v for v in row]
                                  for row in rows], sort_keys=True, separators=(',', ':'))
            result[table] = hashlib.sha256(encoded.encode()).hexdigest()
        identity = connection.execute('SELECT node_id FROM node_identity WHERE singleton=1').fetchone()[0]
        generation = connection.execute('SELECT generation FROM frontiercloud_schema WHERE singleton=1').fetchone()[0]
        assert connection.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        return identity, generation, result
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-image', required=True)
    parser.add_argument('--target-image', required=True)
    parser.add_argument('--edge-image', required=True)
    parser.add_argument('--target-binary', type=Path, required=True)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.workspace.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix='fc-legacy4-', dir=args.workspace))
    data, secrets = root / 'data', root / 'secrets'
    for directory in [data, secrets]:
        directory.mkdir(mode=0o700)
        os.chown(directory, 10001, 10001)
    folder = data / 'media/music/fixture'
    folder.mkdir(parents=True)
    payload = b'ID3-isolated-prior-generation-native-media' * 64
    (folder / 'song.mp3').write_bytes(payload)
    for path in [data / 'media', data / 'media/music', folder, folder / 'song.mp3']:
        os.chown(path, 10001, 10001)
    name = 'fc-legacy4-' + uuid.uuid4().hex
    redis = name + '-redis'
    agent = name + '-certificate'
    edge = name + '-nginx'
    network = name + '-network'
    env = ['-e', 'DB_TYPE=sqlite', '-e', 'DATA_ROOT=/app/data',
           '-e', 'SQLITE_PATH=/app/data/node.sqlite', '-e', 'SECRETS_DIR=/run/frontiercloud-secrets',
           '-e', 'TLS_ENABLED=false', '-e', 'SERVER_NAME=localhost', '-e', 'REDIS_ADDR=' + redis + ':6379']
    mounts = ['-v', str(data) + ':/app/data', '-v', str(secrets) + ':/run/frontiercloud-secrets']
    limits = ['--cpus=1', '--memory=512m', '--memory-swap=512m', '--label', 'frontiercloud.acceptance=' + name]
    report = {'status': 'failed', 'workspace': str(root), 'isolated': True,
              'source_image': args.source_image, 'target_image': args.target_image,
              'target_binary_sha256': hashlib.sha256(args.target_binary.read_bytes()).hexdigest(),
              'target_binary_override': True, 'public_target_release_proof': False}
    created = False
    redis_created = False
    network_created = False
    agent_created = False
    edge_created = False
    cert_mounts = []
    for part, destination in [('certificate-state', '/var/lib/frontiercloud-certificate'),
                              ('certificate-runtime', '/run/frontiercloud-certificate'),
                              ('certificate-published', '/run/frontiercloud-tls')]:
        directory = root / part
        directory.mkdir(mode=0o700)
        cert_mounts += ['-v', str(directory) + ':' + destination]
    mounts += ['-v', str(root / 'certificate-runtime') + ':/run/frontiercloud-certificate:ro']
    def target(*arguments):
        return command(['docker', 'run', '--rm', *limits, *env, *mounts,
                        '-v', str(args.target_binary.resolve()) + ':/fixture-frontiercloud:ro',
                        '--entrypoint', '/fixture-frontiercloud', args.target_image, *arguments])
    try:
        command(['docker', 'image', 'inspect', args.source_image])
        command(['docker', 'network', 'create', '--label', 'frontiercloud.acceptance=' + name, network])
        network_created = True
        command(['docker', 'run', '-d', '--name', redis, '--network', network, '--network-alias', 'redis',
                 '--cpus=1', '--memory=128m', '--memory-swap=128m',
                 '--label', 'frontiercloud.acceptance=' + name, 'redis:7.4.8-alpine'])
        redis_created = True
        command(['docker', 'run', '--rm', '--user', '0:10001', *limits, *env, *cert_mounts,
                 args.source_image, 'init-certificate'])
        command(['docker', 'run', '-d', '--name', agent, '--user', '0:10001',
                 *limits, *env, *cert_mounts, args.source_image, 'certificate-agent'])
        agent_created = True
        traffic = root / 'traffic'
        traffic.mkdir(mode=0o755)
        for initialization in ['init-secrets', 'init-media', 'migrate']:
            command(['docker', 'run', '--rm', *limits, *env, *mounts, args.source_image, initialization])
        command(['docker', 'run', '-d', '--name', name, '--network', network, '--network-alias', 'web', *limits, *env, *mounts,
                 args.source_image])
        created = True
        command(['docker', 'run', '-d', '--name', edge, '--network', network, *limits,
                 '-e', 'TLS_ENABLED=false', '-e', 'SERVER_NAME=localhost', '-e', 'PUBLIC_BIND_ADDRESS=0.0.0.0',
                 '-e', 'NGINX_ENVSUBST_OUTPUT_DIR=/etc/nginx',
                 '-e', 'UPLOAD_INACTIVITY_TIMEOUT=300', '-e', 'INSTANCE_NAME=legacy-acceptance',
                 '-v', str(data) + ':/app/data:ro', '-v', str(root / 'certificate-published') + ':/run/frontiercloud-tls:ro',
                 '-v', str(traffic) + ':/run/frontiercloud-traffic', '-p', '127.0.0.1::80', args.edge_image])
        edge_created = True
        inspected = json.loads(command(['docker', 'inspect', edge]))[0]
        port = inspected['NetworkSettings']['Ports']['80/tcp'][0]['HostPort']
        base = 'http://localhost:' + port
        wait_ready(base, host='localhost')
        _, request = api(base, host='localhost')
        media_id = probe(request, payload)
        command(['docker', 'stop', '--time', '30', name])
        # The old service is already stopped: its one-core/512-MiB budget is
        # never shared with a second Go database inspector during cold capture.
        frozen = subprocess.run(['docker', 'run', '--rm', *limits, *env, *mounts,
                                 args.source_image, 'maintenance', 'enter', '--wait-seconds', '120'], capture_output=True)
        report['source_freeze_exit_code'] = frozen.returncode
        diagnostic = root / 'private-maintenance.log'
        diagnostic.write_bytes(frozen.stdout + frozen.stderr)
        diagnostic.chmod(0o600)
        if frozen.returncode:
            raise RuntimeError('isolated legacy native maintenance proof failed')
        identity, generation, before = table_digest(data / 'node.sqlite')
        assert generation == 4
        key_proofs = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in secrets.iterdir() if p.is_file()}
        archive = root / 'cold-recovery.tar'
        with tarfile.open(archive, 'w') as backup:
            backup.add(data, arcname='data')
            backup.add(secrets, arcname='secrets')
        archive.chmod(0o600)
        backup_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
        target('prepare-release', '--from-generation', '4', '--confirm-generation', '7',
               '--confirm-node-id', identity, '--backup-sha256', backup_sha)
        after_id, after_generation, after = table_digest(data / 'node.sqlite')
        assert after_id == identity and after_generation == 7 and before == after
        assert key_proofs == {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in secrets.iterdir() if p.is_file()}
        assert (data / '.frontiercloud-native-maintenance').exists()
        target('maintenance', 'resume')
        command(['docker', 'rm', name])
        created = False
        command(['docker', 'run', '-d', '--name', name, '--network', network, '--network-alias', 'web', *limits, *env, *mounts,
                 '-v', str(args.target_binary.resolve()) + ':/fixture-frontiercloud:ro',
                 '--entrypoint', '/fixture-frontiercloud', args.target_image])
        created = True
        command(['docker', 'exec', edge, 'nginx', '-s', 'reload'])
        base = 'http://localhost:' + port
        wait_ready(base, host='localhost')
        _, request = api(base, host='localhost')
        assert probe(request, payload) == media_id
        report.update(status='passed', from_generation=4, target_generation=7,
                      node_identity_preserved=True, stable_table_digests_preserved=True,
                      source_secrets_preserved=True, cold_recovery_sha256=backup_sha,
                      offline_gate_kept_through_preparation=True,
                      media_id_and_actual_http_range_preserved=True, idle_cpu_samples=idle_cpu(name))
    except Exception as error:
        report['error_type'] = type(error).__name__
        raise
    finally:
        if created:
            inspected = json.loads(command(['docker', 'inspect', name]))[0]
            assert inspected['Config']['Labels']['frontiercloud.acceptance'] == name
            logs = subprocess.run(['docker', 'logs', name], capture_output=True)
            private = root / 'private-runtime.log'
            private.write_bytes(logs.stdout + logs.stderr)
            private.chmod(0o600)
            command(['docker', 'rm', '-f', name])
        if redis_created:
            inspected = json.loads(command(['docker', 'inspect', redis]))[0]
            assert inspected['Config']['Labels']['frontiercloud.acceptance'] == name
            command(['docker', 'rm', '-f', redis])
        if agent_created:
            inspected = json.loads(command(['docker', 'inspect', agent]))[0]
            assert inspected['Config']['Labels']['frontiercloud.acceptance'] == name
            command(['docker', 'rm', '-f', agent])
        if edge_created:
            inspected = json.loads(command(['docker', 'inspect', edge]))[0]
            assert inspected['Config']['Labels']['frontiercloud.acceptance'] == name
            logs = subprocess.run(['docker', 'logs', edge], capture_output=True)
            private = root / 'private-edge.log'
            private.write_bytes(logs.stdout + logs.stderr)
            private.chmod(0o600)
            command(['docker', 'rm', '-f', edge])
        if network_created:
            inspected = json.loads(command(['docker', 'network', 'inspect', network]))[0]
            assert inspected['Labels']['frontiercloud.acceptance'] == name and not inspected['Containers']
            command(['docker', 'network', 'rm', network])
        report['owned_container_removed'] = True
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
