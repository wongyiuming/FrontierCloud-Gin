"""Isolated compiled-fc guards and private native Install protocol acceptance.

The shipping fc executable is used unchanged for read-only doctor and rejected
installation attempts. Successful installation uses an opt-in Go test binary
with explicitly injected publication/image proofs and a private local CA. This
does NOT certify unpublished source as an approved public release. No production
trust switch is added. Owned fixtures are stopped; data and volumes survive the
removal of their stopped containers and empty networks for bounded subnet use.
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

SOURCE = Path(__file__).resolve().parents[1]
FILES = ('docker-compose.yaml', 'docker-compose.gin-mysql.yaml', 'docker-compose.storage.yaml')


def call(args, **kwargs):
    result = subprocess.run([str(arg) for arg in args], capture_output=True, text=True, **kwargs)
    if result.returncode:
        raise RuntimeError('private fixture command failed: ' + str(args[0]))
    return result.stdout


def tree(root):
    result = {}
    for path in root.rglob('*'):
        if path.is_symlink():
            result[str(path.relative_to(root))] = {'symlink': os.readlink(path)}
        elif path.is_file():
            result[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
        elif path.is_dir():
            result[str(path.relative_to(root)) + '/'] = 'directory'
    return result


def inventory(project):
    return {
        'containers': call(['docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project=' + project]).split(),
        'volumes': call(['docker', 'volume', 'ls', '-q', '--filter', 'label=com.docker.compose.project=' + project]).split(),
    }


def compose_command(directory, role, database):
    files = ['docker-compose.storage.yaml' if role == 'storage' else 'docker-compose.yaml']
    if database == 'mysql':
        files.append('docker-compose.gin-mysql.yaml')
    command = ['docker', 'compose', '--project-directory', str(directory)]
    for file in files:
        command += ['-f', str(directory / file)]
    return command


def compose(directory, role, database, *args):
    return call(compose_command(directory, role, database) + list(args))


def cleanup_case(directory):
    """Remove only stopped owned containers and empty project networks.

    Native data, named volumes, receipts and the captured test log survive.
    Docker logs can contain one-time pairing credentials and are never copied
    into ordinary acceptance reports.
    """
    directory = Path(directory)
    assert directory.resolve() == directory and directory.name.startswith('fc-ops-install-')
    assert directory.parent.name.startswith('fc-ops-install-suite-')
    spec = json.loads((directory / 'install-test-spec.json').read_text())
    assert spec['directory'] == str(directory)
    project = directory.name
    test_log = directory / 'install-test.log'
    assert test_log.is_file(), 'retain the captured test log before removing containers'
    before = inventory(project)
    states = []
    for ident in before['containers']:
        value = json.loads(call(['docker', 'inspect', ident]))[0]
        assert value['Config']['Labels']['com.docker.compose.project'] == project
        assert value['Config']['Labels']['com.docker.compose.project.working_dir'] == str(directory)
        assert not value['State']['Running'], 'an active fixture cannot be cleaned up'
        states.append({'id': value['Id'], 'service': value['Config']['Labels']['com.docker.compose.service'],
                       'image': value['Image'], 'status': value['State']['Status'], 'exit_code': value['State']['ExitCode']})
    receipt = directory / '.fc-deployment.json'
    receipt_hash = hashlib.sha256(receipt.read_bytes()).hexdigest() if receipt.is_file() else None
    command = compose_command(directory, spec['role'], spec['database'])
    for name in ('.fc-images.json', 'private-runtime.yaml'):
        if (directory / name).is_file():
            command += ['-f', str(directory / name)]
    call(command + ['rm', '-f'])  # Deliberately no -v: every native volume remains.
    networks = call(['docker', 'network', 'ls', '-q', '--filter', 'label=com.docker.compose.project=' + project]).split()
    removed = []
    for ident in networks:
        value = json.loads(call(['docker', 'network', 'inspect', ident]))[0]
        assert value['Labels']['com.docker.compose.project'] == project and not value['Containers']
        call(['docker', 'network', 'rm', ident])
        removed.append(value['Id'])
    after = inventory(project)
    assert not after['containers'] and sorted(after['volumes']) == sorted(before['volumes'])
    assert receipt_hash == (hashlib.sha256(receipt.read_bytes()).hexdigest() if receipt.is_file() else None)
    result = {'removed_stopped_containers': states, 'removed_empty_networks': removed,
              'named_volumes_retained': after['volumes'], 'receipt_sha256': receipt_hash,
              'test_log_sha256': hashlib.sha256(test_log.read_bytes()).hexdigest()}
    (directory / 'install-cleanup.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def new_case(work, name, role='master', database='sqlite', profile='business'):
    project = 'fc-ops-install-' + name + '-' + uuid.uuid4().hex[:10]
    directory = work / project
    directory.mkdir(mode=0o755)
    for file in FILES:
        shutil.copyfile(SOURCE / file, directory / file)
    environment = f'COMPOSE_PROJECT_NAME={project}\nDB_TYPE={database}\n'
    if role == 'storage':
        port = 8443 if profile == 'relay' else 443
        environment += (f'TLS_ENABLED=true\nSERVER_NAME=storage.fixture.test\n'
                        f'STORAGE_TRANSPORT={profile}\nSTORAGE_PORT={port}\n'
                        f'STORAGE_ENDPOINT=https://storage.fixture.test' + (':8443' if port == 8443 else '') + '\n')
    else:
        environment += 'TLS_ENABLED=false\nSERVER_NAME=localhost\n'
    (directory / '.env').write_text(environment)
    return directory, project


def driver(args, directory, spec, path_env):
    filename = directory / 'install-test-spec.json'
    filename.write_text(json.dumps(spec))
    completed = subprocess.run([str(args.operator_test_binary), '-test.v', '-test.timeout=9m',
                                '-test.run=^TestOperatorInstallComposeAcceptance$'],
                               env=dict(path_env, FRONTIERCLOUD_TEST_OPERATOR_INSTALL=str(filename)),
                               capture_output=True, text=True, timeout=550)
    (directory / 'install-test.log').write_text(completed.stdout + completed.stderr)
    assert completed.returncode == 0 and '--- PASS:' in completed.stdout and '--- SKIP:' not in completed.stdout, str(directory / 'install-test.log')
    return json.loads((directory / 'install-evidence.json').read_text())


def guards(args, work, path_env, image):
    results = []
    for name in ('dns', 'occupied-port', 'database', 'identity', 'changed-mount', 'project-drift', 'owned-volume'):
        directory, project = new_case(work, name)
        listener = None
        owned = []
        old_container = None
        volume_canary = None
        if name == 'dns':
            with (directory / '.env').open('a') as env:
                env.write('TLS_ENABLED=true\nSERVER_NAME=missing-install.fixture.invalid\n')
        elif name == 'occupied-port':
            listener = socket.socket()
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            # Use the real rendered Compose port inventory without taking a
            # production port. No container is started for this case.
            raw = compose(directory, 'master', 'sqlite', 'config', '--format', 'json')
            cfg = json.loads(raw)
            cfg['services']['nginx']['ports'] = [{'target': 80, 'published': str(listener.getsockname()[1]), 'protocol': 'tcp'}]
            (directory / 'docker-compose.yaml').write_text(json.dumps(cfg))
        elif name in ('database', 'identity', 'changed-mount'):
            data = directory / 'data'
            data.mkdir()
            (data / ('node-vault.key' if name == 'identity' else 'frontiercloud.db')).write_bytes(b'preserve-existing-installation-state\x00\xff')
            if name == 'changed-mount':
                with (directory / '.env').open('a') as env:
                    env.write('DATA_DIRECTORY=./new-empty-data\n')
        elif name == 'project-drift':
            # A stopped old project in this same working directory must not
            # be hidden by COMPOSE_PROJECT_NAME pointing at a new project.
            old = project + '-old'
            ident = call(['docker', 'create', '--network', 'none', '--name', old,
                          '--label', 'com.docker.compose.project=' + old,
                          '--label', 'com.docker.compose.project.working_dir=' + str(directory),
                          '--entrypoint', '/app/frontiercloud', image, '--help']).strip()
            detail = json.loads(call(['docker', 'inspect', ident]))[0]
            old_container = (ident, detail['Image'], detail['State'])
            owned.append({'container': ident, 'project': old})
        else:
            cfg = json.loads(compose(directory, 'master', 'sqlite', 'config', '--format', 'json'))
            volume = cfg['volumes']['runtime_secrets']['name']
            call(['docker', 'volume', 'create', '--label', 'com.docker.compose.project=' + project,
                  '--label', 'frontiercloud.acceptance=' + project, volume])
            detail = json.loads(call(['docker', 'volume', 'inspect', volume]))[0]
            assert detail['Name'] == volume and detail['Labels']['frontiercloud.acceptance'] == project
            volume_canary = Path(detail['Mountpoint']) / 'preserved-install-fixture'
            volume_canary.write_bytes(b'existing-volume-authoritative-state\x00\xff')
            owned.append({'volume': volume, 'project': project})
        before, resources = tree(directory), inventory(project)
        try:
            base = [str(args.binary), '--directory', str(directory), '--json']
            observed = subprocess.run(base + ['doctor'], env=path_env, capture_output=True, text=True, timeout=120)
            report = json.loads(observed.stdout)
            items = {value['item']: value for value in report['checks']}
            assert report['read_only'] and before == tree(directory) and resources == inventory(project)
            expected = 'dns' if name == 'dns' else 'ports' if name == 'occupied-port' else 'fresh_target'
            assert items[expected]['state'] == ('blocked' if name == 'dns' else 'warning'), report
            rejected = subprocess.run(base + ['install', 'master'], env=path_env, capture_output=True, text=True, timeout=120)
            assert rejected.returncode != 0 and before == tree(directory) and resources == inventory(project)
            result = {'case': name, 'compiled_fc_doctor_and_rejected_install': True,
                      'expected_observation': items[expected], 'doctor_report': report,
                      'state_and_resources_unchanged': True, 'host_compilers_on_path': False,
                      'shipping_install_success_claimed': False, 'retained_fixture_resources': owned}
            if name not in ('dns', 'occupied-port'):
                # Registry availability can prevent the shipping CLI reaching
                # Install itself. Independently exercise that exact protection
                # with real Docker and controlled proofs, before any pull/up.
                result['native_install_guard'] = driver(args, directory, {'directory': str(directory),
                    'role': 'master', 'database': 'sqlite', 'profile': 'business', 'case': 'guard'}, path_env)
                assert resources == inventory(project)
                for filename, digest in before.items():
                    assert tree(directory)[filename] == digest
            if old_container:
                detail = json.loads(call(['docker', 'inspect', old_container[0]]))[0]
                assert (detail['Id'], detail['Image'], detail['State']) == old_container
                result['old_project_container_unchanged'] = True
            if volume_canary:
                assert volume_canary.read_bytes() == b'existing-volume-authoritative-state\x00\xff'
                result['existing_volume_bytes_unchanged'] = True
            results.append(result)
        finally:
            if listener:
                listener.close()
    return results


def private_install(args, work, path_env, name, role, database, profile, case, web, edge):
    directory, project = new_case(work, name, role, database, profile)
    if role == 'master':
        with (directory / '.env').open('a') as env:
            env.write('TLS_ENABLED=true\nSERVER_NAME=business.fixture.test\n')
    control = directory / 'control'
    control.mkdir(mode=0o755)
    cfg = json.loads(compose(directory, role, database, 'config', '--format', 'json'))
    actual, mappings = {}, {}
    for name, service in cfg['services'].items():
        image = service['image']
        component = 'web' if 'frontiercloud-gin-web' in image else 'nginx' if 'frontiercloud-gin-nginx' in image else ''
        if component:
            concrete = web if component == 'web' else edge
            mappings['ghcr.io/wongyiuming/frontiercloud-gin-' + component + '@sha256:' + 'c' * 64] = concrete
        else:
            try:
                detail = json.loads(call(['docker', 'image', 'inspect', image]))[0]
            except RuntimeError:
                call(['docker', 'pull', image])
                detail = json.loads(call(['docker', 'image', 'inspect', image]))[0]
            concrete = detail['Id']
            mappings[image] = concrete
        actual[name] = concrete
    # The private overlay changes only test network/trust/image/resource limits.
    # Install's Config and receipt continue to bind the canonical Compose input.
    overlay = 'services:\n'
    for name, concrete in actual.items():
        overlay += f'  {name}:\n    image: {concrete}\n'
        if name == 'certificate-agent':
            overlay += ('    entrypoint: [/certificate.test]\n'
                        '    command: [-test.v, -test.timeout=13m, -test.run=^TestAutomaticTLSInstallFixture$]\n'
                        '    restart: "no"\n    network_mode: !reset null\n    networks: [default]\n'
                        f'    environment:\n      FRONTIERCLOUD_TEST_INSTALL_TLS_PROFILE: {profile}\n'
                        f'      FRONTIERCLOUD_TEST_INSTALL_CA_FAILURE: "{1 if case == "certificate-failure" else 0}"\n'
                        '    volumes:\n'
                        f'      - {args.certificate_test_binary}:/certificate.test:ro\n      - {control}:/fixture\n')
        if name == 'web':
            alias = 'business-web.fixture.test' if role == 'master' else 'storage.fixture.test'
            overlay += ('    cpus: 1\n    mem_limit: 512m\n    memswap_limit: 512m\n    ports: !reset []\n'
                        f'    networks:\n      default:\n        aliases: [{alias}]\n'
                        f'    volumes:\n      - {control / "ca.pem"}:/etc/ssl/certs/ca-certificates.crt:ro\n')
        if name == 'nginx':
            overlay += ('    ports: !reset []\n    networks:\n      default:\n        aliases: [business.fixture.test]\n'
                        f'    volumes:\n      - {control / "ca.pem"}:/etc/ssl/certs/ca-certificates.crt:ro\n')
        if name == 'stun':
            overlay += '    ports: !reset []\n'
        if name == 'mysql':
            overlay += ('    cpus: 1\n    mem_limit: 768m\n    memswap_limit: 768m\n'
                        '    command: [--skip-log-bin, --innodb-buffer-pool-size=64M, --performance-schema=OFF, --max-connections=64]\n')
    (directory / 'private-runtime.yaml').write_text(overlay)
    spec = {'directory': str(directory), 'role': role, 'database': database, 'profile': profile,
            'case': case, 'images': mappings}
    try:
        if case == 'pull-failure':
            # Reserve a TCP port without listening; Docker receives an actual
            # connection refusal, with no chance of contacting an external registry.
            with socket.socket() as unavailable:
                unavailable.bind(('127.0.0.1', 0))
                spec['pull_failure_image'] = f'127.0.0.1:{unavailable.getsockname()[1]}/fc-install-fixture:unavailable'
                result = driver(args, directory, spec, path_env)
        else:
            result = driver(args, directory, spec, path_env)
    finally:
        cleanup = cleanup_case(directory)
    result['fixture_directory'] = str(directory)
    result['retained_resources'] = inventory(project)
    result['cleanup'] = cleanup
    assert not call(['docker', 'ps', '-q', '--filter', 'label=com.docker.compose.project=' + project]).strip(), 'fixture was not stopped'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'operator-test-binary', 'certificate-test-binary', 'workspace', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--edge-image', required=True)
    parser.add_argument('--guards-only', action='store_true')
    parser.add_argument('--skip-guards', action='store_true')
    parser.add_argument('--private-cases', nargs='+', choices=('master-sqlite', 'master-mysql', 'direct', 'relay', 'pull-failure', 'certificate-failure'))
    args = parser.parse_args()
    assert os.geteuid() == 0 and os.name == 'posix', 'isolated root Linux Docker development host required'
    for name in ('binary', 'operator_test_binary', 'certificate_test_binary', 'workspace', 'output'):
        setattr(args, name, getattr(args, name).resolve())
    args.workspace.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='fc-ops-install-suite-', dir=args.workspace))
    os.chmod(work, 0o755)
    bin_dir = work / 'host-tools'
    bin_dir.mkdir()
    (bin_dir / 'docker').symlink_to(Path(shutil.which('docker')).resolve())
    path_env = dict(os.environ, PATH=str(bin_dir))
    assert all(shutil.which(name, path=str(bin_dir)) is None for name in ('go', 'node', 'nodejs', 'python', 'python3', 'gcc', 'cc'))
    web = json.loads(call(['docker', 'image', 'inspect', args.image]))[0]['Id']
    edge = json.loads(call(['docker', 'image', 'inspect', args.edge_image]))[0]['Id']
    result = {'scope': 'compiled shipping fc early guards and private real-Docker Install protocol',
              'public_release_first_installation_verified': False, 'workspace': str(work),
              'successful_installation_driver_has_test_only_publication_and_local_ca': True,
              'selected_private_cases': args.private_cases, 'guards_requested': not args.skip_guards}
    try:
        if not args.skip_guards:
            result['guards'] = guards(args, work, path_env, web)
        if not args.guards_only:
            result['private_installations'] = []
            for name, role, database, profile, case in (
                ('master-sqlite', 'master', 'sqlite', 'business', 'success'),
                ('master-mysql', 'master', 'mysql', 'business', 'success'),
                ('direct', 'storage', 'sqlite', 'direct', 'success'),
                ('relay', 'storage', 'sqlite', 'relay', 'success'),
                ('pull-failure', 'storage', 'sqlite', 'direct', 'pull-failure'),
                ('certificate-failure', 'storage', 'sqlite', 'relay', 'certificate-failure')):
                if args.private_cases and name not in args.private_cases:
                    continue
                result['private_installations'].append(private_install(args, work, path_env, name, role, database, profile, case, web, edge))
        result['passed'] = True
    finally:
        args.output.write_text(json.dumps(result, indent=2) + '\n')
    print('PASS: compiled fc guards and private native installation protocol; public release installation remains unclaimed')


if __name__ == '__main__':
    main()
