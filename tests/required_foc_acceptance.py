"""Development-only default Compose/global foc acceptance inside an isolated Engine.

The outer fixture supplies a disposable Docker-in-Docker node and prebuilt images.
No published host ports or production target are used. Private TLS cases inject
release proof only through the existing compiled Go test, never a shipping bypass.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP_REVISION = '1ce61b545727a19059a7ba82eb8bd45a9c93aa14'
BOOTSTRAP_IMAGE = 'ghcr.io/wongyiuming/frontiercloud-gin-web@sha256:8101bf3e423648ed4f1c2a29e671286a6391963ef562f55be4579476d45779de'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('node', 'workspace', 'revision', 'image', 'edge-image', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    work = Path(args.workspace).resolve()
    assert work.name.startswith('foc-required-fixtures-') and not work.exists()
    work.mkdir()
    records = []
    result = {'candidate_revision': args.revision, 'production_accessed': False,
              'host_installation_isolated_in_dind': args.node, 'cases': [], 'inputs': records}

    def save():
        Path(args.output).write_text(json.dumps(result, indent=2) + '\n')

    def execute(argv, allowed=(0,), env=None):
        record = {'argv': [str(x) for x in argv]}
        records.append(record)
        completed = subprocess.run(record['argv'], capture_output=True, text=True, env=env, timeout=240)
        record['exit_code'] = completed.returncode
        # Keep command inputs and bounded structured facts, never container logs/secrets.
        record['stdout_sha256'] = hashlib.sha256(completed.stdout.encode()).hexdigest()
        record['stderr_sha256'] = hashlib.sha256(completed.stderr.encode()).hexdigest()
        save()
        if completed.returncode not in allowed:
            (work / 'failed-command.txt').write_text(completed.stdout + completed.stderr)
            raise RuntimeError('fixture input failed: ' + ' '.join(record['argv']) + '\n' + completed.stderr[-2000:])
        return completed.stdout

    def inner(*argv, allowed=(0,)):
        return execute(['docker', 'exec', args.node, *argv], allowed=allowed)

    def engine(*argv):
        return inner('docker', *argv)

    def compose(directory, filename, *argv):
        return engine('compose', '--project-directory', str(directory), '-f', str(directory / filename), *argv)

    def wait_file(path, limit=90):
        deadline = time.monotonic() + limit
        while time.monotonic() < deadline:
            if path.is_file():
                return
            time.sleep(.25)
        raise RuntimeError('private TLS fixture marker timed out: ' + path.name)

    def image_id(name):
        return json.loads(engine('image', 'inspect', '--format', '{{json .Id}}', name))

    def node_identity(status):
        line = next(x['reason'] for x in status['checks'] if x['item'] == 'database_generation')
        return line.split(';')[0]

    def status(directory):
        # Absolute-directory selection is necessary while several fixtures coexist.
        data = inner('sh', '-lc', 'cd /; foc --directory ' + str(directory) + ' --json status', allowed=(0, 3))
        facts = json.loads(data)
        assert all(x['state'] == 'pass' or x['item'] == 'business_read' and x['state'] == 'unverified' for x in facts['checks']), facts
        return facts

    # Real published bytes, no release-proof injection or extra runtime overrides.
    case = work / 'public-master'
    case.mkdir()
    shutil.copyfile(ROOT / 'docker-compose.yaml', case / 'docker-compose.yaml')
    (case / '.env').write_text('COMPOSE_PROJECT_NAME=foc-required-public-master\nFRONTIERCLOUD_REVISION=' + BOOTSTRAP_REVISION + '\n')
    compose(case, 'docker-compose.yaml', 'up', '-d', '--pull', 'never', '--wait', '--wait-timeout', '90')
    assert inner('sh', '-lc', 'cd /; command -v foc').strip() == '/usr/local/bin/foc'
    raw = inner('sh', '-lc', 'cd /; foc --json status', allowed=(0, 3))
    before = json.loads(raw)
    assert all(x['state'] == 'pass' or x['item'] == 'business_read' for x in before['checks']), before
    assert (case / '.fc-deployment.json').is_file()
    first = inner('sha256sum', '/usr/local/lib/frontiercloud/foc/fc').split()[0]
    compose(case, 'docker-compose.yaml', 'up', '-d', '--pull', 'never', '--wait', '--wait-timeout', '90')
    assert first == inner('sha256sum', '/usr/local/lib/frontiercloud/foc/fc').split()[0]
    assert node_identity(before) == node_identity(status(case))
    result['cases'].append({'case': 'published-default-master', 'actual_input': 'docker compose up -d --pull never --wait',
                            'public_release_proof_injected': False, 'global_status_from_root': True,
                            'metadata_registration_executed': True, 'repeat_preserved_backend_and_identity': True})

    # Refresh to the candidate through its actual Compose installer, then repeat
    # older default bootstrap: it must not downgrade a different managed backend.
    env = ['-e', 'FOC_OPERATOR_IMAGE=' + args.image, '-e', 'FOC_OPERATOR_REVISION=' + args.revision,
           '-e', 'FOC_DEPLOYMENT_DIRECTORY=' + str(case), '-e', 'FOC_OPERATOR_PULL_POLICY=never']
    execute(['docker', 'exec', *env, args.node, 'docker', 'compose', '-f', str(ROOT / 'compose.foc.yaml'), 'run', '--rm', '--no-deps', 'install'])
    assert inner('foc', 'version').strip() == args.revision
    compose(case, 'docker-compose.yaml', 'up', '-d', '--pull', 'never', '--wait', '--wait-timeout', '90')
    assert inner('foc', 'version').strip() == args.revision
    result['cases'].append({'case': 'candidate-refresh-and-repeat', 'candidate_installer_real': True,
                            'older_bootstrap_did_not_downgrade': True, 'public_candidate_proof_claimed': False})
    compose(case, 'docker-compose.yaml', 'stop')

    for profile, database in (('business', 'sqlite'), ('business', 'mysql'), ('direct', 'sqlite'), ('relay', 'sqlite')):
        name = profile + '-' + database
        print('START', name, flush=True)
        directory = work / name
        directory.mkdir()
        control = directory / 'control'
        control.mkdir()
        (control / 'ca.pem').touch()
        filename = 'docker-compose.yaml' if profile == 'business' else 'docker-compose.storage.yaml'
        shutil.copyfile(ROOT / filename, directory / filename)
        shutil.copyfile(ROOT / 'docker-compose.gin-mysql.yaml', directory / 'docker-compose.gin-mysql.yaml')
        domain = 'business.fixture.test' if profile == 'business' else 'storage.fixture.test'
        port = 8443 if profile == 'relay' else 443
        (directory / '.env').write_text('COMPOSE_PROJECT_NAME=foc-required-' + name + '\nTLS_ENABLED=true\nSERVER_NAME=' + domain + '\nDB_TYPE=' + database + '\nSTORAGE_TRANSPORT=' + profile + '\nSTORAGE_PORT=' + str(port) + '\nSTORAGE_ENDPOINT=https://' + domain + (':8443' if port == 8443 else '') + '\n')
        command = ['compose', '--project-directory', str(directory), '-f', str(directory / filename)]
        if database == 'mysql':
            command += ['-f', str(directory / 'docker-compose.gin-mysql.yaml')]
        cfg = json.loads(engine(*command, 'config', '--format', 'json'))
        for service, spec in cfg['services'].items():
            image = spec['image']
            if service != 'foc-host-init' and 'frontiercloud-gin-web' in image:
                spec['image'] = args.image
            elif 'frontiercloud-gin-nginx' in image:
                spec['image'] = args.edge_image
        agent = cfg['services']['certificate-agent']
        agent.pop('network_mode', None)
        agent['networks'] = {'default': {}}
        agent['entrypoint'] = ['/certificate.test']
        agent['command'] = ['-test.v', '-test.timeout=10m', '-test.run=^TestAutomaticTLSInstallFixture$']
        agent['environment']['FRONTIERCLOUD_TEST_INSTALL_TLS_PROFILE'] = profile
        agent['volumes'] += [{'type': 'bind', 'source': str(ROOT / '.ci-out/certificate.test'), 'target': '/certificate.test', 'read_only': True},
                             {'type': 'bind', 'source': str(control), 'target': '/fixture'}]
        web = cfg['services']['web']
        web['cpus'], web['mem_limit'], web['memswap_limit'] = 1, '512m', '512m'
        web['networks'] = {'default': {'aliases': ['business-web.fixture.test' if profile == 'business' else domain]}}
        consumers = ['web', 'nginx'] if profile == 'business' else ['web']
        for consumer in consumers:
            cfg['services'][consumer].setdefault('volumes', []).append({'type': 'bind', 'source': str(control / 'ca.pem'), 'target': '/etc/ssl/certs/ca-certificates.crt', 'read_only': True})
        if profile == 'business':
            cfg['services']['nginx']['networks'] = {'default': {'aliases': [domain]}}
        # Fold private CA and image substitutions into the canonical fixture file
        # so registration still verifies the exact selected Compose-file roster.
        if database == 'mysql':
            cfg['services']['mysql'].update(cpus=1, mem_limit='768m', memswap_limit='768m')
            (directory / 'docker-compose.gin-mysql.yaml').write_text('{}\n')
        (directory / filename).write_text(json.dumps(cfg))
        engine(*command, 'up', '-d', '--pull', 'never', 'certificate-agent')
        wait_file(control / 'ca-ready')
        engine(*command, 'up', '-d', '--pull', 'never', '--wait', '--wait-timeout', '90')
        spec = {'directory': str(directory), 'role': 'master' if profile == 'business' else 'storage', 'database': database,
                'installer_revision': BOOTSTRAP_REVISION, 'config_digests': {'web': image_id(args.image), 'nginx': image_id(args.edge_image), 'installer': image_id(BOOTSTRAP_IMAGE)}}
        specfile = directory / 'registration-spec.json'
        specfile.write_text(json.dumps(spec))
        execute(['docker', 'exec', '-e', 'FC_COMPOSE_REGISTRATION_SPEC=' + str(specfile), args.node,
                 str(ROOT / '.ci-out/operator.test'), '-test.v', '-test.timeout=4m', '-test.run=^TestNativeDefaultComposeRegistersGlobalFoc$'])
        before = status(directory)
        certificate = json.loads(engine(*command, 'exec', '-T', 'web', '/app/frontiercloud', 'certificate-status'))
        assert certificate['https_ready'] and certificate['serving_matches'], certificate
        engine(*command, 'up', '-d', '--pull', 'never', '--wait', '--wait-timeout', '90')
        assert node_identity(before) == node_identity(status(directory))
        assert inner('foc', 'version').strip() == args.revision
        result['cases'].append({'case': name, 'normal_required_installer_executed': True,
                                'real_native_identity_and_database': True, 'private_ca_https_verified': True,
                                'serving_fingerprint_matches': True, 'registration_and_global_status': True,
                                'repeat_preserved_identity_and_newer_backend': True,
                                'publication_proof_injected_for_candidate': True, 'trust_bypass': False})
        engine(*command, 'stop')
        save()
        print('PASS', name, flush=True)

    # A foreign command must fail before any native initializer creates identity.
    directory = work / 'collision'
    directory.mkdir()
    shutil.copyfile(ROOT / 'docker-compose.yaml', directory / 'docker-compose.yaml')
    (directory / '.env').write_text('COMPOSE_PROJECT_NAME=foc-required-collision\nFRONTIERCLOUD_REVISION=' + BOOTSTRAP_REVISION + '\n')
    inner('cp', '/usr/local/bin/foc', '/root/foc-before-collision')
    inner('sh', '-ec', "printf '#!/bin/sh\\nexit 0\\n' > /usr/local/bin/foc")
    before = inner('sha256sum', '/usr/local/bin/foc').split()[0]
    execute(['docker', 'exec', args.node, 'docker', 'compose', '--project-directory', str(directory), '-f', str(directory / 'docker-compose.yaml'), 'up', '-d', '--pull', 'never', '--wait', '--wait-timeout', '30'], allowed=(1,))
    assert before == inner('sha256sum', '/usr/local/bin/foc').split()[0]
    assert not (directory / 'data/node-vault.key').exists()
    raw = compose(directory, 'docker-compose.yaml', 'ps', '--all', '--format', 'json')
    try:
        services = json.loads(raw)
    except json.JSONDecodeError:
        services = [json.loads(line) for line in raw.splitlines() if line.strip()]
    if isinstance(services, dict):
        services = [services]
    assert all(row['State'] != 'running' for row in services if row['Service'] in ('web', 'secrets-init', 'media-init', 'certificate-init'))
    inner('cp', '/root/foc-before-collision', '/usr/local/bin/foc')
    result['cases'].append({'case': 'foreign-command-collision', 'startup_refused': True, 'foreign_command_unchanged': True,
                            'native_initializers_not_started': True})
    result['passed'] = True
    save()
    print('PASS: required Compose installation, global status, all profiles, retry and collision', flush=True)


if __name__ == '__main__':
    main()
