"""Development-only optional foc and independent Compose acceptance in an isolated Engine.

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
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP_REVISION = '1ce61b545727a19059a7ba82eb8bd45a9c93aa14'
BOOTSTRAP_IMAGE = 'ghcr.io/wongyiuming/frontiercloud-gin-web@sha256:8101bf3e423648ed4f1c2a29e671286a6391963ef562f55be4579476d45779de'
ACTIVE_COMMANDS = []
CLEANUP_OUTPUT = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('node', 'workspace', 'revision', 'image', 'edge-image', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    global CLEANUP_OUTPUT
    CLEANUP_OUTPUT = Path(args.output)
    work = Path(args.workspace).resolve()
    assert work.name.startswith('foc-required-fixtures-') and not work.exists()
    work.mkdir()
    records = []
    result = {'candidate_revision': args.revision, 'production_accessed': False,
              'host_installation_isolated_in_dind': args.node, 'cases': [], 'inputs': records}

    def save():
        Path(args.output).write_text(json.dumps(result, indent=2) + '\n')

    def execute(argv, allowed=(0,), env=None, timeout=240):
        record = {'argv': [str(x) for x in argv]}
        records.append(record)
        try:
            completed = subprocess.run(record['argv'], capture_output=True, text=True, env=env, timeout=timeout)
        except subprocess.TimeoutExpired:
            record.update(exit_code=None, timed_out=True)
            save()
            raise RuntimeError('fixture input timed out: ' + ' '.join(record['argv'])) from None
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

    def native_identity(command):
        value = json.loads(engine(*command, 'exec', '-T', 'web', '/app/frontiercloud', 'operator-status'))
        assert value['node_id'] and not value['maintenance'], value
        return value['node_id']

    def healthy(command, tls=False):
        engine(*command, 'exec', '-T', 'web', '/app/frontiercloud', 'healthcheck')
        if tls:
            certificate = json.loads(engine(*command, 'exec', '-T', 'web', '/app/frontiercloud', 'certificate-status'))
            assert certificate['https_ready'] and certificate['serving_matches'], certificate
            assert certificate['fingerprint'] == certificate['serving_fingerprint'], certificate
            return certificate['fingerprint']

    def no_operator(directory, command):
        inner('sh', '-ec', 'test ! -e /usr/local/bin/foc; test ! -e /usr/local/lib/frontiercloud/foc; '
              'test ! -e /etc/frontiercloud/foc-deployments')
        assert not (directory / '.fc-deployment.json').exists()
        configuration = json.loads(engine(*command, 'config', '--format', 'json'))
        assert 'foc-host-init' not in configuration['services']
        containers = engine('ps', '--all', '--filter', 'label=com.docker.compose.project=' + configuration['name'],
                            '--format', '{{.Label "com.docker.compose.service"}}').splitlines()
        assert 'foc-host-init' not in containers

    def cpu_recovered(command):
        container = engine(*command, 'ps', '-q', 'web').strip()
        assert container and '\n' not in container
        limits = json.loads(engine('inspect', '--format', '{{json .HostConfig}}', container))
        assert limits['NanoCpus'] == 1000000000 and limits['Memory'] == 512 * 1024 * 1024
        result.setdefault('web_limits', []).append({'container': container,
                                                    'nano_cpus': limits['NanoCpus'], 'memory_bytes': limits['Memory']})
        samples, consecutive = [], 0
        started = time.monotonic()
        deadline = started + 30
        while time.monotonic() < deadline:
            raw = execute(['docker', 'exec', args.node, 'docker', 'stats', '--no-stream',
                           '--format', '{{.CPUPerc}}', container],
                          timeout=min(5, max(.1, deadline - time.monotonic()))).strip()
            value = float(raw.removesuffix('%'))
            samples.append({'elapsed_seconds': round(time.monotonic() - started, 3), 'cpu_percent': value})
            consecutive = consecutive + 1 if value < 20 else 0
            if consecutive == 5 and time.monotonic() <= deadline:
                return samples
            time.sleep(1)
        # Stop the affected Web before reporting a compute-caused failure.
        engine(*command, 'stop', 'web')
        result['cpu_failure_samples'] = samples
        save()
        raise RuntimeError('Web failed one-core CPU recovery acceptance')

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

    # Real published bytes, no release-proof injection. The development-only
    # resource overlay bounds Web to the same one-core acceptance budget.
    case = work / 'public-master'
    case.mkdir()
    shutil.copyfile(ROOT / 'docker-compose.yaml', case / 'docker-compose.yaml')
    (case / '.env').write_text('COMPOSE_PROJECT_NAME=foc-required-public-master\nFRONTIERCLOUD_REVISION=' + BOOTSTRAP_REVISION + '\n')
    resources = case / 'resources.json'
    resources.write_text(json.dumps({'services': {'web': {'cpus': 1, 'mem_limit': '512m', 'memswap_limit': '512m'}}}))
    public_command = ['compose', '--project-directory', str(case), '-f', str(case / 'docker-compose.yaml'), '-f', str(resources)]
    ACTIVE_COMMANDS.append((args.node, public_command))
    no_operator(case, public_command)
    engine(*public_command, 'up', '-d', '--pull', 'never', '--wait', '--wait-timeout', '90')
    healthy(public_command)
    public_identity = native_identity(public_command)
    no_operator(case, public_command)
    engine(*public_command, 'up', '-d', '--pull', 'never', '--wait', '--wait-timeout', '90')
    healthy(public_command)
    assert public_identity == native_identity(public_command)
    no_operator(case, public_command)
    result['cases'].append({'case': 'published-default-master', 'actual_input': 'docker compose up -d --pull never --wait',
                            'public_business_bytes': True, 'publication_proof_injected': False,
                            'development_only_resource_limits': True,
                            'operator_installed': False, 'receipt_created': False,
                            'default_repeat_preserved_identity': True,
                            'cpu_percent_samples': cpu_recovered(public_command)})
    engine(*public_command, 'stop')

    candidate_alias = 'ghcr.io/wongyiuming/frontiercloud-gin-web:' + args.revision
    # Only this private Engine supplies the candidate alias; its release proof
    # remains injected by the compiled test and is never claimed as publication.
    engine('image', 'tag', args.image, candidate_alias)

    fixtures = []
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
        cfg = json.loads(engine(*command, '--profile', 'operator', 'config', '--format', 'json'))
        for service, spec in cfg['services'].items():
            # Dedicated private networks permit all fresh profiles to remain
            # idle until every profile has proved startup without a host tool.
            spec.pop('ports', None)
            image = spec['image']
            if service != 'foc-host-init' and 'frontiercloud-gin-web' in image:
                spec['image'] = candidate_alias
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
        ACTIVE_COMMANDS.append((args.node, command))
        engine(*command, 'up', '-d', '--pull', 'never', 'certificate-agent')
        wait_file(control / 'ca-ready')
        engine(*command, 'up', '-d', '--pull', 'never', '--wait', '--wait-timeout', '90')
        wait_file(control / 'issued-and-serving')
        no_operator(directory, command)
        identity = native_identity(command)
        fingerprint = healthy(command, tls=True)
        result['cases'].append({'case': name + '-without-operator', 'normal_up_without_foc': True,
                                'registry_created': False, 'receipt_created': False, 'installer_container_created': False,
                                'real_native_identity_and_database': True, 'private_ca_https_verified': True,
                                'serving_fingerprint_matches': True, 'publication_proof_injected': False,
                                'candidate_publication_claimed': False, 'trust_bypass': False,
                                'cpu_percent_samples': cpu_recovered(command)})
        fixtures.append((name, directory, command, identity, fingerprint))
        save()

    # Only after every runtime topology has proved fresh startup independently,
    # register the running private candidate through the compiled proof fixture.
    for name, directory, command, identity, fingerprint in fixtures:
        database = 'mysql' if name == 'business-mysql' else 'sqlite'
        spec = {'directory': str(directory), 'role': 'master' if name.startswith('business-') else 'storage', 'database': database,
                'installer_revision': BOOTSTRAP_REVISION, 'config_digests': {'web': image_id(args.image), 'nginx': image_id(args.edge_image), 'installer': image_id(BOOTSTRAP_IMAGE)}}
        specfile = directory / 'registration-spec.json'
        specfile.write_text(json.dumps(spec))
        execute(['docker', 'exec', '-e', 'FC_COMPOSE_REGISTRATION_SPEC=' + str(specfile), args.node,
                 str(ROOT / '.ci-out/operator.test'), '-test.v', '-test.timeout=4m', '-test.run=^TestNativeDefaultComposeRegistersGlobalFoc$'])
        # The separate installer consumes an existing verified receipt; no
        # candidate publication is inferred from this isolated test image.
        env = ['-e', 'FOC_OPERATOR_IMAGE=' + args.image, '-e', 'FOC_OPERATOR_REVISION=' + args.revision,
               '-e', 'FOC_DEPLOYMENT_DIRECTORY=' + str(directory), '-e', 'FOC_OPERATOR_PULL_POLICY=never']
        execute(['docker', 'exec', *env, args.node, 'docker', 'compose', '-f', str(ROOT / 'deploy/compose.foc.yaml'),
                 'run', '--rm', '--no-deps', 'install'])
        assert inner('foc', 'version').strip() == args.revision
        engine(*command, '--profile', 'operator', 'run', '--rm', '--no-deps', 'foc-host-init')
        assert inner('foc', 'version').strip() == args.revision
        before = status(directory)
        assert native_identity(command) == identity
        assert healthy(command, tls=True) == fingerprint
        failure = directory / 'installer-failure.json'
        failure.write_text(json.dumps({'services': {'foc-host-init': {
            'entrypoint': ['/bin/sh', '-ec', 'exit 1'], 'command': []}}}))
        execute(['docker', 'exec', args.node, 'docker', *command, '-f', str(failure), '--profile', 'operator',
                 'run', '--rm', '--no-deps', 'foc-host-init'], allowed=(1,))
        assert native_identity(command) == identity
        assert healthy(command, tls=True) == fingerprint
        engine(*command, 'up', '-d', '--pull', 'never', '--wait', '--wait-timeout', '90')
        assert node_identity(before) == node_identity(status(directory))
        assert inner('foc', 'version').strip() == args.revision
        result['cases'].append({'case': name + '-optional-operator', 'installer_explicitly_selected': True,
                                'failing_installer_exit_code': 1, 'failure_preserved_identity_and_tls': True,
                                'real_native_identity_and_database': True, 'private_ca_https_verified': True,
                                'serving_fingerprint_matches': True, 'registration_and_global_status': True,
                                'repeat_preserved_identity_and_newer_backend': True,
                                'publication_proof_injected_for_candidate': True, 'trust_bypass': False,
                                'cpu_percent_samples': cpu_recovered(command)})
        engine(*command, 'stop')
        save()
        print('PASS', name, flush=True)

    # A foreign host command refuses explicit installation, while the ordinary
    # business deployment keeps operating with the same native identity.
    directory = work / 'collision'
    directory.mkdir()
    shutil.copyfile(ROOT / 'docker-compose.yaml', directory / 'docker-compose.yaml')
    (directory / '.env').write_text('COMPOSE_PROJECT_NAME=foc-required-collision\nFRONTIERCLOUD_REVISION=' + BOOTSTRAP_REVISION + '\n')
    inner('cp', '/usr/local/bin/foc', '/root/foc-before-collision')
    inner('sh', '-ec', "printf '#!/bin/sh\\nexit 0\\n' > /usr/local/bin/foc")
    before = inner('sha256sum', '/usr/local/bin/foc').split()[0]
    resources = directory / 'resources.json'
    resources.write_text(json.dumps({'services': {'web': {'cpus': 1, 'mem_limit': '512m', 'memswap_limit': '512m'}}}))
    collision_command = ['compose', '--project-directory', str(directory), '-f', str(directory / 'docker-compose.yaml'), '-f', str(resources)]
    ACTIVE_COMMANDS.append((args.node, collision_command))
    engine(*collision_command, 'up', '-d', '--pull', 'never', '--wait', '--wait-timeout', '90')
    healthy(collision_command)
    identity = native_identity(collision_command)
    execute(['docker', 'exec', args.node, 'docker', *collision_command, '--profile', 'operator',
             'run', '--rm', '--no-deps', 'foc-host-init'], allowed=(2,))
    assert before == inner('sha256sum', '/usr/local/bin/foc').split()[0]
    healthy(collision_command)
    assert identity == native_identity(collision_command)
    inner('cp', '/root/foc-before-collision', '/usr/local/bin/foc')
    result['cases'].append({'case': 'foreign-command-collision', 'business_startup_succeeded': True,
                            'explicit_installer_refused': True, 'foreign_command_unchanged': True,
                            'native_identity_preserved': True, 'cpu_percent_samples': cpu_recovered(collision_command)})
    engine(*collision_command, 'stop')
    result['passed'] = True
    save()
    print('PASS: independent default Compose, optional operator, all profiles, TLS and installer failure isolation', flush=True)


if __name__ == '__main__':
    try:
        main()
    finally:
        cleanup = []
        failed = sys.exc_info()[0] is not None
        for node, command in reversed(ACTIVE_COMMANDS):
            # Failure handling stops Web before other cleanup, including an
            # assertion failure outside the subprocess helper.
            steps = [('stop', 'web'), ('stop',)] if failed else [('stop',)]
            for step in steps:
                argv = ['docker', 'exec', node, 'docker', *command, *step]
                try:
                    completed = subprocess.run(argv, capture_output=True, text=True, timeout=60)
                    cleanup.append({'argv': argv, 'exit_code': completed.returncode})
                except (OSError, subprocess.TimeoutExpired):
                    cleanup.append({'argv': argv, 'exit_code': None})
        if CLEANUP_OUTPUT is not None and CLEANUP_OUTPUT.exists():
            facts = json.loads(CLEANUP_OUTPUT.read_text())
            facts['finally_cleanup'] = cleanup
            facts['cleanup_passed'] = all(item['exit_code'] == 0 for item in cleanup)
            if not facts['cleanup_passed']:
                facts['passed'] = False
            CLEANUP_OUTPUT.write_text(json.dumps(facts, indent=2) + '\n')
        if not failed and any(item['exit_code'] != 0 for item in cleanup):
            raise RuntimeError('isolated Compose cleanup failed; stop the outer disposable Engine')
