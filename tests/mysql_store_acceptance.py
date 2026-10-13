"""Owned development-only MySQL store/schema race acceptance.

No published or deployed database is selected. Each call creates a fresh private
server and retains its bind-mounted data and secrets for diagnostics.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import uuid


def run(options):
    if os.geteuid() != 0:
        raise RuntimeError('isolated root Linux development host required')
    root = Path.cwd().resolve()
    options.output.mkdir(parents=True, exist_ok=True)
    project = 'fc-mysql-final-' + str(uuid.uuid4())
    # Honor TMPDIR so retained MySQL data need not consume a host tmpfs.
    work = Path(tempfile.mkdtemp(prefix='fc-mysql-final-'))
    (work / 'secrets').mkdir(mode=0o700)
    (work / 'data').mkdir(mode=0o700)
    password = secrets.token_urlsafe(32)
    (work / 'secrets' / 'password').write_text(password + '\n')
    (work / 'secrets' / 'client.cnf').write_text('[client]\nuser=root\npassword=' + password + '\nhost=127.0.0.1\n')
    for path in (work / 'secrets').iterdir():
        path.chmod(0o600)
    name, network = project + '-mysql', project + '-network'
    prefix = uuid.uuid4().hex[:12] + '_'
    result = {'status': 'running', 'project': project, 'workspace': str(work),
              'large_migration_selected': options.large, 'mysql_memory_bytes': 768 << 20,
              'mysql_cpus': 1, 'data_retained': True}

    def command(arguments):
        value = subprocess.run(arguments, capture_output=True, timeout=120)
        if value.returncode:
            raise RuntimeError('owned MySQL fixture operation failed')
        return value.stdout

    try:
        command(['docker', 'network', 'create', '--label', 'frontiercloud.acceptance=' + project, network])
        command(['docker', 'run', '-d', '--name', name, '--label', 'frontiercloud.acceptance=' + project,
                 '--network', network, '--network-alias', 'mysql', '--memory=768m', '--memory-swap=768m', '--cpus=1',
                 '-v', str(work / 'data') + ':/var/lib/mysql', '-v', str(work / 'secrets') + ':/run/frontiercloud-secrets:ro',
                 '-e', 'MYSQL_DATABASE=fc_business', '-e', 'MYSQL_ROOT_PASSWORD_FILE=/run/frontiercloud-secrets/password',
                 '-e', 'MYSQL_ROOT_HOST=%', 'mysql:8.4.11', '--skip-log-bin', '--innodb-buffer-pool-size=64M',
                 '--performance-schema=OFF', '--max-connections=64', '--table-open-cache=128',
                 '--table-open-cache-instances=1', '--table-definition-cache=400'])
        client = ['docker', 'exec', name, 'mysql', '--defaults-extra-file=/run/frontiercloud-secrets/client.cnf']
        for attempt in range(90):
            ready = subprocess.run(client + ['-N', '-e', 'SELECT 1'], capture_output=True, timeout=10)
            if ready.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError('owned MySQL fixture did not become ready')
        for suffix in ('preserve', 'interrupted', 'bindingspreserve', 'bindingsinterrupted', 'planspreserve', 'plansinterrupted'):
            command(client + ['-e', 'CREATE DATABASE `fc_schema_' + prefix + suffix + '` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci'])
        environment = {'GOMAXPROCS': '2', 'GOMEMLIMIT': '512MiB', 'GOGC': '25',
                       'FRONTIERCLOUD_TEST_MYSQL_HOST': 'mysql', 'FRONTIERCLOUD_TEST_MYSQL_DATABASE': 'fc_business',
                       'FRONTIERCLOUD_TEST_MYSQL_USER': 'root', 'FRONTIERCLOUD_TEST_MYSQL_DATABASE_PREFIX': 'fc_test_' + prefix,
                       'FRONTIERCLOUD_TEST_MYSQL_PASSWORD_FILE': '/run/frontiercloud-secrets/password',
                       'FRONTIERCLOUD_SCHEMA_TEST_MYSQL_HOST': 'mysql', 'FRONTIERCLOUD_SCHEMA_TEST_MYSQL_USER': 'root',
                       'FRONTIERCLOUD_SCHEMA_TEST_MYSQL_DATABASE_PREFIX': 'fc_schema_' + prefix,
                       'FRONTIERCLOUD_SCHEMA_TEST_MYSQL_PASSWORD_FILE': '/run/frontiercloud-secrets/password'}
        if options.large:
            environment['FRONTIERCLOUD_TEST_LARGE_MIGRATION'] = '1'
        arguments = ['docker', 'run', '--rm', '--network', network, '--label', 'frontiercloud.acceptance=' + project,
                     '--cpus=2', '--memory=3g', '--memory-swap=3g', '-v', str(root) + ':/workspace',
                     '-v', str(root.parent / 'modcache') + ':/go/pkg/mod', '-v', str(root.parent / 'buildcache') + ':/root/.cache/go-build',
                     '-v', str(work / 'secrets') + ':/run/frontiercloud-secrets:ro', '-w', '/workspace']
        for key, value in environment.items():
            arguments += ['-e', key + '=' + value]
        arguments += ['golang:1.26.8-bookworm', 'go', 'test', '-race', '-count=1', '-p', '1', '-v',
                      './internal/store/business', './internal/store/schema']
        with (options.output / 'tests.txt').open('wb') as log:
            completed = subprocess.run(arguments, stdout=log, stderr=subprocess.STDOUT, timeout=1800)
        value = json.loads(command(['docker', 'inspect', name]))[0]
        result.update(exit_code=completed.returncode, mysql_oom_killed=value['State']['OOMKilled'])
        if completed.returncode or result['mysql_oom_killed']:
            raise RuntimeError('MySQL race acceptance failed; exact fixture evidence retained')
        result['status'] = 'passed'
    except BaseException as error:
        result.update(status='failed', error_type=type(error).__name__)
        raise
    finally:
        value = subprocess.run(['docker', 'inspect', name], capture_output=True, timeout=30)
        if value.returncode == 0:
            inspected = json.loads(value.stdout)[0]
            if inspected['Config'].get('Labels', {}).get('frontiercloud.acceptance') != project:
                raise RuntimeError('MySQL fixture ownership changed')
            result['mysql_oom_killed'] = inspected['State']['OOMKilled']
            command(['docker', 'stop', '--time', '15', name])
            command(['docker', 'rm', name])
        value = subprocess.run(['docker', 'network', 'inspect', network], capture_output=True, timeout=30)
        if value.returncode == 0:
            inspected = json.loads(value.stdout)[0]
            if inspected.get('Labels', {}).get('frontiercloud.acceptance') != project or inspected.get('Containers'):
                raise RuntimeError('MySQL fixture network ownership changed')
            command(['docker', 'network', 'rm', network])
        (options.output / 'evidence.json').write_text(json.dumps(result, indent=2) + '\n')
    print('PASS: isolated MySQL store/schema race acceptance', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--large', action='store_true')
    run(parser.parse_args())
