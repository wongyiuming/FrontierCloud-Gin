"""Development-host-only actual Compose rendering and read-only doctor proof.

This does not start product containers or certify installation/TLS/recovery.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


def tree(directory):
    return {str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in directory.rglob('*') if path.is_file()}


def run(source, binary, workspace):
    results = []
    for role, database, transport in (('master', 'sqlite', ''), ('master', 'mysql', ''),
                                       ('storage', 'sqlite', 'direct'), ('storage', 'sqlite', 'relay')):
        directory = Path(tempfile.mkdtemp(prefix='fc-doctor-', dir=workspace))
        for name in ('docker-compose.yaml', 'docker-compose.gin-mysql.yaml', 'docker-compose.storage.yaml'):
            shutil.copyfile(source / name, directory / name)
        project = directory.name
        environment = f'COMPOSE_PROJECT_NAME={project}\nTLS_ENABLED=false\nSERVER_NAME=storage.invalid\n'
        if role == 'storage':
            port = 443 if transport == 'direct' else 8443
            endpoint = 'https://storage.invalid' + ('' if port == 443 else ':8443')
            environment += f'TLS_ENABLED=true\nSTORAGE_TRANSPORT={transport}\nSTORAGE_PORT={port}\nSTORAGE_ENDPOINT={endpoint}\n'
        if database == 'mysql':
            environment += 'DB_TYPE=mysql\n'
        (directory / '.env').write_text(environment)
        before = tree(directory)
        completed = subprocess.run([str(binary), '--directory', str(directory), '--role', role,
                                    '--database', database, '--json', 'doctor'], capture_output=True, text=True)
        report = json.loads(completed.stdout)
        assert report['read_only'] is True
        assert before == tree(directory), 'doctor changed a file'
        assert not (directory / 'data').exists() and not (directory / 'storage-data').exists()
        assert not (directory / '.fc-install.lock').exists()
        assert not (directory / '.fc-operation.lock').exists()
        items = {item['item']: item for item in report['checks']}
        assert items['configuration']['state'] == 'pass', report
        assert items['fresh_target']['state'] == 'pass', report
        assert items['database_generation']['state'] == 'unverified', report
        if role == 'storage':
            assert items['dns']['state'] == 'blocked', report
            assert items['inbound_http01']['state'] == 'unverified', report
            assert completed.returncode == 2
        compose = ['docker', 'compose', '--project-directory', str(directory), '-f',
                   str(directory / ('docker-compose.storage.yaml' if role == 'storage' else 'docker-compose.yaml'))]
        if database == 'mysql':
            compose += ['-f', str(directory / 'docker-compose.gin-mysql.yaml')]
        configuration = json.loads(subprocess.check_output(compose + ['config', '--format', 'json'], text=True))
        assert all('build' not in service for service in configuration['services'].values())
        assert configuration['services']['web']['image'].startswith('ghcr.io/wongyiuming/frontiercloud-gin-web:')
        assert configuration['services']['web']['environment']['DB_TYPE'] == database
        results.append({'role': role, 'database': database, 'transport': transport,
                        'exit_code': completed.returncode, 'doctor_read_only': True,
                        'compose_rendered': True, 'installation_executed': False, 'report': report})
    return {'scope': 'actual Compose rendering and read-only doctor; no installation/TLS acceptance',
            'results': results}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.workspace.mkdir(parents=True, exist_ok=True)
    result = run(Path(__file__).resolve().parents[1], args.binary, args.workspace)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print('PASS: four actual Compose profiles and read-only doctor; no installation claimed')
