"""Development-only real Nginx IP-SAN, internal relay and counter acceptance.

All listeners stay inside one --network none container. Loopback SANs are private
test certificates, never an exception to product public-IP subject validation.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time
import uuid


def command(*args):
    value = subprocess.run(args, capture_output=True, text=True, timeout=30)
    if value.returncode:
        raise RuntimeError('fixture command failed: ' + args[0] + '\n' + value.stderr[-4096:])
    return value.stdout


def certificates(work):
    for name in ('ca', 'other-ca'):
        command('openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '2', '-subj', '/CN=Gin IP fixture ' + name, '-keyout', str(work / (name + '.key')), '-out', str(work / (name + '.pem')))
    cases = [('good', 'IP:127.0.0.1,IP:::1', 'ca'), ('dns-only', 'DNS:127.0.0.1,DNS:::1', 'ca'), ('wrong-ip', 'IP:127.0.0.2,IP:::2', 'ca'), ('untrusted', 'IP:127.0.0.1,IP:::1', 'other-ca'), ('dns-good', 'DNS:peer.fixture.test', 'ca')]
    for serial, (name, san, issuer) in enumerate(cases, 10):
        command('openssl', 'req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-subj', '/CN=Gin private fixture', '-keyout', str(work / (name + '.key')), '-out', str(work / (name + '.csr')))
        extension = work / (name + '.ext')
        extension.write_text('subjectAltName=' + san + '\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature\n')
        command('openssl', 'x509', '-req', '-in', str(work / (name + '.csr')), '-CA', str(work / (issuer + '.pem')), '-CAkey', str(work / (issuer + '.key')), '-set_serial', str(serial), '-days', '1', '-extfile', str(extension), '-out', str(work / (name + '.pem')))


def counter(path):
    connection = http.client.HTTPConnection('counter', timeout=2)
    connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.sock.settimeout(2)
    connection.sock.connect(str(path))
    try:
        connection.request('GET', '/traffic')
        response = connection.getresponse()
        raw = response.read(4097)
        assert response.status == 200 and len(raw) <= 4096
        return json.loads(raw)
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', required=True)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--module', required=True)
    parser.add_argument('--work', required=True)
    parser.add_argument('--image', default='nginx:1.30.4-alpine')
    args = parser.parse_args()
    work = Path(args.work).resolve()
    work.mkdir(mode=0o755, parents=True, exist_ok=False)
    os.chmod(work, 0o755)
    certificates(work)
    source = Path(args.source).read_text()
    # Run the actual entrypoint selector twice: restarting must not double-wrap
    # the bare IPv6 identity, and all public listener templates must agree.
    templates = work / 'render-templates'
    templates.mkdir()
    (templates / 'nginx.conf.template').write_text(source)
    command('docker', 'run', '--rm', '--network', 'none', '--cpus', '1', '--memory', '64m', '--entrypoint', '/bin/sh', '-e', 'SERVER_NAME=2606:4700:4700::1111', '-e', 'TLS_ENABLED=true', '-e', 'PUBLIC_BIND_ADDRESS=::', '-v', f'{templates}:/etc/nginx/templates', '-v', f'{Path(args.source).resolve().parent / "transport"}:/etc/nginx/transport:ro', '-v', f'{Path(args.source).resolve().parent / "15-select-tls.sh"}:/select.sh:ro', args.image, '-ec', 'sh /select.sh; sh /select.sh')
    for template in (templates / 'nginx.conf.template', templates / 'runtime/extra-servers.conf.template'):
        body = template.read_text()
        assert 'server_name [${SERVER_NAME}];' in body and '[[${SERVER_NAME}]]' not in body
    blocks = []
    for kind in ('media', 'recording'):
        found = re.search(r'(        location ~ "\^/_relay_' + kind + r'/.*?\n        })', source, re.S)
        assert found is not None
        blocks.append(found[1].replace('/etc/ssl/certs/ca-certificates.crt', '/fixture/ca.pem'))
    paths, listeners = [], []
    names = ('good', 'dns-only', 'wrong-ip', 'untrusted')
    for offset, name in enumerate(names):
        port = 8443 + offset
        listeners.append(f'''server {{ listen 127.0.0.1:{port} ssl; listen [::1]:{port} ssl;
 ssl_certificate /fixture/{name}.pem; ssl_certificate_key /fixture/{name}.key;
 location / {{ return 200 "$http_host|$ssl_server_name"; }} }}''')
        for kind, length in [('media', 64), ('recording', 32)]:
            for family, host in [('ipv4', '127.0.0.1'), ('ipv6', '[::1]')]:
                path = '/' + '-'.join((kind, family, name))
                target = f'/_relay_{kind}/{host}/{port}/' + 'a' * length + '/fixture_token'
                paths.append((path, 200 if name == 'good' else 502, host + ':' + str(port) + '|'))
                blocks.append(f'location = {path} {{ rewrite ^ "{target}" last; }}')
    listeners.append('''server { listen 127.0.0.1:8448 ssl; ssl_certificate /fixture/dns-good.pem; ssl_certificate_key /fixture/dns-good.key; return 200 "dns-unchanged"; }''')
    blocks.append('''location = /dns-good { proxy_pass https://127.0.0.1:8448; proxy_ssl_name peer.fixture.test; proxy_ssl_verify on; proxy_ssl_trusted_certificate /fixture/ca.pem; }''')
    blocks.append('''location = /dns-wrong { proxy_pass https://127.0.0.1:8448; proxy_ssl_name wrong.fixture.test; proxy_ssl_verify on; proxy_ssl_trusted_certificate /fixture/ca.pem; }''')
    paths.extend([('/dns-good', 200, 'dns-unchanged'), ('/dns-wrong', 502, '')])
    config = '''load_module /usr/lib/nginx/modules/ngx_http_fc_traffic_module.so;
worker_processes 1;
error_log /dev/stderr warn;
events { worker_connections 64; }
http {
 fc_business_traffic;
 sendfile on; access_log off;
 server { listen unix:/counter/counter.sock; location = /traffic { fc_business_traffic_status; } }
''' + '\n'.join(listeners) + '''
 server { listen 127.0.0.1:8080;
 set $media_resource_id ""; set $media_owner_id ""; set $media_object_id "";
 set $trace_id ""; set $parent_request_id ""; set $forwarded_traceparent "";
 set $frontiercloud_csp "default-src 'none'";
 set $frontiercloud_hsts "";
 location = /payload { alias /fixture/payload.bin; }
''' + '\n'.join(blocks) + '\n }\n}\n'
    (work / 'nginx.conf').write_text(config)
    (work / 'payload.bin').write_bytes(b'x' * (1024 * 1024))
    (work / 'counter').mkdir(mode=0o755)
    name = 'fc-ip-nginx-' + uuid.uuid4().hex
    report = {'status': 'failed', 'network': 'none', 'public_ports': [], 'cases': [], 'binary_sha256': hashlib.sha256(Path(args.binary).read_bytes()).hexdigest()}
    started = False
    try:
        command('docker', 'run', '-d', '--name', name, '--label', 'frontiercloud.acceptance=' + name, '--network', 'none', '--cpus', '1', '--memory', '64m', '--memory-swap', '64m', '--pids-limit', '64', '--entrypoint', '/usr/sbin/nginx', '-v', f'{Path(args.binary).resolve()}:/usr/sbin/nginx:ro', '-v', f'{Path(args.module).resolve()}:/usr/lib/nginx/modules/ngx_http_fc_traffic_module.so:ro', '-v', f'{work}:/fixture:ro', '-v', f'{work / "nginx.conf"}:/etc/nginx/nginx.conf:ro', '-v', f'{work / "counter"}:/counter', '-v', f'{Path(args.source).resolve().parent / "proxy-response-headers.conf"}:/etc/nginx/proxy-response-headers.conf:ro', '-v', f'{Path(args.source).resolve().parent / "security-headers.conf"}:/etc/nginx/security-headers.conf:ro', args.image, '-g', 'daemon off;')
        started = True
        for _ in range(50):
            if (work / 'counter/counter.sock').exists(): break
            time.sleep(.1)
        command('docker', 'exec', name, 'nginx', '-t')
        before = counter(work / 'counter/counter.sock')
        for path, expected, body in paths:
            result = subprocess.run(['docker', 'exec', name, 'wget', '-T', '3', '-S', '-O', '-', 'http://127.0.0.1:8080' + path], capture_output=True, text=True, timeout=10)
            statuses = re.findall(r'HTTP/\S+\s+(\d+)', result.stderr)
            status = int(statuses[-1]) if statuses else 0
            assert status == expected, (path, expected, status, result.stderr)
            if expected == 200: assert result.stdout == body, (path, result.stdout, body)
            report['cases'].append({'path': path, 'status': status, 'passed': True})
        result = subprocess.run(['docker', 'exec', name, 'sh', '-c', "printf '%s\\r\\n' 'GET /payload HTTP/1.1' 'Host: 127.0.0.1' 'Range: bytes=100-199' 'Connection: close' '' | nc -w 3 127.0.0.1 8080"], capture_output=True, text=True, timeout=10)
        headers, separator, body = result.stdout.partition('\n\n')
        assert separator and '206 Partial Content' in headers and body == 'x' * 100, (headers, len(body), result.stderr)
        after = counter(work / 'counter/counter.sock')
        assert after['format'] == 'frontiercloud-nginx-traffic' and after['egress_bytes_per_second'] > 0
        report.update(range_sendfile=True, traffic_module_compatible=True, traffic_before=before, traffic_after=after, ipv6_entrypoint_restart_idempotent=True)
        samples, consecutive, deadline = [], 0, time.monotonic() + 30
        while time.monotonic() < deadline and consecutive < 5:
            value = float(command('docker', 'stats', '--no-stream', '--format', '{{.CPUPerc}}', name).strip().rstrip('%'))
            samples.append(value)
            consecutive = consecutive + 1 if value < 20 else 0
        assert consecutive == 5, samples
        report.update(status='passed', idle_cpu_samples_percent=samples, resource={'cpus': 1, 'memory_bytes': 64 * 1024 * 1024})
    finally:
        if started or subprocess.run(['docker', 'inspect', name], capture_output=True, timeout=10).returncode == 0:
            stopped = subprocess.run(['docker', 'stop', '-t', '2', name], capture_output=True, timeout=10)
            report['logs'] = subprocess.run(['docker', 'logs', name], capture_output=True, text=True, timeout=10).stderr[-8192:]
            removed = subprocess.run(['docker', 'rm', name], capture_output=True, timeout=10)
            report['cleanup'] = {'stop_exit_code': stopped.returncode, 'remove_exit_code': removed.returncode}
            if stopped.returncode or removed.returncode:
                report['status'] = 'failed'
        (work / 'result.json').write_text(json.dumps(report, indent=2))
    assert report['status'] == 'passed', 'Nginx fixture cleanup failed'
    print(json.dumps({k: v for k, v in report.items() if k != 'logs'}, indent=2))


if __name__ == '__main__':
    main()
