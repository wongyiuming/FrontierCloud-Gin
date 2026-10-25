"""Real development-only Compose certificate acceptance, outside hosted CI."""
import datetime
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
IP_AUDIT = None


def audit_command(args, started, output, code):
    if IP_AUDIT is not None:
        path, record = IP_AUDIT
        record['commands'].append({'argv': list(args), 'started_at': started,
                                   'exit_code': code, 'stdout_sha256': hashlib.sha256(output.encode()).hexdigest()})
        path.write_text(json.dumps(record, indent=2))


def call(args, **kwargs):
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    try:
        output = subprocess.check_output(args, text=True, **kwargs).strip()
        audit_command(args, started, output, 0)
        return output
    except subprocess.CalledProcessError as error:
        audit_command(args, started, error.output or '', error.returncode)
        print((error.output or "")[-8192:], flush=True)
        raise


def inspect(name):
    return json.loads(call(["docker", "inspect", name]))[0]


def available_port(kind):
    with socket.socket(socket.AF_INET, kind) as connection:
        connection.bind(("127.0.0.1", 0))
        return connection.getsockname()[1]


def cleanup(work):
    resources = json.loads((work / "resources.json").read_text())
    project = resources["project"]
    assert re.fullmatch(r"fc-certificate-[a-f0-9-]{36}", project)
    # Stop the exact business fixture before failure or resource cleanup.
    for name in resources["containers"]:
        found = subprocess.run(["docker", "inspect", name], capture_output=True, text=True)
        if found.returncode == 0:
            item = json.loads(found.stdout)[0]
            scopes = {project + "-" + prefix + profile for prefix in ("", "ip4-", "ip6-")
                      for profile in ("business", "direct", "relay")}
            assert item["Config"]["Labels"].get("frontiercloud.acceptance") == project or item["Config"]["Labels"].get("com.docker.compose.project") in scopes
            subprocess.run(["docker", "stop", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            subprocess.run(["docker", "rm", "-v", name], stdout=subprocess.DEVNULL, check=True)
    for name in resources["networks"]:
        found = subprocess.run(["docker", "network", "inspect", name], capture_output=True, text=True)
        if found.returncode == 0:
            assert not json.loads(found.stdout)[0]["Containers"]
            subprocess.run(["docker", "network", "rm", name], stdout=subprocess.DEVNULL, check=True)
    for name in resources["volumes"]:
        if subprocess.run(["docker", "volume", "inspect", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            assert not call(["docker", "ps", "-aq", "--filter", "volume=" + name])
            subprocess.run(["docker", "volume", "rm", name], stdout=subprocess.DEVNULL, check=True)
    assert not call(["docker", "ps", "-aq", "--filter", "label=com.docker.compose.project=" + project])
    print("PASS: exact certificate containers, network and volumes cleaned")


def run(work, project, revision):
    assert re.fullmatch(r"fc-certificate-[a-f0-9-]{36}", project)
    assert re.fullmatch(r"[a-f0-9]{40}", revision)
    resources = {"project": project, "containers": [], "volumes": [], "networks": []}
    (work / "resources.json").write_text(json.dumps(resources))
    for profile in ("business", "direct", "relay"):
        case = work / profile
        case.mkdir(mode=0o755)
        domain = ("business" if profile == "business" else "storage") + ".fixture.test"
        environment = dict(os.environ, COMPOSE_PROJECT_NAME=project + "-" + profile,
                           FRONTIERCLOUD_REVISION=revision, TLS_ENABLED="true",
                           SERVER_NAME=domain, STORAGE_TRANSPORT=profile,
                           STORAGE_PORT="8443" if profile == "relay" else "443",
                           STORAGE_ENDPOINT="https://" + domain + (":8443" if profile == "relay" else ""),
                           DATA_DIRECTORY=str(case / "data"))
        base = ROOT / ("docker-compose.yaml" if profile == "business" else "docker-compose.storage.yaml")
        native = os.environ.get('FC_CERTIFICATE_TEST_WEB_IMAGE', 'frontiercloud-go-web:' + revision)
        edge = os.environ.get('FC_CERTIFICATE_TEST_EDGE_IMAGE', 'frontiercloud-go-nginx:' + revision)
        agent_override = f"""services:
  certificate-init:
    image: {native}
  secrets-init:
    image: {native}
  media-init:
    image: {native}
  certificate-agent:
    image: {native}
    entrypoint: [/certificate.test]
    command: [-test.v, -test.timeout=5m, -test.run=^TestAutomaticTLSContainerLifecycle$]
    restart: "no"
    network_mode: !reset null
    networks: [default]
    environment:
      FRONTIERCLOUD_TEST_AUTOMATIC_TLS_PROFILE: {profile}
    volumes:
      - {work / 'certificate.test'}:/certificate.test:ro
      - {case}:/fixture
  web:
    image: {native}
    cpus: 1
    mem_limit: 256m
    memswap_limit: 256m
    ports: !reset []
    networks:
      default:
        aliases: [{"business-web.fixture.test" if profile == "business" else "storage.fixture.test"}]
    volumes:
      - {case / 'ca.pem'}:/etc/ssl/certs/ca-certificates.crt:ro
"""
        if profile == "business":
            agent_override += f"""  nginx:
    image: {edge}
    ports: !reset []
    networks:
      default:
        aliases: [business.fixture.test]
    volumes:
      - {case / 'ca.pem'}:/etc/ssl/certs/ca-certificates.crt:ro
  stun:
    ports: !reset []
"""
        overlay = case / "fixture.yaml"
        overlay.write_text(agent_override)
        def compose(*args):
            return call(["docker", "compose", "--project-directory", str(ROOT), "-f", str(base), "-f", str(overlay), *args], env=environment)
        rendered = json.loads(compose("config", "--format", "json"))
        assert not any(service.get("ports") for service in rendered["services"].values())
        names = {name: rendered["name"] + "-" + name + "-1" for name in rendered["services"]}
        resources["containers"] += [names["web"], *[name for key, name in names.items() if key != "web"]]
        resources["volumes"] += [value["name"] for value in rendered["volumes"].values()]
        resources["networks"] += [value["name"] for value in rendered.get("networks", {}).values()]
        (work / "resources.json").write_text(json.dumps(resources))
        compose("up", "-d", "--no-build", "--pull", "never", "certificate-agent")
        def wait_file(name):
            end = time.monotonic() + 100
            while time.monotonic() < end:
                if (case / name).is_file():
                    return
                if inspect(names["certificate-agent"])["State"]["Status"] != "running":
                    raise AssertionError(call(["docker", "logs", names["certificate-agent"]])[-4096:])
                time.sleep(0.25)
            raise AssertionError("certificate fixture timed out: " + name)
        wait_file("ca-ready")
        targets = ["web", "nginx"] if profile == "business" else ["web"]
        compose("up", "-d", "--no-build", "--pull", "never", *targets)
        (case / "serving-started").write_text("ready")
        wait_file("active")
        # Exercise the shipping CLI and real socket with the same cgroup split
        # used by foc: Web issues status reads, the 0.05 CPU agent owns TLS.
        assert inspect(names["certificate-agent"])["HostConfig"]["NanoCpus"] == 50_000_000
        def concurrent_status(stage):
            agent = names["certificate-agent"]
            inputs = [["docker", "exec", names["web"], "/app/frontiercloud", "certificate-status"] for _ in range(3)]
            inputs.append(["docker", "exec", agent, "/app/frontiercloud", "certificate-healthcheck"])
            def check(args):
                started = time.monotonic()
                raw = call(args, timeout=45)
                if args[-1] == "certificate-status":
                    view = json.loads(raw)
                    assert view["controller_running"] and view["https_ready"] and view["serving_matches"], view
                    assert view["state"] == "ACTIVE" and not view.get("last_error"), view
                return {"argv": args, "elapsed_seconds": round(time.monotonic() - started, 3)}
            results = []
            with ThreadPoolExecutor(max_workers=4) as pool:
                for round_number in range(3):
                    # Span the controller's five-second observation ticker.
                    if round_number:
                        time.sleep(4)
                    results.append(list(pool.map(check, inputs)))
            print(json.dumps({"profile": profile, "stage": stage, "agent_cpus": 0.05,
                              "concurrent_inputs": results}), flush=True)
        concurrent_status("issued")
        call(["docker", "exec", names["web"], "/app/frontiercloud", "healthcheck"])
        if profile != "business":
            pair = json.loads(call(["docker", "exec", names["web"], "/app/frontiercloud", "storage-pair"]))["payload"]
            assert pair["endpoint"] == environment["STORAGE_ENDPOINT"]
            # Do not print one-time credentials to the acceptance log.
            assert pair["storage_transport"] == profile
            assert time.time() + 280 < pair["expires_at"] <= time.time() + 301
        before = {name: inspect(names[name])["Id"] for name in targets}
        compose("up", "-d", "--no-build", "--pull", "never", "--force-recreate", "--no-deps", *targets)
        assert all(inspect(names[name])["Id"] != before[name] for name in targets)
        (case / "serving-recreated").write_text("ready")
        wait_file("renewed")
        concurrent_status("renewed-after-restart")
        call(["docker", "exec", names["web"], "/app/frontiercloud", "healthcheck"])
        (case / "verified").write_text("ready")
        code = json.loads(call(["docker", "wait", names["certificate-agent"]]))
        assert code == 0, call(["docker", "logs", names["certificate-agent"]])[-4096:]
        logs = call(["docker", "logs", names["certificate-agent"]])
        assert "--- SKIP" not in logs and "PASS: actual local-CA issuance" in logs
        samples = []
        for _ in range(5):
            raw = call(["docker", "stats", "--no-stream", "--format", "{{.CPUPerc}}", names["web"]])
            value = float(raw.rstrip("%"))
            assert 0 <= value < 20, (profile, value)
            samples.append(value)
        print(json.dumps({"profile": profile, "web_cpu_percent": samples}))
        print("PASS: automatic TLS Compose lifecycle " + profile, flush=True)
        compose("down", "-v")
    print("PASS: all profiles used local CA; no production CA, host ports or services touched")


def run_ip(work, project, revision):
    """Real shipping consumers; only the compiled controller fixture is replaced."""
    global IP_AUDIT
    assert re.fullmatch(r"fc-certificate-[a-f0-9-]{36}", project)
    assert re.fullmatch(r"[a-f0-9]{40}", revision)
    record = {'format': 'native-ip-certificate-containers-v1', 'source_base': revision,
              'working_tree_candidate': os.environ.get('FC_CERTIFICATE_TEST_CANDIDATE') == '1',
              'public_ca_requests': 0, 'host_port_publications': 0,
              'production_operations': False, 'commands': [], 'cases': [], 'source_sha256': {}}
    for name in ('internal/certmanager/manager.go', 'internal/certmanager/storage.go',
                 'internal/certmanager/ip_storage.go', 'internal/certmanager/acme_test.go',
                 'internal/certmanager/container_real_test.go', 'tests/storage_certificate_containers.py'):
        record['source_sha256'][name] = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
    evidence = work / 'ip-delivery-evidence.json'
    IP_AUDIT = (evidence, record)
    resources = {'project': project, 'containers': [], 'volumes': [], 'networks': []}
    (work / 'resources.json').write_text(json.dumps(resources))
    native = os.environ.get('FC_CERTIFICATE_TEST_WEB_IMAGE', 'frontiercloud-go-web:' + revision)
    edge = os.environ.get('FC_CERTIFICATE_TEST_EDGE_IMAGE', 'frontiercloud-go-nginx:' + revision)
    record['image_ids'] = {name: json.loads(call(['docker', 'image', 'inspect', image]))[0]['Id']
                           for name, image in (('web', native), ('nginx', edge))}
    versions = [('ip4', '93.184.216.10')]
    probe = project + '-ipv6-probe'
    try:
        call(['docker', 'network', 'create', '--internal', '--ipv6', '--subnet', '93.184.217.0/24',
              '--subnet', '2606:4700:fc00::/64', probe], stderr=subprocess.STDOUT)
        versions.append(('ip6', '2606:4700:fc00::10'))
        record['ipv6_capability'] = 'isolated dual-stack network created successfully'
    except subprocess.CalledProcessError as error:
        record['ipv6_capability'] = 'unsupported by development Engine: ' + (error.output or '')[-1024:]
    finally:
        found = subprocess.run(['docker', 'network', 'inspect', probe], capture_output=True)
        if found.returncode == 0:
            call(['docker', 'network', 'rm', probe])
    for family, identity in versions:
        for profile in ('business', 'direct', 'relay'):
            name = family + '-' + profile
            case = work / name
            case.mkdir(mode=0o755)
            (case / 'ca.pem').touch()
            port = 8443 if profile == 'relay' else 443
            endpoint = 'https://' + ('[' + identity + ']' if family == 'ip6' else identity)
            if port != 443:
                endpoint += ':' + str(port)
            environment = {key: value for key, value in os.environ.items() if not key.startswith('COMPOSE_')}
            environment.update(COMPOSE_PROJECT_NAME=project + '-' + name, FRONTIERCLOUD_REVISION=revision,
                               TLS_ENABLED='true', SERVER_NAME=identity, STORAGE_TRANSPORT=profile,
                               STORAGE_PORT=str(port), STORAGE_ENDPOINT=endpoint,
                               PUBLIC_BIND_ADDRESS='::' if family == 'ip6' else '0.0.0.0',
                               DATA_DIRECTORY=str(case / 'data'))
            base = ROOT / ('docker-compose.yaml' if profile == 'business' else 'docker-compose.storage.yaml')
            cfg = json.loads(call(['docker', 'compose', '--project-directory', str(ROOT), '-f', str(base),
                                   'config', '--format', 'json'], env=environment))
            for service, spec in cfg['services'].items():
                spec.pop('ports', None)
                if 'frontiercloud-gin-web' in spec['image']:
                    spec['image'] = native
                elif 'frontiercloud-gin-nginx' in spec['image']:
                    spec['image'] = edge
            agent = cfg['services']['certificate-agent']
            agent.pop('network_mode', None)
            agent.update(entrypoint=['/certificate.test'], command=['-test.v', '-test.timeout=6m',
                         '-test.run=^TestAutomaticTLSIPContainerLifecycle$'], restart='no')
            agent['environment'].update(FRONTIERCLOUD_TEST_AUTOMATIC_TLS_PROFILE=profile,
                                        FRONTIERCLOUD_TEST_AUTOMATIC_TLS_IP=identity)
            agent['volumes'] += [{'type': 'bind', 'source': str(work / 'certificate.test'), 'target': '/certificate.test', 'read_only': True},
                                 {'type': 'bind', 'source': str(case), 'target': '/fixture'}]
            web = cfg['services']['web']
            web.update(cpus=1, mem_limit='512m', memswap_limit='512m')
            trust = {'type': 'bind', 'source': str(case / 'ca.pem'), 'target': '/etc/ssl/certs/ca-certificates.crt', 'read_only': True}
            web['volumes'].append(trust)
            ipv4 = '93.184.216.10'
            fixed = {'ipv4_address': ipv4}
            identity_network = {'name': project + '-' + name + '_ip_identity', 'internal': True,
                                'ipam': {'config': [{'subnet': '93.184.216.0/24'}]}}
            if family == 'ip6':
                fixed['ipv6_address'] = identity
                identity_network.update(enable_ipv6=True)
                identity_network['ipam']['config'].append({'subnet': '2606:4700:fc00::/64'})
            cfg['networks'] = {'default': {'name': project + '-' + name + '_default', 'internal': True},
                               'ip_identity': identity_network}
            if profile == 'business':
                # Keep the actual private proxy hop on its ordinary Docker LAN;
                # only the edge's independent public identity sits on 93/IPv6.
                agent['networks'] = {'default': {}, 'ip_identity': {}}
                cfg['services']['nginx']['networks'] = {'default': {}, 'ip_identity': fixed}
                cfg['services']['nginx']['volumes'].append(trust)
            else:
                # Production storage shares the host network for temporary 80.
                # A test-only namespace holder reproduces that shared network
                # without binding any host socket or extending product access.
                cfg['services']['ip-netns'] = {'image': native, 'entrypoint': ['/bin/sleep'], 'command': ['600'],
                                               'read_only': True, 'cap_drop': ['ALL'], 'mem_limit': '16m', 'cpus': 0.01,
                                               'sysctls': {'net.ipv4.ip_unprivileged_port_start': '0'},
                                               'networks': {'default': {}, 'ip_identity': fixed}}
                for spec in (agent, web):
                    spec.pop('networks', None)
                    spec.pop('sysctls', None)
                    spec['network_mode'] = 'service:ip-netns'
            fixture = case / 'compose.json'
            fixture.write_text(json.dumps(cfg))

            def compose(*args):
                return call(['docker', 'compose', '--project-directory', str(case), '-f', str(fixture), *args], env=environment)

            rendered = json.loads(compose('config', '--format', 'json'))
            assert not any(spec.get('ports') for spec in rendered['services'].values())
            assert all(network.get('internal') for network in rendered['networks'].values())
            names = {key: rendered['name'] + '-' + key + '-1' for key in rendered['services']}
            resources['containers'] += [names['web'], *[value for key, value in names.items() if key != 'web']]
            resources['volumes'] += [value['name'] for value in rendered['volumes'].values()]
            resources['networks'] += [value['name'] for value in rendered['networks'].values()]
            (work / 'resources.json').write_text(json.dumps(resources))
            compose('up', '-d', '--no-build', '--pull', 'never', 'certificate-agent')

            def wait_file(marker, timeout=140):
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    if (case / marker).is_file():
                        return
                    if inspect(names['certificate-agent'])['State']['Status'] != 'running':
                        raise AssertionError(call(['docker', 'logs', names['certificate-agent']])[-6000:])
                    time.sleep(0.25)
                raise AssertionError('IP fixture timed out: ' + name + '/' + marker)

            def status(expected):
                view = json.loads(call(['docker', 'exec', names['web'], '/app/frontiercloud', 'certificate-status'], timeout=30))
                assert view['state'] == expected and view['https_ready'] and view['serving_matches'], view
                assert view['san'] == [identity], view
                call(['docker', 'exec', names['web'], '/app/frontiercloud', 'healthcheck'], timeout=30)
                return view

            wait_file('ca-ready')
            targets = ['web', 'nginx'] if profile == 'business' else ['web']
            compose('up', '-d', '--no-build', '--pull', 'never', *targets)
            wait_file('active')
            before = status('ACTIVE')
            assert inspect(names['web'])['HostConfig']['NanoCpus'] == 1_000_000_000
            assert inspect(names['certificate-agent'])['HostConfig']['NanoCpus'] == 50_000_000
            ids = {key: inspect(names[key])['Id'] for key in targets}
            compose('up', '-d', '--no-build', '--pull', 'never', '--force-recreate', '--no-deps', *targets)
            assert all(inspect(names[key])['Id'] != ids[key] for key in targets)
            (case / 'serving-recreated').write_text('ready')
            wait_file('renewal-failed')
            failed = status('DEGRADED')
            assert failed['fingerprint'] == before['fingerprint'] and failed['last_error'] == 'rate_limited', failed
            (case / 'failure-verified').write_text('ready')
            wait_file('renewed')
            after = status('ACTIVE')
            assert after['fingerprint'] != before['fingerprint'] and after['last_renewal'] == 'success', after
            (case / 'verified').write_text('ready')
            assert int(call(['docker', 'wait', names['certificate-agent']])) == 0
            logs = call(['docker', 'logs', names['certificate-agent']])
            (case / 'controller.log').write_text(logs)
            assert '--- SKIP' not in logs and 'PASS: actual local-CA IP issuance' in logs
            facts = json.loads((case / 'ip-evidence.json').read_text())
            facts['web_cpu_percent'] = []
            for _ in range(5):
                value = float(call(['docker', 'stats', '--no-stream', '--format', '{{.CPUPerc}}', names['web']]).rstrip('%'))
                assert 0 <= value < 20, (name, value)
                facts['web_cpu_percent'].append(value)
            record['cases'].append(facts)
            evidence.write_text(json.dumps(record, indent=2))
            print('PASS: IP automatic TLS shipping Compose lifecycle ' + name, flush=True)
            compose('down', '-v')
    record['passed'] = True
    evidence.write_text(json.dumps(record, indent=2))
    print('PASS: all supported IP profiles, private CA, no host ports, 1 CPU Web, bounded cleanup')


if __name__ == "__main__":
    action, path = sys.argv[1:3]
    work = Path(path)
    assert re.fullmatch(r"/tmp/fc-certificate-[A-Za-z0-9]{8}", str(work)) and work.resolve() == work and not work.is_symlink()
    if action == "cleanup":
        cleanup(work)
    else:
        assert action in ("run", "run-ip")
        try:
            (run_ip if action == 'run-ip' else run)(work, *sys.argv[3:5])
        except BaseException:
            if action == 'run-ip' and (work / 'resources.json').is_file():
                resources = json.loads((work / 'resources.json').read_text())
                for name in resources['containers']:
                    if name.endswith(('-web-1', '-nginx-1', '-certificate-agent-1')):
                        result = subprocess.run(['docker', 'logs', '--tail', '160', name], capture_output=True, text=True)
                        (work / (name + '.log')).write_text(result.stdout + result.stderr)
            cleanup(work)
            raise
