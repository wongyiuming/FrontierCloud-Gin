"""Real development-only Compose certificate acceptance, outside hosted CI."""
import datetime
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


def call(args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()


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
            assert item["Config"]["Labels"].get("frontiercloud.acceptance") == project or item["Config"]["Labels"].get("com.docker.compose.project") == project
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
    image = "frontiercloud-go-web:" + revision
    labels = json.loads(call(["docker", "image", "inspect", image]))[0]["Config"]["Labels"]
    assert labels["frontiercloud.revision"] == revision and labels["frontiercloud.component"] == "web"
    # Test bootstrap certificate only; no public CA or production path is used.
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2", "-subj", "/CN=storage.fixture.test", "-addext", "subjectAltName=DNS:storage.fixture.test", "-keyout", str(work / "key.pem"), "-out", str(work / "cert.pem")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    os.chown(work / "key.pem", 0, 10001)
    (work / "key.pem").chmod(0o640)
    http_port, stun_port = available_port(socket.SOCK_STREAM), available_port(socket.SOCK_DGRAM)
    env = dict(os.environ, COMPOSE_PROJECT_NAME=project, FRONTIERCLOUD_REVISION=revision,
               SERVER_NAME="storage.fixture.test", STORAGE_ENDPOINT=f"https://storage.fixture.test:{http_port}",
               STORAGE_PORT=str(http_port), WEBRTC_STUN_PORT=str(stun_port),
               SSL_CERT_PATH=str(work / "cert.pem"), SSL_KEY_PATH=str(work / "key.pem"),
               DATA_DIRECTORY=str(work / "data"), PUBLIC_BIND_ADDRESS="127.0.0.1")
    fixture = work / "fixture.yaml"
    fixture.write_text("services:\n  web:\n    cpus: 1\n    mem_limit: 256m\n    memswap_limit: 256m\n")
    files = [ROOT / "docker-compose.storage.yaml", ROOT / "docker-compose.storage-certificate.yaml", fixture]
    def compose(*args, temporary=False):
        selected = files + ([ROOT / "docker-compose.storage-certificate-temporary.yaml"] if temporary else [])
        command = ["docker", "compose", "--project-directory", str(ROOT)]
        for path in selected:
            command += ["-f", str(path)]
        return call(command + list(args), env=env)
    config = json.loads(compose("config", "--format", "json"))
    volumes = {key: value["name"] for key, value in config["volumes"].items()}
    network_names = [value["name"] for value in config["networks"].values()]
    names = {key: project + "-" + key + "-1" for key in config["services"]}
    reader, tester = project + "-reader", project + "-tester"
    resources = {"project": project, "containers": [names["web"], reader, tester, *[v for k, v in names.items() if k != "web"]], "volumes": list(volumes.values()), "networks": network_names}
    (work / "resources.json").write_text(json.dumps(resources))
    def wait_agent():
        for _ in range(60):
            result = subprocess.run(["docker", "exec", names["certificate-agent"], "/app/frontiercloud", "certificate-healthcheck"], capture_output=True)
            if result.returncode == 0:
                return
            time.sleep(0.5)
        raise AssertionError("certificate container never ready")
    def status(container):
        return json.loads(call(["docker", "exec", container, "/app/frontiercloud", "certificate-status"]))
    compose("up", "-d", "--no-build", "certificate-agent")
    wait_agent()
    agent = inspect(names["certificate-agent"])
    host = agent["HostConfig"]
    assert agent["Config"]["User"] == "0:10001" and host["ReadonlyRootfs"]
    assert host["NanoCpus"] == 50000000 and host["Memory"] == host["MemorySwap"] == 134217728
    assert host["PidsLimit"] == 24 and host["CapDrop"] == ["ALL"] and not host["CapAdd"]
    assert not host["Privileged"] and not host["PidMode"] and not host["PortBindings"]
    assert all(m["Type"] == "volume" for m in agent["Mounts"] if m["Destination"] != "/tmp")
    assert status(names["certificate-agent"])["validation"] == "shared_http01"
    common = ["--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--read-only", "--cpus=.05", "--memory=128m", "--memory-swap=128m", "--pids-limit=24", "--label", "frontiercloud.acceptance=" + project]
    call(["docker", "run", "-d", "--name", reader, "--network=none", "--user=10001:10001", *common,
          "-e", "SERVER_NAME=storage.fixture.test", "-v", volumes["certificate_runtime"] + ":/run/frontiercloud-certificate:ro",
          "-v", volumes["certificate_state"] + ":/var/lib/frontiercloud-certificate:ro", "--entrypoint", "/bin/sleep", image, "infinity"])
    assert status(reader)["managed"]
    old_id = agent["Id"]
    compose("up", "-d", "--force-recreate", "--no-deps", "certificate-agent")
    wait_agent()
    assert inspect(names["certificate-agent"])["Id"] != old_id and status(reader)["managed"]
    print("PASS: bridged Compose certificate container; pre-existing reader survives agent recreation")
    compose("stop", "certificate-agent")
    mounts = ["-v", volumes["certificate_state"] + ":/var/lib/frontiercloud-certificate", "-v", volumes["certificate_runtime"] + ":/run/frontiercloud-certificate", "-v", volumes["certificate_http01"] + ":/run/frontiercloud-http01", "-v", str(work / "certificate.test") + ":/certificate.test:ro"]
    result = call(["docker", "run", "--rm", "--name", tester, "--user=0:10001", *common, "--tmpfs", "/tmp:size=16m,mode=1777", "-e", "GOMAXPROCS=1", "-e", "GOMEMLIMIT=64MiB", "-e", "FRONTIERCLOUD_TEST_CERTIFICATE_VOLUMES=1", *mounts, "--entrypoint", "/certificate.test", image, "-test.v", "-test.timeout=30s", "-test.run", "TestCertificateContainerSharedVolumes|TestACMEV2OrderRealHTTPChallengeCSRAndCertificate"])
    print(result)
    assert "--- SKIP" not in result and "PASS" in result
    compose("up", "-d", "--no-build", "certificate-agent")
    wait_agent()
    facts = status(reader)
    assert facts["state"] == "valid" and facts["auto_renew"] and facts["job"]["state"] == "success"
    for private in ["state.json", "account.key"]:
        assert subprocess.run(["docker", "exec", reader, "/bin/cat", "/var/lib/frontiercloud-certificate/" + private], capture_output=True).returncode != 0
    compose("up", "-d", "--no-build", "--wait", "web")
    web = inspect(names["web"])
    assert web["HostConfig"]["NanoCpus"] == 1000000000
    pointer = json.loads(call(["docker", "exec", names["certificate-agent"], "/bin/cat", "/var/lib/frontiercloud-certificate/current.json"]))
    public_cert = call(["docker", "exec", names["certificate-agent"], "/bin/cat", "/var/lib/frontiercloud-certificate/" + pointer["generation"] + "/fullchain.pem"])
    context = ssl.create_default_context(cadata=public_cert)
    with socket.create_connection(("127.0.0.1", http_port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname="storage.fixture.test") as connection:
            served = hashlib.sha256(connection.getpeercert(binary_form=True)).hexdigest()
    assert served == facts["fingerprint"]
    compose("up", "-d", "--force-recreate", "--no-deps", "certificate-agent")
    wait_agent()
    assert inspect(names["web"])["Id"] == web["Id"] and status(reader)["auto_renew"]
    call(["docker", "exec", names["web"], "/app/frontiercloud", "healthcheck"])
    print("PASS: group-readable managed TLS actually served; private account/journal denied; Web and reader survive agent recreation")
    compose("stop", "certificate-agent")
    # Port 80 is used only on the development host after an explicit ownership check.
    with socket.socket() as probe:
        probe.bind(("0.0.0.0", 80))
    result = call(["docker", "run", "--rm", "--name", tester, "--network=host", "--user=0:10001", *common,
                   "--cap-add", "NET_BIND_SERVICE", "--tmpfs", "/tmp:size=16m,mode=1777", "-e", "GOMAXPROCS=1", "-e", "GOMEMLIMIT=64MiB", "-e", "FRONTIERCLOUD_TEST_CERTIFICATE_PORT80=1", *mounts, "--entrypoint", "/certificate.test", image, "-test.v", "-test.timeout=30s", "-test.run", "TestCertificateContainerTemporaryPort80"])
    print(result)
    assert "--- SKIP" not in result and "PASS" in result
    compose("up", "-d", "--no-build", "--no-deps", "certificate-agent", temporary=True)
    wait_agent()
    temporary = inspect(names["certificate-agent"])
    assert temporary["HostConfig"]["NetworkMode"] == "host" and not temporary["HostConfig"]["PortBindings"]
    assert temporary["HostConfig"]["CapAdd"] == ["NET_BIND_SERVICE"]
    facts = status(reader)
    assert facts["validation"] == "temporary_port80" and not facts["job"]["port80_active"]
    with socket.socket() as probe:
        probe.bind(("0.0.0.0", 80))
    print("PASS: actual host-network container owns 80 only during challenge; busy/failure/cancel release; idle 80 available")
    class EngineConnection(http.client.HTTPConnection):
        def connect(self):
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect("/var/run/docker.sock")
    def cpu_stats():
        connection = EngineConnection("localhost", timeout=3)
        try:
            connection.request("GET", f"/containers/{web['Id']}/stats?stream=false&one-shot=true")
            response = connection.getresponse()
            assert response.status == 200
            return json.load(response)["cpu_stats"]
        finally:
            connection.close()
    started = time.monotonic()
    previous = cpu_stats()
    samples = []
    for _ in range(5):
        time.sleep(1)
        raw = cpu_stats()
        elapsed_cpu = raw["cpu_usage"]["total_usage"] - previous["cpu_usage"]["total_usage"]
        elapsed_system = raw["system_cpu_usage"] - previous["system_cpu_usage"]
        assert elapsed_system > 0
        value = 100 * elapsed_cpu / elapsed_system * raw["online_cpus"]
        assert 0 <= value < 20
        samples.append(value)
        previous = raw
    assert time.monotonic() - started <= 30
    print(json.dumps({"status": "passed", "revision": revision, "cpu_percent": samples, "utc": datetime.datetime.now(datetime.timezone.utc).isoformat()}))


if __name__ == "__main__":
    action, path = sys.argv[1:3]
    work = Path(path)
    assert re.fullmatch(r"/tmp/fc-certificate-[A-Za-z0-9]{8}", str(work)) and work.resolve() == work and not work.is_symlink()
    if action == "cleanup":
        cleanup(work)
    else:
        assert action == "run"
        try:
            run(work, *sys.argv[3:5])
        except BaseException:
            cleanup(work)
            raise
