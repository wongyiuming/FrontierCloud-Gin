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
    try:
        return subprocess.check_output(args, text=True, **kwargs).strip()
    except subprocess.CalledProcessError as error:
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
            assert item["Config"]["Labels"].get("frontiercloud.acceptance") == project or item["Config"]["Labels"].get("com.docker.compose.project") in {project + "-" + profile for profile in ("business", "direct", "relay")}
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
        native = "frontiercloud-go-web:" + revision
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
    volumes:
      - {case / 'ca.pem'}:/etc/ssl/certs/ca-certificates.crt:ro
"""
        if profile == "business":
            agent_override += f"""  nginx:
    image: frontiercloud-go-nginx:{revision}
    ports: !reset []
    volumes:
      - {case / 'ca.pem'}:/etc/ssl/certs/ca-certificates.crt:ro
  stun:
    ports: !reset []
  updater:
    image: frontiercloud-go-updater:{revision}
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
        compose("up", "-d", "--no-build", "certificate-agent")
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
        compose("up", "-d", "--no-build", *targets)
        (case / "serving-started").write_text("ready")
        wait_file("active")
        call(["docker", "exec", names["web"], "/app/frontiercloud", "healthcheck"])
        if profile != "business":
            pair = json.loads(call(["docker", "exec", names["web"], "/app/frontiercloud", "storage-pair"]))["payload"]
            assert pair["endpoint"] == environment["STORAGE_ENDPOINT"]
            # Do not print one-time credentials to the acceptance log.
            assert pair["storage_transport"] == profile
            assert time.time() + 280 < pair["expires_at"] <= time.time() + 301
        before = {name: inspect(names[name])["Id"] for name in targets}
        compose("up", "-d", "--no-build", "--force-recreate", "--no-deps", *targets)
        assert all(inspect(names[name])["Id"] != before[name] for name in targets)
        (case / "serving-recreated").write_text("ready")
        wait_file("renewed")
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
