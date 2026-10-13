"""Isolated actual Nginx sendfile/HTTP2/Range/abort counter acceptance."""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import uuid


def run(*args):
    value = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if value.returncode:
        raise RuntimeError("isolated acceptance command failed: " + args[0])
    return value.stdout


def snapshot(path):
    connection = http.client.HTTPConnection("gateway", timeout=2)
    connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.sock.settimeout(2)
    connection.sock.connect(str(path))
    try:
        connection.request("GET", "/traffic")
        reply = connection.getresponse()
        raw = reply.read(4097)
        if reply.status != 200 or len(raw) > 4096:
            raise RuntimeError("private counter unavailable")
        value = json.loads(raw)
        assert value["format"] == "frontiercloud-nginx-traffic"
        assert value["version"] == 1
        assert abs(value["observed_at_ms"] - time.time() * 1000) < 2000
        return value
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--module-image", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--backend-binary", required=True)
    args = parser.parse_args()
    project = "fc-nginx-traffic-" + uuid.uuid4().hex
    root = Path(tempfile.mkdtemp(prefix="fc-nginx-traffic-"))
    os.chmod(root, 0o755)
    counter = root / "counter"
    counter.mkdir(mode=0o755)
    payload = root / "payload.bin"
    with payload.open("wb") as output:
        for _ in range(256):
            output.write(b"x" * 65536)
    dockerfile = root / "Dockerfile"
    (root / "backend").write_bytes(Path(args.backend_binary).read_bytes())
    os.chmod(root / "backend",0o755)
    dockerfile.write_text(f"FROM {args.module_image} AS module\nFROM nginx:1.30.4-alpine\nCOPY --from=module /build/nginx-1.30.4/objs/ngx_http_fc_traffic_module.so /usr/lib/nginx/modules/\nCOPY backend /fixture-backend\n", encoding="utf-8")
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(root / "key.pem"), "-out", str(root / "cert.pem"), "-days", "1", "-subj", "/CN=localhost")
    config = root / "nginx.conf"
    config.write_text("""load_module /usr/lib/nginx/modules/ngx_http_fc_traffic_module.so;
worker_processes 2;
error_log /dev/stderr warn;
events { worker_connections 128; }
http {
 fc_business_traffic;
 sendfile on;
 access_log off;
 server {
  listen unix:/counter/counter.sock;
  location = /traffic { fc_business_traffic_status; }
 }
 server {
  listen 8080;
  listen 8443 ssl;
  http2 on;
  ssl_certificate /fixture/cert.pem;
  ssl_certificate_key /fixture/key.pem;
  location = /slow { alias /fixture/payload.bin; limit_rate 512k; }
  location = /fast { alias /fixture/payload.bin; }
  location = /upload { proxy_request_buffering off; client_max_body_size 32m; proxy_pass http://127.0.0.1:8082; }
  location = /accelerated { proxy_pass http://127.0.0.1:8082; }
  location /_protected_media/ { internal; alias /fixture/; limit_rate 512k; }
  location = /deny-counter { fc_business_traffic_status; }
  location = /api/v1/media/admin/nodes/migrations/fixture { alias /fixture/payload.bin; }
 }
}
""", encoding="utf-8")
    image = project + ":private"
    report = {"status": "failed", "project": project, "workspace": str(root), "private_test_image": True}
    created = False
    try:
        run("docker", "build", "--cpuset-cpus=0,1", "--memory=1g", "--memory-swap=1g", "-t", image, str(root))
        report["image_id"] = json.loads(run("docker", "image", "inspect", image))[0]["Id"]
        report["payload_sha256"] = hashlib.sha256(payload.read_bytes()).hexdigest()
        run("docker", "run", "-d", "--name", project, "--label", "frontiercloud.acceptance=" + project,
            "--cpus=1", "--memory=128m", "--memory-swap=128m", "--pids-limit=64",
            "--mount", f"type=bind,src={root},dst=/fixture,readonly",
            "--mount", f"type=bind,src={config},dst=/etc/nginx/nginx.conf,readonly",
            "--mount", f"type=bind,src={counter},dst=/counter",
            "-p", "127.0.0.1::8080", "-p", "127.0.0.1::8443", "--entrypoint", "sh", image,
            "-c", "/fixture-backend & exec nginx -g 'daemon off;'")
        created = True
        deadline = time.monotonic() + 10
        while not (counter / "counter.sock").exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        initial = snapshot(counter / "counter.sock")
        inspected = json.loads(run("docker", "inspect", project))[0]
        port = int(inspected["NetworkSettings"]["Ports"]["8080/tcp"][0]["HostPort"])
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        connection.request("GET", "/slow")
        response = connection.getresponse()
        assert response.status == 200
        received = 0
        peak = 0
        started = time.monotonic()
        while time.monotonic() - started < 8:
            chunk = response.read(65536)
            assert chunk == b"x" * len(chunk) and chunk
            received += len(chunk)
            view = snapshot(counter / "counter.sock")
            if time.monotonic() - started >= 6:
                peak = max(peak, view["recent_bytes_per_second"])
        assert received < 16 * 1024 * 1024
        assert peak >= 256 * 1024, "unfinished sendfile stream was falsely quiet"
        connection.close()
        report.update(ongoing_sendfile_peak=peak, partial_received_bytes=received,
                      abort_before_completion=True, in_flight_observation=True)
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        connection.request("GET", "/fast", headers={"Range": "bytes=1048541-1048619"})
        response = connection.getresponse()
        assert response.status == 206 and response.read() == b"x" * 79
        connection.close()
        report["actual_range"] = True
        tls_port = int(inspected["NetworkSettings"]["Ports"]["8443/tcp"][0]["HostPort"])
        origin = f"https://127.0.0.1:{tls_port}/accelerated"
        # This private fixture uses a one-day self-signed certificate only.
        version = run("curl", "--http2", "-k", "-sS", "-I", "-o", "/dev/null", "-w", "%{http_version}", origin)
        assert version == "2", "actual HTTP/2 was not negotiated"
        transfer = subprocess.Popen(["curl", "--http2", "-k", "-sS", "-o", str(root / "partial-h2.bin"), origin], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        h2_peak = 0
        try:
            started = time.monotonic()
            while time.monotonic() - started < 8:
                time.sleep(0.2)
                assert transfer.poll() is None, "HTTP/2 fixture completed or failed early"
                sample = snapshot(counter / "counter.sock")
                if time.monotonic() - started >= 6:
                    h2_peak = max(h2_peak, sample["recent_bytes_per_second"])
        finally:
            transfer.terminate()
            transfer.wait(timeout=5)
        assert h2_peak >= 256 * 1024, "in-flight HTTP/2 stream was falsely quiet"
        report["actual_http2"] = True
        report["http2_in_flight_peak"] = h2_peak
        report["actual_x_accel_redirect"] = True
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        connection.request("GET", "/deny-counter")
        response = connection.getresponse()
        assert response.status == 403
        response.read()
        connection.close()
        report["tcp_counter_rejected"] = True
        before = snapshot(counter / "counter.sock")
        run("docker", "exec", project, "nginx", "-s", "reload")
        time.sleep(0.2)
        after = snapshot(counter / "counter.sock")
        assert before["epoch"] == after["epoch"] == initial["epoch"]
        report["reload_epoch_retained"] = True
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            after = snapshot(counter / "counter.sock")
            if after["recent_bytes_per_second"] == 0 and after["egress_bytes_per_second"] == 0:
                break
            time.sleep(0.1)
        assert after["egress_bytes_per_second"] == 0
        connection = http.client.HTTPConnection("127.0.0.1",port,timeout=5)
        connection.putrequest("POST","/upload")
        connection.putheader("Content-Length",str(4*1024*1024))
        connection.endheaders()
        upload_peak = 0
        for _ in range(64):
            connection.send(b"u"*65536)
            time.sleep(0.1)
            upload_sample = snapshot(counter / "counter.sock")
            upload_peak = max(upload_peak,upload_sample["recent_bytes_per_second"])
        response=connection.getresponse()
        assert response.status==200 and response.getheader("X-Fixture-Bytes")==str(4*1024*1024)
        response.read();connection.close()
        assert upload_peak>=256*1024,"unfinished upload was falsely quiet"
        report["actual_upload_bytes"] = 4*1024*1024
        report["upload_in_flight_peak"] = upload_peak
        time.sleep(5.1)
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        connection.request("GET", "/api/v1/media/admin/nodes/migrations/fixture")
        response = connection.getresponse()
        assert response.status == 200 and len(response.read()) == 16 * 1024 * 1024
        connection.close()
        after = snapshot(counter / "counter.sock")
        assert after["egress_bytes_per_second"] == 0
        report["migration_observation_excluded"] = True
        report["status"] = "passed"
    except Exception as error:
        report["error_type"] = type(error).__name__
        raise
    finally:
        if created:
            inspected = json.loads(run("docker", "inspect", project))[0]
            assert inspected["Config"]["Labels"]["frontiercloud.acceptance"] == project
            run("docker", "rm", "-f", project)
            report["owned_container_removed"] = True
        destination = Path(args.output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
