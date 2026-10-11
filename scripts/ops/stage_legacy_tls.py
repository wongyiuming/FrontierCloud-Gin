"""One-time, offline operator migration of an existing verified node identity.

Discover the running project's legacy mounts; never accept certificate paths or
uploaded material. Preserve the original deployment and write a new private
volume only. The automatic Go controller performs final chain/key validation.
"""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tarfile
import uuid


def call(arguments, **kwargs):
    return subprocess.check_output(arguments, **kwargs)


def inspect(container):
    return json.loads(call(["docker", "inspect", container]))[0]


def copy_file(container, path, limit):
    if not path.startswith("/") or ".." in Path(path).parts:
        raise RuntimeError("unsafe historical certificate mount")
    archive = call(["docker", "cp", "-L", container + ":" + path, "-"])
    with tarfile.open(fileobj=io.BytesIO(archive)) as source:
        members = source.getmembers()
        if len(members) != 1 or not members[0].isfile() or not 0 < members[0].size <= limit:
            raise RuntimeError("historical certificate is not a bounded regular file")
        return source.extractfile(members[0]).read()


def stage(project, revision, backup):
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", project) or not re.fullmatch(r"[a-f0-9]{40}", revision):
        raise RuntimeError("exact Compose project and published revision required")
    image = "ghcr.io/wongyiuming/frontiercloud-gin-web:" + revision
    labels = json.loads(call(["docker", "image", "inspect", image]))[0]["Config"]["Labels"]
    if any(labels.get(name) != value for name, value in {
        "frontiercloud.revision": revision, "frontiercloud.runtime": "go",
        "frontiercloud.component": "web", "frontiercloud.schema-generation": "3",
        "frontiercloud.automatic-tls": "1"}.items()):
        raise RuntimeError("published automatic TLS image proof missing")
    ids = call(["docker", "ps", "-q", "--filter", "label=com.docker.compose.project=" + project]).decode().split()
    services = {}
    for item in ids:
        container = inspect(item)
        service = container["Config"]["Labels"].get("com.docker.compose.service")
        if service in services:
            raise RuntimeError("multiple running instances require a maintenance migration")
        services[service] = container
    web = services.get("web")
    if not web or "certificate-agent" in services:
        raise RuntimeError("requires a running legacy external-certificate deployment; managed volumes migrate internally")
    environment = dict(value.split("=", 1) for value in web["Config"]["Env"] if "=" in value)
    domain = environment.get("SERVER_NAME", "").strip().lower()
    if environment.get("TLS_ENABLED", "").lower() != "true" or not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,63}", domain):
        raise RuntimeError("legacy TLS identity unavailable")
    nginx = services.get("nginx")
    if nginx:
        source = nginx
        cert_path, key_path, port = "/etc/nginx/certs/fullchain.pem", "/etc/nginx/certs/privkey.pem", 443
    else:
        source = web
        cert_path = environment.get("STORAGE_TLS_CERT", "")
        key_path = environment.get("STORAGE_TLS_KEY", "")
        port = int(environment.get("STORAGE_PORT", "8443"))
    # Read only files already mounted in the current owned container.
    for path in (cert_path, key_path):
        if not any(path == mount["Destination"] or path.startswith(mount["Destination"].rstrip("/") + "/") for mount in source["Mounts"]):
            raise RuntimeError("historical certificate is not in an owned mounted asset")
    certificate = copy_file(source["Id"], cert_path, 65536)
    private_key = copy_file(source["Id"], key_path, 16384)
    leaf = re.search(rb"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----", certificate, re.S)
    if not leaf:
        raise RuntimeError("historical certificate chain invalid")
    der = base64.b64decode(re.sub(rb"\s+", b"", leaf[1]), validate=True)
    with socket.create_connection((domain, port), timeout=10) as connection:
        with ssl.create_default_context().wrap_socket(connection, server_hostname=domain) as tls:
            if tls.getpeercert(binary_form=True) != der:
                raise RuntimeError("historical pair does not match the currently verified HTTPS identity")
    volume = project + "_certificate_state"
    if subprocess.run(["docker", "volume", "inspect", volume], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
        raise RuntimeError("target certificate volume exists; refusing to overwrite unknown material")
    backup = backup.resolve()
    backup.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.chmod(backup, 0o700)
    generation = uuid.uuid4().hex
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w") as archive:
        for name, content in ((generation + "/fullchain.pem", certificate), (generation + "/privkey.pem", private_key), ("current.json", json.dumps({"generation": generation}).encode())):
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode, entry.uid, entry.gid = len(content), 0o600, 0, 10001
            archive.addfile(entry, io.BytesIO(content))
    raw = payload.getvalue()
    for name, content in (("certificate-recovery.tar", raw), ("old-containers.json", json.dumps(services).encode())):
        descriptor = os.open(backup / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    call(["docker", "volume", "create", "--label", "com.docker.compose.project=" + project,
          "--label", "com.docker.compose.volume=certificate_state", volume])
    subprocess.run(["docker", "run", "--rm", "-i", "--network", "none", "--read-only",
                    "--user", "0:10001", "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE",
                    "--tmpfs", "/tmp:size=1m,mode=0700", "--mount", "type=volume,source=" + volume + ",target=/var/lib/frontiercloud-certificate",
                    "--entrypoint", "/bin/sh", image, "-c",
                    "umask 077; tar -xf - -C /var/lib/frontiercloud-certificate; chmod 0700 /var/lib/frontiercloud-certificate"],
                   input=raw, stdout=subprocess.DEVNULL, check=True)
    proof = {"project": project, "domain": domain, "fingerprint": hashlib.sha256(der).hexdigest(), "volume": volume, "revision": revision}
    (backup / "proof.json").write_text(json.dumps(proof, indent=2))
    os.chmod(backup / "proof.json", 0o600)
    print("Staged verified legacy identity in a new private volume; original services remain running.")
    print("Complete the maintenance Compose migration and require certificate-ready before reopening business.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--backup", required=True, type=Path)
    args = parser.parse_args()
    stage(args.project, args.revision, args.backup)
