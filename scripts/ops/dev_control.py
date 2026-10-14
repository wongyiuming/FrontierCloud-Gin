"""Root-only operator client for the persistent development environment.

Legacy imports remain fenced. Direct invocation is retired; use the explicit
host-side fc workflow for reviewed upgrades.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import ssl
import subprocess
import time
from pathlib import Path

import httpx

ROOT = Path("/root/frontiercloud-dev")


def compose(node, *args):
    result = subprocess.run([
        "docker", "exec", "fc-dev-host-" + node, "docker", "compose",
        "--project-directory", "/node/repo", "-p", "frontiercloud",
        "-f", "/node/repo/docker-compose.yaml", "-f", "/node/override.json", *args,
    ], check=True, capture_output=True, text=True)
    return result.stdout.strip()


class Client:
    def __init__(self, node):
        if (Path(__file__).resolve().parents[2] / "internal/certmanager").is_dir():
            raise RuntimeError("Legacy persistent Admin/whole-fleet control is retired; current Storage uses signed native control and Master-only releases")
        self.node = node
        inventory = json.loads((ROOT / "inventory.json").read_text())
        self.endpoint = next(n["endpoint"] for n in inventory["nodes"] if n["name"] == node)
        self.client = httpx.Client(verify=ssl.create_default_context(cafile=inventory["ca"]),
                                   trust_env=False, timeout=90, follow_redirects=False)
        if len(inventory["nodes"]) != 5:
            raise RuntimeError("Only the five-node native development inventory is supported")
        key = compose(node, "exec", "-T", "web", "sh", "-c",
                      "cat /run/frontiercloud-secrets/admin_key")
        response = self.client.post(self.endpoint + "/api/v1/media/admin/elevate", data={"token": key})
        response.raise_for_status()
        self.csrf = self.client.cookies.get("__Host-admin-csrf")
        if not self.csrf:
            raise RuntimeError("Admin CSRF cookie absent")

    def api(self, path, value=None):
        response = self.client.request("GET" if value is None else "POST", self.endpoint + path,
                                       json=value, headers={"X-CSRF-Token": self.csrf})
        if response.is_error:
            raise RuntimeError(f"{self.node}: {path}: HTTP {response.status_code}: {response.text[:500]}")
        return response.json()

    def nodes(self):
        return self.api("/api/v1/media/admin/nodes")


def bootstrap():
    inventory = json.loads((ROOT / "inventory.json").read_text())
    master = Client("master")
    if master.nodes()["role"] == "Standalone":
        master.api("/api/v1/media/admin/nodes/promote", {
            "role": "Master", "endpoint": master.endpoint, "local_capacity_gib": 50,
        })
    for node in inventory["nodes"][1:]:
        follower = Client(node["name"])
        identity = follower.nodes()
        if identity["role"] == "Standalone":
            follower.api("/api/v1/media/admin/nodes/promote", {"role": "Follower", "endpoint": follower.endpoint})
        relations = master.nodes()["relationships"]
        existing = next((r for r in relations if r["peer_id"] == identity["node_id"] and r["state"] == "active"), None)
        if existing:
            relation = existing["relationship_id"]
        else:
            package = follower.api("/api/v1/media/admin/nodes/pair-package", {})
            relation = master.api("/api/v1/media/admin/nodes/pair", {"package": package})["relationship_id"]
        master.api(f"/api/v1/media/admin/nodes/{relation}/mode", {"mode": node["mode"]})
        master.api(f"/api/v1/media/admin/nodes/{relation}/resources", {
            "storage_enabled": True, "storage_capacity_gib": 50, "backup_enabled": True,
        })
        print(json.dumps({"paired": node["name"], "mode": node["mode"]}), flush=True)


if __name__ == "__main__":
    raise SystemExit("Legacy development CD is retired; use fc upgrade plan/apply/open")
