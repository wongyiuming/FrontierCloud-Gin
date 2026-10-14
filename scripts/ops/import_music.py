"""Import a local music tree through normal Admin uploads, retaining sources.

Run against an internal test environment. Credentials are read from a file;
the manifest is resumable and verifies source bytes before skipping uploads.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
from pathlib import Path
from urllib.parse import urlencode, urlsplit
import uuid


class Importer:
    def __init__(self, endpoint, key):
        url = urlsplit(endpoint)
        if url.scheme not in {"http", "https"} or url.path not in {"", "/"}:
            raise ValueError("Use the environment origin as --url")
        kind = http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
        self.connection = kind(url.hostname, url.port, timeout=300)
        self.cookies = {}
        result = self.request("POST", "/api/v1/media/admin/elevate", urlencode({"token": key}).encode(),
                              {"Content-Type": "application/x-www-form-urlencoded"})
        self.csrf = next((v for k, v in self.cookies.items() if "csrf" in k), "")
        if not self.csrf or result.get("status") != "ok":
            raise RuntimeError("Admin authentication failed")

    def response(self):
        response = self.connection.getresponse()
        for name, value in response.getheaders():
            if name.lower() == "set-cookie":
                key, val = value.split(";", 1)[0].split("=", 1)
                self.cookies[key] = val
        data = response.read()
        if response.status >= 300:
            raise RuntimeError(f"HTTP {response.status}: {data[:300].decode(errors='replace')}")
        return json.loads(data)

    def headers(self):
        result = {"Cookie": "; ".join(f"{k}={v}" for k, v in self.cookies.items())}
        if getattr(self, "csrf", ""):
            result["X-CSRF-Token"] = self.csrf
        return result

    def request(self, method, route, body=None, headers=None):
        self.connection.request(method, route, body, {**self.headers(), **(headers or {})})
        return self.response()

    def upload(self, path, relative):
        boundary = "fc-music-" + uuid.uuid4().hex
        if any(c in path.name for c in '\r\n"'):
            raise ValueError("Unsupported multipart filename")
        preamble = (f'--{boundary}\r\nContent-Disposition: form-data; name="target_dir"\r\n\r\nmusic\r\n'
                    f'--{boundary}\r\nContent-Disposition: form-data; name="relative_path"\r\n\r\n{relative}\r\n'
                    f'--{boundary}\r\nContent-Disposition: form-data; name="storage_mode"\r\n\r\nplain\r\n'
                    f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{path.name}"\r\n'
                    'Content-Type: audio/mpeg\r\n\r\n').encode()
        suffix = f"\r\n--{boundary}--\r\n".encode()
        length = path.stat().st_size
        self.connection.putrequest("POST", "/api/v1/media/admin/upload/item")
        for key, value in {**self.headers(), "Content-Type": f"multipart/form-data; boundary={boundary}",
                           "Content-Length": str(len(preamble) + length + len(suffix))}.items():
            self.connection.putheader(key, value)
        self.connection.endheaders()
        self.connection.send(preamble)
        sent = 0
        digest = hashlib.sha256()
        with path.open("rb") as source:
            while data := source.read(256 * 1024):
                sent += len(data)
                if sent > length:
                    raise RuntimeError("Source changed during upload")
                digest.update(data)
                self.connection.send(data)
        if sent != length:
            raise RuntimeError("Source changed during upload")
        self.connection.send(suffix)
        return self.response(), digest.hexdigest(), length

    def recover_existing(self, path, relative):
        """A finalized upload can lose its HTTP reply; verify before resuming."""
        album = "music/" + relative.parent.as_posix()
        result = self.request("GET", "/api/v1/media/catalog/media?" + urlencode({
            "media_type": "music", "path": album, "playback_session_id": "music-import"}))
        with path.open("rb") as source:
            expected = hashlib.file_digest(source, "sha256").hexdigest()
        for entry in result["entries"]:
            remote = entry["media_path"]
            self.connection.request("GET", "/api/v1/media/admin/download?" + urlencode({
                "paths": json.dumps([remote], ensure_ascii=False)}), headers=self.headers())
            response = self.connection.getresponse()
            if response.status != 200:
                response.read()
                raise RuntimeError("Cannot verify existing upload")
            digest = hashlib.sha256()
            length = 0
            while data := response.read(256 * 1024):
                digest.update(data)
                length += len(data)
            if length == path.stat().st_size and digest.hexdigest() == expected:
                return {"path": remote}, expected, length
        raise RuntimeError("Existing file differs from source; no overwrite performed")


def import_tree(source, manifest, endpoint, key):
    source = Path(source).resolve()
    files = sorted(source.rglob("*.mp3"))
    done = {}
    if manifest.exists():
        for line in manifest.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            if row.get("result") == "uploaded":
                done[row["source"]] = row
    client = Importer(endpoint, key)
    uploaded = skipped = failed = 0
    manifest.parent.mkdir(parents=True, exist_ok=True)
    with manifest.open("a", encoding="utf-8", buffering=1) as log:
        for index, file in enumerate(files):
            relative = file.relative_to(source)
            if len(relative.parts) != 3:
                raise ValueError(f"Expected artist/album/song.mp3: {relative}")
            previous = done.get(relative.as_posix())
            if previous:
                with file.open("rb") as stream:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
                if previous["sha256"] == digest and previous["bytes"] == file.stat().st_size:
                    skipped += 1
                    continue
                raise RuntimeError(f"Previously imported source changed: {relative}")
            row = {"source": relative.as_posix()}
            try:
                try:
                    result, digest, length = client.upload(file, relative.as_posix())
                except RuntimeError as error:
                    if not str(error).startswith("HTTP 409:"):
                        raise
                    result, digest, length = client.recover_existing(file, relative)
                row.update(result="uploaded", path=result["path"], bytes=length, sha256=digest)
                uploaded += 1
            except Exception as error:
                row.update(result="failed", error=str(error))
                failed += 1
                # A broken HTTP body cannot be reused safely.
                client.connection.close()
            log.write(json.dumps(row, ensure_ascii=False) + "\n")
            if row["result"] == "failed":
                raise RuntimeError(f"Upload failed: {relative}: {row['error']}")
            if index % 25 == 0 or row["result"] == "failed":
                print(json.dumps({"completed": index + 1, "total": len(files), "uploaded": uploaded,
                                  "failed": failed}, ensure_ascii=False), flush=True)
    print(json.dumps({"total": len(files), "uploaded": uploaded, "skipped": skipped, "failed": failed}), flush=True)
    if failed:
        raise RuntimeError("Some music uploads failed; inspect the manifest")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--admin-key-file", type=Path, required=True)
    args = parser.parse_args()
    import_tree(args.source, args.manifest, args.url, args.admin_key_file.read_text().strip())
