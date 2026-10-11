"""Real Chromium executes the shipping certificate export function."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request

from playwright.sync_api import sync_playwright


def run(work):
    metadata = work / "browser.json"
    deadline = time.monotonic() + 45
    while not metadata.exists():
        if time.monotonic() > deadline:
            raise RuntimeError("certificate browser fixture not ready")
        time.sleep(.1)
    facts = json.loads(metadata.read_text())
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            executable_path=os.environ["PLAYWRIGHT_CHROMIUM_EXECUTABLE"],
            headless=True, args=["--no-sandbox"])
        try:
            page = browser.new_page(accept_downloads=True)
            page.goto(facts["url"])
            assert page.evaluate("window.isSecureContext && !!crypto.subtle")
            responses = []
            page.on("response", lambda response: responses.append(response)
                    if response.url.endswith("/download") else None)
            with page.expect_download() as pending:
                assert "PEM" in page.evaluate("window.run()")
            download = pending.value
            assert download.suggested_filename == facts["hostname"] + "-tls-key-pair.pem"
            pair = work / "download.pem"
            download.save_as(pair)
            pair.chmod(0o600)
            raw = pair.read_bytes()
            assert b"BEGIN CERTIFICATE" in raw and b"PRIVATE KEY" in raw
            leaf = subprocess.check_output(["openssl", "x509", "-in", str(pair), "-outform", "DER"])
            assert hashlib.sha256(leaf).hexdigest() == facts["fingerprint"]
            certificate_public = subprocess.check_output(["openssl", "x509", "-in", str(pair), "-pubkey", "-noout"])
            private_public = subprocess.check_output(["openssl", "pkey", "-in", str(pair), "-pubout"])
            assert certificate_public == private_public
            assert responses and all("no-store" in response.headers["cache-control"] for response in responses)
            assert all("PRIVATE KEY" not in response.text() and "BEGIN CERTIFICATE" not in response.text() for response in responses)
            for mutation in ("hostname", "nonce", "ciphertext", "fingerprint"):
                def alter(route):
                    response = route.fetch()
                    result = response.json()
                    envelope = result["download"]
                    if mutation == "hostname":
                        envelope["hostname"] = "wrong.fixture.test"
                    elif mutation == "nonce":
                        envelope["browser_nonce"] = "A" * 43
                    elif mutation == "fingerprint":
                        envelope["fingerprint"] = result["fingerprint"] = "0" * 64
                    else:
                        envelope["ciphertext"] = ("A" if envelope["ciphertext"][0] != "A" else "B") + envelope["ciphertext"][1:]
                    route.fulfill(response=response, json=result)
                downloads = []
                def on_download(item):
                    downloads.append(item)
                page.on("download", on_download)
                page.route("**/download", alter)
                failure = page.evaluate("window.run().then(()=>'',error=>error.message || error.name)")
                assert failure and not downloads, mutation
                page.unroute("**/download", alter)
                page.remove_listener("download", on_download)
            urllib.request.urlopen(urllib.request.Request(facts["url"] + "/done", data=b"", method="POST")).close()
            print("PASS: real Chromium certificate/key download, identity, nonce, fingerprint and ciphertext tampering rejected")
        finally:
            browser.close()
            (work / "download.pem").unlink(missing_ok=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("work", type=Path)
    run(parser.parse_args().work)
