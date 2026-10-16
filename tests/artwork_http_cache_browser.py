"""Observe Chromium HTTP cache reuse without changing original image bytes."""
import argparse
import json
import os
from pathlib import Path
import urllib.parse

from playwright.sync_api import sync_playwright


def run(args):
    base = args.base_url.rstrip('/')
    assert base.startswith('http://127.0.0.1:') or base == 'https://rnlsj.520mall.cc'
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as runtime:
        browser = runtime.chromium.launch(executable_path=os.environ['PLAYWRIGHT_CHROMIUM_EXECUTABLE'], headless=True, args=['--no-sandbox'])
        try:
            context = browser.new_context()
            page = context.new_page()
            page.goto(base + '/api/v1/media/', wait_until='networkidle')
            catalog = context.request.get(base + '/api/v1/media/catalog/media?' + urllib.parse.urlencode({
                'media_type': 'music', 'path': args.path, 'playback_session_id': 'original-cache-proof'})).json()
            cover = next((entry['cover'] for entry in catalog['entries'] if '/cover?' in entry.get('cover', '')), None)
            if not cover:
                page.goto(base + '/api/v1/media/music/category?' + urllib.parse.urlencode({'path': args.path}), wait_until='networkidle')
                page.locator('.card-artwork img[src*="/cover?"]').first.wait_for(state='visible', timeout=45000)
                cover = page.locator('.card-artwork img[src*="/cover?"]').first.get_attribute('src')
            cdp = context.new_cdp_session(page)
            cdp.send('Network.enable')
            rows = {}
            cdp.on('Network.requestWillBeSent', lambda e: rows.setdefault(e['requestId'], {}).update(url=e['request']['url']))
            cdp.on('Network.requestServedFromCache', lambda e: rows.setdefault(e['requestId'], {}).update(cached=True))
            cdp.on('Network.responseReceived', lambda e: rows.setdefault(e['requestId'], {}).update(disk=e['response'].get('fromDiskCache', False)))
            cdp.on('Network.loadingFinished', lambda e: rows.setdefault(e['requestId'], {}).update(wire_bytes=e['encodedDataLength']))
            result = {}
            read = """async url=>{const r=await fetch(url);const b=await r.arrayBuffer();return {url:r.url,status:r.status,
                etag:r.headers.get('ETag'),cache:r.headers.get('Cache-Control'),bytes:b.byteLength,
                sha256:[...new Uint8Array(await crypto.subtle.digest('SHA-256',b))].map(x=>x.toString(16).padStart(2,'0')).join('')};}"""
            for kind, url in [('logo', '/api/v1/media/brand/logo/music'), ('plain_cover', cover)]:
                cdp.send('Network.clearBrowserCache')
                rows.clear()
                cold = page.evaluate(read, url)
                page.wait_for_timeout(100)
                cold_rows = list(rows.values())
                rows.clear()
                warm = page.evaluate(read, cold['url'])
                page.wait_for_timeout(100)
                warm_rows = list(rows.values())
                assert cold['status'] == warm['status'] == 200 and cold['bytes'] > 0
                assert cold['sha256'] == warm['sha256'] and cold['bytes'] == warm['bytes']
                assert any(row.get('cached') or row.get('disk') for row in warm_rows), warm_rows
                assert sum(row.get('wire_bytes', 0) for row in warm_rows) == 0, warm_rows
                assert cold['etag']
                conditional = context.request.get(cold['url'], headers={'If-None-Match': cold['etag']})
                assert conditional.status == 304 and conditional.body() == b''
                result[kind] = {'cold': cold, 'cold_network': cold_rows, 'warm': warm,
                                'warm_network': warm_rows, 'conditional_status': conditional.status}
            (output / 'evidence.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        finally:
            browser.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', required=True)
    parser.add_argument('--path', required=True)
    parser.add_argument('--output', required=True)
    run(parser.parse_args())
