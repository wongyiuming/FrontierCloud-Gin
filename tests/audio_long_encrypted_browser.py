"""Trusted-HTTPS GUI upload and real encrypted long-MP3 MSE acceptance on dev."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

from playwright.sync_api import sync_playwright, expect


def run(args):
    state = Path(args.state)
    output = Path(args.output)
    output.mkdir(exist_ok=True)
    folder = 'long-encrypted-' + uuid.uuid4().hex[:12]
    record = {'passed': False, 'folder': 'music/' + folder, 'site': 'primary',
              'inputs': [], 'errors': [], 'transitions': [], 'max_retained_seconds': 0,
              'tls': 'normal CA and hostname verification, no bypass'}
    def save():
        (output / 'encrypted-evidence.json').write_text(json.dumps(record, ensure_ascii=False, indent=2))
    with tempfile.TemporaryDirectory(prefix='fc-long-encrypted-', dir=state) as temporary, sync_playwright() as p:
        root = Path(temporary)
        nss = root / '.pki/nssdb'
        nss.mkdir(parents=True)
        subprocess.run(['certutil', '-N', '-d', 'sql:' + str(nss), '--empty-password'], check=True)
        subprocess.run(['certutil', '-A', '-d', 'sql:' + str(nss), '-n', 'development-ca', '-t',
                        'C,,', '-i', str(state / 'development-ca/ca.crt')], check=True)
        files = root / folder
        files.mkdir()
        for index in [0, 1]:
            os.link(state / 'long-audio' / (str(index) + '.mp3'), files / (str(index) + '.mp3'))
        browser = p.chromium.launch(executable_path=os.environ['PLAYWRIGHT_CHROMIUM_EXECUTABLE'],
            headless=True, env={**os.environ, 'HOME': temporary}, args=['--no-sandbox',
                '--no-proxy-server', '--autoplay-policy=no-user-gesture-required'])
        context = browser.new_context(viewport={'width': 1400, 'height': 1000})
        page = context.new_page()
        page.on('pageerror', lambda e: record['errors'].append(str(e)))
        try:
            page.goto('https://192.168.6.201/dev-login')
            page.locator('#key').fill((state / 'admin-key').read_text())
            page.get_by_role('button', name='登录 Admin GUI', exact=True).click()
            page.wait_for_url('**/api/v1/media/admin/')
            page.get_by_role('button', name='媒体管理', exact=True).click()
            page.locator('.tree-row[data-path="music"]').dblclick()
            page.locator('#uploadSiteType').select_option('primary')
            page.locator('#uploadBtn').click()
            page.locator('#uploadFolder').click()
            with page.expect_file_chooser() as chooser:
                page.get_by_role('button', name='加密落盘', exact=True).click()
            record['inputs'].append({'action': 'GUI upload folder', 'storage_mode': 'encrypted',
                                      'site_type': 'primary', 'bytes': 232856968})
            chooser.value.set_files(str(files))
            expect(page.locator('#uploadSummary')).to_have_text('完成：成功 2，失败 0', timeout=180000)
            page.goto('https://192.168.6.201/api/v1/media/music/category?path=music%2F' + folder,
                      wait_until='domcontentloaded')
            page.wait_for_function('() => typeof art!=="undefined" && art?.currentTime>.05', timeout=45000)
            entries = page.evaluate('currentMediaList.map(t=>({path:t.media_path,encryption:!!t.encryption,url:t.url}))')
            assert len(entries) == 2 and all(e['encryption'] for e in entries), entries
            record['encrypted_catalog_verified'] = True
            record['entries'] = entries
            # Only the browser reads plaintext. Validate authenticated Range
            # bytes against the source without downloading the complete song.
            for index in [0, 1]:
                plain = page.evaluate('''async index=>{
                    const r=await fetch(currentMediaList[index].url,{headers:{Range:'bytes=0-31'}});
                    return {status:r.status,bytes:[...new Uint8Array(await r.arrayBuffer())]};
                }''', index)
                assert plain['status'] == 206, plain
                with (files / (str(index) + '.mp3')).open('rb') as f:
                    assert bytes(plain['bytes']) == f.read(32)
            record['authenticated_plaintext_range_verified'] = True
            src = page.evaluate('art.video.currentSrc')
            visited = [0]
            deadline = time.monotonic() + 240
            while time.monotonic() < deadline:
                sample = page.evaluate('''() => {
                    const s=frontierCloudContinuousAudio.status(),v=art.video;
                    if(v.buffered.length && v.buffered.end(v.buffered.length-1)>v.currentTime+3)
                        v.currentTime=v.buffered.end(v.buffered.length-1)-2;
                    return {index:currentIndex,src:v.currentSrc,pipeline:s.pipeline_error,
                        error:v.error?.message,retained:s.retained_buffer_seconds};
                }''')
                assert sample['src'] == src and not sample['pipeline'] and not sample.get('error'), sample
                record['max_retained_seconds'] = max(record['max_retained_seconds'], sample['retained'])
                assert sample['retained'] < 120, sample
                if sample['index'] != visited[-1]:
                    visited.append(sample['index'])
                    record['transitions'].append(sample)
                    save()
                    if len(visited) == 3:
                        break
                page.wait_for_timeout(100)
            assert visited == [0, 1, 0], visited
            record['automatic_encrypted_long_track_verified'] = True
            page.screenshot(path=str(output / 'encrypted-long-tracks.png'))
            assert not record['errors'], record['errors']
            record['passed'] = True
        finally:
            save()
            browser.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--state', required=True)
    parser.add_argument('--output', required=True)
    run(parser.parse_args())
