"""Cold audio startup comparison and small queue/original cover isolation."""
import argparse
import json
import os
from pathlib import Path
import statistics
import time
import urllib.parse

from playwright.sync_api import sync_playwright


def run(args):
    assert args.base_url.startswith('http://127.0.0.1:'), 'isolated development origin required'
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    proof = {'passed': False, 'samples': [], 'network_throttled': False}
    baseline = Path(args.baseline_dir)
    url = args.base_url + '/api/v1/media/music/category?' + urllib.parse.urlencode({'path': args.encrypted_path})
    with sync_playwright() as runtime:
        browser = runtime.chromium.launch(executable_path=os.environ['PLAYWRIGHT_CHROMIUM_EXECUTABLE'],
            headless=True, args=['--no-sandbox', '--autoplay-policy=no-user-gesture-required'])
        try:
            for round_number in range(3):
                for mode in ('before', 'after'):
                    context = browser.new_context(viewport={'width': 1360, 'height': 900})
                    try:
                        if mode == 'before':
                            for name in ('player.js', 'music-metadata.js'):
                                source = (baseline / name).read_text()
                                context.route('**/static/js/' + name + '*',
                                    lambda route, request, source=source: route.fulfill(body=source, content_type='text/javascript'))
                        reads = []
                        context.on('request', lambda request: reads.append({'range': request.headers.get('range'), 'at': time.monotonic()})
                            if request.service_worker and '/static/' not in request.url else None)
                        page = context.new_page()
                        start = time.monotonic()
                        page.goto(url, wait_until='domcontentloaded')
                        page.wait_for_function('()=>typeof art!=="undefined"&&art?.currentTime>0.1&&frontierCloudContinuousAudio.status().active', timeout=45000)
                        first_play = time.monotonic()
                        proof['samples'].append({'mode': mode, 'round': round_number + 1,
                            'first_play_seconds': round(first_play - start, 3),
                            'ciphertext_requests_before_first_play': len(reads)})
                        page.evaluate('art.pause()')
                    finally:
                        context.close()
            context = browser.new_context(viewport={'width': 1360, 'height': 900})
            context.add_init_script('window.artworkBlobs=new Map();const createArtworkURL=URL.createObjectURL.bind(URL);URL.createObjectURL=b=>{const u=createArtworkURL(b);artworkBlobs.set(u,b);return u;}')
            page = context.new_page()
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            plain_url = args.base_url + '/api/v1/media/music/category?' + urllib.parse.urlencode({'path': args.plain_path})
            page.goto(plain_url, wait_until='domcontentloaded')
            page.wait_for_function('()=>typeof currentMediaList!=="undefined"&&currentMediaList.length&&art', timeout=45000)
            page.evaluate('art.pause()')
            page.wait_for_timeout(1500)
            proof['cold_plain_placeholder'] = page.locator('.media-item img').first.get_attribute('src')
            assert proof['cold_plain_placeholder'].startswith('data:image/svg+xml'), proof
            # Simulate viewing an original elsewhere, then reuse its ordinary HTTP cache in the small player.
            page.evaluate('async()=>{await (await fetch(currentMediaList[0].cover)).arrayBuffer()}')
            page.reload(wait_until='domcontentloaded')
            page.wait_for_function('()=>typeof art!=="undefined"&&art', timeout=45000)
            page.evaluate('art.pause()')
            row = page.locator('.media-item').first
            row.evaluate('(row)=>row.scrollIntoView({block:"nearest"})')
            page.wait_for_timeout(3000)
            # Artwork is explicitly optional, even when cached. Idle cancellation may retain the placeholder.
            proof['plain_picture'] = row.locator('img').evaluate('''async image=>{
                const thumb=artworkBlobs.get(image.src);const original=await (await fetch(currentMediaList[0].cover)).blob();
                const bitmap=await createImageBitmap(original);const result={thumbnail_available:!!thumb,
                    placeholder:image.src.startsWith('data:image/svg+xml'),thumbnail_width:thumb?image.naturalWidth:null,
                    thumbnail_height:thumb?image.naturalHeight:null,thumbnail_bytes:thumb?.size,thumbnail_type:thumb?.type,
                    original_width:bitmap.width,original_height:bitmap.height,original_bytes:original.size,
                    original_sha256:[...new Uint8Array(await crypto.subtle.digest('SHA-256',await original.arrayBuffer()))].map(x=>x.toString(16).padStart(2,'0')).join('')};bitmap.close();return result;}''')
            picture = proof['plain_picture']
            assert picture['original_sha256'] == args.original_sha256, picture
            assert picture['original_width'] == 500, picture
            if picture['thumbnail_available']:
                assert picture['thumbnail_width'] == 96 and picture['thumbnail_type'] == 'image/webp' and picture['thumbnail_bytes'] < picture['original_bytes'], picture
            else:
                assert picture['placeholder'], 'optional artwork must retain a network-free placeholder'
            page.screenshot(path=str(out / 'small-player-original-preserved.png'))
            assert errors == [], errors
            proof['page_errors'] = errors
            context.close()
            legacy = browser.new_context(viewport={'width': 1360, 'height': 900})
            legacy.add_init_script('window.OffscreenCanvas=undefined')
            page = legacy.new_page()
            page.goto(plain_url, wait_until='domcontentloaded')
            page.wait_for_function('()=>typeof currentMediaList!=="undefined"&&currentMediaList.length&&art', timeout=45000)
            proof['legacy_placeholder'] = page.evaluate('''()=>({supported:FrontierMusicMetadata.canThumbnail(),
                source:document.querySelector('.media-item img').getAttribute('src'),original:currentMediaList[0].cover})''')
            original = proof['legacy_placeholder']
            assert not original['supported'] and original['source'].startswith('data:image/svg+xml'), original
            page.evaluate('art.pause()')
            legacy.close()
            proof['artwork_failure_playback'] = []
            for failure, script in (
                ('no-canvas', 'window.OffscreenCanvas=undefined'),
                ('decode-failure', 'window.createImageBitmap=async()=>{throw new Error("artwork decode failure")}'),
                ('no-idle-time', 'window.requestIdleCallback=()=>1;window.cancelIdleCallback=()=>{}'),
            ):
                isolated = browser.new_context(viewport={'width': 1360, 'height': 900})
                isolated.add_init_script(script)
                check = isolated.new_page()
                check.goto(url, wait_until='domcontentloaded')
                check.wait_for_function('()=>typeof art!=="undefined"&&art?.currentTime>1&&frontierCloudContinuousAudio.status().active', timeout=45000)
                check.evaluate('selectMedia(1)')
                check.wait_for_function('()=>currentIndex===1&&art.currentTime>1&&frontierCloudContinuousAudio.status().active', timeout=45000)
                proof['artwork_failure_playback'].append({'failure': failure, 'manual_switch_played': True,
                    'state': check.evaluate('({index:currentIndex,time:art.currentTime,paused:art.video.paused,error:art.video.error?.code||null})')})
                isolated.close()
            proof['medians'] = {mode: statistics.median(s['first_play_seconds'] for s in proof['samples'] if s['mode'] == mode)
                for mode in ('before', 'after')}
            proof['passed'] = True
        finally:
            browser.close()
            (out / 'evidence.json').write_text(json.dumps(proof, ensure_ascii=False, indent=2))
    print(json.dumps(proof, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', default='http://127.0.0.1:18080')
    parser.add_argument('--encrypted-path', required=True)
    parser.add_argument('--plain-path', required=True)
    parser.add_argument('--original-sha256', required=True)
    parser.add_argument('--baseline-dir', required=True)
    parser.add_argument('--output', required=True)
    run(parser.parse_args())
