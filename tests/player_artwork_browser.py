"""Cold audio startup comparison and category original-cover isolation."""
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
                            for name in ('player.js', 'audio-continuous-stream.js'):
                                source = (baseline / name).read_text()
                                if name == 'player.js':
                                    # The current player page no longer injects this script.
                                    source = (baseline / 'music-metadata.js').read_text() + '\n' + source
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
            page = context.new_page()
            errors = []
            player_requests = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.on('request', lambda request: player_requests.append(urllib.parse.urlsplit(request.url).path))
            plain_url = args.base_url + '/api/v1/media/music/category?' + urllib.parse.urlencode({'path': args.plain_path})
            page.goto(plain_url, wait_until='domcontentloaded')
            page.wait_for_function('()=>typeof currentMediaList!=="undefined"&&currentMediaList.length&&art', timeout=45000)
            page.evaluate('art.pause()')
            page.wait_for_timeout(1500)
            assert page.evaluate('''()=>typeof FrontierMusicMetadata==='undefined' &&
                document.querySelectorAll('.media-item img').length===0 && currentMediaList.every(item=>{
                    const file=item.media_path.split('/').pop();return item.title===file.slice(0,file.lastIndexOf('.'));})''')
            assert not any(path in ('/api/v1/media/metadata', '/api/v1/media/cover') for path in player_requests), player_requests
            proof['player_filename_labels_without_artwork'] = True
            page.screenshot(path=str(out / 'player-without-artwork.png'))
            assert errors == [], errors
            proof['page_errors'] = errors
            context.close()

            # The category page renders and retrieves the unchanged original.
            context = browser.new_context(viewport={'width': 1360, 'height': 900})
            page = context.new_page()
            parent, name = args.plain_path.rsplit('/', 1)
            category_url = args.base_url + '/api/v1/media/music'
            if parent != 'music':
                category_url += '/category?' + urllib.parse.urlencode({'path': parent})
            page.goto(category_url, wait_until='domcontentloaded')
            page.wait_for_function('(name)=>[...document.querySelectorAll("a.card")].some(c=>c.title===name)', arg=name, timeout=45000)
            page.get_by_title(name, exact=True).scroll_into_view_if_needed()
            page.wait_for_function('(name)=>!![...document.querySelectorAll("a.card")].find(c=>c.title===name)?.querySelector("img")?.naturalWidth', arg=name, timeout=45000)
            proof['plain_picture'] = page.get_by_title(name, exact=True).locator('img').evaluate('''async image=>{
                const response=await fetch(image.src);if(!response.ok)throw Error('category original unavailable');
                const original=await response.blob();const bitmap=await createImageBitmap(original);
                const result={original_width:bitmap.width,original_height:bitmap.height,original_bytes:original.size,
                    original_sha256:[...new Uint8Array(await crypto.subtle.digest('SHA-256',await original.arrayBuffer()))].map(x=>x.toString(16).padStart(2,'0')).join('')};bitmap.close();return result;}''')
            picture = proof['plain_picture']
            assert picture['original_sha256'] == args.original_sha256, picture
            assert picture['original_width'] == 500, picture
            page.screenshot(path=str(out / 'category-original-preserved.png'))
            context.close()
            legacy = browser.new_context(viewport={'width': 1360, 'height': 900})
            legacy.add_init_script('window.OffscreenCanvas=undefined')
            page = legacy.new_page()
            page.goto(plain_url, wait_until='domcontentloaded')
            page.wait_for_function('()=>typeof currentMediaList!=="undefined"&&currentMediaList.length&&art', timeout=45000)
            proof['legacy_without_artwork'] = page.evaluate('''()=>({parser:typeof FrontierMusicMetadata,
                images:document.querySelectorAll('.media-item img').length})''')
            assert proof['legacy_without_artwork'] == {'parser': 'undefined', 'images': 0}
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
