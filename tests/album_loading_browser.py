"""Compare original image loading with the prior and candidate browser scheduler.

Uses the same real server, catalog and original covers in fresh browser contexts.
An optional fixed network latency is applied equally to both variants.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import statistics
import time
import urllib.parse

from playwright.sync_api import sync_playwright


def run(args):
    root = Path(__file__).resolve().parents[1]
    sources = {'before': Path(args.baseline_js).read_text(), 'after': (root/'static/js/media-browser.js').read_text()}
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    results = []
    with sync_playwright() as runtime:
        browser = runtime.chromium.launch(executable_path=os.environ['PLAYWRIGHT_CHROMIUM_EXECUTABLE'], headless=True, args=['--no-sandbox'])
        try:
            for round_number in range(args.rounds):
                for label in (('before', 'after') if round_number % 2 == 0 else ('after', 'before')):
                    context = browser.new_context(viewport={'width': 1920, 'height': 1080})
                    page = context.new_page()
                    page.add_init_script("""window.__coverLoads=[];
document.addEventListener('load', event => {
    const image=event.target;
    if (image instanceof HTMLImageElement && image.closest('.card-artwork') && image.naturalWidth>0)
        window.__coverLoads.push({url:image.src,at:performance.now()});
}, true);""")
                    errors, covers, requests, failures = [], [], [], []
                    page.on('pageerror', lambda error: errors.append(str(error)))
                    page.on('requestfailed', lambda request: failures.append({'path':urllib.parse.urlsplit(request.url).path,'failure':request.failure}))
                    if label == 'before':
                        page.route('**/static/js/media-browser.js?*', lambda route: route.fulfill(status=200, content_type='application/javascript', body=sources['before']))
                    if args.rtt_ms:
                        session = context.new_cdp_session(page)
                        session.send('Network.enable')
                        session.send('Network.emulateNetworkConditions', {'offline': False, 'latency': args.rtt_ms, 'downloadThroughput': 4*1024*1024, 'uploadThroughput': 4*1024*1024})
                    start = time.monotonic()
                    def response_received(response):
                        if '/api/v1/media/cover?' in response.url:
                            covers.append({'url': response.url, 'at_seconds': time.monotonic()-start, 'response': response})
                    page.on('response', response_received)
                    page.on('request', lambda request: requests.append({'url': request.url, 'at_seconds': time.monotonic()-start}) if '/catalog/artwork?' in request.url else None)
                    target = args.base_url.rstrip('/')+'/api/v1/media/music/category?'+urllib.parse.urlencode({'path': args.path})
                    page.goto(target, wait_until='domcontentloaded', timeout=30000)
                    if label == 'after':
                        source_url=page.locator('script[src*="/static/js/media-browser.js"]').get_attribute('src')
                        actual=context.request.get(urllib.parse.urljoin(args.base_url,source_url)).text()
                        assert hashlib.sha256(actual.encode()).digest()==hashlib.sha256(sources['after'].encode()).digest(), 'server did not serve candidate scheduler'
                    try:
                        page.wait_for_function('(expected) => [...document.querySelectorAll(".card-artwork img")].filter(i=>i.complete&&i.naturalWidth>0).length>=expected', arg=args.expected_covers, timeout=45000)
                    except Exception:
                        (output/'failure.json').write_text(json.dumps({'variant':label,'round':round_number,'errors':errors,'failed_requests':failures,'artwork_requests':requests,'text':page.locator('body').inner_text()},ensure_ascii=False,indent=2))
                        raise
                    wall_elapsed = time.monotonic()-start
                    loads = page.evaluate('window.__coverLoads')
                    assert len(loads) >= args.expected_covers, loads
                    elapsed = sorted(entry['at'] for entry in loads)[args.expected_covers-1]/1000
                    images = page.locator('.card-artwork img').evaluate_all('(images)=>images.map(i=>({url:i.src,width:i.naturalWidth,height:i.naturalHeight}))')
                    for entry in covers:
                        raw = entry.pop('response').body()
                        entry.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
                    assert not errors, errors
                    page.screenshot(path=str(output/f'{label}-{round_number}.png'))
                    results.append({'variant': label, 'round': round_number, 'complete_seconds': elapsed, 'test_wall_seconds': wall_elapsed, 'browser_image_load_events': loads, 'cover_count': len(images), 'images': images, 'covers': covers, 'artwork_requests': requests, 'page_errors': errors})
                    context.close()
                    time.sleep(1)
        finally:
            browser.close()
    before = statistics.median(x['complete_seconds'] for x in results if x['variant']=='before')
    after = statistics.median(x['complete_seconds'] for x in results if x['variant']=='after')
    by_variant = {variant: {urllib.parse.urlsplit(c['url']).query: c['sha256'] for run in results if run['variant']==variant for c in run['covers']} for variant in ('before','after')}
    assert by_variant['before'] == by_variant['after'], 'original cover bytes changed or benchmark loaded different covers'
    proof = {'real_browser': True, 'base_url': args.base_url, 'path': args.path, 'equal_emulated_network_latency_ms': args.rtt_ms, 'median_before_seconds': before, 'median_after_seconds': after, 'improvement_percent': (before-after)/before*100, 'original_cover_sha256_equal': True, 'runs': results}
    (output/'evidence.json').write_text(json.dumps(proof, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({key: value for key,value in proof.items() if key!='runs'}, ensure_ascii=False), flush=True)
    assert after < before, 'candidate did not improve median loading time'


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', required=True)
    parser.add_argument('--path', required=True)
    parser.add_argument('--baseline-js', required=True)
    parser.add_argument('--expected-covers', type=int, default=3)
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--rtt-ms', type=int, default=0)
    parser.add_argument('--output', required=True)
    run(parser.parse_args())
