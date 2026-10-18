"""Development-only, real long-MP3 MSE boundary and rolling-buffer acceptance.

The private development page serves byte-identical copies, never production.
Clock acceleration seeks only within already appended audio; every file byte is
still appended to the real MSE pipeline before a track can finish. This is not
an assertion that every audio sample was listened to in real time.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from playwright.sync_api import sync_playwright


def run(args):
    assert args.base_url == 'https://192.168.6.201', 'development only'
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    record = {'passed': False, 'inputs': [], 'transitions': [], 'errors': [],
              'max_retained_seconds': 0, 'max_js_heap_bytes': 0, 'max_backing_storage_bytes': 0,
              'clock_acceleration': 'seek within appended ranges; no claim of full real-time listening',
              'certificate_validation': 'trusted CA and hostname; no bypass'}
    def save():
        (output / 'evidence.json').write_text(json.dumps(record, ensure_ascii=False, indent=2))
    with tempfile.TemporaryDirectory(prefix='fc-long-audio-browser-') as home, sync_playwright() as p:
        nss = Path(home) / '.pki/nssdb'
        nss.mkdir(parents=True)
        subprocess.run(['certutil', '-N', '-d', 'sql:' + str(nss), '--empty-password'], check=True)
        subprocess.run(['certutil', '-A', '-d', 'sql:' + str(nss), '-n', 'development-ca',
                        '-t', 'C,,', '-i', args.ca], check=True)
        browser = p.chromium.launch(executable_path=os.environ['PLAYWRIGHT_CHROMIUM_EXECUTABLE'],
            headless=True, env={**os.environ, 'HOME': home},
            args=['--no-sandbox', '--no-proxy-server', '--autoplay-policy=no-user-gesture-required'])
        page = browser.new_page(viewport={'width': 1400, 'height': 1000})
        page.on('pageerror', lambda e: record['errors'].append(str(e)))
        page.on('console', lambda m: record['errors'].append(m.text)
                if m.type == 'warning' and 'pipeline' in m.text else None)
        cdp = page.context.new_cdp_session(page)
        cdp.send('Performance.enable')
        try:
            record['inputs'].append({'action': 'open', 'url': args.base_url + '/dev-long-audio'})
            page.goto(args.base_url + '/dev-long-audio', wait_until='domcontentloaded')
            page.wait_for_function('() => typeof art!=="undefined" && art?.currentTime > .05', timeout=30000)
            identity = page.evaluate('({src:art.video.currentSrc,generation:frontierCloudContinuousAudio.status().current_index})')
            record['catalog'] = page.evaluate('currentMediaList.map(t=>({title:t.title,bytes:t.bytes,sha256:t.sha256}))')
            last_index = 0
            visited = [0]
            deadline = time.monotonic() + 420
            samples = []
            while time.monotonic() < deadline:
                state = page.evaluate('''() => {
                    const s=frontierCloudContinuousAudio.status(), v=art.video;
                    const ranges=[...Array(v.buffered.length)].map((_,i)=>[v.buffered.start(i),v.buffered.end(i)]);
                    const before=v.currentTime;
                    if(ranges.length && ranges.at(-1)[1] > before+3) v.currentTime=ranges.at(-1)[1]-2;
                    return {index:currentIndex,time:before,src:v.currentSrc,error:v.error?.message,
                        pipeline:s.pipeline_error,retained:s.retained_buffer_seconds,ranges,
                        active:s.active_segment,localDuration:art.duration};
                }''')
                assert state['src'] == identity['src'], 'automatic boundary replaced the MSE session'
                assert not state.get('error') and not state['pipeline'], state
                record['max_retained_seconds'] = max(record['max_retained_seconds'], state['retained'])
                assert state['retained'] < 120, state
                metrics = {v['name']: v['value'] for v in cdp.send('Performance.getMetrics')['metrics']}
                record['max_js_heap_bytes'] = max(record['max_js_heap_bytes'], metrics.get('JSHeapUsedSize', 0))
                heap = cdp.send('Runtime.getHeapUsage')
                record['max_backing_storage_bytes'] = max(record['max_backing_storage_bytes'], heap.get('backingStorageSize', 0))
                assert heap.get('backingStorageSize', 0) < 64 * 1024 * 1024, heap
                if state['index'] != last_index:
                    record['transitions'].append({'from': last_index, 'to': state['index'],
                        'same_mse_src': True, 'state': state})
                    last_index = state['index']
                    visited.append(last_index)
                    save()
                    if len(visited) == 6:
                        break
                if len(samples) < 1000:
                    samples.append({'index': state['index'], 'time': state['time'],
                                    'retained': state['retained'], 'range_start': state['ranges'][0][0] if state['ranges'] else 0})
                page.wait_for_timeout(100)
            assert visited == [0, 1, 2, 3, 4, 0], visited
            assert max(s['range_start'] for s in samples if s['index'] == 1) > 1000, 'long active track never pruned'
            record['samples'] = samples
            record['automatic_long_tracks_verified'] = True
            save()
            # A backward seek after rolling removal must fetch a Range and keep
            # the same logical track. A deliberate unbuffered seek may restart MSE.
            record['inputs'].append({'action': 'manual select', 'index': 1})
            if page.get_by_role('button', name='展开播放队列', exact=True).count():
                page.get_by_role('button', name='展开播放队列', exact=True).click()
            page.locator('.media-item[data-index="1"]').click()
            page.wait_for_function('() => currentIndex===1 && art.currentTime>.05', timeout=30000)
            page.evaluate('art.currentTime=4000')
            page.wait_for_function('() => currentIndex===1 && art.currentTime>3999 && art.video.readyState>=2', timeout=30000)
            page.evaluate('art.currentTime=10')
            page.wait_for_function('() => currentIndex===1 && art.currentTime>=9 && art.currentTime<30 && art.video.readyState>=2', timeout=30000)
            record['seek_after_pruning_verified'] = True
            page.screenshot(path=str(output / 'long-tracks.png'))
            assert record['errors'] == [], record['errors']
            record['passed'] = True
        finally:
            save()
            browser.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--base-url', default='https://192.168.6.201')
    parser.add_argument('--ca', required=True)
    parser.add_argument('--output', required=True)
    run(parser.parse_args())
