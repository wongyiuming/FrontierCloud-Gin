"""Additional real Chromium gate for the default five-node, two-database fleet.

Run alongside scripts/test-native-matrix.sh with FRONTIERCLOUD_TEST_MEDIA_BROWSER=1.
The printed workspace is this client's --workspace. No application imports,
TLS exceptions or deployed environments are supported. The account-outage
subcase explicitly injects an HTTP 503; ordinary playback uses real responses.
The native Go driver still performs its complete default matrix afterwards.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import time
from urllib.parse import urlencode, urlsplit
import uuid
import zlib

from playwright.sync_api import sync_playwright


FORMAT = 'frontiercloud-gin-native-media-browser-v1'
CASES = {(site, mode) for site in ('primary', 'direct', 'relay') for mode in ('plain', 'encrypted')}
LONG_TEXT = '这句歌词超过屏幕宽度需要自动换行而不能截掉文字顶部和底部' * 3


def digest(value):
    return hashlib.sha256(value).hexdigest()


def private_json(path, value):
    temporary = path.with_name('.media-browser-' + uuid.uuid4().hex + '.tmp')
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    if path.exists():
        temporary.unlink()
        raise ValueError('existing browser evidence will not be overwritten')
    os.replace(temporary, path)


def regular(path, root, maximum):
    if not path.is_absolute() or not path.is_relative_to(root):
        raise ValueError('absolute owned fixture file required')
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ValueError('fixture symlink refused')
        if parent == root:
            break
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum:
        raise ValueError('bounded regular fixture file required')
    return path.read_bytes()


def read_fixture(path, workspace):
    if path != workspace / path.parent.name / 'media-browser-fixture.json' or path.parent.name not in ('go-sqlite', 'go-mysql'):
        raise ValueError('exact database browser handoff required')
    value = json.loads(regular(path, workspace, 32768))
    if value.get('format') != FORMAT or value.get('database') != path.parent.name or not re.fullmatch('[a-f0-9]{32}', value.get('nonce', '')):
        raise ValueError('browser handoff format or identity invalid')
    if value.get('origin') != 'https://site0.fleet.invalid' or value.get('web_cpu_limit') != 1 or value.get('web_memory_bytes') != 512 * 1024**2:
        raise ValueError('native HTTPS origin and resource bounds required')
    hosts = value.get('hosts')
    if not isinstance(hosts, dict) or set(hosts) != {f'site{i}.fleet.invalid' for i in range(5)}:
        raise ValueError('exact five native fixture hosts required')
    for address in hosts.values():
        ip = ipaddress.ip_address(address)
        if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_unspecified:
            raise ValueError('private Docker IPv4 required')
    owners = value.get('owners')
    origins = {'https://site' + str(i) + '.fleet.invalid' + (':8443' if i > 2 else '') for i in range(5)}
    if not isinstance(owners, dict) or set(owners.values()) != origins or len(owners) != 5 or any(not re.fullmatch('[a-f0-9]{32}', key) for key in owners):
        raise ValueError('exact native owner identities required')
    expected = {'ca_file': path.parent / 'certs/ca.pem', 'admin_key_file': path.parent / 'site0/secrets/admin_key'}
    for field, target in expected.items():
        if value.get(field) != str(target):
            raise ValueError('fixture credential or CA path mismatch')
    ca = regular(expected['ca_file'], workspace, 65536)
    key = regular(expected['admin_key_file'], workspace, 4096).decode().strip()
    if not ca.startswith(b'-----BEGIN CERTIFICATE-----') or not 16 <= len(key) <= 512 or expected['admin_key_file'].stat().st_mode & 0o077:
        raise ValueError('bounded private admin key and actual public CA required')
    return value, key, digest(ca)


def picture(index):
    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))
    scan = b''.join(b'\0' + bytes((220 if index == 0 else 20, row, 220 if index == 1 else 20)) * 64 for row in range(64))
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 64, 64, 8, 2, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(scan)) + chunk(b'IEND', b'')


def tag(title, image):
    def frame(name, data):
        return name.encode() + struct.pack('>I', len(data)) + b'\0\0' + data
    body = frame('TIT2', b'\x03' + title.encode()) + frame('TPE1', b'\x03Native acceptance') + frame('TALB', b'\x03Native album') + frame('APIC', b'\x03image/png\0\x03\0' + image)
    size = len(body)
    return b'ID3\x03\0\0' + bytes((size >> shift) & 127 for shift in (21, 14, 7, 0)) + body


def audio_fixtures(audio, root):
    # A pre-generated, disposable MP3 tone is a test input. No encoder or new
    # media-processing dependency is added to any product container.
    tone = audio.read_bytes()
    if not 1000 <= len(tone) <= 8 * 1024**2:
        raise ValueError('bounded real MP3 tone input required')
    source_sha = digest(tone)
    if tone.startswith(b'ID3'):
        tone = tone[10 + sum((byte & 127) << shift for byte, shift in zip(tone[6:10], (21, 14, 7, 0))):]
    if len(tone) < 1000 or tone[0] != 255:
        raise ValueError('real MPEG audio frames required')
    root.mkdir(mode=0o700)
    images = [picture(0), picture(1)]
    with (root / '01-long.mp3').open('xb') as stream:
        stream.write(tag('Long original', images[0]))
        for _ in range((129 * 1024**2) // len(tone) + 1):
            stream.write(tone)
    (root / '02-next.mp3').write_bytes(tag('Next original', images[1]) + tone * 3)
    for path in root.iterdir():
        path.chmod(0o600)
    return images, source_sha


def wait_file(path, nonce, seconds=60):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.exists():
            value = json.loads(regular(path, path.parent.parent, 32768))
            if value.get('nonce') != nonce:
                raise ValueError('browser handoff nonce mismatch')
            return value
        time.sleep(.2)
    raise TimeoutError('owned browser handoff expired')


def open_media(admin):
    heading = admin.locator('[data-admin-module="media"] .module-heading')
    if heading.get_attribute('aria-expanded') != 'true':
        heading.click()


def choose_upload(admin, button, mode, files, count):
    admin.locator('#uploadBtn').click()
    admin.locator(button).click()
    dialog = admin.locator('dialog.upload-storage-mode-dialog')
    dialog.wait_for(state='visible')
    if dialog.locator('div button').all_text_contents() != ['加密落盘', '明文落盘']:
        raise AssertionError('upload mode must be explicitly chosen')
    with admin.expect_file_chooser() as chooser:
        dialog.get_by_role('button', name='加密落盘' if mode == 'encrypted' else '明文落盘', exact=True).click()
    chooser.value.set_files(str(files))
    admin.wait_for_function('() => !uploadRunning && document.getElementById("uploadSummary").textContent.startsWith("完成：")', timeout=180000)
    assert admin.locator('#uploadSummary').inner_text() == f'完成：成功 {count}，失败 0', 'real GUI upload failed'


def observe_address(admin, folder, fixture, site, mode):
    value = admin.evaluate('''async folder => {
        currentPath=folder;document.getElementById('mediaSearch').value='';await renderTree();
        return visibleMediaItems.map(item=>({path:item.path,kind:item.kind,owner:item.storage_member_id,
            transport:item.transport,address:item.storage_address,local:item.storage_address_local,
            encrypted:!!(item.encryption||item.encrypted)}));
    }''', folder)
    assert len(value) == 2 and all(row['kind'] == 'file' for row in value), 'actual Admin file inventory mismatch'
    for row in value:
        assert row['address'] == fixture['owners'].get(row['owner']), 'address must follow exact persisted owner'
        assert row['local'] is (site == 'primary') and row['encrypted'] is (mode == 'encrypted')
        assert row['transport'] == {'primary': 'Local', 'direct': 'Direct', 'relay': 'Relay'}[site]
    expected = {row['path']: row['address'] for row in value}
    actual = admin.locator('.tree-row[data-path] .media-node-address').evaluate_all('nodes=>nodes.map(n=>({path:n.closest(".tree-row").dataset.path,address:n.title,text:n.textContent}))')
    assert {row['path']: row['address'] for row in actual} == expected, 'actual address DOM missing or incorrect'
    assert all(row['text'] == row['address'].split('://', 1)[1] for row in actual)
    searched = admin.evaluate('''async()=>{
        document.getElementById('mediaSearch').value='01-long';await renderTree();
        return visibleMediaItems.map(item=>({path:item.path,address:item.storage_address,local:item.storage_address_local}));
    }''')
    assert len(searched) == 1 and searched[0]['address'] == expected[searched[0]['path']]
    assert admin.locator('.media-node-address').count() == 1
    return value


def exercise_player(browser, fixture, folder, mode, site, images, record):
    context = browser.new_context(viewport={'width': 1400, 'height': 1000})
    page = context.new_page()
    errors, responses = [], []
    page.on('pageerror', lambda error: errors.append(type(error).__name__))
    page.on('response', lambda response: responses.append({'path': urlsplit(response.url).path, 'status': response.status}))
    proof = dict(site_type=site, storage_mode=mode, above_128mib=False, manual_mse=False, automatic_mse=False,
                 visible_metadata=False, original_pictures=False, admin_address=True, plaintext_range=False)
    try:
        page.goto(fixture['origin'] + '/api/v1/media/music/category?' + urlencode({'path': folder}), wait_until='domcontentloaded')
        page.wait_for_function('() => typeof art!=="undefined" && art && currentMediaList.length===2', timeout=45000)
        page.evaluate('()=>{window.FrontierPlayerLayout?.expand();selectMedia(currentMediaList.findIndex(t=>t.media_path.endsWith("/01-long.mp3")));}')
        page.wait_for_function('() => currentMediaList[currentIndex].media_path.endsWith("/01-long.mp3") && art.currentTime>.2 && art.duration>8000 && frontierCloudContinuousAudio.status().active && !art.video.error', timeout=45000)
        assert page.evaluate('(encrypted)=>currentMediaList.every(t=>!!t.encryption===encrypted && (encrypted ? !t.native_metadata : t.native_metadata===true))', mode == 'encrypted')
        proof['above_128mib'] = True
        ranged = page.evaluate('''async()=>{const response=await fetch(currentMediaList[0].url,{headers:{Range:'bytes=0-31'}});
            return {status:response.status,bytes:[...new Uint8Array(await response.arrayBuffer())],range:response.headers.get('Content-Range')};}''')
        with (Path(record['source_album']) / '01-long.mp3').open('rb') as stream:
            assert ranged['status'] == 206 and bytes(ranged['bytes']) == stream.read(32)
        proof['plaintext_range'] = True
        proof['range'] = {'status': ranged['status'], 'bytes': len(ranged['bytes']), 'sha256': digest(bytes(ranged['bytes']))}
        page.locator('.media-item[data-index="1"]').click()
        page.wait_for_function('() => currentIndex===1 && art.currentTime>.1 && !art.video.paused && !art.video.error && frontierCloudContinuousAudio.status().active', timeout=30000)
        page.locator('.media-item[data-index="0"]').click()
        page.wait_for_function('() => currentIndex===0 && art.currentTime>.1 && art.duration>8000', timeout=30000)
        proof['manual_mse'] = True
        page.evaluate('()=>{art.currentTime=art.duration-2;return art.play();}')
        page.wait_for_function('() => currentIndex===0 && art.duration>8000 && art.currentTime>=art.duration-3 && !art.video.seeking && frontierCloudContinuousAudio.status().active', timeout=30000)
        page.evaluate('()=>{window.nativeMSEVideo=art.video;window.nativeMSESource=art.url;window.nativeMSECurrentSrc=art.video.currentSrc;}')
        page.wait_for_function('() => currentIndex===1 && art.currentTime>.1 && !art.video.paused && !art.video.error', timeout=45000)
        assert page.evaluate('art.video===nativeMSEVideo && art.url===nativeMSESource && art.video.currentSrc===nativeMSECurrentSrc && frontierCloudContinuousAudio.status().active && !frontierCloudContinuousAudio.status().pipeline_error')
        proof['automatic_mse'] = True
        # Observe normal selected/visible metadata work before making any
        # explicit tag call. This catches permanently starved visible queues.
        page.wait_for_function('() => currentMediaList.every(t=>["Long original","Next original"].includes(t.title) && t.cover && t.cover!=="/favicon.ico")', timeout=30000)
        proof['visible_metadata'] = True
        metadata = page.evaluate('''async()=>Promise.all(currentMediaList.map(async item=>{
            let bytes;if(item.encryption){const url=FrontierMediaCrypto.virtualUrl(item.media_path,false,item.encryption.file_id);
                const response=await fetch(url,{headers:{Range:'bytes=0-16383'},cache:'no-store'});
                if(response.status!==206)throw Error('plaintext tag range failed');
                bytes=FrontierMusicMetadata.parse(new Uint8Array(await response.arrayBuffer())).picture.bytes;
            }else{const response=await fetch(item.cover);if(!response.ok)throw Error('original cover failed');bytes=new Uint8Array(await response.arrayBuffer());}
            const dimensions=await new Promise((resolve,reject)=>{const image=new Image();image.onload=()=>resolve([image.naturalWidth,image.naturalHeight]);
                image.onerror=()=>reject(Error('original picture decode failed'));image.src=item.cover;});
            return {path:item.media_path,title:item.title,dimensions,sha256:[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(v=>v.toString(16).padStart(2,'0')).join('')};
        }))''')
        assert [row['title'] for row in metadata] == ['Long original', 'Next original']
        assert [row['sha256'] for row in metadata] == [digest(image) for image in images]
        assert all(row['dimensions'] == [64, 64] for row in metadata)
        proof.update(original_pictures=True, metadata=metadata, real_tail_seek=True, whole_track_elapsed=False)
        page.evaluate('()=>art.pause()')
        assert not errors, 'player page script error'
        proof['page_errors'] = errors
        proof['karaoke_id'] = page.evaluate('currentMediaList[1].karaoke_id')
        page.screenshot(path=str(Path(record['output']) / (site + '-' + mode + '.png')))
        return proof
    except BaseException:
        record['failed_case'] = site + '-' + mode
        record['failed_responses'] = responses[-30:]
        record['page_error_types'] = errors
        raise
    finally:
        context.close()


def lyric_geometry(page, selector):
    return page.locator(selector).evaluate('''line=>{
        line.style.whiteSpace='nowrap';const before=getComputedStyle(line).fontSize;line.style.removeProperty('white-space');
        const style=getComputedStyle(line),box=line.getBoundingClientRect(),range=document.createRange();range.selectNodeContents(line);
        const rows=[...range.getClientRects()],panel=line.closest('.sync-lyrics-lines,.fullscreen-lyrics-column,#lyrics'),clip=panel?.getBoundingClientRect();
        return {before,after:style.fontSize,textLength:line.textContent.length,whiteSpace:style.whiteSpace,rows:rows.length,
            glyphsInside:rows.every(row=>row.top>=box.top-1&&row.bottom<=box.bottom+1),
            glyphsInsidePanel:!clip||rows.every(row=>row.top>=clip.top-1&&row.bottom<=clip.bottom+1),
            scrollWidth:line.scrollWidth,clientWidth:line.clientWidth,scrollHeight:line.scrollHeight,clientHeight:line.clientHeight};}''')


def check_geometry(value, require_visible=True):
    assert value['before'] == value['after'] and value['whiteSpace'] == 'normal' and value['rows'] > 1 and value['glyphsInside']
    if require_visible:
        assert value['glyphsInsidePanel']
    assert value['scrollWidth'] <= value['clientWidth'] + 1 and value['scrollHeight'] <= value['clientHeight'] + 1


def lyric_viewport(page, selector):
    return page.locator(selector).evaluate('''line=>{
        const panel=line.closest('.sync-lyrics-lines,.fullscreen-lyrics-column,#lyrics');
        if(!panel)throw Error('actual lyric viewport required');
        const range=document.createRange();range.selectNodeContents(line);const glyphs=[...range.getClientRects()];
        const box=panel.getBoundingClientRect(),style=getComputedStyle(panel);
        return {glyphTop:Math.min(...glyphs.map(r=>r.top)),glyphBottom:Math.max(...glyphs.map(r=>r.bottom)),
            top:box.top+panel.clientTop,bottom:box.top+panel.clientTop+panel.clientHeight,
            height:panel.clientHeight,scrollHeight:panel.scrollHeight,scrollTop:panel.scrollTop,
            x:box.left+box.width/4,overflowY:style.overflowY,pointerEvents:style.pointerEvents,
            fontSize:getComputedStyle(line).fontSize,textLength:line.textContent.length};
    }''')


def native_lyric_scroll(page, selector, edge, mechanism):
    cdp = page.context.new_cdp_session(page) if mechanism == 'touch' else None
    count = 0
    try:
        for _ in range(12):
            state = lyric_viewport(page, selector)
            if edge == 'start':
                reached = state['glyphTop'] >= state['top']-1 and state['glyphTop'] < state['bottom']-1
                delta = state['glyphTop']-state['top']-6
            else:
                reached = state['glyphBottom'] <= state['bottom']+1 and state['glyphBottom'] > state['top']+1
                delta = state['glyphBottom']-state['bottom']+6
            if reached:
                return {**state, 'native_input_count': count}
            assert state['overflowY'] in ('auto', 'scroll') and state['pointerEvents'] != 'none'
            if mechanism == 'wheel':
                page.mouse.move(state['x'], (state['top']+state['bottom'])/2)
                page.mouse.wheel(0, delta)
            else:
                distance = min(max(abs(delta), 24), state['height']*.55)
                direction = 1 if delta > 0 else -1
                start = state['top']+state['height']*(.8 if direction > 0 else .2)
                assert page.locator(selector).evaluate('''(line,point)=>line.closest('.sync-lyrics-lines,.fullscreen-lyrics-column,#lyrics')
                    .contains(document.elementFromPoint(point.x,point.y))''', {'x': state['x'], 'y': start}), 'touch must start on lyrics, outside playback controls'
                cdp.send('Input.dispatchTouchEvent', {'type': 'touchStart', 'touchPoints': [{'x': state['x'], 'y': start}]})
                for step in range(1, 13):
                    point = {'x': state['x'], 'y': start-direction*distance*step/12}
                    cdp.send('Input.dispatchTouchEvent', {'type': 'touchMove', 'touchPoints': [point]})
                    page.wait_for_timeout(24)
                # A real finger pause before release avoids an uncontrolled fling.
                page.wait_for_timeout(100)
                cdp.send('Input.dispatchTouchEvent', {'type': 'touchEnd', 'touchPoints': []})
            count += 1
            page.wait_for_timeout(120)
        raise AssertionError('lyric edge not reachable using actual '+mechanism)
    finally:
        if cdp is not None:
            cdp.detach()


def check_native_scroll_evidence(value, inputs):
    check_geometry(value, require_visible=False)
    assert len(inputs) == 2 and {row['mechanism'] for row in inputs} == {'wheel', 'touch'}
    for row in inputs:
        start, end = row['start'], row['end']
        assert all(type(v['native_input_count']) is int and v['native_input_count'] > 0 for v in (start, end))
        assert start['fontSize'] == end['fontSize'] == value['after']
        assert start['textLength'] == end['textLength'] == value['textLength']
        assert start['glyphTop'] >= start['top']-1 and start['glyphTop'] < start['bottom']-1
        assert end['glyphBottom'] <= end['bottom']+1 and end['glyphBottom'] > end['top']+1


def verify_lyric_access(page, selector, preserve_playback=False):
    value, viewport = lyric_geometry(page, selector), lyric_viewport(page, selector)
    tall = viewport['glyphBottom']-viewport['glyphTop'] > viewport['height']
    check_geometry(value, require_visible=not tall)
    if not tall:
        return {'geometry': value, 'viewport': viewport, 'all_glyphs_visible': True}
    before = page.evaluate('()=>({index:currentIndex,time:art.currentTime,paused:art.video.paused})') if preserve_playback else None
    inputs = []
    for mechanism in ('wheel', 'touch'):
        end = native_lyric_scroll(page, selector, 'end', mechanism)
        start = native_lyric_scroll(page, selector, 'start', mechanism)
        inputs.append({'mechanism': mechanism, 'start': start, 'end': end})
    check_native_scroll_evidence(value, inputs)
    if before is not None:
        viewport_node = page.locator(selector).locator('xpath=..')
        assert viewport_node.get_attribute('id') == 'inlineLyricsTrack'
        viewport_node.locator('xpath=..').focus()
        scroll_before = lyric_viewport(page, selector)['scrollTop']
        page.keyboard.press('PageDown')
        page.wait_for_function('(before)=>document.getElementById("inlineLyricsLines").scrollTop>before+1', arg=scroll_before)
        after = page.evaluate('()=>({index:currentIndex,time:art.currentTime,paused:art.video.paused})')
        assert before['index'] == after['index'] and before['paused'] and after['paused']
        assert abs(before['time']-after['time']) < .05, 'vertical lyric input must not seek'
    return {'geometry': value, 'viewport': viewport, 'all_glyphs_visible_at_once': False,
            'complete_text_accessible_by_actual_input': inputs, 'keyboard_scroll_preserved_playback': before is not None}


def verify_center_play(page):
    inputs = []
    for text in ('短句', LONG_TEXT):
        for mechanism in ('mouse', 'touch'):
            page.evaluate('''text=>{art.pause();const base=art.currentTime;
                activeLyricEntries=Array.from({length:7},(_,i)=>({time:i<=3?0:base+(i-3)*60,text:i===3?text:'短句'}));
                document.getElementById('inlineLyrics').classList.remove('hidden');renderLyricWindow(3);}''', text)
            page.wait_for_function('()=>art.video.paused && !art.video.seeking && !art.maskElement.hidden')
            before = page.evaluate('''()=>{const button=art.maskElement,box=button.getBoundingClientRect();
                const x=box.left+box.width/2,y=box.top+box.height/2;
                return {x,y,buttonHit:document.elementFromPoint(x,y)?.closest('.art-center-play')===button,
                    index:currentIndex,sequence:playerSwitchSequence,source:art.video.currentSrc,time:art.currentTime,
                    lyricLength:document.querySelector('#inlineLyricsTrack .sync-lyric.current').textContent.length};}''')
            assert before['buttonHit'] and before['lyricLength'] == len(text)
            state = page.evaluate_handle('''()=>{const state={video:art.video,seeks:0};
                state.onSeek=()=>state.seeks++;state.video.addEventListener('seeking',state.onSeek);return state;}''')
            try:
                if mechanism == 'mouse':
                    page.mouse.click(before['x'], before['y'])
                else:
                    page.touchscreen.tap(before['x'], before['y'])
                page.wait_for_function('(before)=>!art.video.paused && art.currentTime>before+.05', arg=before['time'], timeout=30000)
                # Observe beyond the background gesture's 250ms next-track timer.
                page.wait_for_timeout(400)
                after = page.evaluate('''state=>({index:currentIndex,sequence:playerSwitchSequence,
                    source:art.video.currentSrc,time:art.currentTime,paused:art.video.paused,pending:clickTimer!==null,
                    sameVideo:state.video===art.video,seeks:state.seeks})''', state)
            finally:
                page.evaluate("state=>state.video.removeEventListener('seeking',state.onSeek)", state)
                state.dispose()
            assert not after['paused'] and not after['pending']
            assert (before['index'], before['sequence'], before['source']) == (after['index'], after['sequence'], after['source'])
            assert after['sameVideo'] and after['seeks'] == 0 and before['time'] < after['time'], 'center play must resume without seeking'
            inputs.append({'mechanism': mechanism, 'before': before, 'after': after})
    page.evaluate('()=>art.pause()')
    return inputs


def verify_lyric_gestures(page):
    page.evaluate('()=>selectMedia(0)')
    page.wait_for_function('() => currentIndex===0 && art.currentTime>.1 && !art.video.paused', timeout=30000)
    point = page.locator('#inlineLyricsLines').evaluate('node=>{const r=node.getBoundingClientRect();return {x:r.left+r.width*.55,y:r.top+r.height*.35};}')
    page.mouse.click(point['x'], point['y'])
    page.wait_for_function('() => currentIndex===1 && art.currentTime>.1 && !art.video.paused', timeout=30000)
    page.mouse.dblclick(point['x'], point['y'], delay=80)
    page.wait_for_function('() => currentIndex===0 && art.currentTime>.1 && !art.video.paused', timeout=30000)
    page.evaluate('()=>art.pause()')
    before = page.evaluate('()=>art.currentTime')
    page.mouse.move(point['x']-45, point['y']);page.mouse.down()
    page.mouse.move(point['x']+45, point['y'], steps=12);page.mouse.up()
    page.wait_for_function('(before)=>currentIndex===0 && art.video.paused && art.currentTime>=before+15 && art.currentTime<=before+22', arg=before, timeout=30000)
    return {'single_click_next': True, 'double_click_previous': True, 'horizontal_drag_seeks_without_track_change': True,
            'horizontal_delta_seconds': page.evaluate('()=>art.currentTime')-before}


def exercise_lyrics_and_karaoke(browser, fixture, folder, karaoke_id, record):
    context = browser.new_context(viewport={'width': 390, 'height': 844}, has_touch=True)
    page = context.new_page()
    geometry = []
    try:
        page.goto(fixture['origin'] + '/api/v1/media/music/category?' + urlencode({'path': folder}), wait_until='domcontentloaded')
        page.wait_for_function('() => typeof art!=="undefined" && art && typeof FrontierLyricsUI!=="undefined"', timeout=45000)
        page.wait_for_function('() => art.currentTime>.1 && !art.video.seeking && art.video.readyState>=2 && inlineLyricsRequest===null', timeout=30000)
        page.evaluate('()=>art.pause()')
        page.wait_for_function('() => art.video.paused')
        for width, height in ((390, 844), (768, 1024), (1360, 768)):
            page.set_viewport_size({'width': width, 'height': height})
            # Layout-only fixture data passes through the actual served shared
            # renderer. No response, asset or player implementation is replaced.
            page.evaluate('''text=>{const base=art.currentTime;activeLyricEntries=Array.from({length:11},(_,i)=>({time:i<=3?0:base+i-3,text:i===3?text:'短句 '+i}));
                document.getElementById('inlineLyrics').classList.remove('hidden');renderLyricWindow(3);}''', LONG_TEXT)
            page.wait_for_function('() => (document.getElementById("inlineLyricsTrack").children.length===7)')
            page.wait_for_function('(text)=>activeLyricIndex===3 && document.querySelector("#inlineLyricsTrack .sync-lyric.current").textContent===text', arg=LONG_TEXT)
            inline = verify_lyric_access(page, '#inlineLyricsTrack .sync-lyric.current', preserve_playback=True)
            wrapped = page.evaluate('''()=>{const track=document.getElementById('inlineLyricsTrack');
                animateLyricForward(4);return {stationary:new DOMMatrixReadOnly(getComputedStyle(track).transform).isIdentity,
                    rows:track.children.length,active:activeLyricIndex};}''')
            assert wrapped == {'stationary': True, 'rows': 7, 'active': 4}
            page.evaluate('()=>{activeLyricEntries.forEach(entry=>entry.text="短句");renderLyricWindow(3);}')
            animation = page.evaluate('''()=>{const track=document.getElementById('inlineLyricsTrack'),height=track.firstElementChild.offsetHeight;
                animateLyricForward(4);return {height,transform:track.style.transform,rows:track.children.length};}''')
            assert animation['height'] > 0 and animation['transform'] == f"translateY(-{animation['height']}px)" and animation['rows'] == 8
            page.wait_for_function('() => (document.getElementById("inlineLyricsTrack").children.length===7)')
            page.evaluate('''text=>{activeLyricEntries[3].text=text;renderLyricWindow(3);}''', LONG_TEXT)
            page.evaluate('()=>{openFullscreenLyrics();renderFullscreenLyrics();sizeFullscreenLyrics();}')
            full = verify_lyric_access(page, '.fullscreen-lyric-line[data-lyric-index="3"]')
            assert page.locator('.fullscreen-lyrics-column').count() == 3
            page.screenshot(path=str(Path(record['output']) / f'lyrics-{width}.png'))
            page.evaluate('()=>closeFullscreenLyrics()')
            center_play = verify_center_play(page)
            geometry.append({'viewport': [width, height], 'inline': inline, 'fullscreen': full,
                             'row_offset': animation, 'wrapped_direct_render': wrapped,
                             'center_play_inputs': center_play})
        gestures = verify_lyric_gestures(page)
        record['shared_lyrics'] = {'actual_served_renderer': True, 'layout_fixture_not_lyric_relation': True, 'layouts': geometry, 'gestures': gestures}
        record['shared_lyrics_verified'] = True
    finally:
        context.close()
    context = browser.new_context(viewport={'width': 1360, 'height': 900})
    context.add_init_script('''window.nativeKaraoke={context200:false,account200:false,accountStatus:0,prematureEnable:false,microphoneCalls:0};
        const savedFetch=window.fetch.bind(window);window.fetch=(...args)=>{const result=savedFetch(...args);result.then(response=>{
            const path=new URL(response.url).pathname;if(path==='/api/v1/karaoke/context')nativeKaraoke.context200=response.status===200;
            if(path==='/api/v1/karaoke/account/status'){nativeKaraoke.account200=response.status===200;
                nativeKaraoke.accountStatus=response.status;}},()=>{});return result;};
        const media=navigator.mediaDevices;if(media?.getUserMedia){const original=media.getUserMedia.bind(media);
            media.getUserMedia=(...args)=>{nativeKaraoke.microphoneCalls++;return original(...args);};}
        new MutationObserver(()=>{const button=document.getElementById('record');if(button&&!button.disabled&&
            !nativeKaraoke.context200)nativeKaraoke.prematureEnable=true;
        }).observe(document,{subtree:true,childList:true,attributes:true,attributeFilter:['disabled']});''')
    page = context.new_page()
    try:
        page.goto(fixture['origin'] + '/karaoke/?' + urlencode({'media': karaoke_id}), wait_until='domcontentloaded')
        page.wait_for_function('() => (typeof state!=="undefined" && state.ready && nativeKaraoke.account200 && !document.getElementById("record").disabled)', timeout=30000)
        actual = page.evaluate('({...nativeKaraoke,ready:state.ready,shared:!!window.FrontierLyricsUI,rows:document.querySelector("#lyrics").children.length,phase:state.phase})')
        assert actual['context200'] and actual['account200'] and not actual['prematureEnable'] and actual['microphoneCalls'] == 0
        assert actual['ready'] and actual['shared'] and actual['rows'] == 7 and actual['phase'] == 'idle'
        page.evaluate('''text=>{state.lyrics=Array.from({length:7},(_,i)=>({time:Math.max(0,i-3),text:i===3?text:'短句'}));
            state.activeLyric=3;renderLyricContainer(elements.lyrics,3);}''', LONG_TEXT[:40])
        karaoke_geometry = lyric_geometry(page, '#lyrics .sync-lyric.current')
        check_geometry(karaoke_geometry)
        page.locator('#fullLyrics').click()
        assert page.locator('#lyricsOverlay .fullscreen-lyrics-column').count() == 3
        page.screenshot(path=str(Path(record['output']) / 'karaoke-ready.png'))
        def account_failure(route):
            route.fulfill(status=503, content_type='application/json', body='{"detail":"Account unavailable in fault injection"}')
        context.route('**/api/v1/karaoke/account/status', account_failure)
        guest = context.new_page()
        guest.goto(fixture['origin'] + '/karaoke/?' + urlencode({'media': karaoke_id}), wait_until='domcontentloaded')
        guest.wait_for_function('() => (typeof state!=="undefined" && state.ready && nativeKaraoke.accountStatus===503 && !elements.record.disabled)', timeout=30000)
        guest_state = guest.evaluate('''({...nativeKaraoke,ready:state.ready,disabled:elements.record.disabled,
            guest:state.account===null,uploadDisabled:elements.upload.disabled})''')
        assert guest_state['context200'] and not guest_state['account200'] and not guest_state['prematureEnable']
        assert guest_state['ready'] and not guest_state['disabled'] and guest_state['guest'] and guest_state['uploadDisabled']
        assert guest_state['microphoneCalls'] == 0
        guest.close()
        context.unroute('**/api/v1/karaoke/account/status', account_failure)
        failed = context.new_page()
        failed.goto(fixture['origin'] + '/karaoke/', wait_until='domcontentloaded')
        failed.wait_for_function('() => (typeof state!=="undefined" && document.getElementById("status").textContent.includes("初始化失败"))', timeout=30000)
        refused = failed.evaluate('''async()=>{await startRecording();return {ready:state.ready,disabled:elements.record.disabled,
            phase:state.phase,microphoneCalls:nativeKaraoke.microphoneCalls};}''')
        assert refused == {'ready': False, 'disabled': True, 'phase': 'idle', 'microphoneCalls': 0}
        failed.close()
        record['karaoke'] = {'valid': actual, 'invalid_media_refused': refused, 'lyrics': karaoke_geometry,
                             'guest_account_503': guest_state, 'account_fault_injection': True,
                             'microphone_or_recording_tested': False, 'response_observation_only': True}
        record['karaoke_readiness_verified'] = True
    finally:
        context.close()


def run_fixture(path, workspace, audio):
    fixture, key, ca_sha = read_fixture(path, workspace)
    root = path.parent
    output = root / 'media-browser-evidence'
    output.mkdir(mode=0o700)
    record = {'format': FORMAT, 'nonce': fixture['nonce'], 'database': fixture['database'], 'passed': False,
              'tls_errors_ignored': False, 'production_changed': False, 'playback': [], 'inputs': [],
              'output': str(output), 'source_album': str(output / 'album'), 'test_ca_sha256': ca_sha,
              'whole_default_matrix_complete': False, 'web_cpu_limit': 1, 'web_memory_bytes': 512 * 1024**2}
    browser = None
    try:
        images, tone_sha = audio_fixtures(audio, output / 'album')
        record['tone_input_sha256'] = tone_sha
        home = output / 'browser-home'
        nss = home / '.pki/nssdb'
        nss.mkdir(mode=0o700, parents=True)
        for command in (['certutil', '-N', '-d', 'sql:' + str(nss), '--empty-password'],
                        ['certutil', '-A', '-d', 'sql:' + str(nss), '-n', 'native-fleet-ca', '-t', 'C,,', '-i', fixture['ca_file']]):
            completed = subprocess.run(command, capture_output=True, timeout=30)
            if completed.returncode:
                raise RuntimeError('normal NSS fixture CA trust setup failed')
        executable = os.environ['PLAYWRIGHT_CHROMIUM_EXECUTABLE']
        rules = ','.join('MAP ' + host + ' ' + address for host, address in sorted(fixture['hosts'].items()))
        with sync_playwright() as runtime:
            arguments = ['--no-sandbox', '--no-proxy-server', '--disable-background-networking',
                         '--autoplay-policy=no-user-gesture-required', '--host-resolver-rules=' + rules]
            record['browser'] = {'executable': executable, 'arguments': arguments, 'normal_nss_trust': True}
            browser = runtime.chromium.launch(executable_path=executable, headless=True,
                env={**os.environ, 'HOME': str(home), 'TMPDIR': '/tmp'}, args=arguments)
            context = browser.new_context(viewport={'width': 1400, 'height': 1000})
            admin = context.new_page()
            ready = admin.goto(fixture['origin'] + '/health/ready', wait_until='domcontentloaded')
            assert ready and ready.status == 200, 'normal certificate verified HTTPS must be ready'
            landing = admin.goto(fixture['origin'] + '/api/v1/media/', wait_until='domcontentloaded')
            assert landing and landing.status == 200, 'normal HTTPS public document required before login fetch'
            login = admin.evaluate('''async key=>(await fetch('/api/v1/media/admin/elevate',{
                method:'POST',body:new URLSearchParams({token:key})})).status''', key)
            assert login == 200
            admin.goto(fixture['origin'] + '/api/v1/media/admin/', wait_until='domcontentloaded')
            admin.wait_for_function('() => (typeof runUploadTask==="function" && typeof FrontierMediaCrypto!=="undefined" && uploadSiteType.options.length===4)')
            open_media(admin)
            albums, placements, karaoke_ids = [], {}, []
            for site, mode in (('primary', 'plain'), ('primary', 'encrypted'), ('direct', 'plain'), ('direct', 'encrypted'), ('relay', 'plain'), ('relay', 'encrypted')):
                name = 'native-' + fixture['nonce'][:12] + '-' + site + '-' + mode
                folder = 'music/' + name
                files = output / name
                files.mkdir(mode=0o700)
                for source in (output / 'album').iterdir():
                    os.link(source, files / source.name)
                admin.evaluate('''async()=>{currentPath='music';document.getElementById('mediaSearch').value='';await renderTree();await refreshStoragePool();}''')
                admin.select_option('#uploadSiteType', site)
                choose_upload(admin, '#uploadFolder', mode, files, 2)
                record['inputs'].append({'action': 'GUI folder upload', 'site_type': site, 'storage_mode': mode, 'path': folder,
                    'files': [{'name': file.name, 'bytes': file.stat().st_size} for file in sorted(files.iterdir())]})
                assert (files / '01-long.mp3').stat().st_size > 128 * 1024**2
                placements[folder] = observe_address(admin, folder, fixture, site, mode)
                albums.append(folder)
                playback = exercise_player(browser, fixture, folder, mode, site, images, record)
                karaoke_ids.append(playback.pop('karaoke_id'))
                record['playback'].append(playback)
            assert {(case['site_type'], case['storage_mode']) for case in record['playback']} == CASES
            # The Go fixture stops only this exact observed durable follower;
            # this browser never receives Docker control permissions.
            offline_folder = albums[2]
            owner = placements[offline_folder][0]['owner']
            private_json(root / 'media-browser-offline-request.json', {'nonce': fixture['nonce'], 'member_id': owner})
            stopped = wait_file(root / 'media-browser-offline-ready.json', fixture['nonce'])
            assert stopped.get('stopped') is True and stopped.get('member_id') == owner
            offline = observe_address(admin, offline_folder, fixture, 'direct', 'plain')
            assert offline == placements[offline_folder], 'offline owner address must not fall back or disappear'
            record['offline_address_verified'] = True
            record['offline_owner'] = {'member_id': owner, 'address': fixture['owners'][owner], 'actual_owned_web_stopped': True}
            private_json(root / 'media-browser-offline-result.json', {'nonce': fixture['nonce'], 'passed': True})
            assert wait_file(root / 'media-browser-online-ready.json', fixture['nonce']).get('restored') is True
            exercise_lyrics_and_karaoke(browser, fixture, albums[-1], karaoke_ids[-1], record)
            # Remove only this test's known paths through the normal managed
            # business API, so the unchanged later retirement checks start clean.
            deleted = admin.evaluate('''async paths=>await api('/api/v1/media/admin/delete',{
                method:'POST',headers:requestHeaders(),body:JSON.stringify({paths})})''', albums)
            assert deleted.get('deleted') == 12 and not deleted.get('pending_delete'), 'managed fixture cleanup did not converge'
            for folder in albums:
                remaining = admin.evaluate('''async folder=>{
                    const response=await fetch('/api/v1/media/admin/tree?'+new URLSearchParams({path:folder}));
                    if(response.status===404)return [];if(!response.ok)throw Error('cleanup read failed');return (await response.json()).items;
                }''', folder)
                assert remaining == [], 'browser fixture still owns business media'
            record['managed_fixture_cleanup_verified'] = True
            record['passed'] = True
            context.close()
            browser.close()
            browser = None
    except BaseException as error:
        record['error_type'] = type(error).__name__
        raise
    finally:
        close_failed = False
        if browser is not None:
            try:
                browser.close()
            except Exception as error:
                record['browser_close_error_type'] = type(error).__name__
                record['passed'] = False
                close_failed = True
        # Private screenshots and per-case paths are not a public CI artifact.
        private_json(root / 'media-browser-result.json', record)
        if close_failed and 'error_type' not in record:
            raise RuntimeError('owned browser did not close normally')
    print(json.dumps({'database': fixture['database'], 'passed': True, 'normal_tls': True, 'cases': 6,
                      'default_matrix_still_required': True}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--audio', type=Path, required=True, help='pre-generated disposable real MP3 tone, at most 8 MiB')
    arguments = parser.parse_args()
    workspace = arguments.workspace
    if not workspace.is_absolute() or not workspace.is_dir() or workspace.is_symlink() or not re.fullmatch(r'fc-native-matrix-[A-Za-z0-9]+', workspace.name):
        raise ValueError('explicit fresh native matrix workspace required')
    if os.environ.get('FRONTIERCLOUD_TEST_NATIVE_MATRIX_WORKSPACE', str(workspace)) != str(workspace):
        raise ValueError('workspace does not match explicit native fixture selection')
    completed = set()
    deadline = time.monotonic() + 45 * 60
    while time.monotonic() < deadline:
        for database in ('go-sqlite', 'go-mysql'):
            fixture = workspace / database / 'media-browser-fixture.json'
            if database not in completed and fixture.is_file():
                run_fixture(fixture, workspace, arguments.audio)
                completed.add(database)
        if completed == {'go-sqlite', 'go-mysql'}:
            return
        time.sleep(.5)
    raise TimeoutError('both default database browser handoffs did not complete')


if __name__ == '__main__':
    main()
