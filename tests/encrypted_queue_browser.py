"""Real encrypted MP3 queue, original artwork and MSE acceptance on isolated nodes."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import struct
import urllib.parse
import uuid
import zlib

from playwright.sync_api import sync_playwright


def digest(data):
    return hashlib.sha256(data).hexdigest()


def syncsafe(size):
    return bytes((size >> shift) & 127 for shift in (21, 14, 7, 0))


def picture(index):
    # Distinct, valid source pictures expose accidental first-track reuse.
    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))
    color = bytes((220 if index == 0 else 30, 220 if index == 1 else 30, 220 if index == 2 else 30))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 64, 64, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress((b'\x00' + color * 64) * 64)) + chunk(b'IEND', b''))


def fixture_tracks(source):
    raw = Path(source).read_bytes()
    if raw.startswith(b'ID3'):
        size = sum((raw[6 + i] & 127) << shift for i, shift in enumerate((21, 14, 7, 0)))
        raw = raw[10 + size:]
    assert raw and raw[0] == 255, 'real MP3 audio frames required'
    result = []
    for index in range(3):
        image = picture(index)
        def frame(name, data):
            return name.encode() + syncsafe(len(data)) + b'\x00\x00' + data
        body = (frame('TIT2', b'\x03' + ('Queue track ' + str(index + 1)).encode())
                + frame('TPE1', b'\x03Queue acceptance') + frame('TALB', b'\x03Encrypted queue')
                + frame('APIC', b'\x03image/png\x00\x03\x00' + image))
        result.append({'name': f'{index + 1:02d}-queue.mp3', 'bytes': b'ID3\x04\x00\x00' + syncsafe(len(body)) + body + raw,
                       'picture_sha256': digest(image)})
    return result


def run(args):
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    fixture = json.loads(Path(args.fleet).read_text()) if args.fleet else {}
    base = fixture.get('origin', args.base_url).rstrip('/')
    assert (fixture or base.startswith('http://127.0.0.1:') or base == 'https://rnlsj.520mall.cc'), 'isolated acceptance origin required'
    key = Path(fixture['admin_key_file']).read_text().strip() if fixture else os.environ['ADMIN_KEY']
    tracks = fixture_tracks(args.audio)
    folder = 'music/Encrypted-queue-' + uuid.uuid4().hex
    proof = {'passed': False, 'fixture_directory': folder, 'relay_verified': False}
    with sync_playwright() as runtime:
        rules = ','.join('MAP ' + host + ' ' + ip for host, ip in fixture.get('hosts', {}).items())
        browser = runtime.chromium.launch(executable_path=os.environ['PLAYWRIGHT_CHROMIUM_EXECUTABLE'], headless=True,
            args=['--no-sandbox', '--autoplay-policy=no-user-gesture-required', '--no-proxy-server']
                 + (['--host-resolver-rules=' + rules, '--ignore-certificate-errors'] if rules else []))
        context = browser.new_context(ignore_https_errors=bool(fixture), viewport={'width': 1400, 'height': 1100})
        context.add_init_script("""window.queueBlobs=new Map();const queueCreateURL=URL.createObjectURL.bind(URL);
URL.createObjectURL=blob=>{const url=queueCreateURL(blob);queueBlobs.set(url,blob);return url;};""")
        worker_requests = []
        key_requests = []
        context.on('request', lambda request: worker_requests.append(request.url)
                   if request.service_worker and '/static/' not in request.url else None)
        context.on('request', lambda request: key_requests.append(request.url) if request.url.endswith('/crypto/key') else None)
        page = context.new_page()
        errors = []
        failures = []
        messages = []
        page.on('console', lambda message: messages.append({'type': message.type, 'text': message.text[:1000]}))
        page.on('requestfailed', lambda request: failures.append({'url': request.url, 'error': request.failure}))
        page.on('pageerror', lambda error: errors.append(str(error)))
        try:
            page.goto(base + '/api/v1/media/', wait_until='domcontentloaded')
            proof['login_page'] = {'url': page.url, 'title': page.title()}
            login = page.evaluate("""async key=>{const r=await fetch('/api/v1/media/admin/elevate',{
                method:'POST',body:new URLSearchParams({token:key})});return r.status;}""", key)
            assert login == 200, login
            page.goto(base + '/api/v1/media/admin/', wait_until='networkidle')
            page.wait_for_function('() => !!window.FrontierMediaCrypto && typeof uploadOne === "function"')
            proof['uploads'] = []
            for track in tracks:
                uploaded = page.evaluate("""async ({payload,name,relative,site})=>{
                    const original=Uint8Array.from(atob(payload),c=>c.charCodeAt(0));
                    const encrypted=await FrontierMediaCrypto.encryptUploadFile(new File([original],name,{type:'audio/mpeg'}));
                    try {
                        const pool=await api('/api/v1/media/admin/storage-pool');
                        if (!pool.standalone) {
                            const reservation=await api('/api/v1/media/admin/upload/session',{
                                method:'POST',headers:requestHeaders(),body:JSON.stringify({site_type:site,target_dir:'music',
                                    relative_path:relative,filename:name,size_bytes:encrypted.file.size,storage_mode:'encrypted',
                                    encryption:encrypted.encryption,preparation_token:encrypted.preparation_token})});
                            try {
                                await uploadRaw(reservation.upload_url,encrypted.file,()=>{},reservation.transport==='Direct');
                                return {path:reservation.path,transport:reservation.transport,member_id:reservation.member_id};
                            } catch(error) {await cancelClusterReservation(reservation);throw error;}
                        }
                        const form=new FormData();form.append('storage_mode','encrypted');form.append('target_dir','music');
                        form.append('site_type',site);form.append('relative_path',relative);
                        form.append('encryption',JSON.stringify(encrypted.encryption));form.append('preparation_token',encrypted.preparation_token);
                        form.append('file',encrypted.file,name);return await uploadOne(form,()=>{});
                    } finally {await encrypted.cleanup();}
                }""", {'payload': base64.b64encode(track['bytes']).decode(), 'name': track['name'],
                        'relative': folder.removeprefix('music/') + '/' + track['name'], 'site': args.site})
                assert uploaded['path'] == folder + '/' + track['name'], uploaded
                proof['uploads'].append({'path': uploaded['path'], 'plaintext_sha256': digest(track['bytes']),
                                         'original_picture_sha256': track['picture_sha256']})
            tree = page.evaluate("""async path=>await api('/api/v1/media/admin/tree?'+new URLSearchParams({path}))""", folder)
            if args.site == 'relay':
                assert len(tree['items']) == 3 and all(item['transport'] == 'Relay' and item.get('storage_member_id') for item in tree['items']), tree
                proof['relay_verified'] = True
            proof['placement'] = tree
            url = base + '/api/v1/media/music/category?' + urllib.parse.urlencode({'path': folder})
            page.goto(url, wait_until='domcontentloaded')
            page.wait_for_function('() => typeof currentMediaList !== "undefined" && currentMediaList.length === 3 && art', timeout=45000)
            page.wait_for_function('() => [...document.querySelectorAll(".media-item img")].length === 3 && [...document.querySelectorAll(".media-item img")].every(i=>i.src.startsWith("blob:") && i.naturalWidth===64)', timeout=60000)
            images = page.locator('.media-item img').evaluate_all("""async images=>Promise.all(images.map(async image=>{
                const blob=queueBlobs.get(image.src);const bytes=await blob.arrayBuffer();return {width:image.naturalWidth,height:image.naturalHeight,type:blob.type,
                sha256:[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(x=>x.toString(16).padStart(2,'0')).join('')};}))""")
            assert all(image['type'] == 'image/webp' for image in images), images
            assert len({image['sha256'] for image in images}) == 3, images
            original_hashes = page.evaluate("""async()=>Promise.all(currentMediaList.map(async media=>{
                const bytes=await queueBlobs.get(media.cover).arrayBuffer();
                return [...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(x=>x.toString(16).padStart(2,'0')).join('');}))""")
            assert original_hashes == [track['picture_sha256'] for track in tracks], original_hashes
            proof['original_picture_hashes'] = original_hashes
            proof['pictures'] = images
            proof['own_original_pictures_verified'] = True
            entries = page.evaluate('currentMediaList.map(t=>({path:t.media_path,encryption:!!t.encryption,delivery:t.delivery_mode,site:t.site_type}))')
            assert all(entry['encryption'] for entry in entries), entries
            if args.site == 'relay':
                catalog = page.evaluate("""async path=>(await fetch('/api/v1/media/catalog/media?'+new URLSearchParams({media_type:'music',path,playback_session_id:'queue-proof'}))).json()""", folder)
                assert len(catalog['entries']) == 3
                assert all(entry.get('encryption') for entry in catalog['entries'])
                proof['catalog'] = catalog
            proof['manual'] = []
            for index in (1, 2, 0):
                page.locator(f'.media-item[data-index="{index}"]').click()
                page.wait_for_function('index => currentIndex===index && art.currentTime>0.1 && frontierCloudContinuousAudio.status().active && !frontierCloudContinuousAudio.status().pipeline_error', arg=index, timeout=45000)
                state = page.evaluate('({status:frontierCloudContinuousAudio.status(),title:art.title,track:currentMediaList[currentIndex].title})')
                assert state['track'] == 'Queue track ' + str(index + 1), state
                proof['manual'].append(state)
            proof['manual_mse_verified'] = True
            page.evaluate('window.queueVideo=art.video; window.queueSource=art.url')
            proof['automatic'] = []
            for index in (1, 2):
                page.wait_for_function('() => frontierCloudContinuousAudio.status().active_segment?.end !== null', timeout=45000)
                page.evaluate('art.currentTime=art.duration-0.8')
                page.wait_for_function('index => currentIndex===index && art.currentTime>0.1', arg=index, timeout=45000)
                assert page.evaluate('art.video===queueVideo && art.url===queueSource'), 'automatic transition recreated MSE'
                proof['automatic'].append(page.evaluate('frontierCloudContinuousAudio.status()'))
            proof['automatic_mse_verified'] = True
            # Repeated virtual tag reads exercise the real worker, not mocked metadata.
            page.evaluate('art.pause()')
            page.wait_for_timeout(1000)
            assert worker_requests, 'network observation must see the initial ciphertext reads'
            before_cache = len(worker_requests)
            cache = page.evaluate("""async()=>{const entry={...currentMediaList[0]};await FrontierMediaCrypto.prepareCatalog([entry]);
                const one=await (await fetch(entry.url,{headers:{Range:'bytes=0-31'}})).arrayBuffer();
                const two=await (await fetch(entry.url,{headers:{Range:'bytes=0-31'}})).arrayBuffer();
                return {same:[...new Uint8Array(one)].join() === [...new Uint8Array(two)].join(),bytes:two.byteLength};}""")
            assert cache == {'same': True, 'bytes': 32}, cache
            proof['cache_reads'] = cache
            assert len(worker_requests) == before_cache, worker_requests[before_cache:]
            proof['cache_worker_network_requests'] = worker_requests[before_cache:]
            proof['initial_worker_network_requests'] = before_cache
            proof['cipher_cache_reuse_verified'] = True
            page.screenshot(path=str(output / 'encrypted-queue.png'), full_page=True)
            assert errors == [], errors
            proof['page_errors'] = errors
            before_keys = len(key_requests)
            revisit = context.new_page()
            revisit.goto(url, wait_until='domcontentloaded')
            revisit.wait_for_function('() => [...document.querySelectorAll(".media-item img")].length===3 && [...document.querySelectorAll(".media-item img")].every(i=>i.naturalWidth===64)', timeout=45000)
            revisit.evaluate('art.pause()')
            assert len(key_requests) > before_keys, 'a new page must obtain its own authorization'
            assert len(worker_requests) == before_cache, 'page navigation should reuse cached ciphertext while obtaining fresh keys'
            proof['cross_page_cache'] = {'fresh_key_requests': len(key_requests) - before_keys,
                                         'ciphertext_requests': len(worker_requests) - before_cache}
            revisit.close()
            admin = context.new_page()
            admin.goto(base + '/api/v1/media/admin/', wait_until='networkidle')
            hidden_path = folder + '/' + tracks[0]['name']
            hidden_applied = False
            try:
                admin.evaluate("""async path=>await api('/api/v1/media/admin/hide',{
                    method:'POST',headers:requestHeaders(),body:JSON.stringify({paths:[path],hidden:true})})""", folder)
                hidden_applied = True
                denied = page.evaluate("""async()=>{
                    try {const response=await fetch(currentMediaList[0].url,{headers:{Range:'bytes=0-31'}});
                        const {value}=await response.body.getReader().read();return {delivered:value?.byteLength||0,rejected:false};
                    } catch(error) {return {delivered:0,rejected:true};}
                }""")
                assert denied == {'delivered': 0, 'rejected': True}, denied
                proof['warm_cache_hidden_source_denied'] = denied
            finally:
                if hidden_applied:
                    admin.evaluate("""async path=>await api('/api/v1/media/admin/hide',{
                        method:'POST',headers:requestHeaders(),body:JSON.stringify({paths:[path],hidden:false})})""", folder)
                admin.close()
            page.evaluate('path=>FrontierMediaCrypto.resetFault(path)', hidden_path)
            recovered = page.evaluate("""async()=>{
                const r=await fetch(currentMediaList[0].url,{headers:{Range:'bytes=0-31'}});
                return {status:r.status,bytes:(await r.arrayBuffer()).byteLength};}
            """)
            assert recovered == {'status': 206, 'bytes': 32}, recovered
            proof['explicit_retry_after_unhide'] = recovered
            proof['passed'] = True
        except Exception as error:
            proof['error'] = str(error)
            try:
                proof['failure_state'] = page.evaluate("""() => ({index:typeof currentIndex==='undefined'?null:currentIndex,
                    status:window.frontierCloudContinuousAudio?.status(), notice:typeof art==='undefined'?null:art?.notice?.show,
                    audio:typeof art==='undefined'?null:{time:art?.currentTime,duration:art?.duration,paused:art?.video?.paused,
                        readyState:art?.video?.readyState,error:art?.video?.error?.message},
                    tracks:typeof currentMediaList==='undefined'?null:currentMediaList.map(t=>({title:t.title,type:t.type,path:t.media_path}))})""")
                page.screenshot(path=str(output / 'failure.png'), full_page=True)
            except Exception as diagnostic_error:
                proof['diagnostic_error'] = str(diagnostic_error)
            raise
        finally:
            proof['console'] = messages
            proof['request_failures'] = failures
            browser.close()
            (output / 'evidence.json').write_text(json.dumps(proof, ensure_ascii=False, indent=2), encoding='utf-8')
            if fixture:
                Path(args.fleet).with_name('encrypted-queue-result.json').write_text(json.dumps(proof, ensure_ascii=False, indent=2), encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fleet')
    parser.add_argument('--base-url', default='http://127.0.0.1:18080')
    parser.add_argument('--site', choices=('primary', 'relay'), default='relay')
    parser.add_argument('--audio', required=True)
    parser.add_argument('--output', required=True)
    run(parser.parse_args())
