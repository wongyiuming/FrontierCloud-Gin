"""Real browser disconnect/refresh acceptance on an owned loopback preview."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import time
import uuid
from playwright.sync_api import sync_playwright


def run(args):
    assert args.base_url == 'http://127.0.0.1:18080', 'owned development preview only'
    root = Path(args.media_root).resolve()
    assert str(root).startswith('/home/wyium/fc-music-preview-20261014/data-v2/'), root
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    folder = '生命周期验收-' + uuid.uuid4().hex
    facts = []
    def stages():
        result={}
        for path in root.glob('.upload-*.part'):
            try: result[path.name]=path.stat().st_size
            except FileNotFoundError: pass  # Cleanup can unlink between listing and stat.
        return result
    original = stages()
    with sync_playwright() as runtime:
        browser = runtime.chromium.launch(executable_path=os.environ['PLAYWRIGHT_CHROMIUM_EXECUTABLE'], headless=True, args=['--no-sandbox'])
        try:
            context = browser.new_context()
            response = context.request.post(args.base_url+'/api/v1/media/admin/elevate', form={'token': os.environ['ADMIN_KEY']})
            assert response.status == 200
            status = context.request.get(args.base_url+'/api/v1/media/admin/status').json()
            csrf = next(c['value'] for c in context.cookies() if c['name']==status['csrf_cookie_name'])
            page = context.new_page()
            page.goto(args.base_url+'/api/v1/media/admin/', wait_until='networkidle')
            session = context.new_cdp_session(page)
            session.send('Network.enable')
            for failure in ('refresh', 'offline'):
                session.send('Network.emulateNetworkConditions', {'offline':False,'latency':0,'downloadThroughput':1024*1024,'uploadThroughput':64*1024})
                relative = folder+'/'+failure+'.mp3'
                page.evaluate("""({csrf,relative}) => {
                    const bytes=new Uint8Array(8*1024*1024);bytes.set([73,68,51,3,0,0,0,0,0,0]);
                    const form=new FormData();form.append('storage_mode','plain');form.append('target_dir','music');
                    form.append('relative_path',relative);form.append('file',new File([bytes],relative.split('/').pop(),{type:'audio/mpeg'}));
                    window.uploadOutcome='pending';uploadOne(form,()=>{}).then(()=>window.uploadOutcome='complete').catch(()=>window.uploadOutcome='aborted');
                }""", {'csrf':csrf,'relative':relative})
                deadline=time.monotonic()+15
                partial={}
                while time.monotonic()<deadline:
                    partial={k:v for k,v in stages().items() if k not in original and v>0}
                    if partial:break
                    page.wait_for_timeout(100)
                assert partial, 'did not observe actual partial server bytes before failure'
                start=time.monotonic()
                if failure=='refresh':
                    page.reload(wait_until='domcontentloaded')
                else:
                    context.set_offline(True)
                while time.monotonic()-start<20 and stages()!=original:
                    page.wait_for_timeout(100)
                assert stages()==original, ('partial bytes retained', stages())
                facts.append({'case':failure,'partial_bytes_observed':sum(partial.values()),'physical_cleanup_seconds':time.monotonic()-start,'remaining_stages':stages()})
                context.set_offline(False)
                session.send('Network.emulateNetworkConditions', {'offline':False,'latency':0,'downloadThroughput':-1,'uploadThroughput':-1})
            # No new offline event fires when retrying while already disconnected.
            # Observe the real queue before any encryption or network transfer.
            context.set_offline(True)
            blocked=page.evaluate("""async folder => {
                currentPath='music/'+folder;uploadSiteType.value='primary';uploadInterrupted=true;
                const encrypt=window.FrontierMediaCrypto?.encryptUploadFile;
                const transfer=uploadOne;const originalAlert=window.alert;
                let encryptionCalls=0,transferCalls=0;const alerts=[];
                if(window.FrontierMediaCrypto) window.FrontierMediaCrypto.encryptUploadFile=async()=>{encryptionCalls++;throw new Error('offline encryption started');};
                uploadOne=async()=>{transferCalls++;throw new Error('offline transfer started');};
                window.alert=message=>alerts.push(message);
                try {
                    const files=[new File(['ID3'],'offline-a.mp3'),new File(['ID3'],'offline-b.mp3')];
                    await runUploadTask(files,null,false,'encrypted');
                    await runUploadTask(files,null,false,'plain');
                    return {online:navigator.onLine,encryptionCalls,transferCalls,interrupted:uploadInterrupted,running:uploadRunning,alerts};
                } finally {
                    uploadOne=transfer;window.alert=originalAlert;
                    if(encrypt) window.FrontierMediaCrypto.encryptUploadFile=encrypt;
                }
            }""",folder)
            assert blocked['online'] is False and blocked['interrupted'] is True and blocked['running'] is False,blocked
            assert blocked['encryptionCalls']==0 and blocked['transferCalls']==0 and len(blocked['alerts'])==2,blocked
            assert all('离线' in alert for alert in blocked['alerts']),blocked
            facts.append({'case':'retry-while-already-offline','queue':blocked,'remaining_stages':stages()})
            context.set_offline(False)
            payload=b'ID3\x03\0\0\0\0\0\0'+b'bounded-download-fixture'*(100000)
            relative=folder+'/complete.mp3'
            def upload(data):
                return context.request.post(args.base_url+'/api/v1/media/admin/upload/item', headers={'X-CSRF-Token':csrf}, multipart={'storage_mode':'plain','target_dir':'music','relative_path':relative,'file':{'name':'complete.mp3','mimeType':'audio/mpeg','buffer':data}})
            uploaded=upload(payload)
            assert uploaded.status==200, (uploaded.status, uploaded.text())
            duplicate=upload(b'ID3\x03\0\0\0\0\0\0different')
            assert duplicate.status==409, (duplicate.status,duplicate.text())
            path='music/'+relative
            cancelled=page.evaluate("""async path => {
                const controller=new AbortController();const response=await fetch('/api/v1/media/stream?'+new URLSearchParams({file_path:path}),{signal:controller.signal});
                const reader=response.body.getReader();const first=await reader.read();controller.abort();await reader.cancel().catch(()=>{});
                return {status:response.status,read_bytes:first.value?.byteLength||0};
            }""",path)
            assert cancelled['status']==200 and cancelled['read_bytes']>0, cancelled
            response=context.request.get(args.base_url+'/api/v1/media/stream',params={'file_path':path})
            assert response.status==200 and response.body()==payload
            assert stages()==original
            facts.append({'case':'retry-conflict-download-abort','upload_status':uploaded.status,'duplicate_status':duplicate.status,'cancelled_download':cancelled,'subsequent_original_sha256':hashlib.sha256(response.body()).hexdigest(),'remaining_stages':stages()})
            context.request.post(args.base_url+'/api/v1/media/admin/logout',headers={'X-CSRF-Token':csrf})
            (output/'evidence.json').write_text(json.dumps({'real_chromium':True,'real_http_server':True,'role':'Standalone','base_url':args.base_url,'cases':facts},indent=2))
            print(json.dumps(facts),flush=True)
        finally:
            browser.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url',required=True)
    parser.add_argument('--media-root',required=True)
    parser.add_argument('--output',required=True)
    run(parser.parse_args())
