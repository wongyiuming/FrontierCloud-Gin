"""Original encrypted artwork round-trip on the isolated RN HTTPS staging site."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import urllib.parse
import uuid
from playwright.sync_api import sync_playwright


def run(args):
    assert args.base_url == 'https://rnlsj.520mall.cc', 'isolated RN staging origin required'
    base=args.base_url
    output=Path(args.output)
    output.mkdir(parents=True,exist_ok=True)
    payload=Path(args.fixture).read_bytes()
    assert payload.startswith(b'ID3') and len(payload)<4*1024*1024
    folder='music/加密封面验收-'+uuid.uuid4().hex
    uploads=[]
    with sync_playwright() as runtime:
        browser=runtime.chromium.launch(executable_path=os.environ['PLAYWRIGHT_CHROMIUM_EXECUTABLE'],headless=True,args=['--no-sandbox'])
        try:
            context=browser.new_context(viewport={'width':1360,'height':900})
            context.add_init_script("""window.artworkTestBlobs=new Map();
const createArtworkTestURL=URL.createObjectURL.bind(URL);
URL.createObjectURL=blob=>{const url=createArtworkTestURL(blob);window.artworkTestBlobs.set(url,blob);return url;};""")
            assert context.request.post(base+'/api/v1/media/admin/elevate',form={'token':os.environ['ADMIN_KEY']}).status==200
            assert context.request.get(base+'/api/v1/media/admin/storage-pool').json().get('standalone') is True, 'independent staging role required'
            page=context.new_page()
            page.goto(base+'/api/v1/media/admin/',wait_until='networkidle')
            page.wait_for_function('() => !!window.FrontierMediaCrypto')
            def record_upload(request):
                if request.url.endswith('/upload/item'):
                    uploads.append({'method':request.method})
            context.on('request',record_upload)
            failed_requests=[]
            page_errors=[]
            context.on('requestfailed',lambda request:failed_requests.append({'path':urllib.parse.urlsplit(request.url).path,'failure':request.failure}))
            page.on('pageerror',lambda error:page_errors.append(str(error)))
            result=page.evaluate("""async ({payload,relative}) => {
                const bytes=Uint8Array.from(atob(payload),c=>c.charCodeAt(0));
                const encrypted=await FrontierMediaCrypto.encryptUploadFile(new File([bytes],'01-cover.mp3',{type:'audio/mpeg'}));
                try {
                    const form=new FormData();form.append('storage_mode','encrypted');form.append('target_dir','music');form.append('relative_path',relative);
                    form.append('encryption',JSON.stringify(encrypted.encryption));form.append('preparation_token',encrypted.preparation_token);form.append('file',encrypted.file,'01-cover.mp3');
                    const cipher=await encrypted.file.arrayBuffer();
                    const ciphertext_sha256=[...new Uint8Array(await crypto.subtle.digest('SHA-256',cipher))].map(x=>x.toString(16).padStart(2,'0')).join('');
                    return {result:await uploadOne(form,()=>{}),ciphertext_sha256,ciphertext_bytes:cipher.byteLength};
                } finally { await encrypted.cleanup(); }
            }""",{'payload':base64.b64encode(payload).decode(),'relative':folder.removeprefix('music/')+'/Album/01-cover.mp3'})
            encrypted_upload=result
            result=encrypted_upload['result']
            remaining=page.evaluate("""async () => {
                const directory=await (await navigator.storage.getDirectory()).getDirectoryHandle('frontiercloud-cipher-upload-v1');
                const names=[];for await (const [name] of directory.entries()) names.push(name);return names;
            }""")
            assert remaining==[],remaining
            assert result['path']==folder+'/Album/01-cover.mp3',result
            assert len(uploads)==1,uploads
            candidates=context.request.get(base+'/api/v1/media/catalog/artwork',params={'path':folder+'/Album'}).json()
            assert not candidates.get('cover') and len(candidates['metadata_tracks'])==1,candidates
            entry=candidates['metadata_tracks'][0]
            assert entry.get('encryption'),entry
            raw=context.request.get(base+'/api/v1/media/stream',params={'file_path':entry['media_path']})
            assert raw.status==200 and raw.body()!=payload
            assert hashlib.sha256(raw.body()).hexdigest()==encrypted_upload['ciphertext_sha256'] and len(raw.body())==encrypted_upload['ciphertext_bytes']
            page.goto(base+'/api/v1/media/music/category?'+urllib.parse.urlencode({'path':folder}),wait_until='domcontentloaded')
            try:
                page.wait_for_function('() => !!document.querySelector(".card-artwork img")?.naturalWidth',timeout=45000)
            except Exception:
                diagnostic=page.evaluate('async entry => { try { return {tags:await FrontierMusicMetadata.metadata(entry)}; } catch(error) { return {error:error.message}; } }',entry)
                (output/'failure.json').write_text(json.dumps({'failed_requests':failed_requests,'page_errors':page_errors,'metadata_retry':diagnostic,'text':page.locator('body').inner_text()},ensure_ascii=False,indent=2))
                raise
            picture=page.locator('.card-artwork img').evaluate("""async image => {
                const bytes=await window.artworkTestBlobs.get(image.src).arrayBuffer();
                return {source:image.src.startsWith('blob:'),sha256:[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(x=>x.toString(16).padStart(2,'0')).join(''),width:image.naturalWidth,height:image.naturalHeight};
            }""")
            assert picture['source'] and picture['sha256']==args.cover_sha256,picture
            roundtrip=page.evaluate("""async entry => {
                await FrontierMediaCrypto.prepareCatalog([entry]);
                const response=await fetch(entry.url);const bytes=await response.arrayBuffer();
                const ranged=await fetch(entry.url,{headers:{Range:'bytes=3-9'}});
                return {status:response.status,sha256:[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(x=>x.toString(16).padStart(2,'0')).join(''),range_status:ranged.status,range:[...new Uint8Array(await ranged.arrayBuffer())]};
            }""",entry)
            assert roundtrip['sha256']==hashlib.sha256(payload).hexdigest() and roundtrip['range_status']==206 and bytes(roundtrip['range'])==payload[3:10],roundtrip
            page.screenshot(path=str(output/'encrypted-album.png'))
            proof={'real_chromium':True,'verified_public_https':True,'base_url':base,'original_picture':picture,'browser_encrypted_upload':encrypted_upload,'browser_temporary_files_after_upload':remaining,'server_ciphertext_matches_browser':True,'browser_roundtrip':roundtrip,'fixture_path':result['path']}
            (output/'evidence.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2))
            print(json.dumps(proof,ensure_ascii=False),flush=True)
        finally:
            browser.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url',required=True)
    parser.add_argument('--fixture',required=True)
    parser.add_argument('--cover-sha256',required=True)
    parser.add_argument('--output',required=True)
    run(parser.parse_args())
