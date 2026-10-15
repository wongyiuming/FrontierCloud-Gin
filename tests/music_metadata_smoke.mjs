import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {webcrypto} from 'node:crypto';
const context = {window: {addEventListener() {}}, TextDecoder, Uint8Array, DataView, Blob, URL, crypto: webcrypto, AbortController, setTimeout, clearTimeout};
vm.runInNewContext(fs.readFileSync(new URL('../static/js/music-metadata.js', import.meta.url), 'utf8'), context);
const api = context.window.FrontierMusicMetadata;
const size = n => [n >> 21 & 127, n >> 14 & 127, n >> 7 & 127, n & 127];
const ascii = text => [...new TextEncoder().encode(text)];
const frame = (version, name, body) => [...ascii(name), ...(version === 2 ? [0, body.length >> 8, body.length & 255] : version === 3 ? [0, 0, body.length >> 8, body.length & 255, 0, 0] : [...size(body.length), 0, 0]), ...body];
const tag = (version, body) => Uint8Array.from([73, 68, 51, version, 0, 0, ...size(body.length), ...body]);
const image = [255, 216, 255, 224, ...Array(100).fill(0)];
for (const version of [2, 3, 4]) {
    const data = tag(version, [
        ...frame(version, version === 2 ? 'TT2' : 'TIT2', [1, 255, 254, 0x60, 0x4f, 0x7d, 0x59]),
        ...frame(version, version === 2 ? 'TP1' : 'TPE1', [3, ...ascii('Artist')]),
        ...frame(version, version === 2 ? 'TAL' : 'TALB', [3, ...ascii('Album')]),
        ...frame(version, version === 2 ? 'PIC' : 'APIC', [3, ...ascii(version === 2 ? 'JPG' : 'image/jpeg\0'), 3, 0, ...image]),
    ]);
    const result = api.parse(data);
    assert.equal(result.title, '\u4f60\u597d'); assert.equal(result.artist, 'Artist'); assert.equal(result.album, 'Album');
    assert.equal(result.picture.mime, 'image/jpeg'); assert.deepEqual(Array.from(result.picture.bytes), image);
}
for (const invalid of [new Uint8Array(), Uint8Array.from([73, 68, 51, 4, 0, 0, 127, 127, 127, 127]), tag(4, frame(4, 'APIC', [3, ...ascii('image/svg+xml\0'), 3, 0, ...ascii('<svg onload="bad()"></svg>')]))]) {
    assert.equal(api.parse(invalid).picture, undefined);
}
assert.equal(Object.keys(await api.metadata({media_path: 'music/plain.mp3'})).length, 0);
{
    const withIndicator = (name, body, indicator = size(body.length), unsync = false) => {
        const payload = unsync ? body.flatMap(byte => byte === 255 ? [255, 0] : [byte]) : body;
        const bytes = frame(4, name, [...indicator, ...payload]); bytes[9] = unsync ? 3 : 1; return bytes;
    };
    const title = [3, ...ascii('Indicator title')], art = [3, ...ascii('image/jpeg\0'), 3, 0, ...image];
    const result = api.parse(tag(4, [...withIndicator('TIT2', title), ...withIndicator('APIC', art, size(art.length), true)]));
    assert.equal(result.title, 'Indicator title');
    assert.deepEqual(Array.from(result.picture.bytes), image, 'DLI length describes the de-unsynchronized payload');
    for (const indicator of [[128, 0, 0, 0], size(title.length + 1)]) {
        assert.equal(api.parse(tag(4, withIndicator('TIT2', title, indicator))).title, undefined);
    }
}
{
    const requests = [];
    let invalidHeader;
    context.window.FrontierMediaCrypto = {prepareCatalog: async entries => { entries[0].url = '/authorized'; }};
    context.window.FrontierCryptoCommon = {validate() {}, boundedBytes: async response => response.bytes};
    context.fetch = async (_url, options) => {
        const range = options.headers.Range; requests.push(range);
        const tail = new Uint8Array(128); tail.set(ascii('TAGFooter title'), 0); tail.set(ascii('Footer artist'), 33); tail.set(ascii('Footer album'), 63);
        return {status: 206, headers: {get: () => `bytes ${range.slice(6)}/256`}, bytes: range === 'bytes=0-9' ? invalidHeader : tail};
    };
    for (const [index, length] of [[128, 0, 0, 0], size(9 * 1024 * 1024), size(300)].entries()) {
        invalidHeader = Uint8Array.from([73, 68, 51, 4, 0, 0, ...length]); requests.length = 0;
        const tags = await api.metadata({media_path: `music/bad-v2-${index}.mp3`, encryption: {plaintext_size: 256}});
        assert.equal(tags.title, 'Footer title'); assert.equal(tags.artist, 'Footer artist'); assert.equal(tags.album, 'Footer album');
        assert.deepEqual(requests, ['bytes=0-9', 'bytes=128-255'], 'invalid/oversized v2 must retain the bounded v1 fallback without fetching the tag');
    }
}
{
    let expire;
    context.setTimeout=(callback,delay)=>{assert.equal(delay,15000);expire=callback;return 1;};
    context.clearTimeout=()=>{};
    context.fetch=async (_url,options)=>new Promise((_resolve,reject)=>options.signal.addEventListener('abort',()=>reject(new Error('test slow Range aborted')),{once:true}));
    const entry={media_path:'music/slow-retry.mp3',encryption:{plaintext_size:256}};
    const pending=api.metadata(entry);
    await new Promise(setImmediate);
    assert.ok(expire,'Range request must own a bounded deadline');
    expire();await assert.rejects(pending,/slow Range aborted/);
    context.fetch=async (_url,options)=>({status:206,headers:{get:()=>`bytes ${options.headers.Range.slice(6)}/256`},bytes:new Uint8Array(options.headers.Range==='bytes=0-9'?10:128)});
    assert.deepEqual(Object.keys(await api.metadata(entry)),[],'timed-out metadata must remain retryable');
}
console.log('music-metadata-smoke-ok: ID3 versions, Unicode, image signatures, bounded fallback and slow Range retry');
