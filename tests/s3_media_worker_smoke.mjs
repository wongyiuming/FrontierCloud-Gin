import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {webcrypto} from 'node:crypto';
import {MessageChannel} from 'node:worker_threads';

const directory = process.env.FC_CRYPTO_COMPILED === '1' ? 'static/js/compiled' : 'static/js';
const source = name => fs.readFileSync(`${directory}/${name}`, 'utf8');
const payload = new Uint8Array(2 * 1024 * 1024 + 19); payload.fill(81);
const etag = '"opaque-provider-etag"';
let elapsed = 0, pageMessage, worker, tamper = false, wrongObject = false;
let providerPayload = payload, grantOverride = null;
let holdTransfer = false, faultCount = 0;
let backendCalls = [], providerCalls = [], maxRead = 0;
const events = new Map();
const client = {id: 'tab', postMessage(data, ports) {
    if (grantOverride && data.type === 'fc-crypto-grant') ports[0].postMessage(grantOverride);
    else pageMessage({data, ports, source: controller});
}};
const controller = {postMessage(data, ports = []) {
    for (const listener of events.get('message') || []) listener({data, ports, source: client});
}};
const shared = {crypto: webcrypto, TextEncoder, TextDecoder, Uint8Array, Uint32Array, ArrayBuffer, DataView,
    URL, URLSearchParams, Blob, Headers, Request, Response, ReadableStream, AbortController,
    MessageChannel, Date, atob, btoa, setTimeout, clearTimeout, console,
    performance: {timeOrigin: 1700000000000, now: () => elapsed}};
const key = await webcrypto.subtle.generateKey({name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt']);
worker = {...shared, CryptoKey: key.constructor, location: new URL('https://master.example/media-crypto-sw.js'),
    clients: {get: async id => id === 'tab' ? client : null, claim: async () => {}}, skipWaiting: async () => {},
    addEventListener(name, listener) { if (!events.has(name)) events.set(name, []); events.get(name).push(listener); },
    importScripts() { vm.runInContext(source('media-crypto-common.js'), worker); },
    async fetch(input, init) {
        providerCalls.push({input, init});
        assert.equal(init.credentials, 'omit'); assert.equal(init.mode, 'cors'); assert.equal(init.redirect, 'error');
        assert.equal(init.referrerPolicy, 'no-referrer');
        assert.equal(init.headers['If-Match'], etag);
        assert(!Object.keys(init.headers).some(name => /authorization|cookie|csrf/i.test(name)));
        if (holdTransfer) await new Promise((_resolve, reject) => init.signal.addEventListener('abort', () => {
            const error = new Error('request cancelled'); error.name = 'AbortError'; reject(error);
        }, {once: true}));
        if (init.method === 'HEAD') {
            assert.equal(input, 'https://objects.example/head?signed=head');
            assert.equal(init.headers['X-Amz-Checksum-Mode'], 'ENABLED', 'HEAD forwards the SDK signed checksum mode');
            return new Response(null, {headers: {'ETag': etag, 'Content-Length': String(payload.length)}});
        }
        assert.equal(input, 'https://objects.example/get?signed=get');
        const range = /^bytes=(\d+)-(\d+)$/.exec(init.headers.Range); assert(range);
        const start = Number(range[1]), end = Number(range[2]); maxRead = Math.max(maxRead, end - start + 1);
        assert(end - start + 1 <= 1024 * 1024 + (grantOverride ? 16 : 0), 'source is fetched in bounded chunks');
        return new Response(providerPayload.slice(start, end + 1), {status: 206, headers: {
            'Content-Range': `bytes ${start}-${end}/${providerPayload.length}`, 'Content-Length': String(end - start + 1),
            ETag: tamper ? '"replaced"' : etag,
        }});
    },
};
worker.self = worker; vm.createContext(worker); vm.runInContext(source('media-crypto-sw.js'), worker);
const page = {...shared, isSecureContext: true, location: new URL('https://master.example/'),
    document: {getElementById() { return null; }, createElement() { return {click() {}}; }},
    navigator: {serviceWorker: {controller, register: async () => ({}), ready: Promise.resolve({}),
        addEventListener(name, callback) { if (name === 'message') pageMessage = callback; }}},
    addEventListener() {}, dispatchEvent() { faultCount += 1; }, CustomEvent: class {},
    async fetch(url, init) {
        backendCalls.push(url); assert.equal(url, '/api/v1/media/crypto/source', 'plain S3 needs no ECDH or file key');
        assert.equal(init.credentials, 'same-origin');
        const request = JSON.parse(init.body); assert.equal(request.object_id, 'object-immutable');
        return Response.json({transport: 'S3', object_id: wrongObject ? 'object-replaced' : 'object-immutable',
            size_bytes: payload.length, content_type: 'audio/mpeg', filename: 'test.mp3',
            source_url: 'https://objects.example/get?signed=get', source_headers: {'If-Match': etag},
            source_head_url: 'https://objects.example/head?signed=head',
            source_head_headers: {'If-Match': etag, 'X-Amz-Checksum-Mode': 'ENABLED'},
            expires_in: 30, expires_at: 1700000030});
    },
};
page.window = page; vm.createContext(page);
vm.runInContext(source('media-crypto-common.js'), page); vm.runInContext(source('media-crypto.js'), page);
const catalog = [{media_path: 'music/a/test.mp3', transport: 'S3', object_id: 'object-immutable'}];
await page.FrontierMediaCrypto.prepareCatalog(catalog);
assert.match(catalog[0].url, /object=object-immutable/);
async function read(options = {}, download = false) {
    let pending;
    const target = new URL(catalog[0].url, 'https://master.example');
    if (download) target.searchParams.set('download', '1');
    const request = new Request(target, options);
    for (const listener of events.get('fetch') || []) listener({request, clientId: 'tab', respondWith(value) { pending = value; }});
    return pending;
}
let response = await read({headers: {Range: 'bytes=1048541-1048619'}});
assert.equal(response.status, 206); assert.equal(response.headers.get('Content-Length'), '79');
assert.deepEqual(new Uint8Array(await response.arrayBuffer()), payload.slice(1048541, 1048620));
assert.equal(backendCalls.length, 1);
response = await read({method: 'HEAD'}); assert.equal(response.status, 200);
assert.equal(providerCalls.at(-1).init.method, 'HEAD', 'HEAD never reuses a GET signature');
response = await read({}, true);
assert.match(response.headers.get('Content-Disposition'), /^attachment; filename\*=UTF-8''test\.mp3$/);
assert.deepEqual(new Uint8Array(await response.arrayBuffer()), payload, 'S3 plaintext attachment bytes stay on the signed-header worker path');
response = await read(); assert.deepEqual(new Uint8Array(await response.arrayBuffer()), payload);
assert.equal(maxRead, 1048576);
assert.equal(vm.runInContext('cipherBytes', worker), 0, 'plain S3 data is never stored in the ciphertext cache');
elapsed = 31000;
response = await read({headers: {Range: 'bytes=-19'}});
assert.deepEqual(new Uint8Array(await response.arrayBuffer()), payload.slice(-19));
assert.equal(backendCalls.length, 2, 'expired source grants are refreshed using monotonic TTL');
const beforeCancel = faultCount;
holdTransfer = true;
const abort = new AbortController(); response = await read({signal: abort.signal});
const cancelled = response.arrayBuffer(); setTimeout(() => abort.abort(), 5);
await assert.rejects(cancelled, /cancelled/); holdTransfer = false;
assert.equal(faultCount, beforeCancel, 'ordinary seek/navigation cancellation is not an integrity fault');
tamper = true;
response = await read({headers: {Range: 'bytes=0-1'}});
await assert.rejects(response.arrayBuffer(), /对象|授权/);
assert(!JSON.stringify(backendCalls).includes('signed='), 'bearer URLs never pass through business authorization requests');
tamper = false; wrongObject = true; elapsed += 31000;
response = await read({headers: {Range: 'bytes=0-1'}});
assert.equal(response.status, 502); assert.match(await response.text(), /替换/);
// The same signed-header transport wraps authenticated ciphertext without
// falling back to a native media-element redirect or exposing a file key.
const common = page.FrontierCryptoCommon;
const plaintext = payload.slice(0, 1024 * 1024 + 37);
const metadata = {version: 1, algorithm: 'AES-256-GCM', file_id: 'c'.repeat(32),
    nonce_prefix: btoa('12345678'), plaintext_size: plaintext.length,
    ciphertext_size: plaintext.length + 32, chunk_size: 1048576};
providerPayload = new Uint8Array(metadata.ciphertext_size);
for (let index = 0; index < 2; index += 1) {
    const encrypted = new Uint8Array(await webcrypto.subtle.encrypt(common.parameters(metadata, index), key,
        plaintext.subarray(index * 1048576, Math.min(plaintext.length, (index + 1) * 1048576))));
    providerPayload.set(encrypted, common.cipherRange(metadata, index).start);
}
grantOverride = {transport: 'S3', object_id: 'cipher-object', source_url: 'https://objects.example/get?signed=get',
    source_headers: {'If-Match': etag}, encryption: metadata, key, deadline: 1700000000000 + elapsed + 30000};
catalog[0].url = catalog[0].url.replace(/\/[^/?]+\?object=.*/, '/' + encodeURIComponent('music/encrypted.mp3') + '?object=' + metadata.file_id);
response = await read({headers: {Range: 'bytes=1048550-1048600'}});
assert.equal(response.status, 206);
assert.deepEqual(new Uint8Array(await response.arrayBuffer()), plaintext.slice(1048550, 1048601));
console.log(`s3-media-worker-smoke-ok (${directory}; signed If-Match, HEAD, bounded Range, expiry, replacement refusal)`);
