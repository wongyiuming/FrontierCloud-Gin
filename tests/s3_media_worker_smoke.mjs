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
let providerPayload = payload, grantOverride = null, sourceOverride = null;
let holdTransfer = false, faultCount = 0;
let readFailure = null;
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
        let body = providerPayload.slice(start, end + 1), contentRange = `bytes ${start}-${end}/${providerPayload.length}`;
        if (readFailure?.start === start) {
            const failure = readFailure; readFailure = null;
            if (failure.kind === 'fetch') throw new TypeError('temporary S3 fetch interruption');
            if (failure.kind === 'replace') { elapsed += 31000; wrongObject = true; }
            if (failure.kind === 'status') return new Response(null, {status: failure.status});
            if (failure.kind === 'range') contentRange = `bytes ${start + 1}-${end + 1}/${providerPayload.length}`;
            if (failure.kind === 'oversize') body = new Uint8Array(body.length + 1);
            if (failure.kind === 'body') {
                let partial = false;
                body = new ReadableStream({pull(output) {
                    if (!partial) { partial = true; output.enqueue(new Uint8Array([81])); }
                    else output.error(new TypeError('temporary S3 body interruption'));
                }}, {highWaterMark: 0});
            }
            if (failure.kind === 'short') body = body.subarray(0, body.length - 1);
        }
        return new Response(body, {status: 206, headers: {
            'Content-Range': contentRange, 'Content-Length': String(end - start + 1),
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
            expires_in: 30, expires_at: 1700000030, ...sourceOverride});
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
for (const failure of [{kind: 'fetch'}, {kind: 'body'}, {kind: 'short'}, {kind: 'status', status: 503},
    {kind: 'status', status: 429}]) {
    const before = faultCount;
    readFailure = {...failure, start: 0}; response = await read();
    await assert.rejects(response.arrayBuffer());
    assert.equal(faultCount, before, `${failure.kind}/${failure.status || ''} must not poison playback`);
    assert(!page.FrontierMediaCrypto.failureFor(catalog[0].url), 'a transient read remains eligible for the existing retry guard');
    response = await read({headers: {Range: 'bytes=0-'}});
    assert.deepEqual(new Uint8Array(await response.arrayBuffer()), payload);
}
// Exercise the shipped continuous-player retry wrapper against the actual worker,
// including a failure after one complete chunk has already reached the player.
const grantFetch = page.fetch;
const mediaRequests = [];
page.fetch = async (input, init = {}) => {
    if (!new URL(String(input), page.location).pathname.startsWith('/__fc_media/')) return grantFetch(input, init);
    mediaRequests.push(new Headers(init.headers).get('Range'));
    return read(init);
};
page.PLAYER_KIND = 'audio'; page.playerSwitchSequence = 1;
vm.runInContext(fs.readFileSync('static/js/player-directory-label.js', 'utf8'), page);
for (const kind of ['fetch', 'body']) {
    const before = faultCount, beforeRequests = mediaRequests.length;
    const previousResumes = page.frontierCloudContinuousFetchRetry.status().resume_count;
    const beforeProvider = providerCalls.length;
    readFailure = {kind, start: 1048576};
    response = await page.fetch(catalog[0].url, {credentials: 'same-origin'});
    assert.deepEqual(new Uint8Array(await response.arrayBuffer()), payload,
        `${kind} interruption must recover without duplicated or omitted bytes`);
    assert.equal(faultCount, before);
    assert.deepEqual(mediaRequests.slice(beforeRequests), [null, 'bytes=1048576-'],
        'retry starts at the exact bytes already delivered to the player');
    assert.equal(providerCalls.slice(beforeProvider).filter(row => row.init.headers.Range === 'bytes=1048576-2097151').length, 2,
        'the incomplete worker chunk is retried from its start without advancing the player offset');
    assert.equal(page.frontierCloudContinuousFetchRetry.status().resume_count, previousResumes + 1);
}
page.fetch = grantFetch;
for (const failure of [{kind: 'status', status: 401}, {kind: 'status', status: 403},
    {kind: 'status', status: 404}, {kind: 'status', status: 412}, {kind: 'status', status: 416},
    {kind: 'range'}, {kind: 'oversize'}]) {
    const before = faultCount;
    readFailure = {...failure, start: 0}; response = await read();
    await assert.rejects(response.arrayBuffer());
    assert.equal(faultCount, before + 1, `${failure.kind}/${failure.status || ''} must remain a terminal authorization/integrity fault`);
    assert(page.FrontierMediaCrypto.failureFor(catalog[0].url), 'the player retry guard retains verified faults');
    page.FrontierMediaCrypto.resetFault('music/a/test.mp3');
}
tamper = true;
response = await read({headers: {Range: 'bytes=0-1'}});
await assert.rejects(response.arrayBuffer(), /对象|授权/);
assert(page.FrontierMediaCrypto.failureFor(catalog[0].url), 'verified ETag replacement stays terminal');
page.FrontierMediaCrypto.resetFault('music/a/test.mp3');
assert(!JSON.stringify(backendCalls).includes('signed='), 'bearer URLs never pass through business authorization requests');
tamper = false;
readFailure = {kind: 'replace', start: 0}; response = await read();
await assert.rejects(response.arrayBuffer(), /替换/);
assert(page.FrontierMediaCrypto.failureFor(catalog[0].url), 'verified replacement during source refresh stays terminal');
page.FrontierMediaCrypto.resetFault('music/a/test.mp3');
response = await read({headers: {Range: 'bytes=0-1'}});
assert.equal(response.status, 409); assert.match(await response.text(), /替换/);
wrongObject = false;
for (const override of [{expires_in: 0}, {source_url: 'invalid URL'}, {source_url: 'http://objects.example/get'},
    {source_headers: {}}, {size_bytes: 0}]) {
    sourceOverride = override; page.FrontierMediaCrypto.resetFault('music/a/test.mp3');
    const beforeProvider = providerCalls.length;
    response = await read();
    assert.equal(response.status, override.size_bytes === 0 ? 409 : 403,
        'verified invalid source authorization/identity is terminal, not a network retry');
    assert.equal(providerCalls.length, beforeProvider, 'an invalid grant never reads provider bytes');
}
sourceOverride = {source_head_url: 'http://objects.example/head'};
page.FrontierMediaCrypto.resetFault('music/a/test.mp3');
const beforeInvalidHead = providerCalls.length;
response = await read({method: 'HEAD'}); assert.equal(response.status, 403);
assert.equal(providerCalls.length, beforeInvalidHead, 'invalid HEAD authorization fails before provider access');
sourceOverride = null; page.FrontierMediaCrypto.resetFault('music/a/test.mp3');
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
const beforeEncryptedTransient = faultCount;
readFailure = {kind: 'status', status: 503, start: 0};
response = await read({headers: {Range: 'bytes=0-1'}});
await assert.rejects(response.arrayBuffer());
assert.equal(faultCount, beforeEncryptedTransient, 'an encrypted S3 provider 503 is not an ETag/integrity failure');
assert(!page.FrontierMediaCrypto.failureFor(catalog[0].url));
response = await read({headers: {Range: 'bytes=1048550-1048600'}});
assert.equal(response.status, 206);
assert.deepEqual(new Uint8Array(await response.arrayBuffer()), plaintext.slice(1048550, 1048601));
console.log(`s3-media-worker-smoke-ok (${directory}; signed If-Match, HEAD, bounded Range, expiry, replacement refusal, transient exact-offset recovery)`);
