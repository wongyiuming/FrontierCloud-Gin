import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {webcrypto} from 'node:crypto';
const context = {window: {addEventListener() {}}, TextEncoder, TextDecoder, Uint8Array, DataView, Blob, URL, URLSearchParams, crypto: webcrypto, AbortController, setTimeout, clearTimeout};
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
    assert.deepEqual(Object.keys(result), ['picture'], 'text frames must be ignored');
    assert.equal(result.picture.mime, 'image/jpeg'); assert.deepEqual(Array.from(result.picture.bytes), image);
}
for (const invalid of [new Uint8Array(), Uint8Array.from([73, 68, 51, 4, 0, 0, 127, 127, 127, 127]), tag(4, frame(4, 'APIC', [3, ...ascii('image/svg+xml\0'), 3, 0, ...ascii('<svg onload="bad()"></svg>')]))]) {
    assert.equal(api.parse(invalid).picture, undefined);
}
assert.equal(Object.keys(await api.metadata({media_path: 'music/plain.mp3'})).length, 0);
{
    const path = 'music/plain-without-crypto.mp3', identity = 'c'.repeat(64), requests = [];
    const cover = '/api/v1/media/cover?' + new URLSearchParams({file_path: path, resource_id: identity});
    // A plaintext page may never load either browser encryption component.
    const plain = {window: {addEventListener() {}, location: {href: 'https://media.test/album', origin: 'https://media.test'}},
        TextEncoder, TextDecoder, Uint8Array, DataView, Blob, URL, URLSearchParams,
        AbortController, setTimeout, clearTimeout,
        fetch: async (url, options) => {
            requests.push(url);
            const actual = new URL(url, 'https://media.test');
            assert.equal(actual.pathname, '/api/v1/media/metadata');
            assert.equal(actual.searchParams.get('file_path'), path);
            assert.equal(actual.searchParams.get('resource_id'), identity);
            assert.equal(options.credentials, 'same-origin');
            return new Response(JSON.stringify({cover}));
        }};
    vm.runInNewContext(fs.readFileSync(new URL('../static/js/music-metadata.js', import.meta.url), 'utf8'), plain);
    assert.equal(plain.window.FrontierMediaCrypto, undefined);
    assert.equal(plain.window.FrontierCryptoCommon, undefined);
    const entry = {media_path: path, resource_id: identity, native_metadata: true};
    const tags = await plain.window.FrontierMusicMetadata.metadata(entry);
    assert.equal(tags.cover, cover);
    assert.equal((await plain.window.FrontierMusicMetadata.metadata(entry)).cover, tags.cover);
    assert.equal(requests.length, 1, 'plaintext selected and visible metadata share their own cache without crypto globals');
    await assert.rejects(plain.window.FrontierMusicMetadata.metadata({media_path: 'music/still-encrypted.mp3',
        encryption: {plaintext_size: 256}}), /浏览器解密组件未加载/, 'encrypted reads retain the required crypto boundary');
}
{
    function busyNative(responder) {
        const timers = new Map(), signals = [], state = {requests: 0, cancelled: 0};
        let next = 0;
        const sandbox = {window: {addEventListener() {}, location: {href: 'https://media.test/', origin: 'https://media.test'}},
            TextDecoder, Uint8Array, DataView, Blob, URL, URLSearchParams, AbortController,
            setTimeout(callback, delay) {const id = ++next; timers.set(id, {callback, delay}); return id;},
            clearTimeout(id) {timers.delete(id);},
            fetch: async (_url, options) => {state.requests++; signals.push(options.signal); return responder(state.requests, state);}};
        vm.runInNewContext(fs.readFileSync(new URL('../static/js/music-metadata.js', import.meta.url), 'utf8'), sandbox);
        return {api: sandbox.window.FrontierMusicMetadata, state, timers, signals,
            fire(delay) {const found = [...timers].find(([, value]) => value.delay === delay);
                assert.ok(found, `expected scheduled delay ${delay}`);timers.delete(found[0]);found[1].callback();}};
    }
    function busyResponse(state, retry = '2', status = 503) {
        const body = new ReadableStream({start(controller) {controller.enqueue(new TextEncoder().encode('busy'));},
            cancel() {state.cancelled++;}});
        return new Response(body, {status, headers: retry === null ? {} : {'Retry-After': retry}});
    }
    const entry = () => ({media_path: 'music/busy-native.mp3', resource_id: 'd'.repeat(64), native_metadata: true});
    const recovered = busyNative((count, state) => count === 1 ? busyResponse(state) : new Response('{}'));
    const success = recovered.api.metadata(entry());
    // Attach a handler before advancing turns, so the old implementation gives
    // an assertion failure rather than an unhandled rejection in the RED run.
    const settled = success.then(value => ({value}), error => ({error}));
    await new Promise(setImmediate);
    assert.equal(recovered.state.requests, 1);
    assert.equal(recovered.state.cancelled, 1, 'the busy response body is cancelled before backoff');
    assert.ok([...recovered.timers.values()].some(timer => timer.delay === 2000), '503 must own one Retry-After delay');
    assert.ok([...recovered.timers.values()].some(timer => timer.delay === 15000), 'the original total deadline remains armed');
    recovered.fire(2000);
    const outcome = await settled;
    assert.ifError(outcome.error);assert.deepEqual(Object.keys(outcome.value), []);
    assert.equal(recovered.state.requests, 2);assert.equal(recovered.signals[0], recovered.signals[1]);
    assert.equal(recovered.timers.size, 0, 'successful retry releases its deadline and delay');

    const permanent = busyNative((_count, state) => busyResponse(state));
    const failed = assert.rejects(permanent.api.metadata(entry()), /音乐标签读取失败/);
    await new Promise(setImmediate);permanent.fire(2000);await failed;
    assert.equal(permanent.state.requests, 2, 'a permanent 503 is retried only once');
    assert.equal(permanent.state.cancelled, 2);assert.equal(permanent.timers.size, 0);

    const controller = new AbortController(), abandoned = busyNative((_count, state) => busyResponse(state));
    const cancelled = assert.rejects(abandoned.api.metadata(entry(), {signal: controller.signal}), error => error.name === 'AbortError');
    await new Promise(setImmediate);controller.abort();await cancelled;
    assert.equal(abandoned.state.requests, 1, 'track cancellation while waiting must prevent the second HTTP request');
    assert.equal(abandoned.timers.size, 0);

    const deadline = busyNative((_count, state) => busyResponse(state));
    const expired = assert.rejects(deadline.api.metadata(entry()), error => error.name === 'AbortError');
    await new Promise(setImmediate);deadline.fire(15000);await expired;
    assert.equal(deadline.state.requests, 1, 'the original timeout also aborts backoff');
    assert.equal(deadline.timers.size, 0);

    for (const [status, retry] of [[503, null], [503, 'invalid'], [503, '1.5'], [503, '15'], [429, '2'], [404, '2']]) {
        const refused = busyNative((_count, state) => busyResponse(state, retry, status));
        await assert.rejects(refused.api.metadata(entry()), /音乐标签读取失败/);
        assert.equal(refused.state.requests, 1, 'only a bounded supported 503 delay permits one retry');
        assert.equal(refused.state.cancelled, 1);assert.equal(refused.timers.size, 0);
    }
}
{
    const withIndicator = (name, body, indicator = size(body.length), unsync = false) => {
        const payload = unsync ? body.flatMap(byte => byte === 255 ? [255, 0] : [byte]) : body;
        const bytes = frame(4, name, [...indicator, ...payload]); bytes[9] = unsync ? 3 : 1; return bytes;
    };
    const title = [3, ...ascii('Indicator title')], art = [3, ...ascii('image/jpeg\0'), 3, 0, ...image];
    const result = api.parse(tag(4, [...withIndicator('TIT2', title), ...withIndicator('APIC', art, size(art.length), true)]));
    assert.deepEqual(Object.keys(result), ['picture']);
    assert.deepEqual(Array.from(result.picture.bytes), image, 'DLI length describes the de-unsynchronized payload');
    for (const indicator of [[128, 0, 0, 0], size(art.length + 1)]) {
        assert.equal(api.parse(tag(4, withIndicator('APIC', art, indicator))).picture, undefined);
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
        assert.deepEqual(Object.keys(tags), []);
        assert.deepEqual(requests, ['bytes=0-9'], 'text-only suffixes must never be fetched');
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
for (const commonFile of ['media-crypto-common.js', 'compiled/media-crypto-common.js']) {
    context.window.location = {href: 'https://media.test/album', origin: 'https://media.test'};
    context.setTimeout = setTimeout; context.clearTimeout = clearTimeout;
    vm.runInNewContext(fs.readFileSync(new URL('../static/js/' + commonFile, import.meta.url), 'utf8'), context);
    context.window.FrontierCryptoCommon = context.FrontierCryptoCommon;
    const path = 'music/native/one.mp3', requests = [], identity = 'b'.repeat(64);
    let value = {cover: '/api/v1/media/cover?' + new URLSearchParams({file_path: path, resource_id: identity})};
    context.window.FrontierMediaCrypto = {prepareCatalog: async () => {throw new Error('native plaintext must not request a key');}};
    let response = () => new Response(JSON.stringify(value), {headers: {'Content-Type': 'application/json'}});
    const nativeFetch = async (url, options) => {
        requests.push(url); assert.equal(options.priority, 'low'); assert.equal(options.cache, 'no-store');
        assert.equal(options.credentials, 'same-origin'); assert.equal(options.headers, undefined);
        return response();
    };
    context.fetch = nativeFetch;
    const entry = {media_path: path, resource_id: identity, native_metadata: true};
    const tags = await api.metadata(entry);
    assert.equal(tags.cover, value.cover); assert.deepEqual(Object.keys(tags), ['cover']);
    assert.equal(requests.length, 1); assert.equal(new URL(requests[0], context.window.location.href).pathname, '/api/v1/media/metadata');
    await api.metadata(entry); assert.equal(requests.length, 1, 'selected and visible native metadata share a bounded cache');
    await api.metadata({...entry}); assert.equal(requests.length, 2, 'a fresh native catalog reauthorizes instead of reusing a source without a version stamp');
    value = {cover: '/api/v1/media/cover?' + new URLSearchParams({file_path: path, resource_id: ''})};
    const local = await api.metadata({media_path: path, media_id: 'local-stable-id', native_metadata: true});
    assert.equal(local.cover, value.cover);
    assert.equal(new URL(requests.at(-1), context.window.location.href).searchParams.get('resource_id'), '', 'Standalone must not invent a global resource ID');
    function streamed(chunks, fail = false) {
        const stats = {cancelled: 0, released: 0, underlyingCancelled: 0};
        let index = 0;
        const body = new ReadableStream({
            pull(controller) {
                if (index < chunks.length) controller.enqueue(chunks[index++]);
                else if (fail) controller.error(new Error('native metadata stream broke'));
                else controller.close();
            },
            cancel() { stats.underlyingCancelled++; },
        });
        const getReader = body.getReader.bind(body);
        body.getReader = () => {
            const reader = getReader(), cancel = reader.cancel.bind(reader), release = reader.releaseLock.bind(reader);
            reader.cancel = reason => { stats.cancelled++; return cancel(reason); };
            reader.releaseLock = () => { stats.released++; return release(); };
            return reader;
        };
        return {response: new Response(body), body, stats};
    }
    value = {cover: '/api/v1/media/cover?' + new URLSearchParams({file_path: path, resource_id: identity})};
    const bytes = new TextEncoder().encode(JSON.stringify(value));
    const chunked = streamed([bytes.subarray(0, 21), bytes.subarray(21, 22), bytes.subarray(22)]);
    response = () => chunked.response;
    assert.equal((await api.metadata({...entry})).cover, value.cover);
    assert.equal(chunked.stats.released, 1); assert.equal(chunked.body.locked, false);
    const maximum = 128 * 1024, boundary = new TextEncoder().encode('{}');
    const exactLimit = streamed([boundary, new Uint8Array(maximum - boundary.length).fill(32)]);
    response = () => exactLimit.response;
    assert.deepEqual(Object.keys(await api.metadata({...entry})), [], 'the JSON byte limit is inclusive');
    assert.equal(exactLimit.stats.released, 1);
    const oversized = streamed([new Uint8Array(maximum), new Uint8Array(1), new Uint8Array(1)]);
    response = () => oversized.response;
    await assert.rejects(api.metadata({...entry}), /标签响应超过上限/);
    assert.equal(oversized.stats.cancelled, 1); assert.equal(oversized.stats.underlyingCancelled, 1);
    assert.equal(oversized.stats.released, 1); assert.equal(oversized.body.locked, false);
    const broken = streamed([new TextEncoder().encode('{"title":')], true);
    response = () => broken.response;
    await assert.rejects(api.metadata({...entry}), /native metadata stream broke/);
    assert.equal(broken.stats.cancelled, 1); assert.equal(broken.stats.released, 1);
    assert.equal(broken.body.locked, false);
    response = () => new Response('{"title":"unfinished');
    await assert.rejects(api.metadata({...entry}), error => error.name === 'SyntaxError');
    response = () => new Response(JSON.stringify(value));
    value = {cover: 'https://untrusted.test/secret'};
    await assert.rejects(api.metadata({...entry, media_path: 'music/native/bad.mp3'}), /来源无效/);
    for (value of [{cover: 'x'.repeat(65537)}, {cover: 3}, {title: 'ignored text'}, {unknown: 'field'}, [], null]) {
        await assert.rejects(api.metadata({...entry}), /标签响应无效/);
    }
    await assert.rejects(context.FrontierCryptoCommon.boundedBytes(new Response(new Uint8Array(9)), 10),
        /加密数据分块不完整/, 'encrypted Range reads still require the exact byte count');
    const controller = new AbortController();
    context.fetch = async (_url, options) => new Promise((_resolve, reject) => {
        options.signal.addEventListener('abort', () => reject(new Error('native cancelled')), {once: true});
    });
    const cancelledEntry = {...entry, media_path: 'music/native/cancel.mp3'};
    const pending = api.metadata(cancelledEntry, {signal: controller.signal});
    await new Promise(setImmediate); controller.abort();
    await assert.rejects(pending, /native cancelled/);
    value = {};
    context.fetch = nativeFetch;
    assert.deepEqual(Object.keys(await api.metadata(cancelledEntry)), []);
    context.window.FrontierMediaCrypto = {prepareCatalog: async entries => {entries[0].url = '/authorized';}};
    context.window.FrontierCryptoCommon = {validate() {}, boundedBytes: async response => response.bytes};
}
{
    const requests = [];
    const data = tag(4, [...frame(4, 'TIT2', [3, ...ascii('Wrong title')]), ...frame(4, 'APIC', [3, ...ascii('image/jpeg\0'), 3, 0, ...image])]);
    const object = {media_path: 'music/s3.mp3', transport: 'S3', object_id: 'owned-object', size_bytes: data.length};
    const s3 = {window: {addEventListener() {}, FrontierCryptoCommon: {
        validate() { throw new Error('plaintext needs no encryption metadata'); },
        async boundedBytes(response, size) { const bytes = new Uint8Array(await response.arrayBuffer()); assert.equal(bytes.length, size); return bytes; }},
        FrontierMediaCrypto: {async prepareCatalog(entries) {
            assert.equal(entries[0].object_id, 'owned-object'); entries[0].url = '/__fc_media/signed-header-route';
        }}},
        TextEncoder, TextDecoder, Uint8Array, DataView, Blob, URL, URLSearchParams, crypto: webcrypto, AbortController, setTimeout, clearTimeout,
        fetch: async (url, options) => {
            assert.equal(url, '/__fc_media/signed-header-route'); requests.push(options.headers.Range);
            const range = /^bytes=(\d+)-(\d+)$/.exec(options.headers.Range);
            const start = Number(range[1]), end = Number(range[2]);
            return new Response(data.slice(start, end + 1), {status: 206, headers: {
                'Content-Range': `bytes ${start}-${end}/${data.length}`, 'Content-Length': String(end - start + 1)}});
        }};
    vm.runInNewContext(fs.readFileSync(new URL('../static/js/music-metadata.js', import.meta.url), 'utf8'), s3);
    const metadata = await s3.window.FrontierMusicMetadata.metadata(object);
    assert.deepEqual(Object.keys(metadata), ['cover']);
    assert.deepEqual(Array.from(new Uint8Array(await (await fetch(metadata.cover)).arrayBuffer())), image);
    assert.deepEqual(requests, ['bytes=0-9', `bytes=10-${data.length - 1}`]);
}
console.log('music-metadata-smoke-ok: cover-only ID3, bounded retry and S3 artwork');
