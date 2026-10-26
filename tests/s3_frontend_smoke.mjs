import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {webcrypto} from 'node:crypto';

// Exercise the actual bounded browser uploader with real SHA256, Blob slices
// and concurrent provider requests. No provider URL or credential is logged.
const source = fs.readFileSync('static/js/admin-upload-integrity.js', 'utf8');
const uploader = source.slice(source.indexOf('const S3_PART_BYTES'), source.indexOf('\nrunUploadTask ='));
const partBytes = 8 * 1024 * 1024;
const bytes = new Uint8Array(partBytes + 17); bytes.fill(37);
const file = new Blob([bytes]);
const checksum = async value => Buffer.from(await webcrypto.subtle.digest('SHA-256', value)).toString('base64');
const checksums = [await checksum(bytes.subarray(0, partBytes)), await checksum(bytes.subarray(partBytes))];
let state, requests, transfers, active, peak, failTransfer, badHeaders;
const context = {
    console, crypto: webcrypto, URL, AbortController, Uint8Array, Blob,
    btoa: value => Buffer.from(value, 'binary').toString('base64'),
    setTimeout, clearTimeout, uploadInterrupted: false, uploadRunning: false,
    window: {addEventListener() {}}, document: {getElementById() { return null; }}, $() { return null; },
    requestHeaders: () => ({'X-CSRF-Token': 'only-control'}),
    setUploadControlsDisabled() {}, renderTree: async () => {},
    async api(url, options = {}) {
        requests.push({url, method: options.method || 'GET', body: options.body ? JSON.parse(options.body) : null});
        assert(url.startsWith('/api/v1/media/admin/upload/s3/u1'));
        if (url.endsWith('/begin')) { assert.equal(state.state, 'reserved'); state.state = 'created'; }
        const part = /\/parts\/(\d+)\/(grant|confirm)$/.exec(url);
        if (part) {
            const number = Number(part[1]);
            if (part[2] === 'grant') {
                const body = JSON.parse(options.body);
                assert.deepEqual(Object.keys(body).sort(), ['checksum_sha256', 'size_bytes']);
                assert.equal(body.checksum_sha256, checksums[number - 1]);
                state.parts = state.parts.filter(value => value.number !== number);
                state.parts.push({number, ...body, confirmed: false});
                return {url: `https://objects.example/part/${number}?signature=private`, expires_at: 2000000000,
                    headers: badHeaders ? {'X-CSRF-Token': 'must-not-send'} : {'X-Amz-Checksum-Sha256': body.checksum_sha256,
                        'Content-Length': String(body.size_bytes)}};
            }
            assert.deepEqual(JSON.parse(options.body), {}, 'client never supplies ETag or provider proof');
            state.parts.find(value => value.number === number).confirmed = true;
        }
        if (url.endsWith('/finalize')) return {path: 'music/a/test.mp3'};
        return structuredClone(state);
    },
    async fetch(url, options) {
        active += 1; peak = Math.max(peak, active);
        try {
            assert.equal(options.method, 'PUT'); assert.equal(options.credentials, 'omit');
            assert.equal(options.mode, 'cors'); assert.equal(options.redirect, 'error');
            assert.equal(options.referrerPolicy, 'no-referrer');
            assert(!Object.keys(options.headers).some(name => /csrf|cookie|authorization|content-length/i.test(name)));
            assert(options.body.byteLength <= partBytes);
            transfers.push(url);
            await new Promise(resolve => setTimeout(resolve, 4));
            if (failTransfer) throw new Error('provider URL is intentionally private');
            return {status: 200, body: {async cancel() {}}};
        } finally { active -= 1; }
    },
};
vm.createContext(context); vm.runInContext(uploader, context);
function reset() {
    state = {state: 'reserved', reservation: {expected_bytes: file.size}, parts: []};
    requests = []; transfers = []; active = 0; peak = 0; failTransfer = false; badHeaders = false;
}
reset();
const progress = [];
const result = await context.uploadS3Parts({upload_id: 'u1'}, file, value => progress.push(value));
assert.equal(result.path, 'music/a/test.mp3'); assert.equal(peak, 2); assert.equal(active, 0);
assert.equal(transfers.length, 2); assert.equal(progress.at(-1), 1);
assert.equal(requests.filter(item => item.url.endsWith('/begin')).length, 1);
assert(requests.find(item => item.url.endsWith('/touch')));

reset(); state.state = 'created';
state.parts = [{number: 1, size_bytes: partBytes, checksum_sha256: checksums[0], confirmed: true}];
await context.uploadS3Parts({upload_id: 'u1'}, file, () => {});
assert.equal(transfers.length, 1, 'confirmed bytes are validated then skipped');
assert(!requests.some(item => item.url.endsWith('/begin')), 'resume never replays CreateMultipart');

reset(); state.state = 'created';
state.parts = [{number: 1, size_bytes: partBytes, checksum_sha256: 'different-bytes', confirmed: true}];
await assert.rejects(context.uploadS3Parts({upload_id: 'u1'}, file, () => {}), /不一致/);
assert.equal(transfers.length, 0); assert(!requests.some(item => item.url.endsWith('/grant')));

reset(); state.state = 'create_unknown';
await assert.rejects(context.uploadS3Parts({upload_id: 'u1'}, file, () => {}), /核验/);
assert.equal(requests.length, 1, 'ambiguous creation is retained without a new mutation');

reset(); failTransfer = true;
await assert.rejects(context.uploadS3Parts({upload_id: 'u1'}, file, () => {}), /可恢复/);
assert.equal(active, 0, 'both workers settle before returning an error');
assert(!requests.some(item => item.method === 'DELETE' || item.url.endsWith('/finalize')));

reset(); badHeaders = true;
await assert.rejects(context.uploadS3Parts({upload_id: 'u1'}, file, () => {}), /请求头/);
assert.equal(transfers.length, 0);
assert(!source.includes('/session/${encodeURIComponent(reservation.upload_id)}/s3'));
console.log('s3-frontend-smoke-ok (bounded two-part upload, durable resume, failure retention, no credential relay)');
