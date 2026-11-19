import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {createHash, webcrypto} from 'node:crypto';

const source = fs.readFileSync('static/js/upload-sha256.js', 'utf8');
const context = vm.createContext({crypto: webcrypto, Uint8Array, Uint32Array, DataView,
    btoa: value => Buffer.from(value, 'binary').toString('base64')});
const hashUpload = vm.runInContext(`${source}\nuploadSHA256`, context);
const size = 8 * 1024 * 1024 + 17;
const data = Buffer.alloc(size, 37);
let reads = 0;
const file = {size, slice(start, end) { reads++; const chunk = data.subarray(start, end); return {
    async arrayBuffer() { return Uint8Array.from(chunk).buffer; },
}; }};
const parts = [];
const digest = await hashUpload(file, () => {}, part => parts.push(part));
assert.equal(digest, createHash('sha256').update(data).digest('hex'));
assert.deepEqual(parts, [data.subarray(0, 8 * 1024 * 1024), data.subarray(8 * 1024 * 1024)]
    .map(part => createHash('sha256').update(part).digest('base64')));
assert.equal(reads, 9, 'ciphertext is read once in bounded slices');
console.log('selected S3 precommit smoke passed');
