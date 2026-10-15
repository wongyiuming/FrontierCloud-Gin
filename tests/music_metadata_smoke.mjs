import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {webcrypto} from 'node:crypto';
const context = {window: {addEventListener() {}}, TextDecoder, Uint8Array, DataView, Blob, URL, crypto: webcrypto};
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
console.log('music-metadata-smoke-ok: ID3 versions, Unicode, image signatures, bounded malformed fallback');
