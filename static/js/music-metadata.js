(() => {
    'use strict';
    const TAG_LIMIT = 8 * 1024 * 1024, IMAGE_LIMIT = 4 * 1024 * 1024, IMAGE_BUDGET = 32 * 1024 * 1024;
    const cache = new Map(), pictures = new Map();
    let imageBytes = 0, active = 0;
    const queue = [];
    const ascii = bytes => String.fromCharCode(...bytes);
    function syncSafe(bytes) {
        if (bytes.length !== 4 || bytes.some(byte => byte > 127)) return -1;
        return bytes.reduce((n, byte) => n * 128 + byte, 0);
    }
    function unSync(bytes) {
        const out = [];
        for (let i = 0; i < bytes.length; i++) { out.push(bytes[i]); if (bytes[i] === 255 && bytes[i + 1] === 0) i++; }
        return Uint8Array.from(out);
    }
    function terminator(bytes, offset, wide) {
        for (let i = offset; i < bytes.length; i += wide ? 2 : 1) {
            if (bytes[i] === 0 && (!wide || bytes[i + 1] === 0)) return i + (wide ? 2 : 1);
        }
        return -1;
    }
    function picture(bytes, version) {
        if (bytes.length < 6 || bytes[0] > 3) return null;
        let offset = version === 2 ? 4 : terminator(bytes, 1, false);
        if (offset < 0 || offset >= bytes.length) return null;
        const type = bytes[offset++];
        offset = terminator(bytes, offset, bytes[0] === 1 || bytes[0] === 2);
        if (offset < 0) return null;
        const image = bytes.subarray(offset);
        if (image.length > IMAGE_LIMIT || image.length < 12) return null;
        let mime = '';
        if (image[0] === 255 && image[1] === 216 && image[2] === 255) mime = 'image/jpeg';
        else if (ascii(image.subarray(0, 8)) === '\x89PNG\r\n\x1a\n') mime = 'image/png';
        else if (['GIF87a', 'GIF89a'].includes(ascii(image.subarray(0, 6)))) mime = 'image/gif';
        else if (ascii(image.subarray(0, 4)) === 'RIFF' && ascii(image.subarray(8, 12)) === 'WEBP') mime = 'image/webp';
        return mime ? {bytes: image.slice(), mime, front: type === 3} : null;
    }
    function parse(bytes) {
        const result = {};
        if (bytes.length < 10 || ascii(bytes.subarray(0, 3)) !== 'ID3') return result;
        const version = bytes[3], size = syncSafe(bytes.subarray(6, 10));
        if (version < 2 || version > 4 || size < 0 || size > TAG_LIMIT || bytes.length < size + 10) return result;
        // ID3v2.2's compression format is not a tag frame stream.
        if (version === 2 && (bytes[5] & 64)) return result;
        let data = bytes.subarray(10, size + 10);
        if (version < 4 && (bytes[5] & 128)) data = unSync(data);
        if (version >= 3 && (bytes[5] & 64)) {
            if (data.length < 4) return result;
            const skip = version === 4 ? syncSafe(data.subarray(0, 4)) : new DataView(data.buffer, data.byteOffset, 4).getUint32(0) + 4;
            if (skip < 4 || skip > data.length) return result;
            data = data.subarray(skip);
        }
        while (data.length >= (version === 2 ? 6 : 10)) {
            const width = version === 2 ? 6 : 10, name = ascii(data.subarray(0, version === 2 ? 3 : 4));
            if (!/^[A-Z0-9]+$/.test(name)) break;
            const length = version === 2 ? data[3] * 65536 + data[4] * 256 + data[5]
                : version === 4 ? syncSafe(data.subarray(4, 8)) : new DataView(data.buffer, data.byteOffset + 4, 4).getUint32(0);
            if (length <= 0 || length > data.length - width) break;
            const flags = version === 2 ? 0 : data[9];
            let body = data.subarray(width, width + length); data = data.subarray(width + length);
            if (name !== 'APIC' && name !== 'PIC') continue;
            if ((version === 3 && (flags & 224)) || (version === 4 && (flags & 76))) continue;
            if (version === 4 && ((flags & 2) || (bytes[5] & 128))) body = unSync(body);
            if (version === 4 && (flags & 1)) {
                if (body.length < 4 || syncSafe(body.subarray(0, 4)) !== body.length - 4) continue;
                body = body.subarray(4);
            }
            if (name === 'APIC' || name === 'PIC') {
                const candidate = picture(body, version);
                if (candidate && (!result.picture || candidate.front)) result.picture = candidate;
            }
        }
        return result;
    }
    function limited(work, priority = false) {
        return new Promise((resolve, reject) => {
            const job = {work, resolve, reject};
            if (priority) queue.unshift(job); else queue.push(job);
            pump();
        });
    }
    function pump() {
        while (active < 2 && queue.length) {
            const job = queue.shift(); active++;
            Promise.resolve().then(job.work).then(job.resolve, job.reject).finally(() => { active--; pump(); });
        }
    }
    async function range(url, start, end, size, signal) {
        const controller = new AbortController();
        const abort = () => controller.abort();
        if (signal?.aborted) controller.abort();
        signal?.addEventListener('abort', abort, {once: true});
        const timeout = setTimeout(() => controller.abort(), 15000);
        try {
            const response = await fetch(url, {credentials: 'same-origin', cache: 'no-store', priority: 'low', signal: controller.signal, headers: {Range: `bytes=${start}-${end}`}});
            if (response.status !== 206 || response.headers.get('Content-Range') !== `bytes ${start}-${end}/${size}`) {
                await response.body?.cancel(); throw new Error('音乐标签分段读取失败');
            }
            return await window.FrontierCryptoCommon.boundedBytes(response, end - start + 1);
        } finally {
            clearTimeout(timeout);
            signal?.removeEventListener('abort', abort);
        }
    }
    async function metadataBytes(response) {
        if (!response.body) throw new Error('音乐标签读取失败');
        const reader = response.body.getReader(), chunks = [];
        let length = 0;
        try {
            while (true) {
                const {done, value} = await reader.read();
                if (done) break;
                length += value.byteLength;
                if (length > 128 * 1024) throw new Error('音乐标签响应超过上限');
                chunks.push(value);
            }
        } catch (error) {
            await reader.cancel().catch(() => {});
            throw error;
        } finally { reader.releaseLock(); }
        const bytes = new Uint8Array(length);
        let offset = 0;
        for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
        return bytes;
    }
    async function nativeMetadata(entry, signal) {
        const path = entry.media_path || entry.path, identity = entry.resource_id || '';
        if (typeof path !== 'string' || typeof identity !== 'string' || (identity && !/^[a-f0-9]{64}$/.test(identity)))
            throw new Error('音乐标签来源无效');
        const query = new URLSearchParams({file_path: path, resource_id: identity});
        const controller = new AbortController(), abort = () => controller.abort();
        signal?.addEventListener('abort', abort, {once: true});
        if (signal?.aborted) controller.abort();
        const timeout = setTimeout(abort, 15000);
        try {
            let response;
            for (let attempt = 0; attempt < 2; attempt++) {
                controller.signal.throwIfAborted();
                response = await fetch('/api/v1/media/metadata?' + query, {
                    credentials: 'same-origin', cache: 'no-store', priority: 'low', signal: controller.signal,
                });
                if (response.ok) break;
                const retry = response.status === 503 ? response.headers.get('Retry-After') : null;
                await response.body?.cancel();
                const seconds = typeof retry === 'string' && /^\d+$/.test(retry) ? Number(retry) : NaN;
                if (attempt !== 0 || !Number.isInteger(seconds) || seconds < 1 || seconds >= 15)
                    throw new Error('音乐标签读取失败');
                await new Promise((resolve, reject) => {
                    const abortDelay = () => {
                        clearTimeout(timer);
                        controller.signal.removeEventListener('abort', abortDelay);
                        reject(controller.signal.reason || new Error('音乐标签读取已取消'));
                    };
                    const timer = setTimeout(() => {
                        controller.signal.removeEventListener('abort', abortDelay);
                        resolve();
                    }, seconds * 1000);
                    controller.signal.addEventListener('abort', abortDelay, {once: true});
                    if (controller.signal.aborted) abortDelay();
                });
            }
            const value = JSON.parse(new TextDecoder().decode(await metadataBytes(response)));
            if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(field =>
                field !== 'cover' || typeof value[field] !== 'string' || value[field].length > 64 * 1024)) throw new Error('音乐标签响应无效');
            if (value.cover) {
                const cover = new URL(value.cover, window.location.href);
                if (!value.cover.startsWith('/api/v1/media/cover?') || cover.origin !== window.location.origin
                    || cover.hash || cover.searchParams.size !== 2 || cover.searchParams.get('file_path') !== path
                    || cover.searchParams.get('resource_id') !== identity) throw new Error('音乐标签来源无效');
            }
            return value;
        } finally {
            clearTimeout(timeout); signal?.removeEventListener('abort', abort);
        }
    }
    async function load(entry, signal) {
        signal?.throwIfAborted();
        if (entry.native_metadata === true && !entry.encryption && entry.transport !== 'S3') return nativeMetadata(entry, signal);
        if (!window.FrontierMediaCrypto || !window.FrontierCryptoCommon) throw new Error('浏览器解密组件未加载');
        if (entry.encryption) window.FrontierCryptoCommon.validate(entry.encryption);
        const size = entry.encryption?.plaintext_size ?? entry.size_bytes ?? entry.size;
        if (!Number.isSafeInteger(size) || size < 1 || size > 10 * 1024 ** 3) throw new Error('媒体长度无效');
        if (size < 10) return {};
        const source = {...entry};
        await window.FrontierMediaCrypto.prepareCatalog([source]);
        const header = await range(source.url, 0, 9, size, signal);
        let result = {};
        if (ascii(header.subarray(0, 3)) === 'ID3') {
            const length = syncSafe(header.subarray(6, 10));
            if (length > 0 && length <= TAG_LIMIT && length <= size - 10) {
                const body = await range(source.url, 10, length + 9, size, signal);
                const bytes = new Uint8Array(length + 10); bytes.set(header); bytes.set(body, 10); result = parse(bytes);
            }
        }
        if (result.picture) {
            const image = result.picture;
            const digest = await crypto.subtle.digest('SHA-256', image.bytes);
            const identity = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
            if (!pictures.has(identity) && imageBytes + image.bytes.length <= IMAGE_BUDGET) {
                const blob = new Blob([image.bytes], {type: image.mime}), url = URL.createObjectURL(blob);
                pictures.set(identity, url); imageBytes += image.bytes.length;
            }
            result.cover = pictures.get(identity); delete result.picture;
        }
        return result;
    }
    function metadata(entry, {priority = false, signal} = {}) {
        if ((!entry?.encryption && entry?.native_metadata !== true && entry?.transport !== 'S3') || !/\.mp3$/i.test(entry.media_path || entry.path || '')) return Promise.resolve({});
        // Native catalog entries must reauthorize after each catalog refresh.
        // Encrypted identities retain descriptor-bound reuse after replacement.
        const key = entry.native_metadata === true && !entry.encryption && entry.transport !== 'S3' ? entry
            : JSON.stringify([entry.media_path || entry.path, entry.object_id || entry.resource_id || entry.media_id, entry.encryption]);
        if (!cache.has(key)) {
            if (cache.size >= 128) cache.delete(cache.keys().next().value);
            const promise = limited(() => load(entry, signal), priority).catch(error => { cache.delete(key); throw error; });
            cache.set(key, promise);
        }
        return cache.get(key);
    }
    window.addEventListener('pagehide', event => {
        if (event.persisted) return;
        for (const url of pictures.values()) URL.revokeObjectURL(url);
        pictures.clear(); cache.clear(); imageBytes = 0;
    });
    window.FrontierMusicMetadata = {metadata, parse};
})();
