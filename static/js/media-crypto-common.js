'use strict';

// Shared by the page and its service worker. Metadata describes independently
// authenticated chunks, so a seek only needs the chunks covering its byte range.
(() => {
    const CHUNK_SIZE = 1024 * 1024;
    const TAG_SIZE = 16;
    const encoder = new TextEncoder();
    function decode(value) {
        const binary = atob(value);
        return Uint8Array.from(binary, character => character.charCodeAt(0));
    }
    function encode(value) {
        return btoa(Array.from(new Uint8Array(value), byte => String.fromCharCode(byte)).join(''));
    }
    function validate(metadata) {
        if (!metadata || metadata.version !== 1 || metadata.algorithm !== 'AES-256-GCM'
            || metadata.chunk_size !== CHUNK_SIZE || !/^[a-f0-9]{32}$/.test(metadata.file_id)
            || !Number.isSafeInteger(metadata.plaintext_size) || metadata.plaintext_size <= 0
            || metadata.plaintext_size > 10 * 1024 * 1024 * 1024
            || Math.ceil(metadata.plaintext_size / CHUNK_SIZE) >= 2 ** 32
            || decode(metadata.nonce_prefix).byteLength !== 8
            || metadata.ciphertext_size !== metadata.plaintext_size
                + TAG_SIZE * Math.ceil(metadata.plaintext_size / CHUNK_SIZE)) {
            throw new Error('加密文件描述无效');
        }
        return metadata;
    }
    function parameters(metadata, index) {
        const iv = new Uint8Array(12);
        iv.set(decode(metadata.nonce_prefix));
        new DataView(iv.buffer).setUint32(8, index, false);
        return {name: 'AES-GCM', iv, tagLength: 128,
            additionalData: encoder.encode(`frontiercloud:chunk:v1:${metadata.file_id}:${metadata.plaintext_size}:${index}`)};
    }
    function cipherRange(metadata, index) {
        const start = index * (CHUNK_SIZE + TAG_SIZE);
        const plainSize = Math.min(CHUNK_SIZE, metadata.plaintext_size - index * CHUNK_SIZE);
        return {start, end: start + plainSize + TAG_SIZE - 1, size: plainSize + TAG_SIZE};
    }
    function range(header, size) {
        if (!header) return {start: 0, end: size - 1, partial: false};
        const match = /^bytes=(\d*)-(\d*)$/.exec(header);
        if (!match || (!match[1] && !match[2]) || size === 0) return null;
        let start;
        let end;
        if (!match[1]) {
            const suffix = Number(match[2]);
            if (!Number.isSafeInteger(suffix) || suffix <= 0) return null;
            start = Math.max(0, size - suffix);
            end = size - 1;
        } else {
            start = Number(match[1]);
            end = match[2] ? Number(match[2]) : size - 1;
        }
        if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end)
            || start < 0 || start >= size || end < start) return null;
        return {start, end: Math.min(end, size - 1), partial: true};
    }
    async function boundedBytes(response, maximum) {
        if (!response.body) throw new Error('加密数据读取失败');
        const reader = response.body.getReader();
        const chunks = [];
        let length = 0;
        try {
            while (true) {
                const {done, value} = await reader.read();
                if (done) break;
                length += value.byteLength;
                if (length > maximum) throw new Error('存储响应超过加密分块边界');
                chunks.push(value);
            }
        } catch (error) {
            await reader.cancel().catch(() => {});
            throw error;
        } finally { reader.releaseLock(); }
        if (length !== maximum) throw new Error('加密数据分块不完整');
        const bytes = new Uint8Array(length);
        let offset = 0;
        for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
        return bytes;
    }
    function parseLyrics(text) {
        let offset = 0;
        const offsetMatch = /\[offset:([+-]?\d+)\]/i.exec(text);
        if (offsetMatch) offset = Number(offsetMatch[1]) / 1000;
        const entries = [];
        for (const line of text.replace(/^\uFEFF/, '').split(/\r?\n/)) {
            const tags = [...line.matchAll(/\[(\d+):(\d{1,2}(?:\.\d+)?)\]/g)];
            const value = line.replace(/\[[^\]]*\]/g, '').trim();
            for (const tag of tags) {
                const time = Number(tag[1]) * 60 + Number(tag[2]) + offset;
                if (time >= 0 && value) entries.push({time, text: value});
            }
        }
        return entries.sort((left, right) => left.time - right.time);
    }
    globalThis.FrontierCryptoCommon = {CHUNK_SIZE, TAG_SIZE, encode, decode, validate,
        parameters, cipherRange, range, boundedBytes, parseLyrics};
})();
