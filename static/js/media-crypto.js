'use strict';

(() => {
    const common = window.FrontierCryptoCommon;
    const admin = Boolean(document.getElementById('uploadFiles'));
    const apiBase = admin ? '/api/v1/media/admin/crypto' : '/api/v1/media/crypto';
    const token = Array.from(crypto.getRandomValues(new Uint8Array(16)),
        byte => byte.toString(16).padStart(2, '0')).join('');
    let session = null;
    let sessionPromise = null;
    let workerPromise = null;
    const envelopes = new Map();
    const sources = new Map();
    const sourceVersions = new Map();
    const faults = new Map();
    const lyricReads = new Map();
    const recordingSources = new Map();
    const temporaryNames = new Set();

    function requireCrypto() {
        if (!window.isSecureContext || !crypto.subtle || !common)
            throw new Error('媒体安全功能需要 HTTPS 和支持 Web Crypto 的浏览器');
    }
    function headers() {
        return admin && typeof requestHeaders === 'function'
            ? requestHeaders() : {'Content-Type': 'application/json'};
    }
    async function jsonRequest(path, body) {
        const response = await fetch(apiBase + path, {method: 'POST', credentials: 'same-origin',
            cache: 'no-store', headers: headers(), body: JSON.stringify(body)});
        const data = await response.json();
        if (!response.ok) {
            const error = new Error(typeof data.detail === 'string' ? data.detail : '浏览器密钥授权失败');
            error.status = response.status;
            throw error;
        }
        return data;
    }
    async function getSession() {
        requireCrypto();
        if (session && session.deadline > common.monotonicNow() + 30000) return session;
        if (sessionPromise) return sessionPromise;
        sessionPromise = (async () => {
            const pair = await crypto.subtle.generateKey({name: 'ECDH', namedCurve: 'P-256'}, false, ['deriveBits']);
            const publicKey = await crypto.subtle.exportKey('raw', pair.publicKey);
            const startedAt = common.monotonicNow();
            const handshake = await jsonRequest('/session', {public_key: common.encode(publicKey)});
            if (!Number.isInteger(handshake.expires_in) || handshake.expires_in < 1 || handshake.expires_in > 900
                || !Number.isSafeInteger(handshake.expires_at)
                || handshake.expires_at <= 0) {
                const error = new Error('临时密钥会话期限无效');
                error.status = 422;
                throw error;
            }
            const deadline = startedAt + handshake.expires_in * 1000;
            if (deadline <= common.monotonicNow()) {
                const error = new Error('临时密钥授权已过期');
                error.status = 403;
                throw error;
            }
            const serverKey = await crypto.subtle.importKey('raw', common.decode(handshake.public_key),
                {name: 'ECDH', namedCurve: 'P-256'}, false, []);
            const secret = await crypto.subtle.deriveBits({name: 'ECDH', public: serverKey}, pair.privateKey, 256);
            const hkdfKey = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
            new Uint8Array(secret).fill(0);
            const wrapKey = await crypto.subtle.deriveKey({name: 'HKDF', hash: 'SHA-256',
                salt: common.decode(handshake.salt),
                info: new TextEncoder().encode('frontiercloud:browser-wrap:v1:' + handshake.session_id)},
            hkdfKey, {name: 'AES-GCM', length: 256}, false, ['decrypt']);
            session = {session_id: handshake.session_id, expires_at: handshake.expires_at, deadline, wrapKey};
            envelopes.clear();
            return session;
        })().finally(() => { sessionPromise = null; });
        return sessionPromise;
    }
    async function unwrap(activeSession, metadata, envelope) {
        common.validate(metadata);
        if (envelope.expires_at !== activeSession.expires_at || activeSession.deadline <= common.monotonicNow()) {
            const error = new Error('临时密钥授权已过期或期限不一致');
            error.status = 403;
            throw error;
        }
        const raw = await crypto.subtle.decrypt({name: 'AES-GCM', tagLength: 128,
            iv: common.decode(envelope.iv), additionalData: new TextEncoder().encode(
                `frontiercloud:key-envelope:v1:${activeSession.session_id}:${metadata.file_id}`)},
        activeSession.wrapKey, common.decode(envelope.wrapped_key));
        try {
            if (raw.byteLength !== 32) throw new Error('临时密钥长度无效');
            return await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
        } finally { new Uint8Array(raw).fill(0); }
    }
    function sourceGrant(data, startedAt) {
        const invalid = message => Object.assign(new Error(message), {status: 403});
        const ttl = data.source_expires_in ?? data.expires_in;
        if (!Number.isInteger(ttl) || ttl < 1 || ttl > 300 || typeof data.object_id !== 'string' || !data.object_id)
            throw invalid('S3 读取授权无效');
        let url;
        try { url = new URL(data.source_url); }
        catch (_) { throw invalid('S3 读取地址无效'); }
        if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.href.length > 16384)
            throw invalid('S3 读取地址无效');
        const signed = data.source_headers;
        if (!signed || Array.isArray(signed) || Object.keys(signed).length !== 1
            || typeof signed['If-Match'] !== 'string' || !/^"[^"\r\n]{1,1024}"$/.test(signed['If-Match']))
            throw invalid('S3 读取身份约束缺失');
        return {transport: 'S3', object_id: data.object_id, source_url: url.href, source_headers: signed,
            source_head_url: data.source_head_url, source_head_headers: data.source_head_headers,
            size_bytes: data.size_bytes, content_type: data.content_type, filename: data.filename,
            expires_at: data.source_expires_at ?? data.expires_at, deadline: startedAt + ttl * 1000};
    }
    function nativePlainGrant(data, descriptor, startedAt, sessionDeadline) {
        const invalid = () => Object.assign(new Error('明文资源授权无效'), {status: 403});
        if (data.transport !== 'Native' || data.resource_id !== descriptor.resource_id || data.object_id !== descriptor.object_id
            || !/^[a-f0-9]{64}$/.test(data.resource_id || '') || !/^[a-f0-9]{64}$/.test(data.object_id || '')
            || !/^[a-f0-9]{64}$/.test(data.source_revision || '') || !Number.isSafeInteger(data.size_bytes)
            || data.size_bytes < 0 || data.size_bytes > 10 * 1024 ** 3 || data.size_bytes !== descriptor.size_bytes
            || !Number.isInteger(data.source_expires_in) || data.source_expires_in < 1 || data.source_expires_in > 300
            || !Number.isSafeInteger(data.source_expires_at)) throw invalid();
        let target, origin;
        try { target = new URL(data.source_url); if (data.source_transport === 'Direct') origin = new URL(data.source_origin); } catch (_) { throw invalid(); }
        const opaque = data.source_object_id !== undefined;
        if (data.source_identity_version !== undefined && data.source_identity_version !== 1
            || descriptor.source_identity_version === 1 && data.source_identity_version !== 1
            || (data.source_identity_version === 1 || descriptor.source_identity_version === 1) && !opaque
            || opaque && data.source_identity_version !== 1) throw invalid();
        if (opaque && (!/^[a-f0-9]{64}$/.test(data.source_object_id) || data.source_object_id === data.object_id || data.source_object_id === data.resource_id
            || !/^[a-f0-9]{32}$/.test(data.source_owner_id || ''))) throw invalid();
        const ownerPath = opaque ? `/internal/v1/opaque-media/${data.source_object_id}` : `/internal/v1/media/${data.object_id}`;
        const opaqueRelayPath = `/api/v1/media/opaque-follower-relay/${data.source_object_id}`;
        const opaqueLocalRelayPath = `/api/v1/media/opaque-local-follower-relay/${data.source_object_id}`;
        const opaqueLyricDirectPath = `/api/v1/media/master-direct-lyric/${data.source_object_id}`;
        const opaqueLyricRelayPath = `/api/v1/media/master-relay/${data.source_object_id}`;
        const opaqueLyricLocalPath = `/api/v1/media/master-local-lyric/${data.source_object_id}`;
        const opaqueMediaLocalPath = `/api/v1/media/master-local/${data.source_object_id}`;
        const direct = data.source_transport === 'Direct' && origin && origin.protocol === 'https:' && origin.origin === data.source_origin
            && origin.pathname === '/' && !origin.username && !origin.password && !origin.search && !origin.hash
            && target.origin === origin.origin && (target.pathname === `/api/v1/media/master-direct${descriptor.kind === 'lyric' ? '-lyric' : ''}/${data.resource_id}`
                || descriptor.kind === 'lyric' && opaque && target.pathname === opaqueLyricDirectPath
                || descriptor.kind !== 'lyric' && target.pathname === ownerPath);
        const relay = data.source_transport === 'Relay' && target.origin === window.location.origin
            && (target.pathname === `/api/v1/media/master-relay/${data.resource_id}`
                || descriptor.kind === 'lyric' && opaque && target.pathname === opaqueLyricRelayPath
                || descriptor.kind !== 'lyric' && (target.pathname === `/api/v1/media/follower-relay/${data.resource_id}` || opaque && (target.pathname === opaqueRelayPath || target.pathname === opaqueLocalRelayPath)));
        const local = data.source_transport === 'Local' && target.origin === window.location.origin
            && (descriptor.kind !== 'lyric' && (target.pathname === ownerPath || opaque && target.pathname === opaqueMediaLocalPath)
                || descriptor.kind === 'lyric' && opaque && target.pathname === opaqueLyricLocalPath);
        const name = relay ? 'X-Media-Relay' : 'X-Media-Capability', headers = data.source_headers;
        if (target.protocol !== 'https:' || target.username || target.password || target.search || target.hash || opaque && target.pathname !== (relay ? descriptor.kind === 'lyric' ? opaqueLyricRelayPath : target.pathname === opaqueLocalRelayPath ? opaqueLocalRelayPath : opaqueRelayPath : descriptor.kind === 'lyric' ? local ? opaqueLyricLocalPath : opaqueLyricDirectPath : local && target.pathname === opaqueMediaLocalPath ? opaqueMediaLocalPath : ownerPath) || !(direct || relay || local)
            || !headers || Array.isArray(headers) || Object.keys(headers).length !== 1
            || typeof headers[name] !== 'string' || headers[name].length > 4096 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(headers[name])) throw invalid();
        return {transport: 'Native', kind: descriptor.kind || 'media', source_identity_version: data.source_identity_version, resource_id: data.resource_id, object_id: data.object_id, track_resource_id: descriptor.track_resource_id, source_object_id: data.source_object_id, source_owner_id: data.source_owner_id, source_revision: data.source_revision,
            size_bytes: data.size_bytes, source_url: target.href, source_headers: {[name]: headers[name]},
            source_transport: data.source_transport, source_origin: data.source_origin, content_type: data.content_type, filename: data.filename,
            deadline: Math.min(sessionDeadline, startedAt + data.source_expires_in * 1000)};
    }
    function sameEncryptionDescriptor(a, b) {
        if (!a || !b) return !a && !b;
        return ['version', 'algorithm', 'file_id', 'nonce_prefix', 'plaintext_size', 'chunk_size', 'ciphertext_size']
            .every(field => a[field] === b[field]);
    }
    function sameSourceDescriptor(a, b) {
        return ['transport', 'object_id', 'resource_id', 'track_resource_id', 'size_bytes', 'native_source', 'source_identity_version', 'kind', 'encrypted']
            .every(field => a[field] === b[field]) && sameEncryptionDescriptor(a.encryption, b.encryption);
    }
    async function fileGrant(filePath, expectedFileId = '', revalidate = false) {
        if (filePath.startsWith('@recording/')) return recordingGrant(filePath, expectedFileId, revalidate);
        const descriptor = sources.get(filePath);
        if (filePath.startsWith('@admin-download/') && !descriptor?.download_snapshot) {
            const error = new Error('下载计划已失效'); error.status = 403; throw error;
        }
        const sourceVersion = sourceVersions.get(filePath);
        const cached = envelopes.get(filePath);
        if (!revalidate && cached && cached.deadline > common.monotonicNow() + 10000
            && (descriptor?.transport !== 'S3' || cached.object_id === descriptor.object_id)
            && (!descriptor?.native_source || cached.resource_id === descriptor.resource_id && cached.object_id === descriptor.object_id && cached.track_resource_id === descriptor.track_resource_id)
            && (!descriptor?.native_source || cached.source_identity_version === descriptor.source_identity_version)
            && (!descriptor?.encryption || sameEncryptionDescriptor(cached.encryption, descriptor.encryption))
            && (!expectedFileId || (cached.encryption?.file_id || cached.object_id) === expectedFileId)) return cached;
        const startedAt = common.monotonicNow();
        let grant;
        if (descriptor?.download_snapshot) {
            const activeSession = await getSession();
            const data = await jsonRequest('/key', {session_id: activeSession.session_id, file_path: descriptor.path,
                resource_id: descriptor.resource_id, download_snapshot: descriptor.download_snapshot});
            if (data.resource_id !== descriptor.resource_id || data.download_snapshot !== descriptor.download_snapshot
                || !sameEncryptionDescriptor(data.encryption, descriptor.encryption) || expectedFileId !== data.encryption?.file_id) {
                const error = new Error('下载资源身份已变化'); error.status = 409; throw error;
            }
            const key = await unwrap(activeSession, data.encryption, data.key_envelope);
            grant = {resource_id: data.resource_id, download_snapshot: data.download_snapshot, encryption: data.encryption, key,
                source_url: data.source_url, content_type: data.content_type, filename: data.filename,
                expires_at: data.key_envelope.expires_at, deadline: activeSession.deadline};
            if (descriptor.transport === 'S3') {
                if (data.transport !== 'S3' || data.object_id !== descriptor.object_id || data.size_bytes !== data.encryption.ciphertext_size) {
                    const error = new Error('S3 下载资源身份已变化'); error.status = 409; throw error;
                }
                Object.assign(grant, sourceGrant(data, startedAt));
                grant.deadline = Math.min(grant.deadline, activeSession.deadline);
            } else if (descriptor.transport === 'Direct') {
                const signed = nativePlainGrant(data, {...descriptor, kind: 'media'}, startedAt, activeSession.deadline);
                if (signed.source_transport !== 'Direct' || signed.source_url !== `${signed.source_origin}/internal/v1/opaque-media/${signed.source_object_id}`) {
                    const error = new Error('直连下载路径无效'); error.status = 403; throw error;
                }
                Object.assign(grant, signed);
            } else {
                let source;
                try { source = new URL(data.source_url, window.location.origin); } catch (_) {}
                if (data.transport !== undefined || !source || source.origin !== window.location.origin || source.username || source.password || source.hash
                    || source.pathname !== '/api/v1/media/admin/download/bytes' || source.searchParams.size !== 2
                    || source.searchParams.get('resource_id') !== descriptor.resource_id || source.searchParams.get('snapshot') !== descriptor.download_snapshot) {
                    const error = new Error('下载密文路径无效'); error.status = 409; throw error;
                }
                grant.source_url = source.href;
                grant.download_session_id = activeSession.session_id;
            }
        } else if (descriptor?.native_source && !descriptor.encryption && !descriptor.encrypted) {
            const activeSession = await getSession();
            const data = await jsonRequest('/native/source', {session_id: activeSession.session_id, file_path: filePath,
                resource_id: descriptor.resource_id, object_id: descriptor.object_id,
                ...(descriptor.track_resource_id ? {track_resource_id: descriptor.track_resource_id} : {})});
            grant = nativePlainGrant(data, descriptor, startedAt, activeSession.deadline);
            if (expectedFileId && grant.object_id !== expectedFileId) { const error = new Error('文件已替换，请重新选择'); error.status = 409; throw error; }
        } else if (descriptor?.transport === 'S3' && !descriptor.encryption && !descriptor.encrypted) {
            const data = await jsonRequest('/source', {file_path: filePath, object_id: descriptor.object_id});
            grant = sourceGrant(data, startedAt);
            if (!Number.isSafeInteger(grant.size_bytes) || grant.size_bytes < 1 || grant.size_bytes > 10 * 1024 ** 3
                || grant.object_id !== descriptor.object_id || expectedFileId && grant.object_id !== expectedFileId) {
                const error = new Error('文件已替换，请刷新目录后重新选择'); error.status = 409; throw error;
            }
        } else {
            const activeSession = await getSession();
            const data = await jsonRequest('/key', {session_id: activeSession.session_id, file_path: filePath,
                ...(descriptor?.native_source ? {resource_id: descriptor.resource_id, object_id: descriptor.object_id,
                    ...(descriptor.kind === 'lyric' ? {track_resource_id: descriptor.track_resource_id} : {})} : {}),
                ...(descriptor?.transport === 'S3' ? {object_id: descriptor.object_id} : {})});
            if (expectedFileId && data.encryption?.file_id !== expectedFileId) {
                const error = new Error('文件已替换，请刷新目录后重新选择'); error.status = 409; throw error;
            }
            const key = await unwrap(activeSession, data.encryption, data.key_envelope);
            if (data.source_error || !(data.source_url || data.download_url)) {
                const error = new Error('当前资源数据路径不可用，请联系管理员');
                error.status = 503;
                throw error;
            }
            // An encrypted Native catalog entry comes from the opaque tree.
            // Require its identity before considering the legacy URL path:
            // deleting all new fields must not turn it into a legacy grant.
            if (descriptor?.native_source && (descriptor.source_identity_version !== 1 || data.source_identity_version !== 1 || data.transport !== 'Native'
                || !data.source_headers || !/^[a-f0-9]{64}$/.test(data.source_object_id || '')
                || !/^[a-f0-9]{32}$/.test(data.source_owner_id || '')
                || !/^[a-f0-9]{64}$/.test(data.source_revision || ''))) {
                const error = new Error('媒体资源授权无效'); error.status = 403; throw error;
            }
            grant = {encryption: data.encryption, key, source_url: data.source_url || data.download_url,
                content_type: data.content_type, filename: data.filename,
                expires_at: data.key_envelope.expires_at, deadline: activeSession.deadline};
            if (data.transport !== 'S3' && data.source_transport !== undefined && data.source_headers === undefined) {
                const error = new Error('资源读取授权无效'); error.status = 403; throw error;
            }
            if (data.transport !== 'S3' && data.source_headers !== undefined) {
                const signed = data.source_headers;
                let target;
                try { target = new URL(grant.source_url, window.location.origin); } catch (_) {}
                const direct = data.source_transport === 'Direct';
                const relay = data.source_transport === 'Relay';
                const localLyric = data.source_transport === 'Local' && descriptor?.native_source && descriptor.kind === 'lyric';
                const localMedia = data.source_transport === 'Local' && descriptor?.native_source && descriptor.kind === 'media';
                let configuredOrigin;
                try { if (direct) configuredOrigin = new URL(data.source_origin); } catch (_) {}
                const validDirect = direct && configuredOrigin && configuredOrigin.protocol === 'https:'
                    && configuredOrigin.origin === data.source_origin && configuredOrigin.pathname === '/'
                    && !configuredOrigin.username && !configuredOrigin.password && !configuredOrigin.search && !configuredOrigin.hash
                    && target?.origin === configuredOrigin.origin
                    && (/^\/api\/v1\/media\/master-direct(?:-lyric)?\/[a-f0-9]{64}$/.test(target.pathname)
                        || /^\/internal\/v1\/(?:media|opaque-media)\/[a-f0-9]{64}$/.test(target.pathname));
                const validLocal = target?.origin === window.location.origin && (data.source_transport === undefined
                    && /^\/internal\/v1\/(?:media|opaque-media)\/[a-f0-9]{64}$/.test(target.pathname)
                    || localLyric && /^\/api\/v1\/media\/master-local-lyric\/[a-f0-9]{64}$/.test(target.pathname)
                    || localMedia && (/^\/api\/v1\/media\/master-local\/[a-f0-9]{64}$/.test(target.pathname)
                        || /^\/internal\/v1\/opaque-media\/[a-f0-9]{64}$/.test(target.pathname)));
                const validRelay = relay && target?.origin === window.location.origin
                    && /^\/api\/v1\/media\/(?:master|follower|opaque-follower|opaque-local-follower)-relay\/[a-f0-9]{64}$/.test(target.pathname);
                const capabilityHeader = relay ? 'X-Media-Relay' : 'X-Media-Capability';
                if (!target || target.protocol !== 'https:' || target.username || target.password
                    || target.search || target.hash || !(validDirect || validLocal || validRelay)
                    || !signed || Array.isArray(signed) || Object.keys(signed).length !== 1
                    || typeof signed[capabilityHeader] !== 'string' || signed[capabilityHeader].length > 4096
                    || !Number.isInteger(data.source_expires_in) || data.source_expires_in < 1 || data.source_expires_in > 300
                    || !Number.isSafeInteger(data.source_expires_at) || data.source_expires_at <= 0
                    || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(signed[capabilityHeader])) {
                    const error = new Error('资源读取授权无效'); error.status = 403; throw error;
                }
                if (descriptor?.native_source && descriptor.kind === 'lyric') {
                    const alias = data.source_object_id;
                    const expectedPath = `/api/v1/media/master-${direct ? 'direct-lyric' : localLyric ? 'local-lyric' : 'relay'}/${alias}`;
                    const metaFields = ['version', 'algorithm', 'file_id', 'nonce_prefix', 'plaintext_size', 'chunk_size', 'ciphertext_size'];
                    if (data.transport !== 'Native' || data.resource_id !== descriptor.resource_id || data.object_id !== descriptor.object_id
                        || !/^[a-f0-9]{64}$/.test(alias || '') || alias === data.resource_id || alias === data.object_id
                        || !/^[a-f0-9]{64}$/.test(data.source_revision || '') || !/^[a-f0-9]{32}$/.test(data.source_owner_id || '') || !(direct || relay || localLyric) || target.pathname !== expectedPath
                        || !descriptor.encryption || !metaFields.every(field => descriptor.encryption[field] === data.encryption[field])) {
                        const error = new Error('歌词资源授权无效'); error.status = 403; throw error;
                    }
                    Object.assign(grant, {transport: 'Native', kind: 'lyric', source_identity_version: 1, resource_id: data.resource_id,
                        object_id: data.object_id, track_resource_id: descriptor.track_resource_id,
                        source_object_id: alias, source_owner_id: data.source_owner_id, source_revision: data.source_revision});
                }
                if (descriptor?.native_source && descriptor.kind === 'media') {
                    const alias = data.source_object_id;
                    const metaFields = ['version', 'algorithm', 'file_id', 'nonce_prefix', 'plaintext_size', 'chunk_size', 'ciphertext_size'];
                    const ownerPath = `/internal/v1/opaque-media/${alias}`;
                    const localPath = `/api/v1/media/master-local/${alias}`;
                    const masterDirectPath = `/api/v1/media/master-direct/${alias}`;
                    const masterRelayPath = `/api/v1/media/master-relay/${alias}`;
                    const relayPath = `/api/v1/media/opaque-follower-relay/${alias}`;
                    const localRelayPath = `/api/v1/media/opaque-local-follower-relay/${alias}`;
                    if (data.transport !== 'Native' || data.resource_id !== descriptor.resource_id || data.object_id !== descriptor.object_id
                        || !/^[a-f0-9]{64}$/.test(alias || '') || alias === data.resource_id || alias === data.object_id
                        || !/^[a-f0-9]{64}$/.test(data.source_revision || '') || !/^[a-f0-9]{32}$/.test(data.source_owner_id || '')
                        || !(direct && (target.pathname === ownerPath || target.pathname === masterDirectPath)
                            || relay && (target.pathname === relayPath || target.pathname === localRelayPath || target.pathname === masterRelayPath)
                            || localMedia && (target.pathname === localPath || target.pathname === ownerPath))
                        || !descriptor.encryption || !metaFields.every(field => descriptor.encryption[field] === data.encryption[field])) {
                        const error = new Error('媒体资源授权无效'); error.status = 403; throw error;
                    }
                    Object.assign(grant, {transport: 'Native', kind: 'media', source_identity_version: 1, resource_id: data.resource_id, object_id: data.object_id,
                        source_object_id: alias, source_owner_id: data.source_owner_id, source_revision: data.source_revision});
                }
                grant.source_headers = {[capabilityHeader]: signed[capabilityHeader]};
                grant.deadline = Math.min(grant.deadline, startedAt + data.source_expires_in * 1000);
                if (direct) { grant.source_transport = 'Direct'; grant.source_origin = configuredOrigin.origin; }
                if (relay) grant.source_transport = 'Relay';
                if (localLyric) grant.source_transport = 'Local';
                if (localMedia) grant.source_transport = 'Local';
            }
            if (data.transport === 'S3') {
                Object.assign(grant, sourceGrant(data, startedAt));
                grant.deadline = Math.min(grant.deadline, activeSession.deadline);
                if (descriptor?.object_id && grant.object_id !== descriptor.object_id) {
                    const error = new Error('文件已替换，请刷新目录后重新选择'); error.status = 409; throw error;
                }
            }
        }
        if (sourceVersions.get(filePath) !== sourceVersion || sources.get(filePath) !== descriptor) {
            const error = new Error('媒体目录已更新，请重新选择'); error.status = 409; throw error;
        }
        if (grant.deadline <= common.monotonicNow()) throw new Error('媒体读取授权已过期');
        if (envelopes.size >= 32) envelopes.delete(envelopes.keys().next().value);
        envelopes.set(filePath, grant); return grant;
    }
    function workerMessage(worker, data) {
        return new Promise((resolve, reject) => {
            const channel = new MessageChannel();
            const timeout = setTimeout(() => { channel.port1.close(); reject(new Error('媒体播放初始化超时')); }, 15000);
            channel.port1.onmessage = event => {
                clearTimeout(timeout);
                channel.port1.close();
                if (event.data?.error) reject(new Error(event.data.error));
                else resolve(event.data);
            };
            worker.postMessage(data, [channel.port2]);
        });
    }
    async function ensureWorker(sealedDownload = false) {
        requireCrypto();
        if (!navigator.serviceWorker) throw new Error('此浏览器不支持媒体流式播放');
        if (!workerPromise) workerPromise = (async () => {
            const registration = await navigator.serviceWorker.register('/media-crypto-sw.js', {scope: '/', updateViaCache: 'none'});
            await navigator.serviceWorker.ready;
            if (!navigator.serviceWorker.controller) {
                await new Promise((resolve, reject) => {
                    const timer = setTimeout(() => {
                        navigator.serviceWorker.removeEventListener('controllerchange', changed);
                        reject(new Error('媒体服务尚未就绪，请刷新页面'));
                    }, 15000);
                    const changed = () => {
                        if (!navigator.serviceWorker.controller) return;
                        clearTimeout(timer);
                        navigator.serviceWorker.removeEventListener('controllerchange', changed);
                        resolve();
                    };
                    navigator.serviceWorker.addEventListener('controllerchange', changed);
                    changed();
                });
            }
            return registration;
        })().catch(error => { workerPromise = null; throw error; });
        const registration = await workerPromise;
        // Worker suspension discards its in-memory capabilities. Register the
        // live page again before each operation, retaining its existing keys.
        const message = {type: 'fc-crypto-register', token};
        const controller = navigator.serviceWorker.controller;
        const features = await workerMessage(controller, message);
        if (!sealedDownload || features?.admin_download === 'sealed-v1' && controller === navigator.serviceWorker.controller)
            return controller;
        // An existing registration can resolve ready while an older worker
        // still controls the tab. It cannot serve a sealed download session.
        const changedWorker = await new Promise((resolve, reject) => {
            const cleanup = () => {
                clearTimeout(timer);
                navigator.serviceWorker.removeEventListener('controllerchange', changed);
            };
            const changed = () => {
                const next = navigator.serviceWorker.controller;
                if (!next || next === controller) return false;
                cleanup();
                resolve(next);
                return true;
            };
            const unavailable = () => {
                cleanup();
                reject(new Error('媒体服务正在更新，请刷新后重试下载'));
            };
            const timer = setTimeout(unavailable, 15000);
            navigator.serviceWorker.addEventListener('controllerchange', changed);
            if (!changed()) registration.update().catch(() => { if (!changed()) unavailable(); });
        });
        const updated = await workerMessage(changedWorker, message);
        if (updated?.admin_download !== 'sealed-v1' || changedWorker !== navigator.serviceWorker.controller)
            throw new Error('媒体服务正在更新，请刷新后重试下载');
        return changedWorker;
    }
    navigator.serviceWorker?.addEventListener('message', async event => {
        const data = event.data;
        if (!data || data.token !== token || event.source !== navigator.serviceWorker.controller) return;
        if (data.type === 'fc-crypto-fault') {
            faults.set(data.file_path, data.error || '加密媒体完整性校验失败');
            window.dispatchEvent(new CustomEvent('frontier-crypto-fault', {detail: data}));
            return;
        }
        if (data.type !== 'fc-crypto-grant' || !event.ports[0]) return;
        try { event.ports[0].postMessage({...await fileGrant(data.file_path, data.file_id, data.revalidate === true),
            revalidated: data.revalidate === true}); }
        catch (error) { event.ports[0].postMessage({error: error.message,
            status: error.status || (error.name === 'OperationError' ? 422 : undefined)}); }
    });
    function virtualUrl(filePath, download = false, fileId = '') {
        const query = new URLSearchParams();
        if (download) query.set('download', '1');
        if (fileId) query.set('object', fileId);
        return `/__fc_media/${token}/${encodeURIComponent(filePath)}${query.size ? '?' + query : ''}`;
    }
    async function prepareCatalog(entries) {
        for (const media of entries || []) {
            const path = media.media_path || media.path;
            if (path && sources.get(path)?.source_identity_version === 1 && media.source_identity_version !== 1)
                throw new Error('媒体身份版本已变化，请刷新页面');
        }
        if (!entries?.some(media => media.encryption || media.encrypted || media.transport === 'S3' || media.native_source)) return entries;
        await ensureWorker();
        for (const media of entries) {
            if (!media.encryption && !media.encrypted && media.transport !== 'S3' && !media.native_source) continue;
            const path = media.media_path || media.path;
            if (!path) throw new Error('加密媒体路径缺失');
            if (media.transport === 'S3' && !media.object_id) throw new Error('S3 对象身份缺失');
            if (media.source_identity_version !== undefined && (media.source_identity_version !== 1 || media.native_source !== true)) throw new Error('媒体身份版本无效');
            const descriptor = {transport: media.transport, object_id: media.object_id, resource_id: media.resource_id,
                size_bytes: media.size_bytes, native_source: media.native_source, source_identity_version: media.source_identity_version, kind: 'media', encryption: media.encryption, encrypted: media.encrypted};
            const previous = sources.get(path);
            if (previous?.source_identity_version === 1 && descriptor.source_identity_version !== 1) throw new Error('媒体身份版本已变化，请刷新页面');
            const version = (sourceVersions.get(path) || 0) + 1;
            sourceVersions.set(path, version);
            if (previous && !sameSourceDescriptor(previous, descriptor)) {
                envelopes.delete(path);
                await workerMessage(navigator.serviceWorker.controller, {type: 'fc-crypto-invalidate', token, file_path: path});
            }
            if (sourceVersions.get(path) !== version) throw new Error('媒体目录已更新，请重新选择');
            sources.set(path, descriptor);
            media.url = virtualUrl(path, false, media.encryption?.file_id || media.object_id);
        }
        return entries;
    }
    async function textFor(filePath, fileId = '') {
        await ensureWorker();
        const response = await fetch(virtualUrl(filePath, false, fileId), {credentials: 'same-origin', cache: 'no-store'});
        if (!response.ok) throw new Error('歌词读取失败');
        // Lyrics are a separately bounded business object (not media content).
        const limit = 8 * 1024 * 1024;
        const expected = Number(response.headers.get('Content-Length'));
        if (!Number.isSafeInteger(expected) || expected < 0 || expected > limit) {
            await response.body?.cancel();
            throw new Error('歌词超出浏览器读取限制');
        }
        // ParseLRC rejects invalid UTF-8 and removes exactly one leading BOM.
        // Preserve that BOM for the shared parser rather than removing it twice.
        return new TextDecoder('utf-8', {fatal: true, ignoreBOM: true})
            .decode(expected === 0 && !response.body ? new Uint8Array() : await common.boundedBytes(response, expected));
    }
    async function lyricTextFor(data) {
        if (!data || typeof data.file_path !== 'string' || !data.file_path.startsWith('lyrics/')
            || !/^[a-f0-9]{64}$/.test(data.resource_id || '') || data.resource_id !== data.object_id
            || data.track_resource_id !== undefined && !/^[a-f0-9]{64}$/.test(data.track_resource_id)
            || !Number.isSafeInteger(data.size_bytes) || data.size_bytes < 0 || data.size_bytes > 8 * 1024 * 1024) throw new Error('歌词身份无效');
        const encrypted = Boolean(data.encrypted || data.encryption);
        const encryption = encrypted ? {...common.validate(data.encryption)} : undefined;
        if (encrypted && (encryption.ciphertext_size !== data.size_bytes || encryption.plaintext_size > 8 * 1024 * 1024)) throw new Error('歌词身份无效');
        if (data.source_identity_version !== undefined && data.source_identity_version !== 1) throw new Error('歌词身份版本无效');
        const descriptor = {native_source: true, source_identity_version: data.source_identity_version, kind: 'lyric', resource_id: data.resource_id,
            object_id: data.object_id, track_resource_id: data.track_resource_id, size_bytes: data.size_bytes, encryption, encrypted};
        const previous = lyricReads.get(data.file_path) || Promise.resolve();
        const pending = previous.catch(() => {}).then(async () => {
            const old = sources.get(data.file_path);
            if (old?.source_identity_version === 1 && descriptor.source_identity_version !== 1) throw new Error('歌词身份版本已变化，请刷新页面');
            const version = (sourceVersions.get(data.file_path) || 0) + 1;
            sourceVersions.set(data.file_path, version);
            if (old && (old.resource_id !== data.resource_id || old.object_id !== data.object_id
                || old.track_resource_id !== data.track_resource_id || old.source_identity_version !== data.source_identity_version || !sameEncryptionDescriptor(old.encryption, encryption))) {
                await ensureWorker();
                envelopes.delete(data.file_path);
                await workerMessage(navigator.serviceWorker.controller, {type: 'fc-crypto-invalidate', token, file_path: data.file_path});
            }
            if (sourceVersions.get(data.file_path) !== version) throw new Error('歌词目录已更新，请重新选择');
            sources.set(data.file_path, descriptor);
            return textFor(data.file_path, encrypted ? encryption.file_id : data.object_id);
        });
        lyricReads.set(data.file_path, pending);
        try { return await pending; }
        finally { if (lyricReads.get(data.file_path) === pending) lyricReads.delete(data.file_path); }
    }
    async function plainTextFor(data) {
        if (data?.encrypted || data?.encryption) throw new Error('歌词身份无效');
        return lyricTextFor(data);
    }
    const MAX_RECORDING_LYRIC_BYTES = 1400 * 1024;
    function recordingLyrics(entries) {
        if (!Array.isArray(entries) || entries.length > 10000
            || entries.some(entry => !Number.isFinite(entry?.time) || entry.time < 0
                || typeof entry.text !== 'string' || entry.text.length > 4096
                || new TextEncoder().encode(entry.text).byteLength > 4096))
            throw new Error('录音歌词快照超过行数或内容限制');
        return entries.map(entry => ({time: entry.time, text: entry.text}));
    }
    async function recordingGrant(path, expectedFileId = '', revalidate = false) {
        const source = recordingSources.get(path);
        const denied = () => Object.assign(new Error('录音读取授权已失效'), {status: 403});
        if (!source) throw denied();
        if (!revalidate && source.grant?.deadline > common.monotonicNow() + 10000) {
            if (expectedFileId && source.grant.encryption.file_id !== expectedFileId) throw denied();
            return source.grant;
        }
        const active = await getSession();
        const startedAt = common.monotonicNow();
        const data = await source.authorize({session_id: active.session_id});
        const encryption = common.validate(data.encryption);
        if (data.recording_id !== source.id || !/^[a-f0-9]{64}$/.test(data.source_revision || '')
            || !/^[a-f0-9]{32}$/.test(active.session_id || '') || encryption.plaintext_size < 1
            || encryption.ciphertext_size > 1024 ** 3 || expectedFileId && encryption.file_id !== expectedFileId
            || !/^(audio\/(webm|ogg|mp4|mpeg|wav)|application\/octet-stream)$/.test(data.content_type || '')
            || typeof data.filename !== 'string' || !data.filename || data.filename.length > 255 || /[\x00-\x1f\x7f/\\]/.test(data.filename)) throw denied();
        let access = {
            source_url: `${location.origin}/api/v1/karaoke/account/recordings/${source.id}/audio-bytes`,
            source_headers: {'X-Fc-Recording-Session': active.session_id},
            deadline: active.deadline,
        };
        if (data.source !== undefined) {
            const direct = data.source;
            let origin;
            try { origin = new URL(direct?.origin); } catch (_) {}
            if (direct?.transport !== 'Direct' || !origin || origin.protocol !== 'https:' || origin.origin !== direct.origin
                || typeof direct.alias !== 'string' || !/^[a-f0-9]{64}$/.test(direct.alias)
                || typeof direct.owner_id !== 'string' || !/^[a-f0-9]{32}$/.test(direct.owner_id)
                || direct.url !== `${origin.origin}/internal/v1/opaque-media/${direct.alias}`
                || typeof direct.capability !== 'string' || direct.capability.length > 4096
                || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(direct.capability)
                || !Number.isInteger(direct.expires_in) || direct.expires_in < 1 || direct.expires_in > 300) throw denied();
            access = {source_url: direct.url, source_headers: {'X-Media-Capability': direct.capability},
                source_transport: 'Direct', source_origin: direct.origin, source_object_id: direct.alias, source_owner_id: direct.owner_id,
                deadline: Math.min(active.deadline, startedAt + direct.expires_in * 1000)};
        }
        const key = await unwrap(active, encryption, data.key_envelope);
        if (recordingSources.get(path) !== source || access.deadline <= common.monotonicNow()) throw denied();
        const previous = source.grant;
        if (previous && (previous.encryption.file_id !== encryption.file_id
            || previous.size_bytes !== encryption.ciphertext_size || previous.source_revision !== data.source_revision
            || previous.source_url !== access.source_url || previous.source_owner_id !== access.source_owner_id)) {
            throw Object.assign(new Error('播放文件已变化，请重新选择'), {status: 409});
        }
        source.grant = {transport: 'Recording', kind: 'recording', object_id: source.id, source_revision: data.source_revision,
            encryption, key, size_bytes: encryption.ciphertext_size,
            filename: data.filename, content_type: data.content_type, ...access};
        return source.grant;
    }
    function forgetRecordingPlayback(id) {
        for (const [path, source] of recordingSources) {
            if (id !== undefined && source.id !== id) continue;
            recordingSources.delete(path);
            navigator.serviceWorker?.controller?.postMessage({type: 'fc-crypto-invalidate', token, file_path: path});
        }
    }
    async function withRecordingSession(id, send) {
        if (admin || !/^[a-f0-9]{32}$/.test(id || '') || typeof send !== 'function') throw new Error('录音身份无效');
        const active = await getSession();
        if (!/^[a-f0-9]{32}$/.test(active.session_id || '') || active.deadline <= common.monotonicNow())
            throw new Error('录音授权已失效');
        return send(active.session_id);
    }
    async function recordingPlayback(id, authorize, download = false) {
        if (admin || !/^[a-f0-9]{32}$/.test(id || '') || typeof authorize !== 'function') throw new Error('录音身份无效');
        await ensureWorker();
        const path = `@recording/${id}`;
        if (!recordingSources.has(path) && recordingSources.size >= 4)
            forgetRecordingPlayback(recordingSources.values().next().value.id);
        const descriptor = {id, authorize};
        recordingSources.set(path, descriptor);
        try {
            const grant = await recordingGrant(path);
            const url = virtualUrl(path, download, grant.encryption.file_id);
            return {url, filename: grant.filename, lyrics: download ? [] : await recordingFooter(url, grant.encryption.plaintext_size)};
        } catch (error) {
            if (recordingSources.get(path) === descriptor) forgetRecordingPlayback(id);
            throw error;
        }
    }
    async function recordingFooter(url, size) {
        const marker = new TextEncoder().encode('FRONTIERCLOUD-KARAOKE-V1');
        const tailSize = marker.length + 8;
        if (size < tailSize) return [];
        const read = async (start, length) => {
            const end = start + length - 1;
            const response = await fetch(url, {credentials: 'same-origin', redirect: 'error', referrerPolicy: 'no-referrer',
                cache: 'no-store', headers: {Range: `bytes=${start}-${end}`}});
            if (response.status !== 206 || response.headers.get('Content-Range') !== `bytes ${start}-${end}/${size}`) {
                await response.body?.cancel().catch(() => {});
                throw new Error('录音元数据读取范围不一致');
            }
            return common.boundedBytes(response, length);
        };
        // The worker already authenticates whole chunks. Read the final chunk
        // containing the trailer once and reuse it for the common small footer.
        const tailStart = Math.floor((size - tailSize) / common.CHUNK_SIZE) * common.CHUNK_SIZE;
        const tail = await read(tailStart, size - tailStart);
        let raw;
        try {
            const end = tail.byteLength - tailSize;
            if (!marker.every((value, index) => tail[end + 8 + index] === value)) return [];
            const length = new DataView(tail.buffer, tail.byteOffset + end, 8).getBigUint64(0);
            if (length < 1n || length > 2n * 1024n ** 2n || length >= BigInt(size - tailSize))
                throw new Error('录音元数据长度无效');
            const start = end - Number(length);
            if (start >= 0) raw = tail.subarray(start, end);
            else {
                const preceding = await read(tailStart + start, -start);
                raw = new Uint8Array(Number(length));
                raw.set(preceding);
                preceding.fill(0);
                raw.set(tail.subarray(0, end), -start);
            }
            const footer = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(raw));
            if (footer?.version !== 1) throw new Error('录音元数据版本无效');
            return recordingLyrics(footer.lyrics);
        } finally { raw?.fill(0); tail.fill(0); }
    }
    async function encryptRecordingLyrics(entries, prepare) {
        const normalized = recordingLyrics(entries);
        const encoder = new TextEncoder();
        let size = 2 + Math.max(0, normalized.length - 1);
        for (const entry of normalized) {
            size += encoder.encode(JSON.stringify(entry)).byteLength;
            if (size > MAX_RECORDING_LYRIC_BYTES) throw new Error('录音歌词快照超过 1400 KiB 限制');
        }
        const plaintext = encoder.encode(JSON.stringify(normalized));
        try {
            if (plaintext.byteLength > MAX_RECORDING_LYRIC_BYTES)
                throw new Error('录音歌词快照超过 1400 KiB 限制');
            const activeSession = await getSession();
            const prepared = await prepare({session_id: activeSession.session_id, plaintext_size: plaintext.byteLength});
            const metadata = common.validate(prepared.encryption);
            if (metadata.plaintext_size !== plaintext.byteLength || !prepared.preparation_token)
                throw new Error('录音歌词加密准备无效');
            const key = await unwrap(activeSession, metadata, prepared.key_envelope);
            const ciphertext = new Uint8Array(metadata.ciphertext_size);
            for (let start = 0, index = 0; start < plaintext.byteLength; start += common.CHUNK_SIZE, index += 1) {
                const chunk = plaintext.subarray(start, Math.min(plaintext.byteLength, start + common.CHUNK_SIZE));
                ciphertext.set(new Uint8Array(await crypto.subtle.encrypt(common.parameters(metadata, index), key, chunk)),
                    common.cipherRange(metadata, index).start);
            }
            return {encrypted_lyrics: {encryption: metadata, ciphertext: common.encode(ciphertext)},
                preparation_token: prepared.preparation_token};
        } finally { plaintext.fill(0); }
    }
    async function decryptRecordingLyrics(authorize) {
        const activeSession = await getSession();
        const grant = await authorize({session_id: activeSession.session_id});
        const snapshot = grant.encrypted_lyrics;
        const metadata = common.validate(snapshot?.encryption);
        if (metadata.plaintext_size > MAX_RECORDING_LYRIC_BYTES || typeof snapshot.ciphertext !== 'string'
            || snapshot.ciphertext.length !== 4 * Math.ceil(metadata.ciphertext_size / 3)
            || !/^[A-Za-z0-9+/]*={0,2}$/.test(snapshot.ciphertext))
            throw new Error('加密录音歌词描述无效');
        const ciphertext = common.decode(snapshot.ciphertext);
        if (ciphertext.byteLength !== metadata.ciphertext_size || common.encode(ciphertext) !== snapshot.ciphertext)
            throw new Error('加密录音歌词长度无效');
        const key = await unwrap(activeSession, metadata, grant.key_envelope);
        const plaintext = new Uint8Array(metadata.plaintext_size);
        try {
            for (let index = 0; index < Math.ceil(metadata.plaintext_size / common.CHUNK_SIZE); index += 1) {
                const range = common.cipherRange(metadata, index);
                const chunk = new Uint8Array(await crypto.subtle.decrypt(common.parameters(metadata, index), key,
                    ciphertext.subarray(range.start, range.end + 1)));
                try { plaintext.set(chunk, index * common.CHUNK_SIZE); }
                finally { chunk.fill(0); }
            }
            return recordingLyrics(JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(plaintext)));
        } catch (error) {
            error.status = error.status || 422;
            throw error;
        } finally { plaintext.fill(0); }
    }
    async function temporaryDirectory() {
        if (!navigator.storage?.getDirectory) throw new Error('加密上传需要支持临时文件存储的浏览器');
        const directory = await navigator.storage.getDirectory();
        return directory.getDirectoryHandle('frontiercloud-cipher-upload-v1', {create: true});
    }
    async function cleanAbandonedTemporaryFiles() {
        if (!navigator.storage?.getDirectory) return;
        const directory = await temporaryDirectory();
        for await (const [name] of directory.entries()) {
            // A live upload is bounded to minutes. Leave other tabs' current
            // files alone; crash leftovers become removable after one day.
            const created = Number(name.split('-', 1)[0]);
            if (created > 0 && Date.now() - created > 86400000)
                await directory.removeEntry(name).catch(() => {});
        }
    }
    async function encryptUploadFile(file, onProgress = () => {}) {
        requireCrypto();
        const extension = /\.[^.]+$/.exec(file.name || '')?.[0].toLowerCase();
        if (extension === '.lrc') {
            if (file.size < 1 || file.size > 2 * 1024 * 1024)
                throw new Error('歌词文件最多允许 2 MiB');
            const payload = await file.slice(0, file.size).arrayBuffer();
            try {
                common.parseLyrics(new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(payload));
            } finally { new Uint8Array(payload).fill(0); }
        } else {
            const head = new Uint8Array(await file.slice(0, Math.min(file.size, 12)).arrayBuffer());
            const starts = values => values.every((value, index) => head[index] === value);
            const word = (start, end) => String.fromCharCode(...head.subarray(start, end));
            const valid = extension === '.mp3' && (word(0, 3) === 'ID3'
                    || head.length >= 2 && head[0] === 0xff && (head[1] & 0xe0) === 0xe0)
                || extension === '.flac' && word(0, 4) === 'fLaC'
                || extension === '.wav' && head.length >= 12 && word(0, 4) === 'RIFF' && word(8, 12) === 'WAVE'
                || ['.m4a', '.mp4'].includes(extension) && head.length >= 12 && word(4, 8) === 'ftyp'
                || ['.webm', '.mkv'].includes(extension) && starts([0x1a, 0x45, 0xdf, 0xa3]);
            head.fill(0);
            if (!valid) throw new Error('上传失败，文件内容不是受支持的媒体格式');
        }
        // Validate the bounded plaintext locally before key preparation or
        // encryption. Neither content validation nor media encryption uses the Master.
        return encryptFile(file, onProgress);
    }
    async function encryptFile(file, onProgress = () => {}) {
        return encryptPreparedFile(file, fields => jsonRequest('/prepare', fields), onProgress);
    }
    async function encryptRecordingAudio(file, prepare, onProgress = () => {}) {
        const maxBytes = 1024 ** 3;
        if (!Number.isSafeInteger(file?.size) || file.size < 1
            || file.size + common.TAG_SIZE * Math.ceil(file.size / common.CHUNK_SIZE) > maxBytes)
            throw new Error('加密录音不能超过 1 GiB');
        let recordingID;
        const result = await encryptPreparedFile(file, async fields => {
            const prepared = await prepare(fields);
            if (!/^[a-f0-9]{32}$/.test(prepared.recording_id || '') || typeof prepared.preparation_token !== 'string'
                || !prepared.preparation_token) throw new Error('录音加密准备无效');
            recordingID = prepared.recording_id;
            return prepared;
        }, onProgress);
        return {...result, recording_id: recordingID};
    }
    async function encryptPreparedFile(file, prepare, onProgress) {
        const activeSession = await getSession();
        const prepared = await prepare({session_id: activeSession.session_id, plaintext_size: file.size});
        const metadata = common.validate(prepared.encryption);
        if (metadata.plaintext_size !== file.size) throw new Error('加密准备与文件长度不一致');
        const key = await unwrap(activeSession, metadata, prepared.key_envelope);
        const directory = await temporaryDirectory();
        const name = `${Date.now()}-${token}-${metadata.file_id}`;
        const handle = await directory.getFileHandle(name, {create: true});
        temporaryNames.add(name);
        let output;
        const cleanup = async () => {
            await directory.removeEntry(name).catch(() => {});
            temporaryNames.delete(name);
        };
        try {
            output = await handle.createWritable();
            for (let start = 0, index = 0; start < file.size; start += common.CHUNK_SIZE, index += 1) {
                const plaintext = await file.slice(start, Math.min(file.size, start + common.CHUNK_SIZE)).arrayBuffer();
                try {
                    const ciphertext = await crypto.subtle.encrypt(common.parameters(metadata, index), key, plaintext);
                    await output.write(ciphertext);
                } finally { new Uint8Array(plaintext).fill(0); }
                onProgress(Math.min(1, (start + common.CHUNK_SIZE) / Math.max(1, file.size)));
            }
            await output.close();
            const ciphertext = await handle.getFile();
            if (ciphertext.size !== metadata.ciphertext_size) throw new Error('加密文件长度校验失败');
            return {file: ciphertext, encryption: metadata, preparation_token: prepared.preparation_token, cleanup,
                retainedName: name, retain() { temporaryNames.delete(name); }};
        } catch (error) {
            if (output) await output.abort().catch(() => {});
            await cleanup();
            throw error;
        }
    }
    function validRetainedName(name) {
        if (typeof name !== 'string' || !/^[0-9]{10,16}-[a-f0-9]{32}-[a-f0-9]{32}$/.test(name))
            throw new Error('本地密文恢复记录无效');
        return name;
    }
    async function readRetainedUpload(name) {
        const directory = await temporaryDirectory();
        return (await directory.getFileHandle(validRetainedName(name))).getFile();
    }
    async function forgetRetainedUpload(name) {
        const directory = await temporaryDirectory();
        await directory.removeEntry(validRetainedName(name)).catch(error => {
            if (error.name !== 'NotFoundError') throw error;
        });
    }
    function failureFor(input) {
        try {
            const path = new URL(String(input), location.href).pathname;
            const prefix = `/__fc_media/${token}/`;
            return path.startsWith(prefix) ? faults.get(decodeURIComponent(path.slice(prefix.length))) : null;
        } catch (_) { return null; }
    }
    function resetFault(filePath) {
        faults.delete(filePath);
        envelopes.delete(filePath);
        navigator.serviceWorker?.controller?.postMessage({type: 'fc-crypto-invalidate', token, file_path: filePath});
    }

    // Stored ZIP entries avoid compression and retain a one-chunk memory bound.
    // ZIP64 supports large folders; browser download receives a
    // ReadableStream through a worker route, rather than an album-sized Blob.
    const crcTable = Uint32Array.from({length: 256}, (_, value) => {
        let crc = value;
        for (let bit = 0; bit < 8; bit += 1) crc = (crc & 1) ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1;
        return crc >>> 0;
    });
    function crcUpdate(crc, bytes) {
        for (const byte of bytes) crc = crcTable[(crc ^ byte) & 255] ^ (crc >>> 8);
        return crc;
    }
    async function downloadPlan(items, forceZIP = false) {
        const sealedDownload = items.some(item => item.download_snapshot !== undefined);
        const worker = await ensureWorker(sealedDownload);
        for (const item of items) if (item.download_snapshot !== undefined) {
            if (!admin || !item.encryption || !/^[a-f0-9]{64}$/.test(item.download_snapshot) || !/^[a-f0-9]{64}$/.test(item.resource_id || ''))
                throw new Error('下载计划身份无效');
            if (item.transport !== undefined && (!['S3', 'Direct', 'Relay'].includes(item.transport) || !/^[a-f0-9]{64}$/.test(item.object_id || '')))
                throw new Error('下载计划存储身份无效');
            const id = `@admin-download/${item.resource_id}/${item.download_snapshot}`;
            sources.set(id, {path: item.path, resource_id: item.resource_id, download_snapshot: item.download_snapshot,
                encryption: item.encryption, transport: item.transport, object_id: item.object_id, size_bytes: item.encryption.ciphertext_size,
                ...(item.transport === 'Direct' ? {source_identity_version: 1} : {})});
        }
        for (const item of items) if (item.transport === 'S3' && !item.download_snapshot) {
            if (!item.object_id) throw new Error('S3 对象身份缺失');
            const descriptor = {transport: 'S3', object_id: item.object_id, encryption: item.encryption, encrypted: item.encrypted};
            const previous = sources.get(item.path);
            if (previous?.source_identity_version === 1) throw new Error('媒体身份版本已变化，请刷新页面');
            const version = (sourceVersions.get(item.path) || 0) + 1;
            sourceVersions.set(item.path, version);
            if (previous && !sameSourceDescriptor(previous, descriptor)) {
                envelopes.delete(item.path);
                await workerMessage(navigator.serviceWorker.controller, {type: 'fc-crypto-invalidate', token, file_path: item.path});
            }
            if (sourceVersions.get(item.path) !== version) throw new Error('媒体目录已更新，请重新选择');
            sources.set(item.path, descriptor);
        }
        const normalized = items.map(item => {
            const filePath = item.download_snapshot ? `@admin-download/${item.resource_id}/${item.download_snapshot}` : item.path;
            return {...item, file_path: filePath, plaintext_size: item.encryption?.plaintext_size ?? item.size ?? item.size_bytes,
                url: item.encryption || item.transport === 'S3' ? virtualUrl(filePath, false, item.encryption?.file_id || item.object_id) : item.url};
        });
        if (normalized.length === 1 && !forceZIP) {
            const anchor = document.createElement('a');
            anchor.href = normalized[0].encryption || normalized[0].transport === 'S3'
                ? virtualUrl(normalized[0].file_path, true, normalized[0].encryption?.file_id || normalized[0].object_id) : normalized[0].url;
            // Chromium's download attribute bypasses the worker fetch handler.
            // Worker-backed attachments already supply Content-Disposition.
            if (!normalized[0].encryption && normalized[0].transport !== 'S3')
                anchor.download = normalized[0].filename || normalized[0].path.split('/').pop();
            anchor.click();
            return;
        }
        if (!normalized.length || normalized.length > 5000) throw new Error('下载任务最多包含 5000 个文件，请分批下载');
        let total = 98;
        for (const item of normalized) {
            const nameBytes = new TextEncoder().encode(item.filename || item.path);
            if (!Number.isSafeInteger(item.plaintext_size) || item.plaintext_size < 0
                || nameBytes.length > 65535)
                throw new Error('下载文件描述无效');
            total += item.plaintext_size + 148 + nameBytes.length * 2;
        }
        if (!Number.isSafeInteger(total)) throw new Error('下载总量超出浏览器长度限制，请分批下载');
        const downloadToken = token + '-' + crypto.randomUUID();
        await workerMessage(worker, {type: 'fc-crypto-zip', token, download_token: downloadToken, items: normalized});
        if (sealedDownload && worker !== navigator.serviceWorker.controller)
            throw new Error('媒体服务已更新，请重试下载');
        const anchor = document.createElement('a');
        anchor.href = '/__fc_zip/' + downloadToken;
        // Attachment navigation lets the worker serve the download body.
        // Chromium's download attribute can bypass its fetch handler.
        anchor.click();
    }
    window.addEventListener('pagehide', event => {
        if (event.persisted) return;
        navigator.serviceWorker?.controller?.postMessage({type: 'fc-crypto-revoke', token});
        session = null;
        envelopes.clear();
        recordingSources.clear();
        if (temporaryNames.size) void temporaryDirectory().then(async directory => {
            for (const name of temporaryNames) await directory.removeEntry(name).catch(() => {});
        }).catch(() => {});
    });
    window.FrontierMediaCrypto = {prepareCatalog, ensureWorker, encryptFile, encryptUploadFile, textFor, lyricTextFor, plainTextFor,
        encryptRecordingAudio, encryptRecordingLyrics, decryptRecordingLyrics, readRetainedUpload, forgetRetainedUpload,
        recordingPlayback, forgetRecordingPlayback, withRecordingSession,
        virtualUrl, failureFor, resetFault, downloadPlan, parseLyrics: common?.parseLyrics, crcUpdate};
    void cleanAbandonedTemporaryFiles().catch(() => {});
})();
