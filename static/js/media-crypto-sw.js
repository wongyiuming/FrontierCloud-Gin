'use strict';

importScripts('/static/js/media-crypto-common.js');
const common = self.FrontierCryptoCommon;
const capabilities = new Map();
const grants = new Map();
const pendingGrants = new Map();
const grantEpochs = new Map();
const zipPlans = new Map();
const PREFIX = '/__fc_media/';
// Only authenticated ciphertext is retained, never keys or plaintext. Fresh
// page capabilities and grants remain mandatory before every cache lookup.
const cipherChunks = new Map();
const CIPHER_CACHE_BYTES = 32 * 1024 * 1024, CIPHER_CACHE_MS = 5 * 60 * 1000;
let cipherBytes = 0;

function forgetCipherChunk(key) {
    const cached = cipherChunks.get(key);
    if (cached) { cipherBytes -= cached.bytes.byteLength; cipherChunks.delete(key); }
}

function cipherChunkKey(metadata, index) {
    return JSON.stringify([metadata.version, metadata.algorithm, metadata.file_id,
        metadata.nonce_prefix, metadata.plaintext_size, metadata.ciphertext_size, metadata.chunk_size, index]);
}

// A continuation or cache hit may renew credentials, but it must not splice
// bytes from a different placement into the response already being served.
function sameResourceIdentity(original, refreshed) {
    if (!original || !refreshed || original.transport !== refreshed.transport) return false;
    if (Boolean(original.encryption) !== Boolean(refreshed.encryption)) return false;
    if (original.encryption && cipherChunkKey(original.encryption, 0) !== cipherChunkKey(refreshed.encryption, 0)) return false;
    for (const name of ['kind', 'source_identity_version', 'resource_id', 'object_id', 'track_resource_id', 'source_object_id', 'source_owner_id', 'source_revision', 'size_bytes', 'download_snapshot']) {
        if (original[name] !== refreshed[name]) return false;
    }
    if (original.transport === 'Recording' && (original.source_transport !== refreshed.source_transport
        || original.source_origin !== refreshed.source_origin)) return false;
    if (original.transport === 'S3' && original.source_headers?.['If-Match'] !== refreshed.source_headers?.['If-Match']) return false;
    return true;
}

function cachedCipherChunk(key) {
    const now = common.monotonicNow();
    for (const [id, cached] of cipherChunks) if (cached.expires <= now) forgetCipherChunk(id);
    const cached = cipherChunks.get(key);
    if (!cached) return null;
    cipherChunks.delete(key); cipherChunks.set(key, cached);
    return cached.bytes;
}

function rememberCipherChunk(key, bytes) {
    if (bytes.byteLength > CIPHER_CACHE_BYTES) return;
    forgetCipherChunk(key);
    while (cipherChunks.size && cipherBytes + bytes.byteLength > CIPHER_CACHE_BYTES)
        forgetCipherChunk(cipherChunks.keys().next().value);
    cipherChunks.set(key, {bytes, expires: common.monotonicNow() + CIPHER_CACHE_MS});
    cipherBytes += bytes.byteLength;
}

function revokeCapability(token) {
    capabilities.delete(token);
    grantEpochs.delete(token);
    for (const key of grants.keys()) if (key.startsWith(token + ':')) grants.delete(key);
    for (const [id, plan] of zipPlans) if (plan.token === token) zipPlans.delete(id);
}

async function registerCapability(event, data) {
    const supported = {ok: true, admin_download: 'sealed-v1'};
    const existing = capabilities.get(data.token);
    if (existing) {
        if (existing.clientId !== event.source.id) {
            event.ports[0]?.postMessage({error: '加密播放会话不属于此页面'});
            return;
        }
        event.ports[0]?.postMessage(supported);
        return;
    }
    if (capabilities.size >= 256 && !capabilities.has(data.token)) {
        // A renderer crash need not send pagehide. Reclaim only capabilities
        // whose owning client is gone, and retain concurrent replacements.
        await Promise.all([...capabilities].map(async ([token, capability]) => {
            if (!await self.clients.get(capability.clientId)
                && capabilities.get(token) === capability) revokeCapability(token);
        }));
    }
    if (capabilities.size >= 256 && !capabilities.has(data.token)) {
        event.ports[0]?.postMessage({error: '加密播放会话过多，请关闭闲置页面'});
        return;
    }
    const current = capabilities.get(data.token);
    if (current) {
        event.ports[0]?.postMessage(current.clientId === event.source.id ? supported : {error: '加密播放会话不属于此页面'});
        return;
    }
    capabilities.set(data.token, {clientId: event.source.id});
    event.ports[0]?.postMessage(supported);
}

self.addEventListener('install', event => event.waitUntil(self.skipWaiting()));
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));
self.addEventListener('message', event => {
    const data = event.data || {};
    if (!event.source?.id || !/^[a-f0-9]{32}$/.test(data.token || '')) return;
    if (data.type === 'fc-crypto-register') {
        const registration = registerCapability(event, data).catch(() => {
            event.ports[0]?.postMessage({error: '加密播放会话检查失败，请重试'});
        });
        event.waitUntil?.(registration);
    } else if (data.type === 'fc-crypto-invalidate'
        && capabilities.get(data.token)?.clientId === event.source.id && typeof data.file_path === 'string') {
        let epochs = grantEpochs.get(data.token);
        if (!epochs) { epochs = new Map(); grantEpochs.set(data.token, epochs); }
        epochs.set(data.file_path, (epochs.get(data.file_path) || 0) + 1);
        for (const key of grants.keys()) if (key.startsWith(data.token + ':' + data.file_path + ':')) grants.delete(key);
        event.ports[0]?.postMessage({ok: true});
    } else if (data.type === 'fc-crypto-zip'
        && capabilities.get(data.token)?.clientId === event.source.id) {
        const now = common.monotonicNow();
        for (const [id, plan] of zipPlans) if (plan.expires < now) zipPlans.delete(id);
        if (!Array.isArray(data.items) || data.items.length > 5000 || zipPlans.size >= 8) {
            event.ports[0]?.postMessage({error: '下载任务过多，请分批下载'});
            return;
        }
        zipPlans.set(data.download_token, {token: data.token, items: data.items, expires: now + 120000});
        event.ports[0]?.postMessage({ok: true});
    } else if (data.type === 'fc-crypto-revoke'
        && capabilities.get(data.token)?.clientId === event.source.id) {
        revokeCapability(data.token);
    }
});

async function requestGrant(token, filePath, expectedFileId = '', fallbackClientId = '', revalidate = false) {
    const capability = capabilities.get(token);
    const client = await self.clients.get(capability?.clientId || fallbackClientId);
    if (!client) {
        if (capabilities.get(token) === capability) revokeCapability(token);
        const error = new Error('媒体会话已失效，请刷新播放页面');
        error.status = 403;
        throw error;
    }
    return new Promise((resolve, reject) => {
        const channel = new MessageChannel();
        const timer = setTimeout(() => {
            channel.port1.close();
            reject(new Error('浏览器媒体授权超时'));
        }, 20000);
        channel.port1.onmessage = event => {
            clearTimeout(timer);
            channel.port1.close();
            if (event.data?.error) {
                const error = new Error(event.data.error);
                error.status = event.data.status;
                reject(error);
            }
            else resolve(event.data);
        };
        client.postMessage({type: 'fc-crypto-grant', token, file_path: filePath, file_id: expectedFileId, revalidate}, [channel.port2]);
    });
}

async function getGrant(token, filePath, expectedFileId = '', fallbackClientId = '', revalidate = false) {
    const identity = token + ':' + filePath + ':' + expectedFileId;
    const recording = filePath.startsWith('@recording/');
    let capability = capabilities.get(token);
    // After a worker restart the owning client can recover its capability.
    // Register it before requesting a grant, so pagehide can revoke it while
    // that request is still in flight and a late reply cannot recreate it.
    if (!capability && fallbackClientId) {
        if (capabilities.size >= 256) {
            const error = new Error('加密播放会话过多，请关闭闲置页面'); error.status = 429; throw error;
        }
        capability = {clientId: fallbackClientId};
        capabilities.set(token, capability);
    }
    if (!capability || recording && capability.clientId !== fallbackClientId) {
        const error = new Error('媒体会话已失效，请刷新播放页面'); error.status = 403; throw error;
    }
    const epoch = grantEpochs.get(token)?.get(filePath) || 0;
    const cached = grants.get(identity);
    if (cached?.failed) {
        const error = new Error('加密媒体完整性校验失败，请重新选择文件');
        error.status = 422;
        throw error;
    }
    if (!revalidate && cached && cached.deadline > common.monotonicNow() + 10000) return cached;
    const pendingIdentity = identity + ':' + epoch + (revalidate ? ':revalidate' : '');
    if (pendingGrants.has(pendingIdentity)) return pendingGrants.get(pendingIdentity);
    const pending = requestGrant(token, filePath, expectedFileId, fallbackClientId, revalidate).then(grant => {
        if ((grantEpochs.get(token)?.get(filePath) || 0) !== epoch || capabilities.get(token) !== capability) {
            const error = new Error('媒体对象已变化，请重新选择'); error.status = 409; throw error;
        }
        if (recording !== (grant.transport === 'Recording')) {
            const error = new Error('录音读取授权无效'); error.status = 403; throw error;
        }
        if (grant.encryption) {
            try { common.validate(grant.encryption); }
            catch (error) { if (grant.transport === 'S3') error.status = 422; throw error; }
        }
        else if ((grant.transport !== 'S3' && grant.transport !== 'Native') || !Number.isSafeInteger(grant.size_bytes) || grant.size_bytes < (grant.transport === 'Native' ? 0 : 1) || grant.size_bytes > 10 * 1024 ** 3
            || typeof grant.object_id !== 'string' || !grant.object_id || expectedFileId && grant.object_id !== expectedFileId) {
            const error = new Error('媒体对象描述无效'); error.status = 422; throw error;
        }
        if (grant.source_identity_version !== undefined && (grant.source_identity_version !== 1
            || grant.transport !== 'Native' || !grant.source_object_id || !/^[a-f0-9]{32}$/.test(grant.source_owner_id || ''))) {
            const error = new Error('媒体身份版本无效'); error.status = 422; throw error;
        }
        if (grant.transport === 'Native' && (!/^[a-f0-9]{64}$/.test(grant.resource_id || '') || !/^[a-f0-9]{64}$/.test(grant.object_id || '') || !/^[a-f0-9]{64}$/.test(grant.source_revision || '') || !['media', 'lyric'].includes(grant.kind) || grant.kind === 'lyric' && grant.resource_id !== grant.object_id || grant.encryption && !grant.source_object_id || grant.source_object_id !== undefined && !/^[a-f0-9]{32}$/.test(grant.source_owner_id || '') || !['Direct', 'Relay', 'Local'].includes(grant.source_transport) || !grant.source_headers)) {
            const error = new Error('明文资源身份无效'); error.status = 422; throw error;
        }
        if (filePath.startsWith('@admin-download/') || grant.download_snapshot !== undefined) {
            if (!grant.encryption || !/^[a-f0-9]{64}$/.test(grant.resource_id || '') || !/^[a-f0-9]{64}$/.test(grant.download_snapshot || '')
                || filePath !== `@admin-download/${grant.resource_id}/${grant.download_snapshot}`) {
                const error = new Error('下载资源授权无效'); error.status = 403; throw error;
            }
            let source;
            try { source = new URL(grant.source_url); } catch (_) {}
            if (grant.transport === 'S3') validateS3Source(grant);
            else if (grant.transport === 'Native') {
                let origin;
                try { origin = new URL(grant.source_origin); } catch (_) {}
                if (grant.source_transport !== 'Direct' || !origin || origin.protocol !== 'https:' || origin.origin !== grant.source_origin || origin.pathname !== '/'
                    || origin.username || origin.password || origin.search || origin.hash || !source || source.href !== `${origin.origin}/internal/v1/opaque-media/${grant.source_object_id}`
                    || !grant.source_headers || Object.keys(grant.source_headers).length !== 1 || typeof grant.source_headers['X-Media-Capability'] !== 'string'
                    || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(grant.source_headers['X-Media-Capability'])) {
                    const error = new Error('直连下载授权无效'); error.status = 403; throw error;
                }
            }
            else if (!source || source.origin !== self.location.origin || source.username || source.password || source.hash
                || source.pathname !== '/api/v1/media/admin/download/bytes' || source.searchParams.size !== 2
                || !/^[a-f0-9]{32}$/.test(grant.download_session_id || '')
                || source.searchParams.get('resource_id') !== grant.resource_id || source.searchParams.get('snapshot') !== grant.download_snapshot
                || grant.transport !== undefined || grant.source_headers !== undefined || grant.source_transport !== undefined) {
                const error = new Error('下载资源授权无效'); error.status = 403; throw error;
            }
        } else if (recording) {
            const id = filePath.slice('@recording/'.length);
            const signed = grant.source_headers;
            const localSource = `${self.location.origin}/api/v1/karaoke/account/recordings/${id}/audio-bytes`;
            const local = grant.source_transport === undefined && grant.source_origin === undefined
                && grant.source_object_id === undefined && grant.source_owner_id === undefined && grant.source_url === localSource
                && typeof signed?.['X-Fc-Recording-Session'] === 'string' && /^[a-f0-9]{32}$/.test(signed['X-Fc-Recording-Session']);
            let origin;
            try { if (grant.source_transport === 'Direct') origin = new URL(grant.source_origin); } catch (_) {}
            const direct = origin && origin.protocol === 'https:' && origin.origin === grant.source_origin
                && typeof grant.source_object_id === 'string' && /^[a-f0-9]{64}$/.test(grant.source_object_id)
                && typeof grant.source_owner_id === 'string' && /^[a-f0-9]{32}$/.test(grant.source_owner_id)
                && grant.source_url === `${origin.origin}/internal/v1/opaque-media/${grant.source_object_id}`
                && typeof signed?.['X-Media-Capability'] === 'string' && signed['X-Media-Capability'].length <= 4096
                && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(signed['X-Media-Capability']);
            if (!/^[a-f0-9]{32}$/.test(id) || grant.object_id !== id || grant.kind !== 'recording'
                || !grant.encryption || grant.encryption.file_id !== expectedFileId || grant.encryption.plaintext_size < 1
                || grant.encryption.ciphertext_size > 1024 ** 3 || grant.size_bytes !== grant.encryption.ciphertext_size
                || !/^[a-f0-9]{64}$/.test(grant.source_revision || '')
                || !/^(audio\/(webm|ogg|mp4|mpeg|wav)|application\/octet-stream)$/.test(grant.content_type || '')
                || !signed || Object.keys(signed).length !== 1 || (!local && !direct)) {
                const error = new Error('录音读取授权无效'); error.status = 403; throw error;
            }
        }
        else if (grant.transport === 'S3') validateS3Source(grant);
        else if (grant.source_transport !== undefined && grant.source_headers === undefined) {
            const error = new Error('资源读取授权无效'); error.status = 403; throw error;
        }
        else if (grant.source_headers !== undefined) {
            const signed = grant.source_headers;
            let target;
            try { target = new URL(grant.source_url, self.location.origin); } catch (_) {}
            const direct = grant.source_transport === 'Direct';
            const relay = grant.source_transport === 'Relay';
            const opaque = grant.source_object_id !== undefined;
            const ownerPath = opaque ? `/internal/v1/opaque-media/${grant.source_object_id}` : `/internal/v1/media/${grant.object_id}`;
            const opaqueRelayPath = `/api/v1/media/opaque-follower-relay/${grant.source_object_id}`;
            const opaqueLocalRelayPath = `/api/v1/media/opaque-local-follower-relay/${grant.source_object_id}`;
            const opaqueLyricDirectPath = `/api/v1/media/master-direct-lyric/${grant.source_object_id}`;
            const opaqueMasterRelayPath = `/api/v1/media/master-relay/${grant.source_object_id}`;
            const opaqueLyricLocalPath = `/api/v1/media/master-local-lyric/${grant.source_object_id}`;
            const opaqueMediaLocalPath = `/api/v1/media/master-local/${grant.source_object_id}`;
            const opaqueMediaDirectPath = `/api/v1/media/master-direct/${grant.source_object_id}`;
            let configuredOrigin;
            try { if (direct) configuredOrigin = new URL(grant.source_origin); } catch (_) {}
            const validDirect = direct && configuredOrigin && configuredOrigin.protocol === 'https:'
                && configuredOrigin.origin === grant.source_origin && configuredOrigin.pathname === '/'
                && !configuredOrigin.username && !configuredOrigin.password && !configuredOrigin.search && !configuredOrigin.hash
                && target?.origin === configuredOrigin.origin
                && (/^\/api\/v1\/media\/master-direct(?:-lyric)?\/[a-f0-9]{64}$/.test(target.pathname)
                    || /^\/internal\/v1\/(?:media|opaque-media)\/[a-f0-9]{64}$/.test(target.pathname));
            const validLocal = target?.origin === self.location.origin && ((grant.source_transport === undefined || grant.transport === 'Native' && grant.source_transport === 'Local' && grant.kind === 'media')
                && /^\/internal\/v1\/(?:media|opaque-media)\/[a-f0-9]{64}$/.test(target.pathname)
                || grant.transport === 'Native' && grant.source_transport === 'Local' && opaque
                    && (grant.kind === 'lyric' && target.pathname === opaqueLyricLocalPath || grant.kind === 'media' && target.pathname === opaqueMediaLocalPath));
            const validRelay = relay && target?.origin === self.location.origin
                && /^\/api\/v1\/media\/(?:master|follower|opaque-follower|opaque-local-follower)-relay\/[a-f0-9]{64}$/.test(target.pathname);
            let validOpaquePath = false;
            if (opaque && target) {
                const path = target.pathname;
                if (grant.kind === 'lyric') {
                    validOpaquePath = direct && path === opaqueLyricDirectPath || relay && path === opaqueMasterRelayPath
                        || grant.source_transport === 'Local' && path === opaqueLyricLocalPath;
                } else {
                    validOpaquePath = direct && (path === ownerPath || grant.encryption && path === opaqueMediaDirectPath)
                        || relay && (path === opaqueRelayPath || path === opaqueLocalRelayPath || grant.encryption && path === opaqueMasterRelayPath)
                        || grant.source_transport === 'Local' && (path === ownerPath || path === opaqueMediaLocalPath);
                }
            }
            const capabilityHeader = relay ? 'X-Media-Relay' : 'X-Media-Capability';
            const opaqueOnlyPath = target && /^\/(?:internal\/v1\/opaque-media|api\/v1\/media\/(?:opaque-follower-relay|opaque-local-follower-relay|master-local|master-local-lyric))\/[a-f0-9]{64}$/.test(target.pathname);
            if (!target || target.protocol !== 'https:' || target.username || target.password
                || target.search || target.hash || !(validDirect || validLocal || validRelay)
                || !signed || Array.isArray(signed) || Object.keys(signed).length !== 1
                || typeof signed[capabilityHeader] !== 'string' || signed[capabilityHeader].length > 4096
                || (opaque || opaqueOnlyPath) && (grant.transport !== 'Native' || grant.source_identity_version !== 1 || !opaque || !/^[a-f0-9]{32}$/.test(grant.source_owner_id || ''))
                || grant.transport === 'Native' && opaque && (!/^[a-f0-9]{64}$/.test(grant.source_object_id) || grant.source_object_id === grant.object_id || grant.source_object_id === grant.resource_id)
                || grant.transport === 'Native' && opaque && !validOpaquePath
                || grant.transport === 'Native' && !opaque && target.pathname !== (grant.source_transport === 'Local' ? `/internal/v1/media/${grant.object_id}` : `/api/v1/media/master-${direct ? 'direct' + (grant.kind === 'lyric' ? '-lyric' : '') : 'relay'}/${grant.resource_id}`)
                    && !(direct && grant.kind === 'media' && target.pathname === `/internal/v1/media/${grant.object_id}`)
                    && !(relay && grant.kind === 'media' && target.pathname === `/api/v1/media/follower-relay/${grant.resource_id}`)
                || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(signed[capabilityHeader])) {
                const error = new Error('资源读取授权无效'); error.status = 403; throw error;
            }
        }
        if (grant.encryption && !(grant.key instanceof CryptoKey) || !grant.source_url || !Number.isFinite(grant.deadline)
            || grant.deadline <= common.monotonicNow() || grant.deadline > common.monotonicNow() + 900000) {
            const error = new Error('解密授权已失效');
            error.status = 403;
            throw error;
        }
        // The worker is a transient byte adapter. Keys are never written to
        // CacheStorage, IndexedDB, cookies or local/session storage.
        if (grants.size >= 32) grants.delete(grants.keys().next().value);
        grants.set(identity, grant);
        return grant;
    }).finally(() => pendingGrants.delete(pendingIdentity));
    pendingGrants.set(pendingIdentity, pending);
    return pending;
}

async function readChunk(grant, index, signal, revalidate) {
    const expected = common.cipherRange(grant.encryption, index);
    if (signal?.aborted) throw new DOMException('Request aborted', 'AbortError');
    const cacheKey = cipherChunkKey(grant.encryption, index);
    const recording = grant.transport === 'Recording';
    const adminDownload = grant.download_snapshot !== undefined;
    const localAdminDownload = adminDownload && grant.transport === undefined;
    let ciphertext = recording || adminDownload ? null : cachedCipherChunk(cacheKey);
    if (ciphertext) {
        // A valid cached key does not prove the source is still visible. The
        // page must obtain a fresh server decision before cached bytes are used.
        try {
            const fresh = await revalidate();
            if (!fresh.revalidated) {
                // Old pages do not acknowledge this protocol; retain their
                // normal authenticated source reads instead of trusting a key cache.
                forgetCipherChunk(cacheKey); ciphertext = null;
            } else {
                if (!sameResourceIdentity(grant, fresh) || cipherChunkKey(fresh.encryption, index) !== cacheKey) {
                    const error = new Error('播放文件已变化，请重新选择'); error.status = 409; throw error;
                }
                Object.assign(grant, fresh);
            }
        } catch (error) { forgetCipherChunk(cacheKey); throw error; }
    }
    if (!ciphertext) {
        const localRecording = recording && grant.source_transport !== 'Direct';
        const capabilitySource = !localRecording && (grant.transport === 'S3' || grant.source_headers);
        const response = await fetch(grant.source_url, {
            headers: {...(grant.source_headers || {}), Range: `bytes=${expected.start}-${expected.end}`,
                ...(localAdminDownload ? {'X-Fc-Download-Session': grant.download_session_id} : {})},
            credentials: capabilitySource ? 'omit' : 'same-origin',
            ...(localRecording || localAdminDownload ? {mode: 'same-origin', redirect: 'error', referrerPolicy: 'no-referrer'}
                : capabilitySource ? {mode: 'cors', redirect: 'error', referrerPolicy: 'no-referrer'} : {}),
            cache: 'no-store', signal,
        });
        if (grant.transport === 'S3' && !response.ok) {
            await response.body?.cancel().catch(() => {});
            const error = new Error('S3 读取请求失败'); error.status = response.status; throw error;
        }
        if (grant.transport === 'S3' && response.headers.get('ETag') !== grant.source_headers['If-Match']) {
            await response.body?.cancel().catch(() => {});
            const error = new Error('S3 对象身份校验失败'); error.status = 422; throw error;
        }
        if (recording && response.ok && response.headers.get('ETag') !== `"${grant.source_revision}"`) {
            await response.body?.cancel().catch(() => {});
            const error = new Error('录音密文身份不一致'); error.status = 422; throw error;
        }
        if (localAdminDownload && response.ok && response.headers.get('ETag') !== `"${grant.download_snapshot}"`) {
            await response.body?.cancel().catch(() => {});
            const error = new Error('下载密文身份不一致'); error.status = 422; throw error;
        }
        const contentRange = /^bytes (\d+)-(\d+)\/(\d+)$/.exec(response.headers.get('Content-Range') || '');
        const exactRange = response.status === 206 && contentRange
            && Number(contentRange[1]) === expected.start && Number(contentRange[2]) === expected.end
            && Number(contentRange[3]) === grant.encryption.ciphertext_size;
        const completeSmallObject = !recording && !adminDownload && response.status === 200 && expected.start === 0
            && expected.size === grant.encryption.ciphertext_size;
        if (!exactRange && !completeSmallObject) {
            await response.body?.cancel().catch(() => {});
            const error = new Error('存储节点未返回所需的加密分块');
            if (response.status >= 400 && response.status < 500) error.status = response.status;
            else if (response.status < 400) { error.fatal = true; error.status = 409; }
            throw error;
        }
        ciphertext = await common.boundedBytes(response, expected.size);
    }
    // AES-GCM verifies each entire chunk before any of its bytes are delivered.
    // It does not prove later chunks exist or will authenticate successfully.
    try {
        const plaintext = new Uint8Array(await crypto.subtle.decrypt(
            common.parameters(grant.encryption, index), grant.key, ciphertext));
        if (!recording && !adminDownload && !signal?.aborted) rememberCipherChunk(cacheKey, ciphertext);
        return plaintext;
    } catch (error) {
        forgetCipherChunk(cacheKey);
        error.fatal = true;
        throw error;
    }
}

function validateS3Source(grant) {
    let url;
    try { url = new URL(grant.source_url); }
    catch (error) { error.status = 403; throw error; }
    const headers = grant.source_headers;
    if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.href.length > 16384
        || !headers || Array.isArray(headers) || Object.keys(headers).length !== 1
        || typeof headers['If-Match'] !== 'string' || !/^"[^"\r\n]{1,1024}"$/.test(headers['If-Match'])
        || grant.deadline > common.monotonicNow() + 300000) {
        const error = new Error('S3 读取授权无效'); error.status = 403; throw error;
    }
}
async function s3Range(grant, start, end, signal, head = false) {
    validateS3Source(grant);
    const target = head ? grant.source_head_url : grant.source_url;
    const signed = head ? grant.source_head_headers : grant.source_headers;
    if (head) {
        let url;
        try { url = new URL(target); }
        catch (error) { error.status = 403; throw error; }
        if (url.protocol !== 'https:' || url.username || url.password || url.hash
            || url.href.length > 16384 || !signed || Array.isArray(signed)
            || Object.entries(signed).some(([name, value]) => name !== 'If-Match'
                && !(name === 'X-Amz-Checksum-Mode' && value === 'ENABLED'))
            || signed['If-Match'] !== grant.source_headers['If-Match']) {
            const error = new Error('S3 HEAD 授权无效'); error.status = 403; throw error;
        }
    }
    const response = await fetch(target, {method: head ? 'HEAD' : 'GET',
        headers: {...signed, ...(!head ? {Range: `bytes=${start}-${end}`} : {})},
        credentials: 'omit', mode: 'cors', redirect: 'error', referrerPolicy: 'no-referrer', cache: 'no-store', signal});
    if (!response.ok) {
        await response.body?.cancel().catch(() => {});
        const error = new Error('S3 读取请求失败'); error.status = response.status; throw error;
    }
    const range = /^bytes (\d+)-(\d+)\/(\d+)$/.exec(response.headers.get('Content-Range') || '');
    const exact = head ? response.status === 200 && Number(response.headers.get('Content-Length')) === grant.size_bytes
        : response.status === 206 && range && Number(range[1]) === start && Number(range[2]) === end && Number(range[3]) === grant.size_bytes
        || response.status === 200 && start === 0 && end + 1 === grant.size_bytes;
    if (!exact || response.headers.get('ETag') !== grant.source_headers['If-Match']
        || !head && Number(response.headers.get('Content-Length')) !== end - start + 1) {
        await response.body?.cancel().catch(() => {});
        const error = new Error('S3 未返回已授权的对象与范围'); error.status = response.status === 403 ? 403 : 422; throw error;
    }
    return response;
}
async function serveS3(request, grant, token, filePath, download, expectedFileId, fallbackClientId) {
    const size = grant.size_bytes, selected = common.range(request.headers.get('Range'), size);
    if (!selected) return new Response(null, {status: 416, headers: {'Content-Range': `bytes */${size}`, 'Cache-Control': 'no-store'}});
    const headers = new Headers({'Content-Type': grant.content_type || 'application/octet-stream',
        'Content-Length': String(selected.end - selected.start + 1), 'Accept-Ranges': 'bytes',
        'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ETag: grant.source_headers['If-Match']});
    if (selected.partial) headers.set('Content-Range', `bytes ${selected.start}-${selected.end}/${size}`);
    if (download) headers.set('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(grant.filename || filePath.split('/').pop())}`);
    if (request.method === 'HEAD') {
        await s3Range(grant, 0, 0, request.signal, true);
        return new Response(null, {status: selected.partial ? 206 : 200, headers});
    }
    let offset = selected.start;
    const controller = new AbortController();
    request.signal.addEventListener('abort', () => controller.abort(), {once: true});
    if (request.signal.aborted) controller.abort();
    const identity = grant.object_id, etag = grant.source_headers['If-Match'];
    const stream = new ReadableStream({
        async pull(output) {
            try {
                if (offset > selected.end) { output.close(); return; }
                if (grant.deadline <= common.monotonicNow() + 10000) {
                    const fresh = await getGrant(token, filePath, expectedFileId, fallbackClientId);
                    if (fresh.encryption || fresh.object_id !== identity || fresh.source_headers?.['If-Match'] !== etag || fresh.size_bytes !== size) {
                        const error = new Error('S3 对象已变化，请重新选择'); error.status = 409; throw error;
                    }
                    Object.assign(grant, fresh);
                }
                const end = Math.min(selected.end, offset + common.CHUNK_SIZE - 1);
                const response = await s3Range(grant, offset, end, controller.signal);
                const bytes = await common.boundedBytes(response, end - offset + 1);
                output.enqueue(bytes); offset = end + 1;
                if (offset > selected.end) output.close();
            } catch (error) {
                const cancelled = request.signal.aborted || error.name === 'AbortError';
                controller.abort();
                // A rejected/short body is a transport interruption. Only
                // proven access or object failures may stop the player's retry.
                if (!cancelled && (error.fatal || [401, 403, 404, 409, 412, 416, 422].includes(error.status))) {
                    const client = await self.clients.get(capabilities.get(token)?.clientId || '');
                    client?.postMessage({type: 'fc-crypto-fault', token, file_path: filePath, error: 'S3 媒体授权或对象校验失败，请重新选择'});
                }
                output.error(error);
            }
        }, cancel() { controller.abort(); },
    }, {highWaterMark: 0});
    return new Response(stream, {status: selected.partial ? 206 : 200, headers});
}

async function nativeRange(grant, start, end, signal) {
    const response = await fetch(grant.source_url, {headers: {...grant.source_headers, Range: `bytes=${start}-${end}`},
        credentials: 'omit', mode: 'cors', redirect: 'error', referrerPolicy: 'no-referrer', cache: 'no-store', signal});
    if (!response.ok) {
        await response.body?.cancel().catch(() => {});
        const error = new Error('明文资源读取失败'); error.status = response.status; throw error;
    }
    const range = /^bytes (\d+)-(\d+)\/(\d+)$/.exec(response.headers.get('Content-Range') || '');
    const exact = response.status === 206 && range && Number(range[1]) === start && Number(range[2]) === end && Number(range[3]) === grant.size_bytes
        || response.status === 200 && start === 0 && end + 1 === grant.size_bytes;
    if (!exact || Number(response.headers.get('Content-Length')) !== end - start + 1) {
        await response.body?.cancel().catch(() => {});
        const error = new Error('资源未返回授权范围'); error.status = 422; throw error;
    }
    return response;
}

async function serveNative(request, grant, token, filePath, download, expectedFileId, fallbackClientId) {
    const size = grant.size_bytes, selected = common.range(request.headers.get('Range'), size);
    if (!selected) return new Response(null, {status: 416, headers: {'Content-Range': `bytes */${size}`, 'Cache-Control': 'no-store'}});
    const headers = new Headers({'Content-Type': grant.content_type || 'application/octet-stream',
        'Content-Length': String(selected.end - selected.start + 1), 'Accept-Ranges': 'bytes',
        'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ETag: `"${grant.source_revision}"`});
    if (selected.partial) headers.set('Content-Range', `bytes ${selected.start}-${selected.end}/${size}`);
    if (download) headers.set('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(grant.filename || filePath.split('/').pop())}`);
    if (size === 0) {
        // An empty grant still requires a live owner request. Do not infer a
        // successful empty file merely from metadata or a cached capability.
        const sourceHeaders = new Headers(grant.source_headers);
        if (request.headers.has('Range')) sourceHeaders.set('Range', request.headers.get('Range'));
        const response = await fetch(grant.source_url, {method: request.method, headers: sourceHeaders,
            credentials: 'omit', mode: 'cors', redirect: 'error', referrerPolicy: 'no-referrer', cache: 'no-store', signal: request.signal});
        const suffix206 = selected.partial && response.status === 206 && response.headers.get('Content-Range') === 'bytes 0--1/0';
        const full200 = response.status === 200 && !response.headers.has('Content-Range');
        if ((!suffix206 && !full200) || response.headers.get('Content-Length') !== '0'
            || response.headers.get('Content-Encoding') && response.headers.get('Content-Encoding') !== 'identity') {
            await response.body?.cancel().catch(() => {});
            const error = new Error('空资源读取失败'); error.status = 422; throw error;
        }
        if (request.method === 'GET' && response.body) await common.boundedBytes(response, 0);
        if (full200) headers.delete('Content-Range');
        return new Response(null, {status: response.status, headers});
    }
    if (request.method === 'HEAD') {
        const probe = await nativeRange(grant, 0, 0, request.signal);
        await probe.body?.cancel().catch(() => {});
        return new Response(null, {status: selected.partial ? 206 : 200, headers});
    }
    let offset = selected.start;
    const controller = new AbortController();
    request.signal.addEventListener('abort', () => controller.abort(), {once: true});
    if (request.signal.aborted) controller.abort();
    const stream = new ReadableStream({
        async pull(output) {
            try {
                if (offset > selected.end) { output.close(); return; }
                if (grant.deadline <= common.monotonicNow() + 10000) {
                    const fresh = await getGrant(token, filePath, expectedFileId, fallbackClientId, true);
                    if (!sameResourceIdentity(grant, fresh) || fresh.transport !== 'Native' || fresh.encryption) {
                        const error = new Error('媒体对象已变化，请重新选择'); error.status = 409; throw error;
                    }
                    Object.assign(grant, fresh);
                }
                const end = Math.min(selected.end, offset + common.CHUNK_SIZE - 1);
                const response = await nativeRange(grant, offset, end, controller.signal);
                output.enqueue(await common.boundedBytes(response, end - offset + 1));
                offset = end + 1;
                if (offset > selected.end) output.close();
            } catch (error) {
                const cancelled = request.signal.aborted || error.name === 'AbortError';
                controller.abort();
                if (!cancelled && (error.fatal || [401, 403, 404, 409, 412, 416, 422].includes(error.status))) {
                    const client = await self.clients.get(capabilities.get(token)?.clientId || '');
                    client?.postMessage({type: 'fc-crypto-fault', token, file_path: filePath, error: '媒体授权或对象校验失败，请重新选择'});
                }
                output.error(error);
            }
        }, cancel() { controller.abort(); },
    }, {highWaterMark: 0});
    return new Response(stream, {status: selected.partial ? 206 : 200, headers});
}

async function servePlaintext(request, token, filePath, download, expectedFileId = '', fallbackClientId = '') {
    const grant = await getGrant(token, filePath, expectedFileId, fallbackClientId);
    if (grant.transport === 'Native' && !grant.encryption) return serveNative(request, grant, token, filePath, download, expectedFileId, fallbackClientId);
    if (!grant.encryption) return serveS3(request, grant, token, filePath, download, expectedFileId, fallbackClientId);
    const size = grant.encryption.plaintext_size;
    const selected = common.range(request.headers.get('Range'), size);
    if (!selected) return new Response(null, {status: 416,
        headers: {'Content-Range': `bytes */${size}`, 'Cache-Control': 'no-store'}});
    const headers = new Headers({
        'Content-Type': grant.content_type || 'application/octet-stream',
        'Content-Length': String(Math.max(0, selected.end - selected.start + 1)),
        'Accept-Ranges': 'bytes', 'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'ETag': '"fc-plain-' + grant.encryption.file_id + '"',
    });
    if (selected.partial) headers.set('Content-Range', `bytes ${selected.start}-${selected.end}/${size}`);
    if (download) headers.set('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(grant.filename || filePath.split('/').pop())}`);
    if (request.method === 'HEAD' || size === 0) return new Response(null,
        {status: selected.partial ? 206 : 200, headers});
    let index = Math.floor(selected.start / common.CHUNK_SIZE);
    const last = Math.floor(selected.end / common.CHUNK_SIZE);
    const epoch = grantEpochs.get(token)?.get(filePath) || 0;
    const controller = new AbortController();
    request.signal.addEventListener('abort', () => controller.abort(), {once: true});
    if (request.signal.aborted) controller.abort();
    const stream = new ReadableStream({
        async pull(output) {
            try {
                if (index > last) { output.close(); return; }
                if (grant.transport === 'Recording' && (capabilities.get(token)?.clientId !== fallbackClientId
                    || (grantEpochs.get(token)?.get(filePath) || 0) !== epoch)) {
                    const error = new Error('录音读取授权已失效'); error.status = 403; throw error;
                }
                if (grant.deadline <= common.monotonicNow() + 10000) {
                    const refreshed = await getGrant(token, filePath, expectedFileId, fallbackClientId);
                    if (!sameResourceIdentity(grant, refreshed)) {
                        const error = new Error('播放文件已变化，请重新选择'); error.status = 409; throw error;
                    }
                    Object.assign(grant, refreshed);
                }
                const plaintext = await readChunk(grant, index, controller.signal,
                    () => getGrant(token, filePath, grant.encryption.file_id, fallbackClientId, true));
                const chunkStart = index * common.CHUNK_SIZE;
                output.enqueue(plaintext.subarray(Math.max(0, selected.start - chunkStart),
                    Math.min(plaintext.length, selected.end - chunkStart + 1)));
                index += 1;
                if (index > last) output.close();
            } catch (error) {
                if (error.fatal || [401, 403, 404, 409, 422, 429].includes(error.status)) {
                    grant.failed = true;
                    const client = await self.clients.get(capabilities.get(token)?.clientId || '');
                    client?.postMessage({type: 'fc-crypto-fault', token, file_path: filePath,
                        error: error.status === 429 ? '媒体授权请求已达到限额，请稍后重新选择文件'
                            : '加密媒体授权或完整性校验失败，请重新选择文件'});
                }
                controller.abort(); output.error(error);
            }
        },
        cancel() { controller.abort(); },
    }, {highWaterMark: 0});
    return new Response(stream, {status: selected.partial ? 206 : 200, headers});
}

self.addEventListener('fetch', event => {
    const url = new URL(event.request.url);
    if (url.origin !== self.location.origin || !url.pathname.startsWith(PREFIX)) return;
    event.respondWith((async () => {
        if (!['GET', 'HEAD'].includes(event.request.method)) return new Response(null, {status: 405});
        const parts = url.pathname.slice(PREFIX.length).split('/');
        const token = parts.shift();
        if (!/^[a-f0-9]{32}$/.test(token || '')) return new Response('媒体会话已失效', {status: 403});
        try {
            const filePath = decodeURIComponent(parts.join('/'));
            return await servePlaintext(event.request, token, filePath, url.searchParams.has('download'),
                url.searchParams.get('object') || '', event.clientId);
        } catch (error) {
            return new Response(error.message || '加密媒体暂不可用', {status: error.status || 502,
                headers: {'Cache-Control': 'no-store', 'Content-Type': 'text/plain; charset=utf-8'}});
        }
    })());
});

const crcTable = Uint32Array.from({length: 256}, (_, value) => {
    let crc = value;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc & 1) ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1;
    return crc >>> 0;
});
function crcUpdate(crc, bytes) {
    for (const byte of bytes) crc = crcTable[(crc ^ byte) & 255] ^ (crc >>> 8);
    return crc;
}
function zipHeader(size, signature) {
    const bytes = new Uint8Array(size);
    const view = new DataView(bytes.buffer);
    view.setUint32(0, signature, true);
    return {bytes, view};
}
async function* archive(plan, signal) {
    const central = [];
    let offset = 0;
    for (const item of plan.items) {
        const name = new TextEncoder().encode(item.path || item.filename);
        if (!name.length || name.length > 65535 || !Number.isSafeInteger(item.plaintext_size)
            || item.plaintext_size < 0) throw new Error('下载文件描述无效');
        const start = offset;
        const local = zipHeader(30 + name.length + 20, 0x04034b50);
        local.view.setUint16(4, 45, true);
        local.view.setUint16(6, 0x0808, true); // UTF-8 + trailing data descriptor.
        local.view.setUint32(18, 0xffffffff, true);
        local.view.setUint32(22, 0xffffffff, true);
        local.view.setUint16(26, name.length, true);
        local.view.setUint16(28, 20, true);
        local.bytes.set(name, 30);
        const extra = 30 + name.length;
        local.view.setUint16(extra, 1, true);
        local.view.setUint16(extra + 2, 16, true);
        local.view.setBigUint64(extra + 4, BigInt(item.plaintext_size), true);
        local.view.setBigUint64(extra + 12, BigInt(item.plaintext_size), true);
        yield local.bytes;
        offset += local.bytes.length;
        const response = item.encryption || item.transport === 'S3'
            ? await servePlaintext(new Request(new URL(item.url, self.location.origin), {signal}),
                plan.token, item.file_path, false, item.encryption?.file_id || item.object_id)
            : await fetch(item.url, {credentials: 'same-origin', cache: 'no-store', signal});
        if (!response.ok || !response.body) throw new Error('下载文件读取失败');
        const reader = response.body.getReader();
        let size = 0;
        let crc = 0xffffffff;
        try {
            while (true) {
                const {done, value} = await reader.read();
                if (done) break;
                size += value.byteLength;
                if (size > item.plaintext_size) throw new Error('下载文件长度发生变化');
                crc = crcUpdate(crc, value);
                yield value;
                offset += value.byteLength;
            }
        } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
        if (size !== item.plaintext_size) throw new Error('下载文件不完整');
        crc = (crc ^ 0xffffffff) >>> 0;
        const descriptor = zipHeader(24, 0x08074b50);
        descriptor.view.setUint32(4, crc, true);
        descriptor.view.setBigUint64(8, BigInt(size), true);
        descriptor.view.setBigUint64(16, BigInt(size), true);
        yield descriptor.bytes;
        offset += descriptor.bytes.length;
        const entry = zipHeader(46 + name.length + 28, 0x02014b50);
        entry.view.setUint16(4, 45, true);
        entry.view.setUint16(6, 45, true);
        entry.view.setUint16(8, 0x0808, true);
        entry.view.setUint32(16, crc, true);
        entry.view.setUint32(20, 0xffffffff, true);
        entry.view.setUint32(24, 0xffffffff, true);
        entry.view.setUint16(28, name.length, true);
        entry.view.setUint16(30, 28, true);
        entry.view.setUint32(42, 0xffffffff, true);
        entry.bytes.set(name, 46);
        const centralExtra = 46 + name.length;
        entry.view.setUint16(centralExtra, 1, true);
        entry.view.setUint16(centralExtra + 2, 24, true);
        entry.view.setBigUint64(centralExtra + 4, BigInt(size), true);
        entry.view.setBigUint64(centralExtra + 12, BigInt(size), true);
        entry.view.setBigUint64(centralExtra + 20, BigInt(start), true);
        central.push(entry.bytes);
    }
    const centralOffset = offset;
    for (const bytes of central) { yield bytes; offset += bytes.length; }
    const centralSize = offset - centralOffset;
    const end = zipHeader(56, 0x06064b50);
    end.view.setBigUint64(4, 44n, true);
    end.view.setUint16(12, 45, true);
    end.view.setUint16(14, 45, true);
    end.view.setBigUint64(24, BigInt(central.length), true);
    end.view.setBigUint64(32, BigInt(central.length), true);
    end.view.setBigUint64(40, BigInt(centralSize), true);
    end.view.setBigUint64(48, BigInt(centralOffset), true);
    yield end.bytes;
    const locator = zipHeader(20, 0x07064b50);
    locator.view.setBigUint64(8, BigInt(offset), true);
    locator.view.setUint32(16, 1, true);
    yield locator.bytes;
    const legacyEnd = zipHeader(22, 0x06054b50);
    legacyEnd.view.setUint16(8, 0xffff, true);
    legacyEnd.view.setUint16(10, 0xffff, true);
    legacyEnd.view.setUint32(12, 0xffffffff, true);
    legacyEnd.view.setUint32(16, 0xffffffff, true);
    yield legacyEnd.bytes;
}
self.addEventListener('fetch', event => {
    const url = new URL(event.request.url);
    if (url.origin !== self.location.origin || !url.pathname.startsWith('/__fc_zip/')) return;
    event.respondWith((async () => {
        const id = url.pathname.slice('/__fc_zip/'.length);
        const plan = zipPlans.get(id);
        if (!plan || plan.expires < common.monotonicNow() || !capabilities.has(plan.token))
            return new Response('下载授权已失效', {status: 403});
        zipPlans.delete(id);
        const controller = new AbortController();
        event.request.signal.addEventListener('abort', () => controller.abort(), {once: true});
        const iterator = archive(plan, controller.signal);
        const stream = new ReadableStream({
            async pull(output) {
                try {
                    const {value, done} = await iterator.next();
                    if (done) output.close(); else output.enqueue(value);
                } catch (error) { controller.abort(); output.error(error); }
            },
            async cancel() { controller.abort(); await iterator.return(); },
        }, {highWaterMark: 0});
        return new Response(stream, {headers: {'Content-Type': 'application/zip',
            'Content-Disposition': 'attachment; filename="media-download.zip"', 'Cache-Control': 'no-store'}});
    })());
});
