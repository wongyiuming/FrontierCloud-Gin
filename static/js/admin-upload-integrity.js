'use strict';

const uploadSiteLabels = {
    primary: '主站',
    direct: '直连站点',
    relay: '中继站点',
    s3: 'S3 存储桶',
};

function ensureUploadSiteTypeSelector() {
    let selector = document.getElementById('uploadSiteType');
    if (selector) return selector;
    selector = document.createElement('select');
    selector.id = 'uploadSiteType';
    selector.className = 'upload-site-type';
    selector.setAttribute('aria-label', '上传目标存储节点');
    selector.innerHTML = '<option value="" selected>请选择目标存储节点</option>';
    const legacy = document.getElementById('uploadStorageMember');
    if (legacy?.parentNode) {
        legacy.hidden = true;
        legacy.setAttribute('aria-hidden', 'true');
        legacy.setAttribute('tabindex', '-1');
        legacy.parentNode.insertBefore(selector, legacy);
    }
    return selector;
}

const uploadSiteType = ensureUploadSiteTypeSelector();
const uploadDestinations = new Map();
let selectedUploadProtocol = null;
let uploadPoolRefresh = null;

for (const [buttonId, inputId, folder, lyric] of [
    ['uploadFiles', 'fileInput', false, false],
    ['uploadFolder', 'folderInput', true, false],
    ['uploadLyrics', 'lyricsInput', false, true],
    ['uploadLyricsFolder', 'lyricsFolderInput', true, true],
]) {
    $(buttonId).onclick = () => $(inputId).click();
    $(inputId).onchange = async event => {
        const files = [...event.target.files].filter(file => !lyric || file.name.toLowerCase().endsWith('.lrc'));
        const paths = folder ? files.map(file => file.webkitRelativePath || file.name) : null;
        try { await runUploadTask(files, paths, lyric); }
        finally { event.target.value = ''; }
    };
}

function siteTypeFromItem(item) {
    const destination = uploadDestinations.get(item?.storage_member_id);
    if (destination) return destination.site_type;
    if (item?.site_type && uploadSiteLabels[item.site_type]) return item.site_type;
    if (item?.transport === 'Direct') return 'direct';
    if (item?.transport === 'Relay') return 'relay';
    if (item?.transport === 'S3' || item?.member_kind === 'S3') return 's3';
    if (item?.transport === 'Local' || item?.storage_address_local === true) return 'primary';
    return '';
}

function mediaStorageAddress(item) {
    const destination = uploadDestinations.get(item.storage_member_id);
    const value = item.storage_address || destination?.address
        || (item.storage_address_local === true ? window.location.origin : '');
    if (typeof value !== 'string' || !value) return '';
    try {
        const address = new URL(value);
        if (!['https:', 'http:'].includes(address.protocol) || address.username || address.password
            || address.search || address.hash) return '';
        return address.origin + address.pathname.replace(/\/$/, '');
    } catch (_) { return ''; }
}

function readyMember(member) {
    return Boolean(
        member?.storage_enabled
        && member?.health === 'online'
        && member?.writable
        && Number(member?.available_bytes || 0) > 0
    );
}

function updateMediaUploadGate() {
    const destination = uploadDestinations.get(uploadSiteType?.value);
    const waitingForPool = selectedUploadProtocol === null;
    const blocked = waitingForPool || uploadRunning || !destination?.writable;
    $('uploadFiles').disabled = blocked;
    $('uploadFolder').disabled = blocked;
    const lyricBlocked = waitingForPool || uploadRunning || selectedUploadProtocol && (blocked || destination.site_type !== 'primary');
    for (const id of ['uploadLyrics', 'uploadLyricsFolder']) {
        $(id).disabled = lyricBlocked;
        $(id).title = selectedUploadProtocol ? '请选择主站作为歌词的目标存储节点' : '';
    }
    if (uploadSiteType) uploadSiteType.disabled = uploadRunning;
}

function refreshUploadSiteTypes() {
    if (!uploadPoolRefresh) {
        uploadPoolRefresh = loadUploadSiteTypes().finally(() => { uploadPoolRefresh = null; });
    }
    return uploadPoolRefresh;
}

async function loadUploadSiteTypes() {
    const pool = await api('/api/v1/media/admin/storage-pool', {cache: 'no-store'});
    if (typeof pool.standalone !== 'boolean') throw new Error('无法确认上传方式');
    const previous = uploadSiteType.value;
    const empty = document.createElement('option');
    empty.value = '';
    empty.textContent = '请选择目标存储节点';
    const options = [empty];
    const next = new Map();

    for (const destination of pool.upload_destinations || []) {
        if (!/^[a-f0-9]{32}$/.test(destination.member_id || '') || !uploadSiteLabels[destination.site_type]
            || next.has(destination.member_id)) continue;
        next.set(destination.member_id, destination);
        const option = document.createElement('option');
        option.value = destination.member_id;
        option.disabled = !destination.writable;
        const address = destination.address || (pool.standalone ? window.location.origin : '地址不可用');
        const bucket = destination.bucket ? ` / ${destination.bucket}` : '';
        option.textContent = `${address}${bucket} · ${uploadSiteLabels[destination.site_type]} · ${destination.member_id}${option.disabled ? ' · 不可上传' : ''}`;
        options.push(option);
    }
    uploadDestinations.clear();
    for (const [id, destination] of next) uploadDestinations.set(id, destination);
    uploadSiteType.replaceChildren(...options);
    uploadSiteType.value = next.get(previous)?.writable ? previous : '';
    clusterUpload = !pool.standalone;
    selectedUploadProtocol = pool.selected_upload === true;
    updateMediaUploadGate();
    if (visibleMediaItems.length) decorateMediaSiteBadges();
    return pool;
}

const originalSetUploadControlsDisabled = setUploadControlsDisabled;
setUploadControlsDisabled = function setUploadControlsDisabledWithSiteType(disabled) {
    originalSetUploadControlsDisabled(disabled);
    updateMediaUploadGate();
};

uploadSiteType.onchange = updateMediaUploadGate;
refreshStoragePool = refreshUploadSiteTypes;

function decorateMediaSiteBadges() {
    const itemsByPath = new Map(visibleMediaItems.map(item => [item.path, item]));
    for (const row of document.querySelectorAll('.tree-row[data-path]')) {
        row.querySelector('.media-site-badge')?.remove();
        row.querySelector('.media-node-address')?.remove();
        const item = itemsByPath.get(row.dataset.path);
        if (item?.kind !== 'file') continue;
        const address = mediaStorageAddress(item);
        const nodeAddress = document.createElement('small');
        nodeAddress.className = 'media-node-address';
        nodeAddress.textContent = address ? address.slice(address.indexOf('://') + 3) : '地址不可用';
        nodeAddress.title = address || '节点地址不可用';
        nodeAddress.setAttribute('aria-label', `节点地址：${address || '不可用'}`);
        row.append(nodeAddress);
        const root = item.path.split('/', 1)[0];
        if (root !== 'music' && root !== 'vido') continue;
        const siteType = siteTypeFromItem(item);
        if (!siteType) continue;
        const badge = document.createElement('span');
        badge.className = `media-site-badge site-${siteType}`;
        badge.textContent = uploadSiteLabels[siteType];
        badge.title = `实际归属：${uploadSiteLabels[siteType]}`;
        row.append(badge);
    }
}

const originalRenderTree = renderTree;
renderTree = async function renderTreeWithPlacementObservation() {
    await originalRenderTree();
    decorateMediaSiteBadges();
};

const S3_PART_BYTES = 8 * 1024 * 1024;
const S3_TASK_KEY = 'frontiercloud-s3-upload-resume-v1';
const s3Tasks = new Map();
const s3Transfers = new Set();
for (const event of ['pagehide', 'offline']) window.addEventListener?.(event, () => {
    for (const controller of s3Transfers) controller.abort();
});
function readS3Tasks() {
    if (!window.localStorage) throw new Error('无法读取恢复信息');
    return decodeS3Tasks(window.localStorage.getItem(S3_TASK_KEY) || '[]');
}
function decodeS3Tasks(raw) {
    if (raw.length > 1024 * 1024) throw new Error('恢复信息无效');
    const stored = JSON.parse(raw);
    if (!Array.isArray(stored) || stored.length > 8) throw new Error('恢复信息无效');
    const tasks = new Map();
    for (const task of stored) {
        if (!(typeof task?.id === 'string' && /^[a-zA-Z0-9_-]{1,160}$/.test(task.id)
            && typeof task.name === 'string' && task.name.length <= 512
            && Number.isSafeInteger(task.originalSize) && task.originalSize > 0 && task.originalSize <= 10 * 1024 ** 3
            && Array.isArray(task.hashes) && task.hashes.length === Math.ceil(task.originalSize / S3_PART_BYTES)
            && task.hashes.every(hash => typeof hash === 'string' && /^[A-Za-z0-9+/]{43}=$/.test(hash))
            && (task.cipherName === undefined || typeof task.cipherName === 'string'
                && /^[a-zA-Z0-9_-]{1,160}$/.test(task.cipherName))
            && (task.selected === undefined || task.selected === true && Boolean(task.cipherName) && /^[a-f0-9]{32}$/.test(task.id))
            && (task.cancel_requested === undefined || typeof task.cancel_requested === 'boolean'))
            || tasks.has(task.id)) throw new Error('恢复信息无效');
        tasks.set(task.id, {id: task.id, name: task.name, originalSize: task.originalSize, hashes: task.hashes,
            ...(task.cipherName ? {cipherName: task.cipherName} : {}),
            ...(task.selected ? {selected: true} : {}),
            ...(task.cancel_requested ? {cancel_requested: true} : {})});
    }
    return tasks;
}
function observeS3Tasks(tasks) {
    s3Tasks.clear();
    for (const [id, task] of tasks) s3Tasks.set(id, task);
}
try { observeS3Tasks(readS3Tasks()); }
catch (_) { /* Invalid or unavailable local metadata never authorizes a resume. */ }
window.addEventListener?.('storage', event => {
    if (event.key !== null && event.key !== S3_TASK_KEY) return;
    try { observeS3Tasks(readS3Tasks()); renderS3Tasks(); }
    catch (_) { /* Preserve the last observation; never overwrite invalid shared data. */ }
});
async function saveS3Tasks(change) {
    if (!window.navigator?.locks?.request) throw new Error('S3 恢复需要支持浏览器存储锁，请更新浏览器');
    // Hold one origin-wide lock while rereading and changing a single record.
    // A stale tab never publishes its in-memory snapshot or resurrects a removal.
    const removed = await window.navigator.locks.request(S3_TASK_KEY, () => {
        let tasks;
        try { tasks = readS3Tasks(); }
        catch (_) { throw new Error('无法读取恢复信息，请先检查浏览器站点存储'); }
        let previous;
        if (change.put) {
            if (uploadInterrupted) throw new Error('上传已中断，请重新选择文件重试');
            if (tasks.has(change.put.id)) throw new Error('恢复任务已存在，请刷新页面后重试');
            if (tasks.size >= 8) throw new Error('待恢复 S3 任务已达 8 个，请先恢复或取消旧任务');
            tasks.set(change.put.id, change.put);
        } else if (change.cancel) {
            const task = tasks.get(change.cancel);
            if (task) task.cancel_requested = true;
        } else if (change.remove) {
            previous = tasks.get(change.remove);
            tasks.delete(change.remove);
        } else throw new Error('恢复信息变更无效');
        const validated = decodeS3Tasks(JSON.stringify([...tasks.values()]));
        try { window.localStorage.setItem(S3_TASK_KEY, JSON.stringify([...validated.values()])); }
        catch (_) { throw new Error('无法保存恢复信息，请释放浏览器站点存储空间后重试'); }
        change.retain?.();
        observeS3Tasks(validated);
        return previous;
    });
    renderS3Tasks();
    return removed;
}
const s3Base = id => `/api/v1/media/admin/upload/s3/${encodeURIComponent(id)}`;
const s3Post = (base, body = {}) => api(base, {method: 'POST', headers: requestHeaders(), body: JSON.stringify(body)});
async function s3FileHashes(file) {
    const hashes = [];
    for (let offset = 0; offset < file.size; offset += S3_PART_BYTES) {
        if (uploadInterrupted) throw new Error('上传已暂停，恢复时将重新核对文件');
        const bytes = new Uint8Array(await file.slice(offset, Math.min(file.size, offset + S3_PART_BYTES)).arrayBuffer());
        try { hashes.push(btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))))); }
        finally { bytes.fill(0); }
    }
    return hashes;
}
async function retainS3Task(id, original, encrypted, displayName, selected = false) {
    if (!encrypted.retainedName || typeof encrypted.retain !== 'function')
        throw new Error('上传恢复组件需要更新，请刷新页面后重试');
    const hashes = await s3FileHashes(original);
    // Save and disarm pagehide cleanup in the same Web Locks callback.
    await saveS3Tasks({put: {id, name: displayName.slice(0, 512), originalSize: original.size, hashes,
        cipherName: encrypted.retainedName, ...(selected ? {selected: true} : {})}, retain: () => encrypted.retain()});
}
async function forgetS3Task(id) {
    const task = await saveS3Tasks({remove: id});
    if (task?.cipherName) await window.FrontierMediaCrypto?.forgetRetainedUpload(task.cipherName);
}
function renderS3Tasks() {
    const host = $('uploadProgress');
    if (!host?.append) return;
    let section = document.getElementById('s3ResumableUploads');
    if (!section) { section = document.createElement('div'); section.id = 's3ResumableUploads'; host.after ? host.after(section) : host.append(section); }
    section.replaceChildren();
    for (const task of s3Tasks.values()) {
        const row = document.createElement('div'); row.className = 's3-resume-row';
        const label = document.createElement('span'); label.textContent = `${task.name} · ${task.cancel_requested ? '等待清理核验' : '待恢复或核验'}`;
        const select = document.createElement('input'); select.type = 'file'; select.hidden = true;
        const resume = document.createElement('button'); resume.type = 'button'; resume.textContent = task.cancel_requested ? '检查清理状态' : '重新选择原文件并恢复';
        resume.onclick = async () => {
            if (!task.cancel_requested) { select.click(); return; }
            try {
                const status = await api(s3Base(task.id), {cache: 'no-store'});
                if (status.state === (task.selected ? 'cancelled' : 'aborted') || task.selected && status.state === 'deleted') await forgetS3Task(task.id);
                else if (status.state === 'published') { await forgetS3Task(task.id); await renderTree(); }
                else label.textContent = `${task.name} · 清理仍在核验，预留配额尚未释放`;
            } catch (_) { label.textContent = `${task.name} · 暂时无法核对清理状态，请稍后重试`; }
        };
        select.onchange = async () => {
            if (uploadRunning || !select.files?.[0]) return;
            const original = select.files[0]; select.value = '';
            uploadInterrupted = false; setUploadControlsDisabled(true);
            try {
                if (original.size !== task.originalSize) throw new Error('文件大小不一致，未恢复上传');
                label.textContent = `${task.name} · 正在逐块校验原文件`;
                const hashes = await s3FileHashes(original);
                if (hashes.length !== task.hashes.length || hashes.some((hash, i) => hash !== task.hashes[i]))
                    throw new Error('文件内容不一致，未恢复上传');
                const outgoing = task.cipherName
                    ? await window.FrontierMediaCrypto.readRetainedUpload(task.cipherName) : original;
                await uploadS3Parts({upload_id: task.id, selected: task.selected}, outgoing, fraction => {
                    label.textContent = `${task.name} · ${Math.floor(fraction * 100)}%`;
                });
                await forgetS3Task(task.id); await renderTree();
            } catch (error) { label.textContent = `${task.name} · ${error.message}`; }
            finally { setUploadControlsDisabled(false); }
        };
        const cancel = document.createElement('button'); cancel.type = 'button'; cancel.textContent = '取消并清理';
        cancel.disabled = Boolean(task.cancel_requested);
        cancel.onclick = async () => {
            cancel.disabled = true;
            try {
                await api(s3Base(task.id), {method: 'DELETE', headers: requestHeaders(false)});
                // A 202 is pending, never proof that provider bytes are gone.
                await saveS3Tasks({cancel: task.id});
            } catch (_) { label.textContent = `${task.name} · 清理请求未确认，请稍后重试`; cancel.disabled = false; }
        };
        row.append(label, resume, cancel, select); section.append(row);
    }
}
async function cancelClusterReservation(reservation) {
    if (!reservation?.upload_id) return;
    await api(reservation.transport === 'S3' ? s3Base(reservation.upload_id) : `/api/v1/media/admin/upload/session/${reservation.upload_id}`, {
        method: 'DELETE', headers: requestHeaders(false),
    }).catch(() => {});
}

// Two bounded parts at most; progress advances only after provider observation
// has been verified and durably confirmed by the Master.
async function uploadS3Parts(reservation, file, onProgress, precomputedHashes = null) {
    if (!Number.isSafeInteger(file.size) || file.size < 1 || file.size > 10 * 1024 ** 3)
        throw new Error('S3 单个对象必须在 1 B 至 10 GiB 之间');
    const base = s3Base(reservation.upload_id);
    let state = await api(base, {cache: 'no-store'});
    const stopIfDeleted = async status => {
        if (reservation.selected && status?.state === 'deleted') {
            await forgetS3Task(reservation.upload_id);
            throw new Error('该上传已被管理员删除');
        }
    };
    await stopIfDeleted(state);
    if (Number(state.reservation?.expected_bytes) !== file.size)
        throw new Error('恢复文件长度不一致');
    const finalize = async () => {
        const result = await s3Post(`${base}/finalize`);
        await stopIfDeleted(result);
        if (reservation.selected && result?.state !== 'published') throw new Error('发布状态未确认，请稍后恢复核验');
        onProgress(1);
        return result;
    };
    if (state.state === 'published') {
        if (!reservation.selected) return s3Post(`${base}/finalize`);
        onProgress(1);
        return state;
    }
    if (reservation.selected && state.state === 'completing') return finalize();
    const startable = reservation.selected ? ['reserved', 'creating', 'create_unknown'] : ['reserved', 'create_rejected'];
    if (startable.includes(state.state)) {
        state = await s3Post(`${base}/begin`);
        await stopIfDeleted(state);
    }
    if (state.state !== 'created') throw new Error('上传正在核验或清理中，请保留恢复信息并稍后检查');
    const known = new Map();
    for (const part of state.parts || []) {
        if (!Number.isInteger(part.number) || part.number < 1 || part.number > Math.ceil(file.size / S3_PART_BYTES)
            || known.has(part.number)) throw new Error('服务端分块记录无效');
        known.set(part.number, part);
    }
    // Verify every existing intent before issuing another bearer. A matching
    // filename or size never authorizes reusing an upload for different bytes.
    const hashes = precomputedHashes || await s3FileHashes(file);
    for (const [number, part] of known) {
        const size = Math.min(S3_PART_BYTES, file.size - (number - 1) * S3_PART_BYTES);
        if (part.checksum_sha256 !== hashes[number - 1] || part.size_bytes !== size)
            throw new Error('恢复文件与已记录分块不一致');
    }
    const confirmed = new Set([...known].filter(([, part]) => part.confirmed).map(([number]) => number));
    const progress = () => onProgress(Math.min(0.98, [...confirmed].reduce((sum, number) =>
        sum + Math.min(S3_PART_BYTES, file.size - (number - 1) * S3_PART_BYTES), 0) / file.size));
    progress();
    let next = 1, failure = null;
    const worker = async () => {
        while (!failure && next <= hashes.length) {
            const number = next++;
            if (confirmed.has(number)) continue;
            if (uploadInterrupted) throw new Error('上传已暂停，可重新选择原文件恢复');
            const offset = (number - 1) * S3_PART_BYTES;
            const bytes = new Uint8Array(await file.slice(offset, Math.min(file.size, offset + S3_PART_BYTES)).arrayBuffer());
            try {
                let sent = false;
                for (let attempt = 0; attempt < 2 && !sent; attempt += 1) {
                    const grant = await s3Post(`${base}/parts/${number}/grant`, {size_bytes: bytes.byteLength, checksum_sha256: hashes[number - 1]});
                    const target = new URL(grant.url);
                    if (target.protocol !== 'https:' || target.username || target.password || target.hash || target.href.length > 16384)
                        throw new Error('S3 上传地址无效');
                    if (!Number.isSafeInteger(grant.expires_at) || grant.expires_at <= 0)
                        throw new Error('S3 上传授权期限无效');
                    const signed = {};
                    if (Object.keys(grant.headers || {}).length > 8) throw new Error('S3 上传请求头无效');
                    for (const [name, value] of Object.entries(grant.headers || {})) {
                        if (name.toLowerCase() === 'content-length') {
                            if (String(value) !== String(bytes.byteLength)) throw new Error('S3 分块长度不一致');
                            continue; // Browser-owned header.
                        }
                        if (!/^(content-type|x-amz-checksum-sha256|x-amz-content-sha256|x-amz-sdk-checksum-algorithm)$/i.test(name)
                            || typeof value !== 'string' || value.length > 2048 || /[\r\n]/.test(value)) throw new Error('S3 上传请求头无效');
                        signed[name] = value;
                    }
                    const checksumHeader = Object.entries(signed).find(([name]) => name.toLowerCase() === 'x-amz-checksum-sha256');
                    if (checksumHeader?.[1] !== hashes[number - 1]) throw new Error('S3 分块校验授权不一致');
                    const controller = new AbortController(); s3Transfers.add(controller);
                    const timer = setTimeout(() => controller.abort(), 120000);
                    let status;
                    try {
                        const response = await fetch(target.href, {method: 'PUT', headers: signed, body: bytes,
                            credentials: 'omit', mode: 'cors', redirect: 'error', referrerPolicy: 'no-referrer',
                            cache: 'no-store', signal: controller.signal});
                        status = response.status;
                        await response.body?.cancel().catch(() => {});
                    } catch (_) { throw new Error('S3 连接中断、超时或跨域规则不匹配，可恢复上传'); }
                    finally { clearTimeout(timer); s3Transfers.delete(controller); }
                    if (status >= 200 && status < 300) sent = true;
                    else if (attempt || ![401, 403].includes(status)) throw new Error(`S3 分块上传失败（${status}）`);
                }
                const receipt = await s3Post(`${base}/parts/${number}/confirm`);
                const proof = receipt.parts?.find(part => part.number === number);
                if (!proof?.confirmed || proof.size_bytes !== bytes.byteLength || proof.checksum_sha256 !== hashes[number - 1])
                    throw new Error('S3 分块确认不一致');
                confirmed.add(number); progress();
            } finally { bytes.fill(0); }
        }
    };
    // Await both workers even after one fails; no request outlives this task.
    const outcomes = await Promise.allSettled([worker().catch(error => { failure = error; throw error; }), worker().catch(error => { failure = error; throw error; })]);
    if (failure) throw failure;
    if (outcomes.some(outcome => outcome.status === 'rejected') || confirmed.size !== hashes.length || uploadInterrupted)
        throw new Error('上传已暂停，可恢复上传');
    await s3Post(`${base}/touch`);
    return finalize();
}
renderS3Tasks();

const selectedUploadBase = '/api/v1/media/admin/upload/selected';

function selectedUploadPost(route, body) {
    return api(route, {method: 'POST', headers: requestHeaders(), body: JSON.stringify(body || {})});
}

function selectedTicketURL(ticket, id, member, action) {
    if (ticket?.upload_id !== id || ticket.member_id !== member || !['Direct', 'Relay', 'Local'].includes(ticket.transport))
        throw new Error('上传凭证与所选节点不一致');
    const direct = ticket.transport === 'Direct';
    const raw = action === 'recover' ? ticket.recovery_url : ticket.upload_url;
    if (typeof raw !== 'string' || !raw) throw new Error('上传地址不可用');
    const url = new URL(raw, window.location.origin);
    const expected = direct ? '/api/v1/node/selected-upload' + (action === 'bytes' ? '' : '/' + action)
        : `${selectedUploadBase}/${id}/${action}`;
    if (url.username || url.password || url.search || url.hash || url.pathname !== expected
        || (direct ? url.protocol !== 'https:' || typeof ticket.capability !== 'string'
            || !ticket.capability || ticket.capability.length > 4096
            : url.origin !== window.location.origin || ticket.capability))
        throw new Error('上传地址无效');
    return {url, direct};
}

async function sendSelectedBytes(ticket, id, member, action, file) {
    const {url, direct} = selectedTicketURL(ticket, id, member, action);
    const headers = direct ? {'X-Fc-Selected-Upload': ticket.capability} : requestHeaders(false);
    if (file) headers['Content-Type'] = 'application/octet-stream';
    const controller = new AbortController();
    activeUploadRequests.add(controller);
    try {
        const response = await fetch(url, {method: file ? 'PUT' : 'POST', headers, body: file,
            signal: controller.signal, redirect: 'error', credentials: direct ? 'omit' : 'same-origin',
            cache: 'no-store', referrerPolicy: 'no-referrer'});
        if (!response.ok) throw new Error('所选存储节点暂不可用');
        const result = await response.json();
        if (!result?.receipt || typeof result.signature !== 'string' || !result.signature)
            throw new Error('无法确认上传状态');
        return result;
    } finally { activeUploadRequests.delete(controller); }
}

async function publishSelectedUpload(encrypted, file, {folder, destination, id, displayName}, onProgress) {
    const check = () => {
        if (uploadInterrupted) throw new Error('上传已中断');
    };
    const selectedS3 = destination.site_type === 's3';
    const partHashes = [];
    const digest = await uploadSHA256(encrypted.file, check, selectedS3 ? hash => partHashes.push(hash) : null);
    const filename = file.name;
    const member = destination.member_id;
    if (selectedS3) {
        await retainS3Task(id, file, encrypted, displayName, true);
        if (uploadInterrupted) await forgetS3Task(id); // This invocation has not sent prepare yet.
    }
    check();
    const route = `${selectedUploadBase}/${id}`;
    const ticket = await selectedUploadPost(`${selectedUploadBase}/prepare`, {
        upload_id: id, storage_member_id: member, parent_path: folder, filename,
        cipher_sha256: digest, encryption: encrypted.encryption, preparation_token: encrypted.preparation_token,
        ...(selectedS3 ? {s3_part_sha256: partHashes} : {}),
    });
    if (selectedS3) {
        if (ticket?.upload_id !== id || ticket.member_id !== member || ticket.transport !== 'S3')
            throw new Error('上传凭证与所选节点不一致');
        await uploadS3Parts({upload_id: id, selected: true}, encrypted.file, onProgress, partHashes);
        await forgetS3Task(id);
        return {path: `${folder}/${filename}`};
    }
    selectedTicketURL(ticket, id, member, 'bytes');
    let signed;
    try {
        check();
        try {
            signed = await sendSelectedBytes(ticket, id, member, 'bytes', encrypted.file);
        } catch (error) {
            check();
            const retry = await selectedUploadPost(`${route}/resume`);
            signed = await sendSelectedBytes(retry, id, member, 'recover');
        }
    } catch (error) {
        if (window.navigator?.onLine === false) throw new Error('网络中断，上传状态未确认');
        try {
            const cleanup = await selectedUploadPost(`${route}/cancel`);
            const receipt = await sendSelectedBytes(cleanup, id, member, 'cleanup');
            await selectedUploadPost(`${route}/cancel/finish`, receipt);
        } catch (_) { throw new Error('上传状态未确认，请刷新目录后检查'); }
        throw error;
    }
    try {
        await selectedUploadPost(`${route}/complete`, signed);
    } catch (error) {
        const status = await api(`${route}/status`, {cache: 'no-store'});
        if (status.state === 'pending' && status.receipt && status.signature) {
            try {
                await selectedUploadPost(`${route}/complete`, {receipt: status.receipt, signature: status.signature});
            } catch (retryError) {
                const latest = await api(`${route}/status`, {cache: 'no-store'});
                if (latest.state !== 'completed') throw retryError;
            }
        } else if (status.state !== 'completed') {
            throw error;
        }
    }
    onProgress(1);
    return {path: `${folder}/${filename}`};
}

async function runUploadTask(fileList, relativePaths = null, lyricUpload = false) {
    if (uploadRunning) return;
    const files = [...fileList];
    if (!files.length) return;
    if (files.length > uploadLimits.max_upload_task_files) {
        alert(`一次上传任务最多选择 ${uploadLimits.max_upload_task_files} 个文件`);
        return;
    }
    const selectedDestination = uploadDestinations.get(uploadSiteType.value);
    const selectedSiteType = selectedDestination?.site_type;
    const selectedProtocol = selectedUploadProtocol;
    if (selectedProtocol === null) {
        alert('上传方式尚未确认，请稍后重试');
        return;
    }
    if (selectedProtocol && lyricUpload && (!selectedDestination?.writable || selectedSiteType !== 'primary')) {
        alert('请选择主站作为歌词的目标存储节点');
        updateMediaUploadGate();
        return;
    }
    if (!lyricUpload && !selectedDestination?.writable) {
        alert('请先选择具体的目标存储节点');
        updateMediaUploadGate();
        return;
    }
    if (!lyricUpload && !relativePaths && !currentPath) {
        alert('上传文件前请先进入 data/media/music 或 data/media/vido 下的分类目录');
        return;
    }

    if (window.navigator?.onLine === false) {
        alert('当前网络已离线，请连接网络后重新选择文件');
        return;
    }
    uploadInterrupted = false;
    setUploadControlsDisabled(true);
    $('uploadProgress').classList.remove('hidden');
    $('uploadResults').innerHTML = '';
    $('uploadTaskTitle').textContent = lyricUpload ? '歌词上传任务' : (relativePaths ? '文件夹上传任务' : '多文件上传任务');
    setProgress('currentProgress', 'currentPercent', 0);
    setProgress('totalProgress', 'totalPercent', 0);

    const totalUnits = files.reduce((sum, file) => sum + Math.max(file.size, 1), 0);
    let completedUnits = 0;
    let successCount = 0;
    let failedCount = 0;
    const reservationOutcomes = new Map();
    const heldReservations = new Set();

    const prepareReservation = (index, encrypted) => {
        if (!clusterUpload || lyricUpload || index >= files.length) return null;
        if (reservationOutcomes.has(index)) return reservationOutcomes.get(index);
        const file = files[index];
        if (file.size > uploadLimits.max_upload_file_size) return null;
        const outcome = api('/api/v1/media/admin/upload/session', {
            method: 'POST', headers: requestHeaders(), body: JSON.stringify({
                storage_member_id: selectedDestination.member_id,
                site_type: selectedSiteType,
                target_dir: currentPath,
                relative_path: relativePaths ? relativePaths[index] : null,
                filename: file.name,
                size_bytes: encrypted.file.size,
                storage_mode: 'encrypted',
                encryption: encrypted.encryption,
                preparation_token: encrypted.preparation_token,
            }),
        }).then(reservation => {
            heldReservations.add(reservation);
            if (reservation.member_id !== selectedDestination.member_id) {
                return {reservation, error: new Error('服务器返回的上传目标与所选节点不一致，已停止上传')};
            }
            return {reservation};
        }, error => ({error}));
        reservationOutcomes.set(index, outcome);
        return outcome;
    };

    const takeReservation = async (index, encrypted) => {
        const outcome = await prepareReservation(index, encrypted);
        if (!outcome) return null;
        if (outcome.error) throw outcome.error;
        heldReservations.delete(outcome.reservation);
        return outcome.reservation;
    };

    try {
        for (let index = 0; index < files.length; index += 1) {
            if (uploadInterrupted) break;
            const file = files[index];
            const displayName = relativePaths ? relativePaths[index] : file.name;
            const fileUnits = Math.max(file.size, 1);
            $('currentFileLabel').textContent = `当前：${displayName}`;
            $('totalTaskLabel').textContent = `任务总进度 ${index + 1}/${files.length}`;
            $('uploadSummary').textContent = `成功 ${successCount}，失败 ${failedCount}`;
            setProgress('currentProgress', 'currentPercent', 0);

            const fileLimit = lyricUpload ? uploadLimits.max_lyric_file_size : uploadLimits.max_upload_file_size;
            if (file.size > fileLimit) {
                failedCount += 1;
                completedUnits += fileUnits;
                addUploadResult(displayName, 'error', `超过 ${formatSize(fileLimit)} 限制`);
                setProgress('totalProgress', 'totalPercent', completedUnits / totalUnits * 100);
                continue;
            }

            let reservation = null;
            let encrypted = null;
            let selectedUploadID = null;
            try {
                const progress = fraction => {
                    setProgress('currentProgress', 'currentPercent', fraction * 100);
                    setProgress(
                        'totalProgress',
                        'totalPercent',
                        (completedUnits + fileUnits * fraction) / totalUnits * 100,
                    );
                };
                if (!window.FrontierMediaCrypto) throw new Error('上传组件未加载，请刷新页面后重试');
                encrypted = await window.FrontierMediaCrypto.encryptUploadFile(file, fraction => progress(fraction * 0.25));
                const outgoingFile = encrypted.file;
                if (uploadInterrupted) throw new Error('上传已中断，请重新选择文件重试');
                const transferProgress = fraction => progress(0.25 + fraction * 0.75);
                let result;
                if (selectedProtocol) {
                    const relativeFolder = relativePaths ? relativePaths[index].split('/').slice(0, -1).join('/') : '';
                    const folder = [lyricUpload ? 'lyrics' : currentPath, relativeFolder].filter(Boolean).join('/');
                    selectedUploadID = crypto.randomUUID().replaceAll('-', '');
                    result = await publishSelectedUpload(encrypted, file, {
                        folder, destination: selectedDestination, id: selectedUploadID, displayName,
                    }, transferProgress);
                } else if (clusterUpload && !lyricUpload) {
                    reservation = await takeReservation(index, encrypted);
                    try {
                        if (uploadInterrupted) throw new Error('上传已中断，请重新选择文件重试');
                        if (reservation.transport === 'S3') {
                            await retainS3Task(reservation.upload_id, file, encrypted, displayName);
                            result = await uploadS3Parts(reservation, outgoingFile, transferProgress);
                            await forgetS3Task(reservation.upload_id);
                        } else {
                            await uploadRaw(reservation.upload_url, outgoingFile, transferProgress, reservation.transport === 'Direct');
                            result = reservation.transport === 'Direct'
                            ? await api(`/api/v1/media/admin/upload/session/${reservation.upload_id}/finalize`, {
                                method: 'POST', headers: requestHeaders(), body: '{}',
                            })
                            : {path: reservation.path};
                        }
                    } catch (error) {
                        if (reservation.transport !== 'S3') await cancelClusterReservation(reservation);
                        else if (!s3Tasks.has(reservation.upload_id)) await cancelClusterReservation(reservation);
                        throw error;
                    }
                } else {
                    const formData = new FormData();
                    if (!lyricUpload) {
                        formData.append('target_dir', currentPath);
                        formData.append('site_type', selectedSiteType);
                        formData.append('storage_member_id', selectedDestination.member_id);
                    }
                    if (relativePaths) formData.append('relative_path', relativePaths[index]);
                    formData.append('storage_mode', 'encrypted');
                    formData.append('encryption', JSON.stringify(encrypted.encryption));
                    formData.append('preparation_token', encrypted.preparation_token);
                    formData.append('file', outgoingFile, file.name);
                    result = await uploadOne(formData, transferProgress,
                        lyricUpload ? '/api/v1/media/admin/upload/lyric' : '/api/v1/media/admin/upload/item');
                }
                successCount += 1;
                const siteType = lyricUpload ? null : (reservation?.site_type || result?.site_type || selectedSiteType);
                const placementDetail = siteType ? `${result.path} · ${uploadSiteLabels[siteType]}` : result.path;
                addUploadResult(displayName, 'ok', placementDetail);
            } catch (error) {
                failedCount += 1;
                addUploadResult(displayName, 'error', error.message);
            } finally {
                const recovery = s3Tasks.get(selectedUploadID || reservation?.upload_id);
                if (!recovery || recovery.cipherName !== encrypted?.retainedName) await encrypted?.cleanup();
            }

            completedUnits += fileUnits;
            // A failed object never presents a successful 100% publication.
            if (successCount + failedCount === index + 1 && failedCount === 0)
                setProgress('currentProgress', 'currentPercent', 100);
            setProgress('totalProgress', 'totalPercent', completedUnits / totalUnits * 100);
        }
    } finally {
        for (const outcomePromise of reservationOutcomes.values()) {
            const outcome = await outcomePromise;
            if (outcome.reservation && heldReservations.has(outcome.reservation)) {
                heldReservations.delete(outcome.reservation);
                await cancelClusterReservation(outcome.reservation);
            }
        }
        setUploadControlsDisabled(false);
        $('uploadSummary').textContent = uploadInterrupted
            ? `已中断：成功 ${successCount}，失败 ${failedCount}，未上传 ${files.length - successCount - failedCount}`
            : `完成：成功 ${successCount}，失败 ${failedCount}`;
        $('currentFileLabel').textContent = '当前文件处理完成';
        await renderTree().catch(() => {});
        if (lyricUpload) await loadLyricCatalog().catch(() => {});
    }
}

$('download').onclick = async () => {
    const paths = [...selected];
    if (!paths.length) return;
    try {
        if (sealedMediaDownload === null || !sealedMediaDownload && selectedUploadProtocol !== false) {
            throw new Error('下载方式尚未确认，请刷新管理台后重试');
        }
        if (sealedMediaDownload) {
            const targets = paths.map(path => ({path, resource_id: selectedItemResourceIDs.get(path), kind: selectedItemKinds.get(path)}));
            if (targets.some(target => !target.resource_id)) throw new Error('请选择有资源标识的文件或子目录');
            const plan = await api('/api/v1/media/admin/download/plan', {
                method: 'POST', headers: requestHeaders(), body: JSON.stringify({targets}), cache: 'no-store',
            });
            await window.FrontierMediaCrypto.downloadPlan(plan.items, plan.force_zip === true);
            return;
        }
        const plan = await api(`/api/v1/media/admin/download/plan?paths=${encodeURIComponent(JSON.stringify(paths))}`, {cache: 'no-store'});
        if (plan.items?.some(item => item.encryption || item.encrypted || item.transport === 'S3')) {
            await window.FrontierMediaCrypto.downloadPlan(plan.items);
            return;
        }
        const anchor = document.createElement('a');
        anchor.href = `/api/v1/media/admin/download?paths=${encodeURIComponent(JSON.stringify(paths))}`;
        anchor.download = paths.length === 1 ? paths[0].split('/').pop() : 'media-download.zip';
        anchor.click();
    } catch (error) { alert(error.message); }
};

updateMediaUploadGate();
refreshUploadSiteTypes().catch(() => updateMediaUploadGate());
