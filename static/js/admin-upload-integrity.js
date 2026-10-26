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
    selector.setAttribute('aria-label', '上传站点类型');
    selector.innerHTML = '<option value="" selected>请选择上传站点类型</option>';
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
const mediaSiteTypes = new Map();
const mediaEncryptionStates = new Map();
const mediaStorageAddresses = new Map();

function chooseUploadStorageMode(inputId) {
    const input = $(inputId);
    delete input.dataset.storageMode;
    const dialog = document.createElement('dialog');
    dialog.className = 'upload-storage-mode-dialog';
    const title = document.createElement('h3');
    title.textContent = '本次上传如何落盘';
    const explanation = document.createElement('p');
    explanation.textContent = '每次选择文件或文件夹都需要重新选择。加密由当前浏览器完成，加密失败会停止上传。';
    const actions = document.createElement('div');
    for (const [mode, label] of [['encrypted', '加密落盘'], ['plain', '明文落盘']]) {
        const button = document.createElement('button');
        button.type = 'button';
        button.textContent = label;
        button.addEventListener('click', () => {
            input.dataset.storageMode = mode;
            dialog.close();
            dialog.remove();
            input.click();
        });
        actions.append(button);
    }
    const cancel = document.createElement('button');
    cancel.type = 'button';
    cancel.textContent = '取消';
    cancel.addEventListener('click', () => { dialog.close(); dialog.remove(); });
    dialog.addEventListener('cancel', () => { delete input.dataset.storageMode; dialog.remove(); });
    dialog.append(title, explanation, actions, cancel);
    document.body.append(dialog);
    dialog.showModal();
}

for (const [buttonId, inputId, folder, lyric] of [
    ['uploadFiles', 'fileInput', false, false],
    ['uploadFolder', 'folderInput', true, false],
    ['uploadLyrics', 'lyricsInput', false, true],
    ['uploadLyricsFolder', 'lyricsFolderInput', true, true],
]) {
    $(buttonId).onclick = () => chooseUploadStorageMode(inputId);
    $(inputId).onchange = async event => {
        const mode = event.target.dataset.storageMode;
        delete event.target.dataset.storageMode;
        const files = [...event.target.files].filter(file => !lyric || file.name.toLowerCase().endsWith('.lrc'));
        const paths = folder ? files.map(file => file.webkitRelativePath || file.name) : null;
        try { await runUploadTask(files, paths, lyric, mode); }
        finally { event.target.value = ''; }
    };
    $(inputId).addEventListener('cancel', () => { delete $(inputId).dataset.storageMode; });
}

function siteTypeFromItem(item) {
    if (item?.site_type && uploadSiteLabels[item.site_type]) return item.site_type;
    if (item?.transport === 'Direct') return 'direct';
    if (item?.transport === 'Relay') return 'relay';
    if (item?.transport === 'S3' || item?.member_kind === 'S3') return 's3';
    return 'primary';
}

function mediaStorageAddress(item) {
    const value = item.storage_address || (item.storage_address_local === true ? window.location.origin : '');
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

function countReadySiteTypes(pool) {
    if (pool?.standalone) return {primary: 1, direct: 0, relay: 0, s3: 0};
    const counts = {primary: 0, direct: 0, relay: 0, s3: 0};
    for (const member of pool?.members || []) {
        if (!readyMember(member) || member.member_kind === 'Auto') continue;
        if (member.member_kind === 'MasterLocal') counts.primary += 1;
        else if (member.transport === 'Direct') counts.direct += 1;
        else if (member.transport === 'Relay') counts.relay += 1;
        else if (member.transport === 'S3' || member.member_kind === 'S3') counts.s3 += 1;
    }
    return counts;
}

function updateMediaUploadGate() {
    const blocked = uploadRunning || !uploadSiteType?.value;
    $('uploadFiles').disabled = blocked;
    $('uploadFolder').disabled = blocked;
    if (uploadSiteType) uploadSiteType.disabled = uploadRunning;
}

async function refreshUploadSiteTypes() {
    const pool = await api('/api/v1/media/admin/storage-pool', {cache: 'no-store'});
    clusterUpload = !pool.standalone;
    const previous = uploadSiteType.value;
    const counts = countReadySiteTypes(pool);
    uploadSiteType.replaceChildren();

    const empty = document.createElement('option');
    empty.value = '';
    empty.textContent = '请选择上传站点类型';
    uploadSiteType.append(empty);

    for (const value of ['primary', 'direct', 'relay', 's3']) {
        const option = document.createElement('option');
        option.value = value;
        option.disabled = counts[value] <= 0;
        option.textContent = counts[value] > 0
            ? `${uploadSiteLabels[value]} · ${counts[value]} ready`
            : `${uploadSiteLabels[value]} · 暂无 ready 站点`;
        uploadSiteType.append(option);
    }
    const previousOption = [...uploadSiteType.options]
        .find(option => option.value === previous && !option.disabled);
    uploadSiteType.value = previousOption ? previous : '';
    updateMediaUploadGate();
    return pool;
}

const originalSetUploadControlsDisabled = setUploadControlsDisabled;
setUploadControlsDisabled = function setUploadControlsDisabledWithSiteType(disabled) {
    originalSetUploadControlsDisabled(disabled);
    updateMediaUploadGate();
};

uploadSiteType.onchange = updateMediaUploadGate;
refreshStoragePool = refreshUploadSiteTypes;

const originalApi = api;
api = async function apiWithPlacementObservation(url, options = {}) {
    const data = await originalApi(url, options);
    if (String(url).startsWith('/api/v1/media/admin/tree') && Array.isArray(data?.items)) {
        mediaSiteTypes.clear();
        mediaEncryptionStates.clear();
        mediaStorageAddresses.clear();
        for (const item of data.items) {
            if (item.kind === 'file') {
                mediaEncryptionStates.set(item.path, Boolean(item.encryption || item.encrypted));
                mediaStorageAddresses.set(item.path, mediaStorageAddress(item));
            }
            const root = String(item.path || '').split('/', 1)[0];
            if (item.kind === 'file' && (root === 'music' || root === 'vido')) {
                mediaSiteTypes.set(item.path, siteTypeFromItem(item));
            }
        }
    }
    return data;
};

function decorateMediaSiteBadges() {
    for (const row of document.querySelectorAll('.tree-row[data-path]')) {
        row.querySelector('.media-site-badge')?.remove();
        row.querySelector('.media-encryption-badge')?.remove();
        row.querySelector('.media-node-address')?.remove();
        if (mediaStorageAddresses.has(row.dataset.path)) {
            const address = mediaStorageAddresses.get(row.dataset.path);
            const nodeAddress = document.createElement('small');
            nodeAddress.className = 'media-node-address';
            nodeAddress.textContent = address ? address.slice(address.indexOf('://') + 3) : '地址不可用';
            nodeAddress.title = address || '节点地址不可用';
            nodeAddress.setAttribute('aria-label', `节点地址：${address || '不可用'}`);
            row.append(nodeAddress);
        }
        if (mediaEncryptionStates.has(row.dataset.path)) {
            const encrypted = mediaEncryptionStates.get(row.dataset.path);
            const encryptionBadge = document.createElement('span');
            encryptionBadge.className = 'media-encryption-badge';
            encryptionBadge.textContent = encrypted ? '加密落盘' : '明文落盘';
            row.append(encryptionBadge);
        }
        const siteType = mediaSiteTypes.get(row.dataset.path);
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
            && (task.cancel_requested === undefined || typeof task.cancel_requested === 'boolean'))
            || tasks.has(task.id)) throw new Error('恢复信息无效');
        tasks.set(task.id, {id: task.id, name: task.name, originalSize: task.originalSize, hashes: task.hashes,
            ...(task.cipherName ? {cipherName: task.cipherName} : {}),
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
                if (status.state === 'aborted') await forgetS3Task(task.id);
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
                await uploadS3Parts({upload_id: task.id, transport: 'S3'}, outgoing, fraction => {
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
async function uploadS3Parts(reservation, file, onProgress) {
    if (!Number.isSafeInteger(file.size) || file.size < 1 || file.size > 10 * 1024 ** 3)
        throw new Error('S3 单个对象必须在 1 B 至 10 GiB 之间');
    const base = s3Base(reservation.upload_id);
    let state = await api(base, {cache: 'no-store'});
    if (Number(state.reservation?.expected_bytes) !== file.size)
        throw new Error('恢复文件长度不一致');
    if (state.state === 'published') return s3Post(`${base}/finalize`);
    if (['reserved', 'create_rejected'].includes(state.state)) state = await s3Post(`${base}/begin`);
    if (state.state !== 'created') throw new Error('上传正在核验或清理中，请保留恢复信息并稍后检查');
    const known = new Map();
    for (const part of state.parts || []) {
        if (!Number.isInteger(part.number) || part.number < 1 || part.number > Math.ceil(file.size / S3_PART_BYTES)
            || known.has(part.number)) throw new Error('服务端分块记录无效');
        known.set(part.number, part);
    }
    // Verify every existing intent before issuing another bearer. A matching
    // filename or size never authorizes reusing an upload for different bytes.
    const hashes = await s3FileHashes(file);
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
    const result = await s3Post(`${base}/finalize`); onProgress(1); return result;
}
renderS3Tasks();

runUploadTask = async function runUploadTaskWithReservationCleanup(fileList, relativePaths = null, lyricUpload = false, storageMode = null) {
    if (uploadRunning) return;
    const files = [...fileList];
    if (!files.length) return;
    if (!['encrypted', 'plain'].includes(storageMode)) {
        alert('本次选择必须明确选择加密落盘或明文落盘');
        return;
    }
    if (files.length > uploadLimits.max_upload_task_files) {
        alert(`一次上传任务最多选择 ${uploadLimits.max_upload_task_files} 个文件`);
        return;
    }
    const selectedSiteType = uploadSiteType.value;
    if (!lyricUpload && !selectedSiteType) {
        alert('请先选择上传站点类型');
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

    const prepareReservation = (index, encrypted = null) => {
        if (!clusterUpload || lyricUpload || index >= files.length) return null;
        if (reservationOutcomes.has(index)) return reservationOutcomes.get(index);
        const file = files[index];
        // Preparing ciphertext first avoids occupying a storage member while
        // browser-side encryption is running or has already failed.
        if (storageMode === 'encrypted' && !encrypted) return null;
        if (file.size > uploadLimits.max_upload_file_size) return null;
        const outcome = api('/api/v1/media/admin/upload/session', {
            method: 'POST', headers: requestHeaders(), body: JSON.stringify({
                site_type: selectedSiteType,
                target_dir: currentPath,
                relative_path: relativePaths ? relativePaths[index] : null,
                filename: file.name,
                size_bytes: encrypted ? encrypted.file.size : file.size,
                storage_mode: storageMode,
                ...(encrypted ? {encryption: encrypted.encryption, preparation_token: encrypted.preparation_token} : {}),
            }),
        }).then(reservation => {
            heldReservations.add(reservation);
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
            try {
                const progress = fraction => {
                    setProgress('currentProgress', 'currentPercent', fraction * 100);
                    setProgress(
                        'totalProgress',
                        'totalPercent',
                        (completedUnits + fileUnits * fraction) / totalUnits * 100,
                    );
                };
                if (storageMode === 'encrypted') {
                    if (!window.FrontierMediaCrypto) throw new Error('浏览器加密组件未加载');
                    $('currentFileLabel').textContent = `浏览器加密：${displayName}`;
                    encrypted = await window.FrontierMediaCrypto.encryptUploadFile(file, fraction => progress(fraction * 0.25));
                    $('currentFileLabel').textContent = `密文上传：${displayName}`;
                }
                const outgoingFile = encrypted?.file || file;
                if (uploadInterrupted) throw new Error('上传已中断，请重新选择文件重试');
                const transferProgress = fraction => progress(encrypted ? 0.25 + fraction * 0.75 : fraction);
                let result;
                if (clusterUpload && !lyricUpload) {
                    reservation = await takeReservation(index, encrypted);
                    try {
                        if (uploadInterrupted) throw new Error('上传已中断，请重新选择文件重试');
                        if (reservation.transport === 'S3') {
                            if (encrypted && (!encrypted.retainedName || typeof encrypted.retain !== 'function'))
                                throw new Error('浏览器加密恢复组件需要更新，请刷新页面后重试');
                            const hashes = await s3FileHashes(file);
                            const task = {id: reservation.upload_id, name: displayName.slice(0, 512), originalSize: file.size, hashes,
                                ...(encrypted ? {cipherName: encrypted.retainedName} : {})};
                            await saveS3Tasks({put: task});
                            if (encrypted) encrypted.retain();
                            result = await uploadS3Parts(reservation, outgoingFile, transferProgress);
                            await forgetS3Task(task.id);
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
                    }
                    if (relativePaths) formData.append('relative_path', relativePaths[index]);
                    formData.append('storage_mode', storageMode);
                    if (encrypted) {
                        formData.append('encryption', JSON.stringify(encrypted.encryption));
                        formData.append('preparation_token', encrypted.preparation_token);
                    }
                    formData.append('file', outgoingFile, file.name);
                    result = await uploadOne(formData, transferProgress,
                        lyricUpload ? '/api/v1/media/admin/upload/lyric' : '/api/v1/media/admin/upload/item');
                }
                successCount += 1;
                const siteType = lyricUpload ? null : (reservation?.site_type || result?.site_type || selectedSiteType);
                const placementDetail = siteType ? `${result.path} · ${uploadSiteLabels[siteType]}` : result.path;
                const detail = `${placementDetail} · ${storageMode === 'encrypted' ? '加密落盘' : '明文落盘'}`;
                addUploadResult(displayName, 'ok', detail);
            } catch (error) {
                failedCount += 1;
                addUploadResult(displayName, 'error', error.message);
            } finally { if (!reservation || !s3Tasks.has(reservation.upload_id)) await encrypted?.cleanup(); }

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
};

$('download').onclick = async () => {
    const paths = [...selected];
    try {
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

$('delete').onclick = () => {
    const paths = [...selected];
    const objectLabel = selectionKind === 'directory'
        ? '目录及其全部内容'
        : (selectionKind === 'file' ? '文件' : '对象');
    showModal(
        '确认删除',
        `将删除选中的 ${paths.length} 个${objectLabel}。此操作不可恢复。`,
        async () => {
            const result = await api('/api/v1/media/admin/delete', {
                method: 'POST', headers: requestHeaders(), body: JSON.stringify({paths}),
            });
            clearMediaSelection();
            await renderTree();
            if (result.pending_delete?.length) {
                alert(`已有 ${result.deleted || 0} 个对象完成删除；仍有 ${result.pending_delete.length} 个对象等待存储节点确认删除。\n\n等待中的路径暂时不会允许同名重传，系统会自动重试。`);
            }
        },
    );
};

updateMediaUploadGate();
refreshUploadSiteTypes().catch(() => updateMediaUploadGate());
