import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';


class ClassList {
    constructor() { this.values = new Set(); }
    add(value) { this.values.add(value); }
    remove(value) { this.values.delete(value); }
    toggle(value, force) {
        if (force === undefined ? !this.values.has(value) : force) this.values.add(value);
        else this.values.delete(value);
    }
    contains(value) { return this.values.has(value); }
}


function makeElement() {
    const element = {
        children: [],
        classList: new ClassList(),
        dataset: {},
        disabled: false,
        value: 0,
        textContent: '',
        scrollHeight: 0,
        scrollTop: 0,
        clientHeight: 100,
        appendChild(child) {
            this.children.push(child);
            this.scrollHeight = this.children.length * 20;
        },
        append(...children) { children.forEach(child => this.appendChild(child)); },
        setAttribute(name, value) { this[name] = String(value); },
        querySelectorAll() { return []; },
    };
    let html = '';
    Object.defineProperty(element, 'innerHTML', {
        get() { return html; },
        set(value) { html = value; if (value === '') this.children = []; },
    });
    return element;
}


const elements = new Map();
const documentListeners = new Map();
const fetchCalls = [];
const element = id => {
    if (!elements.has(id)) elements.set(id, makeElement());
    return elements.get(id);
};

class TestFormData {
    constructor() { this.values = []; }
    append(name, value, filename = undefined) { this.values.push({name, value, filename}); }
}

const context = {
    document: {
        cookie: 'admin_csrf=test-csrf',
        hidden: false,
        getElementById: element,
        createElement: makeElement,
        querySelectorAll: () => [],
        addEventListener: (name, callback) => documentListeners.set(name, callback),
    },
    location: {href: '', protocol: 'http:'},
    alert: message => { throw new Error(`Unexpected alert: ${message}`); },
    fetch: async (url, options = {}) => {
        fetchCalls.push({url: String(url), options});
        return ({
        status: 200,
        ok: true,
        json: async () => {
            if (String(url).includes('/status')) {
                return {
                    status: 'ok',
                    csrf_cookie_name: 'admin_csrf',
                    limits: {max_upload_file_size: 1000, max_upload_task_files: 10},
                };
            }
            if (String(url).includes('/tree')) return {path: '', items: []};
            return {};
        },
        blob: async () => new Blob(),
    });
    },
    FormData: TestFormData,
    URL,
    URLSearchParams,
    AbortController,
    Blob,
    XMLHttpRequest: class {
        constructor() { this.upload = {}; this.listeners = new Map(); }
        open() {}
        setRequestHeader() {}
        addEventListener(name, callback) { this.listeners.set(name, callback); }
        send() {}
        abort() { this.onabort?.(); this.listeners.get('loadend')?.(); }
    },
    window: {addEventListener(name, callback) { documentListeners.set(`window:${name}`, callback); }},
    setInterval: () => 1,
    clearInterval: () => {},
    console,
};
vm.createContext(context);
vm.runInContext(fs.readFileSync('static/js/admin.js', 'utf8'), context);
vm.runInContext('const renderAdminTree = renderTree;', context);
await new Promise(resolve => setTimeout(resolve, 0));

for (const [expression, event] of [
    ['uploadOne(new FormData(), () => {})', 'pagehide'],
    ["uploadRaw('/upload', new Blob(['partial']), () => {})", 'offline'],
]) {
    const pending = vm.runInContext(expression, context);
    assert.equal(vm.runInContext('activeUploadRequests.size', context), 1);
    documentListeners.get(`window:${event}`)();
    await assert.rejects(pending, /上传已取消/);
    assert.equal(vm.runInContext('activeUploadRequests.size', context), 0);
}

await vm.runInContext(`
    adminLastActivityAt = Date.now() - ADMIN_ACTIVITY_GRACE_MS - 1;
    api('/passive-probe');
`, context);
const passiveProbe = fetchCalls.find(call => call.url === '/passive-probe');
assert.equal(passiveProbe.options.headers['X-Admin-Activity'], 'passive');

documentListeners.get('pointerdown')({isTrusted: true});
await vm.runInContext(`api('/active-probe')`, context);
const activeProbe = fetchCalls.find(call => call.url === '/active-probe');
assert.equal(activeProbe.options.headers['X-Admin-Activity'], 'active');

const formatted = vm.runInContext(
    `formatErrorDetail([{loc: ['body', 'files'], msg: 'Field required'}])`,
    context,
);
assert.equal(formatted, 'body.files: Field required');
assert(!formatted.includes('[object Object]'));

vm.runInContext(`
    selected.clear();
    selectionKind = null;
    let selectionRenderCalls = 0;
    renderTree = async () => { selectionRenderCalls += 1; };
    toggleSelection({name: 'one.wav', path: 'folder/one.wav', kind: 'file'});
    globalThis.selectionRenderCalls = selectionRenderCalls;
    globalThis.selectedAfterClick = selected.has('folder/one.wav');
`, context);
assert.equal(context.selectionRenderCalls, 0);
assert.equal(context.selectedAfterClick, true);

vm.runInContext(`
    const selectionItems = [
        {name: 'one.wav', path: 'folder/one.wav', kind: 'file'},
        {name: 'album', path: 'folder/album', kind: 'directory'},
        {name: 'three.wav', path: 'folder/three.wav', kind: 'file'},
    ];
    visibleMediaItems = selectionItems;
    clearMediaSelection();
    toggleSelection(selectionItems[0], {});
    toggleSelection(selectionItems[1], {ctrlKey: true});
    globalThis.ctrlSelection = [...selected];
    globalThis.ctrlSelectionKind = selectionKind;
    toggleSelection(selectionItems[2], {});
    globalThis.plainSelection = [...selected];
    toggleSelection(selectionItems[0], {});
    toggleSelection(selectionItems[2], {shiftKey: true});
    globalThis.shiftSelection = [...selected];
`, context);
assert.deepEqual([...context.ctrlSelection], ['folder/one.wav', 'folder/album']);
assert.equal(context.ctrlSelectionKind, 'mixed');
assert.deepEqual([...context.plainSelection], ['folder/three.wav']);
assert.deepEqual(
    [...context.shiftSelection],
    ['folder/one.wav', 'folder/album', 'folder/three.wav'],
);

vm.runInContext(`
    renderSecurityList({
        legal_api_count: 21,
        active_ban_count: 1,
        threshold: 5,
        ban_seconds: 86400,
        events: [{
            ip: '203.0.113.9', trigger_count: 6, status: 'active', active: true,
            whitelisted: false, banned_at: '2026-08-15T00:00:00',
            expires_at: '2026-08-16T00:00:00', last_method: 'GET', last_path: '/etc/passwd',
        }],
        whitelist: [{ip: '198.51.100.4', created_at: '2026-08-15T00:00:00', note: 'office'}],
    });
`, context);
assert.equal(element('legalApiCount').textContent, '21');
assert.equal(element('activeBanCount').textContent, '1');
assert.equal(element('banList').children.length, 1);
assert.equal(element('whitelistList').children.length, 1);

const adminHtml = fs.readFileSync('static/media/admin.html', 'utf8');
assert(adminHtml.includes('id="currentProgress"'));
assert(adminHtml.includes('id="totalProgress"'));
assert(!adminHtml.includes('Artplayer'));
assert(!adminHtml.includes('id="move"'));
assert(adminHtml.includes('id="mediaSearch"'));
assert(adminHtml.includes('id="securityPanel"'));
assert(adminHtml.includes('id="banList"'));
assert(adminHtml.includes('{{ADMIN_CSS_URL}}'));
assert(adminHtml.includes('{{ADMIN_JS_URL}}'));
assert(adminHtml.includes('{{NODES_JS_URL}}'));
assert(adminHtml.includes('id="randomKey"'));
assert(adminHtml.includes('id="temporaryKeyForm"'));
assert(adminHtml.includes('id="permanentBanForm"'));
assert(adminHtml.match(/class="module-heading"/g).length === 12);
assert(adminHtml.includes('data-admin-module="migrations"'));
assert(adminHtml.includes('data-admin-module="priority"'));
assert(adminHtml.includes('媒体资源排序策略'));
assert(adminHtml.includes('目录与媒体条目的排序优先级'));
assert(!adminHtml.includes('媒体展示优先级'));
assert(adminHtml.includes('id="priorityList"'));
assert(adminHtml.includes('id="priorityPath"'));
assert(adminHtml.includes('id="priorityUp"'));
assert(!adminHtml.includes('施工中'));
assert(adminHtml.includes('data-admin-module="nodes"'));
assert(!adminHtml.includes('id="nodeTestPlayer"'));
assert(!adminHtml.includes('id="nodeBusinessTest"'));
assert(adminHtml.includes('id="lyricsPanel"'));
assert(adminHtml.includes('id="lyricsTrackPath"'));
assert(adminHtml.includes('id="lyricsFilePath"'));
assert(adminHtml.indexOf('id="lyricsFileList"') < adminHtml.indexOf('id="lyricsTrackList"'));
assert(adminHtml.includes('id="lyricsTrackUsage"'));
assert(adminHtml.includes('id="lyricsFileUsage"'));
assert(adminHtml.includes('id="lyricsRelationJson"'));
assert(!adminHtml.includes('id="lyricsEnterLink"'));
assert(!adminHtml.includes('id="lyricsGraph"'));
assert(adminHtml.includes('id="networkPanel"'));
assert(adminHtml.includes('id="networkPublicIp"'));
assert(adminHtml.includes('id="networkWebrtcIp"'));
assert(adminHtml.includes('id="networkMatchMode"'));
assert(adminHtml.includes('id="securityMatchMode"'));
assert(adminHtml.includes('id="networkExpandAll"'));
assert(adminHtml.includes('id="networkCollapseAll"'));
assert(adminHtml.includes('data-network-view="public"'));
assert(adminHtml.includes('data-network-view="webrtc"'));
assert(!adminHtml.includes('data-network-view="pairs"'));
assert(adminHtml.includes('id="uploadLyrics"'));
assert(adminHtml.includes('id="globalAdminActions"'));
assert(!adminHtml.includes('logOutput'));
assert(!adminHtml.includes('securityToggle'));

const adminJs = fs.readFileSync('static/js/admin.js', 'utf8');
const directoryAdminJs = fs.readFileSync('static/js/directory-admin.js', 'utf8');
const nodesJs = fs.readFileSync('static/js/nodes.js', 'utf8');
new vm.Script(directoryAdminJs, {filename: 'static/js/directory-admin.js'});
assert(!adminJs.includes('response.blob()'));
assert(!adminJs.includes('/api/v1/media/admin/download?'), 'the base script never installs a legacy download handler');
assert(!adminJs.includes('function runUploadTask'), 'the upload script owns the upload handler');
assert(!adminJs.includes('attachGlobalActions'));
assert(adminJs.includes("let networkView = 'public'"));
assert(adminJs.includes("api('/api/v1/media/admin/media-priority'"));
assert(adminJs.includes('function renderMediaPriority(data)'));
assert(adminJs.includes('function priorityDirectoryButton(directory)'));
assert(adminJs.includes("params.set('path', priorityScope)"));
assert(adminJs.includes('type="range"'));
assert(adminJs.includes('排序优先级'));
assert(!adminJs.includes('展示优先级'));
assert(adminJs.includes('slider.onchange = async'));
assert(adminJs.includes('value}),'));
assert(!adminJs.includes('delta}'));
assert(adminJs.includes("event.key === 'Escape'"));
assert(adminJs.includes('button.ondblclick = async'));
assert(adminJs.includes("replace(/\\.lrc$/i, '')"));
assert(adminJs.includes("$('lyricsTrackUsage').value = 'unused'"));
assert.deepEqual(
    [...vm.runInContext(`unlinkedLyricTracks([
        {path: 'music/a.mp3', lyric_path: null},
        {path: 'music/b.mp3', lyric_path: 'lyrics/b.lrc'},
        {path: 'music/c.mp3'},
    ]).map(track => track.path)`, context)],
    ['music/a.mp3', 'music/c.mp3'],
);
assert(adminJs.includes('lyricTargets = new Set(unlinkedTracks.map(track => track.path))'));
assert(adminJs.includes('function middleEllipsis'));
assert(adminJs.includes('结果按所在目录分类'));
assert(adminJs.includes('N=${relationCount}'));
assert(adminJs.includes("params.set('match_mode'"));
assert(directoryAdminJs.includes('文件夹优先级'));
assert(directoryAdminJs.includes("/api/v1/media/admin/directory-priority"));
assert(directoryAdminJs.includes("/api/v1/media/admin/directory/rename"));
assert(directoryAdminJs.includes("renameButton.textContent = '改名'"));
assert(directoryAdminJs.includes('priorityDirectoryButton = directoryPriorityRow'));
assert(directoryAdminJs.includes('loadMediaPriority = async function loadMediaPriorityWithDirectories'));
assert(nodesJs.includes('/resources'));
assert(nodesJs.includes('Storage'));
assert(nodesJs.includes('Backup'));
assert(nodesJs.includes('物理 used / all'));
assert(nodesJs.includes('已使用 / 已分配'));
assert(!nodesJs.includes('物理总容量'));
assert(!nodesJs.includes('当前物理'));
assert(!nodesJs.includes('当前项目资源占用'));
assert(!nodesJs.includes('Compute'));
assert(!nodesJs.includes('worker_slots'));
assert(!nodesJs.includes('compute_enabled'));
assert(adminHtml.includes('aria-label="集群节点"'));
assert(nodesJs.includes("failed: 'Failed'"));
assert(!nodesJs.includes('nodeTest'));

assert(adminJs.includes('async function refreshStoragePool()'));
assert(adminJs.includes('storagePoolTimer = setInterval'));
assert(adminJs.includes("'X-Admin-Activity'"));
assert(adminJs.includes("? 'active'"));
assert(adminJs.includes(": 'passive'"));
assert(!adminHtml.includes('storage-capacity-refresh.js'));

const adminCss = fs.readFileSync('static/css/admin.css', 'utf8');
const directoryAdminCss = fs.readFileSync('static/css/directory-admin.css', 'utf8');
assert(adminCss.includes('.admin-side[data-admin-module="media"] { order: -2; }'));
assert(adminCss.includes('.priority-panel { order: -1;'));
assert(!adminCss.includes('#nodeTestPlayer'));
assert.match(adminCss, /\.admin-module\.expanded\s*\{[^}]*flex:\s*1 1 0;/s);
assert.match(adminCss, /\.admin-module > \.module-heading\s*\{[^}]*flex:\s*0 0 56px;/s);
assert.match(adminCss, /\.admin-module\.expanded > \.module-content,[\s\S]*?flex:\s*1 1 0;/s);
assert.match(adminCss, /\.media-content\s*\{[^}]*flex:\s*1 1 0;/s);
assert.match(adminCss, /\.admin-side\.expanded > header \+ \.media-content\s*\{[^}]*display:\s*flex;/s);
assert(!adminCss.includes('.media-content { height: 0;'));
assert.match(adminCss, /\.tree\s*\{[^}]*min-height:\s*80px;/s);
assert(!adminCss.includes('.tree {\n    height: 0;'));
assert.match(adminCss, /\.tree\s*\{[^}]*overflow-y:\s*scroll;/s);
assert.match(adminCss, /\.key-panel\.expanded\s*\{[^}]*flex:\s*0 0 108px;/s);
assert.match(adminCss, /\.key-panel\.expanded\s*\{[^}]*min-height:\s*108px;/s);
assert.match(adminCss, /\.key-panel\.expanded > \.module-heading\s*\{[^}]*width:\s*100%;/s);
assert.match(adminCss, /\.network-list\s*\{[^}]*overflow-y:\s*scroll;/s);
assert.match(adminCss, /\.priority-list\s*\{[^}]*overflow-y:\s*scroll;/s);
assert(adminCss.includes('.priority-directory'));
assert(adminCss.includes('.priority-pathbar'));
assert(adminCss.includes('.priority-control'));
assert(adminCss.includes('.lyrics-relation-json'));
assert(adminCss.includes('.filename-toggle'));
assert(directoryAdminCss.includes('.priority-directory-row'));
assert(directoryAdminCss.includes('.priority-directory-control'));

await vm.runInContext(`(async () => {
    globalThis.lyricRequests = [];
    const lyric = 'lyrics/artist/song.lrc';
    const unusedLyric = 'lyrics/artist/unused.lrc';
    const a = 'music/artist/a.mp3', b = 'music/artist/b.mp3', c = 'music/artist/c.mp3';
    let usageKnown = true;
    api = async (url, options = {}) => {
        lyricRequests.push({url, options});
        if (options.method === 'POST') return {status: 'ok', relations: 2};
        const next = String(url).includes('track_cursor=page-two');
        const usage = String(url).match(/lyric_usage=(used|unused)/)?.[1];
        if (next && lyricRequests.some(call => call.options.method === 'POST')) throw new Error('stale cursor');
        return {
            sealed_scope: 'directory', counts_scope: 'subtree', lyric_usage_filter: usageKnown,
            lyric_usage_scope: usageKnown ? 'track_subtree' : '',
            scopes: {track: 'music/artist', lyric: 'lyrics/artist'},
            counts: {tracks: next ? 1 : 2, lyrics: 1, relations: next ? 0 : 1},
            truncated: {track: !next, lyric: false}, next: {track: next ? '' : 'page-two', lyric: ''},
            track_directories: [], lyric_directories: [], relations: [],
            tracks: next ? [{path: c, name: 'c', lyric_path: null}] : [
                {path: a, name: 'a', lyric_path: lyric}, {path: b, name: 'b', lyric_path: null},
            ],
            lyrics: [
                {path: lyric, name: 'song', lyric_id: 'lyric', linked_count: usageKnown ? 1 : null},
                {path: unusedLyric, name: 'unused', lyric_id: 'unused', linked_count: usageKnown ? 0 : null},
            ].filter(item => !usageKnown || !usage || (usage === 'used') === (item.linked_count > 0)),
        };
    };
    lyricScopes = {track: 'music/artist', lyric: 'lyrics/artist'};
    lyricOrigin = null;
    resetLyricPage('track'); resetLyricPage('lyric');
    $('lyricsTrackUsage').value = 'all'; $('lyricsFileUsage').value = 'all';
    $('lyricsTrackFilter').value = ''; $('lyricsFileFilter').value = '';
    await loadLyricCatalog();
    const fileRows = id => $(id).children.filter(child => child.className === 'lyrics-object');
    globalThis.lyricFirstEnabled = !fileRows('lyricsFileList')[0].disabled;
    globalThis.trackInitiallyDisabled = fileRows('lyricsTrackList')[0].disabled;
    fileRows('lyricsFileList')[0].onclick({detail: 1});
    fileRows('lyricsTrackList')[0].onclick({detail: 1});
    fileRows('lyricsTrackList')[1].onclick({detail: 1});
    await $('lyricsTrackList').children.find(child => child.textContent === '下一页').onclick();
    fileRows('lyricsTrackList')[0].onclick({detail: 1});
    await $('lyricsSaveLink').onclick();
    $('lyricsFileUsage').value = 'used';
    await $('lyricsFileUsage').onchange();
    globalThis.usedLyrics = fileRows('lyricsFileList').map(row => row.innerHTML);
    $('lyricsFileUsage').value = 'unused';
    await $('lyricsFileUsage').onchange();
    globalThis.unusedLyrics = fileRows('lyricsFileList').map(row => row.innerHTML);
    usageKnown = false;
    await loadLyricCatalog();
    globalThis.unknownLyricUsage = {disabled: $('lyricsFileUsage').disabled, value: $('lyricsFileUsage').value,
        items: fileRows('lyricsFileList').map(row => row.innerHTML)};
    usageKnown = true;
    await loadLyricCatalog();
})()`, context);
assert.equal(context.lyricFirstEnabled, true);
assert.equal(context.trackInitiallyDisabled, true);
const lyricPost = context.lyricRequests.find(call => call.options.method === 'POST');
assert.deepEqual(JSON.parse(lyricPost.options.body), {
    origin_kind: 'lyric', origin_path: 'lyrics/artist/song.lrc',
    linked_paths: ['music/artist/b.mp3', 'music/artist/c.mp3'], unlinked_paths: ['music/artist/a.mp3'],
});
assert.equal(element('lyricsAutoLink').disabled, false);
assert.equal(element('lyricsFileUsage').disabled, false);
assert.equal(element('lyricsTrackFilter').placeholder, '搜索当前目录及其子目录');
assert.equal(context.usedLyrics.length, 1);
assert.match(context.usedLyrics[0], /song\.lrc.*1 首/);
assert.equal(context.unusedLyrics.length, 1);
assert.match(context.unusedLyrics[0], /unused\.lrc.*0 首/);
assert.equal(context.unknownLyricUsage.disabled, true);
assert.equal(context.unknownLyricUsage.value, 'all');
assert.equal(context.unknownLyricUsage.items.length, 2);
assert(context.unknownLyricUsage.items.every(row => row.includes('关联数未知')));
assert(context.lyricRequests.some(call => String(call.url).includes('lyric_usage=used')));
assert(element('lyricsTrackList').children.some(child => child.textContent === '下一页'));
assert.match(element('lyricsModeStatus').textContent, /^已保存/);
assert(context.lyricRequests.some(call => String(call.url).includes('track_cursor=page-two')));

await vm.runInContext(`(async () => {
    const catalog = await api('/fixture');
    const oldScope = {track: 'music/stale', lyric: 'lyrics/stale'};
    const result = {linked: 2, preserved: 1, unmatched: 3, ambiguous: 0};
    const button = $('lyricsAutoLink');
    let finishMutation, finishRead, delayNextRead = false, failNextRead = false;
    globalThis.autoLinkCalls = [];
    api = async (url, options = {}) => {
        autoLinkCalls.push({url: String(url), method: options.method, body: options.body, signal: options.signal, disabled: button.disabled});
        if (options.method === 'POST') return new Promise(resolve => { finishMutation = resolve; });
        if (failNextRead) {
            failNextRead = false;
            throw new Error('catalog unavailable');
        }
        if (delayNextRead) {
            delayNextRead = false;
            return new Promise(resolve => { finishRead = resolve; });
        }
        return catalog;
    };
    $('lyricsTrackFilter').value = 'search only';
    lyricEdits.set(catalog.tracks[1].path, true);
    await button.onclick();
    globalThis.autoLinkDraft = {size: lyricEdits.size, message: $('lyricsModeStatus').textContent};
    lyricEdits.clear();
    delayNextRead = true;
    const busy = loadLyricCatalog();
    await button.onclick();
    globalThis.autoLinkReadWasBusy = button.disabled;
    finishRead(catalog);
    await busy;

    lyricCursors = {track: 'stale-track', lyric: 'stale-lyric'};
    lyricCursorHistory = {track: ['previous-track'], lyric: ['previous-lyric']};
    const operation = button.onclick();
    await button.onclick();
    delayNextRead = true;
    const stale = loadLyricCatalog();
    const staleSignal = autoLinkCalls.at(-1).signal;
    finishMutation(result);
    await operation;
    globalThis.obsoleteLyricReadAborted = staleSignal.aborted;
    finishRead({...catalog, scopes: oldScope});
    await stale;
    globalThis.autoLinkRefreshed = {
        scopes: {...lyricScopes}, cursors: {...lyricCursors},
        history: [lyricCursorHistory.track.length, lyricCursorHistory.lyric.length],
        message: $('lyricsModeStatus').textContent,
    };
    const afterRefreshFailure = button.onclick();
    failNextRead = true;
    finishMutation(result);
    await afterRefreshFailure;
    globalThis.autoLinkRefreshFailure = $('lyricsModeStatus').textContent;

    lyricCatalog = {...catalog, sealed_scope: undefined};
    clearLyricSelection();
    const legacy = button.onclick();
    finishMutation(result);
    await legacy;
})()`, context);
assert.deepEqual({...context.autoLinkDraft}, {size: 1, message: '请先保存或退出当前编辑，再执行同名关联'});
assert.equal(context.autoLinkReadWasBusy, true);
assert.equal(context.obsoleteLyricReadAborted, true);
const autoPosts = context.autoLinkCalls.filter(call => call.method === 'POST');
assert.equal(autoPosts.length, 3, 'a draft, a pending read and a duplicate click must not start additional mutations');
for (const post of autoPosts) {
    assert.equal(post.url, '/api/v1/media/admin/lyrics/auto-relate');
    assert.equal(post.disabled, true);
}
assert.deepEqual(JSON.parse(autoPosts[0].body), {manual: true, track_path: 'music/artist', lyric_path: 'lyrics/artist'});
assert.deepEqual(JSON.parse(autoPosts[2].body), {manual: true});
const autoRefresh = context.autoLinkCalls[context.autoLinkCalls.indexOf(autoPosts[0]) + 2];
const autoRefreshParams = new URL(autoRefresh.url, 'https://example.test').searchParams;
assert.equal(autoRefreshParams.get('track_q'), 'search only');
assert.equal(autoRefreshParams.has('track_cursor'), false);
assert.equal(autoRefreshParams.has('lyric_cursor'), false);
assert.equal(autoRefresh.disabled, true);
assert.deepEqual({...context.autoLinkRefreshed.scopes}, {track: 'music/artist', lyric: 'lyrics/artist'});
assert.deepEqual({...context.autoLinkRefreshed.cursors}, {track: '', lyric: ''});
assert.deepEqual([...context.autoLinkRefreshed.history], [0, 0]);
assert.match(context.autoLinkRefreshed.message, /完成：关联 2，保留 1/);
assert.match(context.autoLinkRefreshFailure, /完成：关联 2.*刷新失败/);
assert.equal(element('lyricsAutoLink').disabled, false);

await vm.runInContext(`(async () => {
    const leaf = await api('/fixture');
    api = async () => ({
        ...leaf,
        counts_scope: 'page', lyric_usage_filter: false,
        scopes: {track: 'music', lyric: 'lyrics'},
        counts: {tracks: 0, lyrics: 0, relations: 0},
        track_directories: [{path: 'music/artist', name: 'artist', count: null}],
        lyric_directories: [{path: 'lyrics/artist', name: 'artist', count: null}],
        tracks: [], lyrics: [],
    });
    $('lyricsTrackFilter').value = '';
    await loadLyricCatalog();
})()`, context);
assert.equal(element('lyricsTrackCount').textContent, '本页 1 个目录');
assert.equal(element('lyricsFileCount').textContent, '本页 1 个目录');
assert.equal(element('lyricsRelationCount').textContent, '进入曲目目录查看');

const lyricCountContext = vm.createContext({
    lyricDirectoryButton: () => ({lastElementChild: {textContent: '进入'}}),
});
vm.runInContext(fs.readFileSync('static/js/lyrics-directory-counts.js', 'utf8'), lyricCountContext);
assert.equal(vm.runInContext("lyricDirectoryButton({count: null}, 'lyric').lastElementChild.textContent", lyricCountContext), '进入');
assert.equal(vm.runInContext("lyricDirectoryButton({count: 0}, 'lyric').lastElementChild.textContent", lyricCountContext), '0 份歌词 · 进入');
assert.equal(vm.runInContext("lyricDirectoryButton({count: 3}, 'track').lastElementChild.textContent", lyricCountContext), '3 首曲目 · 进入');

await vm.runInContext(`(async () => {
    const previousAPI = api, previousRender = renderTree;
    globalThis.visibilitySmoke = [];
    try {
        let pending;
        api = async (url, options) => {
            pending = {url, body: options.body, blocked: $('modalOk').disabled};
            return {existing_grants: 'expire_normally'};
        };
        for (const hidden of [true, false]) {
            clearMediaSelection();
            selected.add('music/category');
            selectedItemKinds.set('music/category', 'directory');
            selectionKind = 'directory';
            $('hide').disabled = false;
            $('hide').textContent = hidden ? '隐藏' : '恢复';
            renderTree = async () => {
                if (!hidden) throw new Error('fixture refresh unavailable');
            };
            $('hide').onclick();
            const prompt = $('modalBody').textContent;
            await $('modalOk').onclick();
            visibilitySmoke.push({...pending, prompt, status: $('selection').textContent,
                selection: selected.size, unlocked: !$('modalOk').disabled});
        }
    } finally {
        api = previousAPI;
        renderTree = previousRender;
    }
})()`, context);
for (const [index, hidden] of [true, false].entries()) {
    const result = context.visibilitySmoke[index];
    assert.equal(result.url, '/api/v1/media/admin/hide');
    assert.deepEqual(JSON.parse(result.body), {paths: ['music/category'], hidden});
    assert.equal(result.blocked, true);
    assert.equal(result.unlocked, true);
    assert.equal(result.selection, 0);
}
assert.match(context.visibilitySmoke[0].prompt, /默认列表隐藏.*已知地址和隐藏入口仍可播放/);
assert.match(context.visibilitySmoke[0].status, /目录已隐藏/);
assert.match(context.visibilitySmoke[1].prompt, /上级目录的隐藏仍然有效/);
assert.match(context.visibilitySmoke[1].status, /隐藏设置已恢复.*刷新失败/);

await vm.runInContext(`(async () => {
    const previousAPI = api, previousRender = renderTree;
    const path = 'music/artist/song.mp3', original = 'a'.repeat(64), replacement = 'b'.repeat(64), operation = 'c'.repeat(32);
    globalThis.deleteSmoke = {calls: []};
    try {
        sealedMediaDelete = true;
        mediaDeleteAvailable = true;
        renderTree = async () => {};
        clearMediaSelection();
        selectMediaItem({kind: 'directory', path: 'music/artist', media_id: original});
        updateToolbar();
        deleteSmoke.directoryEnabled = !$('delete').disabled;
        deleteSmoke.directoryTarget = selectedMediaDeleteTargets.get('music/artist');
        clearMediaSelection();
        selectMediaItem({kind: 'directory', path: 'music'});
        updateToolbar();
        deleteSmoke.rootBlocked = $('delete').disabled;
        clearMediaSelection();
        selectMediaItem({kind: 'file', path, media_id: original});
        updateToolbar();
        let pendingOnServer = false;
        api = async (url, options) => {
            if (url.includes('/admin/tree')) {
                return {items: pendingOnServer ? [
                    {kind: 'file', name: 'song.mp3', path, media_id: original, mutation_state: 'pending_delete', mutation_operation: operation},
                    {kind: 'directory', name: 'old', path: 'music/artist/old', mutation_state: 'rename_pending', rename_target: 'music/artist/new'},
                    {kind: 'file', name: 'invalid.mp3', path: 'music/artist/invalid.mp3', media_id: replacement, mutation_state: 'pending_delete', mutation_operation: 'invalid'},
                ] : []};
            }
            const body = JSON.parse(options.body);
            deleteSmoke.calls.push({url, body, busy: $('modalOk').disabled});
            if (!body.targets) return {deleted: 1};
            const state = deleteSmoke.calls.length === 1 ? 'pending' : 'deleted';
            pendingOnServer = state === 'pending';
            return {items: [{...body.targets[0], operation_id: operation, state}]};
        };
        $('delete').onclick();
        await $('modalOk').onclick();
        deleteSmoke.pending = $('deleteStatus').textContent;
        deleteSmoke.retryEnabled = !$('retryDelete').disabled;
        pendingMediaDeletes.clear();
        $('mediaSearch').value = '';
        currentPath = 'music/artist';
        renderTree = renderAdminTree;
        await renderTree();
        deleteSmoke.refreshed = [...pendingMediaDeletes.values()];
        deleteSmoke.refreshRetryEnabled = !$('retryDelete').disabled;
        deleteSmoke.pendingRow = $('tree').children.find(row => row.dataset.path === path).innerHTML;
        deleteSmoke.renameRow = $('tree').children.find(row => row.dataset.path === 'music/artist/old').innerHTML;
        selectMediaItem({kind: 'file', path, media_id: replacement});
        updateToolbar();
        $('retryDelete').onclick();
        await $('modalOk').onclick();
        deleteSmoke.completed = $('deleteStatus').textContent;
        deleteSmoke.retryHidden = $('retryDelete').classList.contains('hidden');
        const deleteAPI = api;
        api = async () => { throw Object.assign(new Error('response lost'), {status: 503}); };
        try {
            await sendSealedMediaDelete([{path, resource_id: replacement}]);
        } catch (error) {
            deleteSmoke.unknown = {message: error.message, status: $('deleteStatus').textContent, retryDisabled: $('retryDelete').disabled};
        }
        api = deleteAPI;
        sealedMediaDelete = false;
        clearMediaSelection();
        selectMediaItem({kind: 'directory', path: 'music/artist'});
        updateToolbar();
        $('delete').onclick();
        await $('modalOk').onclick();
    } finally {
        api = previousAPI;
        renderTree = previousRender;
    }
})()`, context);
const deletes = JSON.parse(JSON.stringify(context.deleteSmoke));
assert.equal(deletes.directoryEnabled, true);
assert.deepEqual(deletes.directoryTarget, {path: 'music/artist', resource_id: 'a'.repeat(64), directory: true});
assert.equal(deletes.rootBlocked, true);
assert.equal(deletes.calls.length, 3);
assert.deepEqual(deletes.calls[0], {url: '/api/v1/media/admin/delete', busy: true,
    body: {targets: [{path: 'music/artist/song.mp3', resource_id: 'a'.repeat(64)}]}});
assert.match(deletes.pending, /1 项删除待完成/);
assert.doesNotMatch(deletes.pending, /已完成/);
assert.equal(deletes.retryEnabled, true);
assert.deepEqual(deletes.refreshed, [{path: 'music/artist/song.mp3', resource_id: 'a'.repeat(64), operation_id: 'c'.repeat(32)}]);
assert.equal(deletes.refreshRetryEnabled, true);
assert.match(deletes.pendingRow, /删除待完成/);
assert.doesNotMatch(deletes.pendingRow, /改名恢复中/);
assert.match(deletes.renameRow, /改名恢复中/);
assert.deepEqual(deletes.calls[1].body, {targets: [{path: 'music/artist/song.mp3', resource_id: 'a'.repeat(64), operation_id: 'c'.repeat(32)}]});
assert.match(deletes.completed, /删除已完成 1 项/);
assert.equal(deletes.retryHidden, true);
assert.equal(deletes.unknown.message, 'response lost');
assert.match(deletes.unknown.status, /刷新列表核对/);
assert.equal(deletes.unknown.retryDisabled, true);
assert.deepEqual(deletes.calls[2].body, {paths: ['music/artist']});

console.log('admin-ui-smoke-ok');

await import('./admin_media_address_smoke.mjs');
