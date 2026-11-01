import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync('static/js/player.js', 'utf8');
const flush = () => new Promise(setImmediate);
function playerContext(fetchImpl) {
    let clock = 10000;
    const requests = [], revoked = [], objects = [];
    const elements = new Map();
    const elementFor = id => {
        if (!elements.has(id)) elements.set(id, {
            id,
            textContent: '',
            style: {setProperty(name, value) { this[name] = value; }},
            classList: {add() {}, remove() {}, toggle() {}, contains(value) { return value === 'hidden'; }},
            clientHeight: 400,
            clientWidth: 500,
            children: [],
            replaceChildren(...children) { this.children = children; },
            appendChild(child) { this.children.push(child); },
            setAttribute() {},
            removeAttribute() {},
        });
        return elements.get(id);
    };
    const context = vm.createContext({
        window: {addEventListener() {}}, navigator: {},
        document: {
            getElementById: id => elementFor(id),
            createElement: () => ({className: '', textContent: '', style: {}, offsetHeight: 100, children: [], appendChild(child) { this.children.push(child); }}),
            querySelector: () => null,
            querySelectorAll: () => [],
        },
        performance: {now: () => clock}, AbortController, Blob, setTimeout, clearTimeout,
        URL: {
            createObjectURL(blob) { objects.push(blob); return `blob:track-${objects.length}`; },
            revokeObjectURL(url) { revoked.push(url); },
        },
        currentMediaList: ['a', 'b', 'c'].map(id => ({media_id: id, type: 'audio', url: `/${id}`, cover: '', play_score: 0})),
        fetch: async (url, options) => { requests.push({url, options}); return fetchImpl(url, options); },
    });
    vm.runInContext(source, context);
    vm.runInContext("art = {duration: 100, currentTime: 5, playing: false, url: '/a', play: async () => {}, notice: {}}", context);
    return {context, elements, requests, revoked, objects, advance: n => {clock += n;}, run: code => vm.runInContext(code, context)};
}

{
    const p = playerContext(async () => new Response(new Uint8Array([1, 2, 3]), {headers: {'Content-Type': 'audio/wav'}}));
    p.run('checkAndPreloadNext(5)');
    await flush();
    assert.equal(p.run('nextPreload.status'), 'ready');
    assert.equal(p.objects[0].size, 3);
    assert.equal(p.requests[0].options.headers, undefined);
    p.run('currentMediaList[2].preference = 7; playNext()');
    await flush();
    assert.equal(p.run('art.url'), 'blob:track-1');
    assert.equal(p.run('currentIndex'), 1);
    assert.equal(p.requests.length, 1);
    p.run('playNext()');
    assert.equal(p.run('art.url'), '/c');
    assert.deepEqual(p.revoked, ['blob:track-1']);
}

for (const failure of ['network', 'status', 'truncated']) {
    let attempts = 0;
    const p = playerContext(async () => {
        if (attempts++ === 0) {
            if (failure === 'network') throw new Error('offline');
            if (failure === 'status') return new Response('failure', {status: 500});
            return new Response(new ReadableStream({start(controller) {controller.error(new Error('body failed'));}}));
        }
        return new Response('complete');
    });
    p.run('checkAndPreloadNext(5)');
    await flush();
    assert.equal(p.run('nextPreload.status'), 'failed');
    p.run('checkAndPreloadNext(6)');
    assert.equal(p.requests.length, 1);
    p.advance(4000);
    p.run('checkAndPreloadNext(10)');
    await flush();
    assert.equal(p.run('nextPreload.status'), 'ready');
    assert.equal(p.requests.length, 2);
}

{
    let release;
    const pending = new Promise(resolve => {release = resolve;});
    const p = playerContext(async () => pending);
    p.run('checkAndPreloadNext(5); playNext()');
    assert.equal(p.run('art.url'), '/b');
    assert.equal(p.requests[0].options.signal.aborted, true);
    release(new Response('late data'));
    await flush();
    assert.equal(p.objects.length, 0);
}

{
    const p = playerContext(async () => new Response('large', {headers: {'Content-Length': String(129 * 1024 * 1024)}}));
    p.run('checkAndPreloadNext(5)');
    await flush();
    assert.equal(p.run('nextPreload.status'), 'skipped');
    assert.equal(p.requests[0].options.signal.aborted, true);
    p.advance(60000);
    p.run('checkAndPreloadNext(65)');
    assert.equal(p.requests.length, 1);
}

{
    let respond;
    const p = playerContext(() => new Promise(resolve => {respond = resolve;}));
    p.context.playbackSessionId = 'session';
    p.run("resetPlaybackAccounting(currentMediaList[0]); playbackState.accumulated=30; reportValidPlayback()");
    p.run('resetPlaybackAccounting(currentMediaList[1])');
    respond(new Response(JSON.stringify({play_score: 1})));
    await flush();
    assert.equal(p.run('playbackState.reported'), false);
    assert.equal(p.run('currentMediaList[0].play_score'), 1);
}

{
    const p = playerContext(async () => new Response('unused'));
    p.run("showSynchronizedLyrics([{time:1,text:'one'},{time:2,text:'two'},{time:3,text:'three'},{time:4,text:'four'}], 2.5)");
    const track = p.elements.get('inlineLyricsTrack');
    assert.deepEqual(track.children.slice(0, 4).map(row => row.textContent), ['one', 'two', 'three', 'four']);
    assert.equal(track.children[1].className, 'sync-lyric current');
    p.run('updateSynchronizedLyrics(3.1)');
    assert.equal(track.style.transform, 'translateY(-100px)', 'slide uses the actual departing row height so wrapped lines are not cut');
    assert.equal(track.children[2].className, 'sync-lyric current');
}

{
    const p = playerContext(async () => new Response('unused'));
    let reloads = 0, resumes = 0, restore;
    p.context.reloadsRef = () => { reloads += 1; };
    p.context.resumesRef = () => { resumes += 1; };
    p.context.restoreRef = listener => { restore = listener; };
    p.run(`
        art = {
            e: {}, notice: {}, loading: {}, mask: {}, controls: {}, url: '/b', playRequested: true,
            video: {
                currentTime: 1800, duration: 2400, paused: false,
                load() { reloadsRef(); },
                async play() { resumesRef(); },
                addEventListener(event, listener) { if (event === 'loadedmetadata') restoreRef(listener); },
            },
            on(name, fn) { (this.e[name] ||= []).push(fn); return this; },
            emit(name) { for (const listener of [...(this.e[name] || [])]) listener(); },
            async play() {},
        };
        currentIndex = 1;
        playerSwitchSequence = 7;
        currentMediaList[1].resource_id = 'owner-b-object';
        resetPlaybackAccounting(currentMediaList[1]);
        playbackState.lastTick = performance.now();
        bindPlayerBusinessEvents();
        art.emit('video:error');
    `);
    assert.equal(reloads, 1);
    assert.equal(p.run('art.video.src'), '/b');
    restore();
    assert.equal(p.run('art.video.currentTime'), 1800);
    assert.equal(resumes, 1);
    p.run('art.emit("video:error")');
    assert.equal(reloads, 1);
    assert.equal(p.run('art.loading.show'), false);
    assert.equal(p.run('art.notice.show'), '媒体暂不可用，请稍后重试');
}

for (const mode of ['native', 'encrypted', 's3']) {
    const p = playerContext(async () => { throw new Error('unexpected metadata or artwork request'); });
    let reads = 0;
    p.context.window.FrontierMusicMetadata = {metadata() { reads++; throw new Error('player must not read tags'); }, thumbnail() { reads++; }};
    p.context.window.FrontierMediaCrypto = {prepareCatalog: async () => {}, resetFault() {}};
    p.context.mode = mode;
    p.run(`currentMediaList = ['晴天', '漂流睡房', '罅隙'].map((title, i) => ({media_id:String(i), media_path:'music/artist/'+title+'.mp3', type:'audio', url:'/track-'+i, title, artist:'前沿娱乐', cover:'/api/v1/media/cover?unwanted', native_metadata:mode==='native', encryption:mode==='encrypted'?{version:1}:undefined, transport:mode==='s3'?'S3':'Local'}));
        art.events = {}; art.on = (name, listener) => { art.events[name] = listener; };
        bindPlayerBusinessEvents(); cryptoPreparedCatalogs.add(currentMediaList); applyMediaCatalog(currentMediaList);`);
    await flush();
    const assertNoArtwork = phase => {
        assert.equal(reads, 0, `${mode} player must not parse metadata or artwork ${phase}`);
        assert.equal(p.requests.length, 0, `${mode} player must not fetch metadata or artwork ${phase}`);
        assert.match(p.elements.get('mediaList').innerHTML, /晴天/);
        assert.doesNotMatch(p.elements.get('mediaList').innerHTML, /<img|cover\?/);
    };
    assertNoArtwork('at startup');
    p.run('selectMedia(1)');
    await flush();
    assert.equal(p.run('currentIndex'), 1);
    assert.equal(p.run('art.title'), '漂流睡房');
    assertNoArtwork('after manual selection');
    p.run("art.events['video:ended']()");
    await flush();
    assert.equal(p.run('currentIndex'), 2);
    assert.equal(p.run('art.title'), '罅隙');
    assertNoArtwork('after automatic next');
}
{
    const styles = {};
    const panel = {clientHeight: 210, clientWidth: 360, style: {setProperty(name, value) { styles[name] = value; }}};
    const track = {children: [], offsetWidth: 300, style: {}, classList: {add() {}, remove() {}},
        replaceChildren(...rows) { this.children = []; rows.forEach(row => this.append(row)); },
        append(row) { this.insertBefore(row, null); },
        insertBefore(row, reference) {
            if (row === reference) return row;
            if (row.parentElement) row.parentElement.removeChild(row);
            const index = reference === null ? this.children.length : this.children.indexOf(reference);
            assert.ok(index >= 0);
            this.children.splice(index, 0, row); row.parentElement = this; return row;
        },
        removeChild(row) {
            const index = this.children.indexOf(row); assert.ok(index >= 0);
            this.children.splice(index, 1); row.parentElement = null; return row;
        }};
    const viewport = {clientHeight: 210, clientTop: 0, scrollTop: 0,
        get scrollHeight() { return track.children.reduce((height, row) => height + row.offsetHeight, 0); },
        getBoundingClientRect: () => ({top: 0, bottom: 210})};
    track.parentElement = viewport;
    function lyricRow() {
        const row = {textContent: '', className: '', dataset: {}};
        row.classList = {contains: name => row.className.split(/\s+/).includes(name)};
        Object.defineProperty(row, 'offsetHeight', {get: () => row.textContent.length > 100 ? 126 : 63});
        row.getBoundingClientRect = () => {
            const top = track.children.slice(0, track.children.indexOf(row))
                .reduce((height, item) => height + item.offsetHeight, 0) - viewport.scrollTop;
            return {top, bottom: top + row.offsetHeight};
        };
        return row;
    }
    const line = 'This long lyric must wrap without clipping or reducing its font size '.repeat(5);
    let timer;
    const lyrics = {console, activeLyricEntries: Array.from({length: 12}, (_, i) => ({time: i, text: i === 0 ? line : 'line ' + i})),
        activeLyricIndex: -1, lyricSlideTimer: null, LYRIC_SLIDE_MS: 480,
        clearLyricSlide() {}, setActiveLyricTime() {}, requestAnimationFrame() {},
        getComputedStyle: () => ({lineHeight: '63px', paddingTop: '0px', paddingBottom: '0px'}),
        setTimeout(fn, delay) { timer = {fn, delay}; return 1; },
        document: {getElementById: id => id === 'inlineLyrics' ? panel : id === 'inlineLyricsTrack' ? track : null,
            createElement: lyricRow},
        renderLyricWindow() {}, updateSynchronizedLyrics() {},
    };
    lyrics.window = lyrics;
    vm.createContext(lyrics);
    vm.runInContext(fs.readFileSync('static/js/lyrics-window.js', 'utf8'), lyrics);
    lyrics.renderLyricWindow(3);
    assert.equal(track.children.length, 7);
    assert.equal(track.children[0].textContent, line, 'a long row retains all text');
    assert.equal(styles['--sync-lyric-row-height'], '30px', 'seven rows have a minimum rather than fixed height');
    const priorFont = styles['--sync-lyric-font-size'];
    lyrics.animateLyricForward(4);
    assert.equal(track.children.length, 7);
    assert.equal(track.style.transform, 'translateY(0)', 'wrapped rows render directly without a conflicting animation');
    assert.equal(timer, undefined);
    assert.equal(styles['--sync-lyric-font-size'], priorFont, 'wrapping must retain the height-derived font');
    lyrics.activeLyricEntries.forEach(entry => { entry.text = 'short line'; });
    lyrics.renderLyricWindow(3);
    lyrics.animateLyricForward(4);
    assert.equal(track.children.length, 8);
    assert.equal(track.style.transform, 'translateY(-63px)', 'ordinary animation follows the measured row height');
    assert.equal(styles['--sync-lyric-font-size'], priorFont, 'wrapping never changes font size during a slide');
    assert.equal(timer.delay, 510); timer.fn();
    assert.equal(track.children.length, 7); assert.equal(track.style.transform, 'translateY(0)');
    const css = fs.readFileSync('static/css/lyrics-window.css', 'utf8');
    assert.match(css, /\.inline-lyrics \.sync-lyric \{ height: auto; min-height:/);
    const fullscreen = css.split('.fullscreen-lyric-line {')[1].split('}')[0];
    assert.match(fullscreen, /white-space: normal/); assert.match(fullscreen, /overflow-wrap: anywhere/);
    assert.match(fullscreen, /overflow: visible/); assert.match(fullscreen, /flex-shrink: 0/);
}
console.log('player-cache-smoke-ok: no player artwork reads, playback and wrapped lyrics');
