import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../static/js/media-browser.js', import.meta.url), 'utf8');
const template = fs.readFileSync(new URL('../static/media/category.html', import.meta.url), 'utf8');
const observationTag = template.match(/<script\b[^>]*src="\{\{NETWORK_OBSERVATION_JS_URL\}\}"[^>]*>/)?.[0];
assert.ok(observationTag, 'category page must retain independent network observation');
assert.match(observationTag, /\basync\b/, 'a stalled observation script must not block document parsing');

function element() {
    return {
        children: [], textContent: '', replacements: 0,
        replaceChildren(...children) { this.replacements++; this.children = children; },
        append(...children) {
            for (const child of children) this.children.push(...(child.fragment ? child.children : [child]));
        },
        addEventListener() {},
        getBoundingClientRect: () => ({top: 0, bottom: 200}),
        querySelector(selector) { return this.children.find(child => child.tagName === selector) || null; },
        remove() { this.removed = true; },
    };
}

function fixture({readyState = 'loading', catalogPresent = true, config, fetchImpl, windowExtras = {}, now = Date.now} = {}) {
    const grid = element();
    const heading = element();
    heading.textContent = '前沿音乐 - 達明一派';
    const elements = new Map(catalogPresent ? [['categoryGrid', grid]] : []);
    const listeners = [];
    const requests = [];
    const context = {
        document: {
            readyState,
            getElementById: id => elements.get(id) || null,
            querySelector: selector => selector === 'h1' ? heading : null,
            querySelectorAll: () => [],
            createElement: name => ({...element(), tagName: name}),
            createDocumentFragment: () => ({...element(), fragment: true}),
        },
        window: {
            location: {href: 'https://catalog.fixture.invalid/api/v1/media/music/category?path=music%2Fartist'},
            frontierCloudCatalogConfig: config ?? {bootstrap: [{name: 'Album', url: '/album'}], cacheKey: '', url: ''},
            addEventListener: (event, callback, options) => listeners.push({event, callback, options}),
            ...windowExtras,
        },
        sessionStorage: {getItem: () => null, setItem() {}},
        URL,
        AbortController,
        clearTimeout() {},
        Date: {now},
        // Do not fire DOMContentLoaded, idle timers, or any observation script:
        // they represent an independent resource download that never completes.
        setTimeout() {},
        fetch: (url, options) => {
            requests.push({url, options});
            return fetchImpl ? fetchImpl(url, options) : Promise.reject(new Error('unexpected catalog request'));
        },
    };
    vm.runInNewContext(source, context);
    return {grid, elements, listeners: listeners.filter(item => item.event === 'DOMContentLoaded'), artworkListeners: listeners, requests};
}

{
    const page = fixture();
    assert.equal(page.listeners.length, 0, 'complete category DOM must initialize without DOMContentLoaded');
    assert.equal(page.grid.children.length, 1, 'bootstrap directory must appear while later resources remain pending');
    assert.equal(page.grid.children[0].href, '/album');
    assert.equal(page.grid.children[0].children[0].className, 'card-artwork');
    assert.equal(page.grid.children[0].children[1].textContent, 'Album');
    assert.equal(page.requests.length, 0, 'bootstrap-only subcategories must not need another catalog request');
}

{
    const page = fixture({catalogPresent: false});
    assert.equal(page.listeners.length, 1, 'early script loading must retain DOM-ready fallback');
    assert.equal(page.listeners[0].event, 'DOMContentLoaded');
    assert.equal(page.listeners[0].options.once, true);
    page.elements.set('categoryGrid', page.grid);
    page.listeners[0].callback();
    page.listeners[0].callback();
    assert.equal(page.grid.replacements, 1, 'a repeated ready callback must not bind/render twice');
    assert.equal(page.grid.children.length, 1);
}

{
    const page = fixture({readyState: 'interactive'});
    assert.equal(page.listeners.length, 0, 'late-loaded scripts must not miss an already-fired DOMContentLoaded');
    assert.equal(page.grid.children.length, 1);
}

{
    let resolveCatalog;
    const pending = new Promise(resolve => { resolveCatalog = resolve; });
    const page = fixture({
        config: {url: '/api/v1/media/catalog/categories?media_type=music', cacheKey: 'music'},
        fetchImpl: () => pending,
    });
    assert.equal(page.requests.length, 1, 'network-backed catalogs must also start without unrelated scripts');
    assert.equal(page.listeners.length, 0);
    resolveCatalog({ok: true, json: async () => ({entries: [{name: 'Fresh', url: '/fresh'}]})});
    await new Promise(setImmediate);
    assert.equal(page.grid.children[0].href, '/fresh');
}

{
    let visible = [], clock = 10000;
    const pendingReads = new Map();
    const reads = [];
    const page = fixture({
        now: () => clock,
        config: {bootstrap: Array.from({length: 18}, (_, i) => ({name: String(i), artwork_url: `/api/v1/media/catalog/artwork?path=${i}`}))},
        fetchImpl: async url => ({ok: true, json: async () => ({metadata_tracks: Array.from({length: 8}, (_, n) => `${new URL(url, 'https://fixture').searchParams.get('path')}/${n}`)})}),
        windowExtras: {
            innerHeight: 800,
            FrontierDirectoryGlobe: {refresh() {}, visibleCards: () => visible},
            FrontierMusicMetadata: {metadata(track) { reads.push(track); return new Promise((resolve, reject) => { pendingReads.set(track, {resolve, reject}); }); }},
        },
    });
    page.grid.contains = card => page.grid.children.includes(card);
    page.grid.children.forEach(card => {card.getBoundingClientRect = () => ({top: 0, bottom: 200});});
    const hydrate = page.artworkListeners.find(item => item.event === 'frontier-directory-visible').callback;
    visible = page.grid.children.slice(0, 9); hydrate();
    await new Promise(setImmediate);
    assert.deepEqual(reads, ['0/0', '1/0', '2/0'], 'directory scans must admit only three visible cards');
    visible = page.grid.children.slice(9); hydrate();
    for (const track of ['0/0', '1/0', '2/0']) { pendingReads.get(track).resolve({}); await new Promise(setImmediate); }
    assert.deepEqual(reads, ['0/0', '1/0', '2/0', '9/0', '10/0', '11/0'], 'after paging away, skip all remaining old-page candidates');
    assert.deepEqual(page.requests.map(item => item.url), [0,1,2,9,10,11].map(n=>`/api/v1/media/catalog/artwork?path=${n}`), 'offscreen directories must not fetch candidate descriptors');
    visible = [];
    for (const track of ['9/0', '10/0', '11/0']) pendingReads.get(track).resolve({});
    await new Promise(setImmediate);
    assert.equal(reads.length, 6, 'no visible cards means no further reads');
    visible = page.grid.children.slice(0, 1); hydrate();
    assert.equal(reads.at(-1), '0/1', 'returning to a page resumes its bounded candidate cursor');
    visible = []; pendingReads.get('0/1').resolve({}); await new Promise(setImmediate);
    visible = page.grid.children.slice(0, 1); hydrate();
    assert.equal(reads.at(-1), '0/2');
    pendingReads.get('0/2').reject(new Error('transient Range failure')); await new Promise(setImmediate);
    const beforeRetry = reads.length; hydrate();
    assert.equal(reads.length, beforeRetry, 'artwork failure needs backoff, not a tight retry loop');
    clock += 2100; hydrate();
    assert.equal(reads.at(-1), '0/2', 'failed candidate must remain available for a later visible retry');
    visible = []; pendingReads.get('0/2').resolve({}); await new Promise(setImmediate);
}

{
    let visible = [], clock = 10000, attempts = 0, reads = 0;
    const page = fixture({
        now: () => clock,
        config: {bootstrap: [{name: 'Retry endpoint', artwork_url: '/api/v1/media/catalog/artwork?path=retry'}]},
        fetchImpl: async () => (++attempts === 1 ? {ok: false} : {ok: true, json: async () => ({metadata_tracks: ['only']})}),
        windowExtras: {innerHeight: 800, FrontierDirectoryGlobe: {refresh() {}, visibleCards: () => visible}, FrontierMusicMetadata: {metadata: async () => { reads++; return {}; }}},
    });
    page.grid.contains = card => page.grid.children.includes(card);
    page.grid.children[0].getBoundingClientRect = () => ({top: 0, bottom: 200});
    visible = page.grid.children;
    const hydrate = page.artworkListeners.find(item => item.event === 'frontier-directory-visible').callback;
    hydrate(); await new Promise(setImmediate); hydrate();
    assert.equal(attempts, 1, 'candidate endpoint failure must back off');
    clock += 2100; hydrate(); await new Promise(setImmediate);
    assert.equal(attempts, 2); assert.equal(reads, 1, 'candidate endpoint must be retryable after a transient failure');
}
console.log('catalog-startup-smoke-ok');

{
    let visible=[], slowResolve;
    const requests=[];
    const page=fixture({
        config:{bootstrap:Array.from({length:9},(_,i)=>({name:String(i),artwork_url:`/api/v1/media/catalog/artwork?path=${i}`}))},
        fetchImpl:url=>{
            requests.push(url);
            const response={ok:true,json:async()=>({cover:'/api/v1/media/cover?file_path='+url.split('=').at(-1)})};
            if(url.endsWith('=0')) return new Promise(resolve=>{slowResolve=()=>resolve(response);});
            return Promise.resolve(response);
        },
        windowExtras:{innerHeight:800,FrontierDirectoryGlobe:{refresh(){},visibleCards:()=>visible}},
    });
    page.grid.contains=card=>page.grid.children.includes(card);visible=page.grid.children;
    const hydrate=page.artworkListeners.find(item=>item.event==='frontier-directory-visible').callback;
    hydrate();assert.equal(requests.length,3,'visible admission must remain bounded');
    await new Promise(setImmediate);
    assert.equal(page.grid.children.filter(card=>card.children[0].querySelector('img')).length,8,'one slow lookup must not block the other covers');
    slowResolve();await new Promise(setImmediate);
    assert.equal(page.grid.children.filter(card=>card.children[0].querySelector('img')).length,9);
}

{
    let page,refreshCatalog,artworkRequests=0;
    const entries=[{name:'Cached',artwork_url:'/api/v1/media/catalog/artwork?path=cached'}];
    page=fixture({config:{bootstrap:entries,url:'/catalog'},
        fetchImpl:url=>url==='/catalog'?new Promise(resolve=>{refreshCatalog=()=>resolve({ok:true,json:async()=>({entries})});}):(artworkRequests++,Promise.resolve({ok:true,json:async()=>({cover:'/api/v1/media/cover?file_path=cached'})})),
        windowExtras:{innerHeight:800,FrontierDirectoryGlobe:{refresh(){},visibleCards:()=>page?.grid.children||[]}},
    });
    page.grid.contains=card=>page.grid.children.includes(card);
    const hydrate=page.artworkListeners.find(item=>item.event==='frontier-directory-visible').callback;
    hydrate();await new Promise(setImmediate);
    assert.equal(artworkRequests,1);
    refreshCatalog();await new Promise(setImmediate);hydrate();await new Promise(setImmediate);
    assert.equal(artworkRequests,1,'same-scope validated catalog re-render must reuse the bounded page-memory lookup cache');
    assert.ok(page.grid.children[0].children[0].querySelector('img'));
}
