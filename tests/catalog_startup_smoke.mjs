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
    };
}

function fixture({readyState = 'loading', catalogPresent = true, config, fetchImpl} = {}) {
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
            createElement: () => element(),
            createDocumentFragment: () => ({...element(), fragment: true}),
        },
        window: {
            location: {href: 'https://catalog.fixture.invalid/api/v1/media/music/category?path=music%2Fartist'},
            frontierCloudCatalogConfig: config ?? {bootstrap: [{name: 'Album', url: '/album'}], cacheKey: '', url: ''},
            addEventListener: (event, callback, options) => listeners.push({event, callback, options}),
        },
        sessionStorage: {getItem: () => null, setItem() {}},
        URL,
        // Do not fire DOMContentLoaded, idle timers, or any observation script:
        // they represent an independent resource download that never completes.
        setTimeout() {},
        fetch: (url, options) => {
            requests.push({url, options});
            return fetchImpl ? fetchImpl(url, options) : Promise.reject(new Error('unexpected catalog request'));
        },
    };
    vm.runInNewContext(source, context);
    return {grid, elements, listeners, requests};
}

{
    const page = fixture();
    assert.equal(page.listeners.length, 0, 'complete category DOM must initialize without DOMContentLoaded');
    assert.equal(page.grid.children.length, 1, 'bootstrap directory must appear while later resources remain pending');
    assert.equal(page.grid.children[0].href, '/album');
    assert.equal(page.grid.children[0].children[0].textContent, '📁 Album');
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

console.log('catalog-startup-smoke-ok');
