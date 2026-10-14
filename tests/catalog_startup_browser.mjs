// Isolated Chromium dependency regression, not a mainland/vehicle network test.
// PLAYWRIGHT_MODULE may name an installed package; no browser download is made.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import {createRequire} from 'node:module';

const require = createRequire(import.meta.url);
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const source = fs.readFileSync(new URL('../static/js/media-browser.js', import.meta.url), 'utf8');
let html = fs.readFileSync(new URL('../static/media/category.html', import.meta.url), 'utf8');
const values = {
    PAGE_TITLE: '前沿音乐 - 達明一派', BACK_URL: '/api/v1/media/music',
    STUN_URLS_JSON: '[]', WEBRTC_INTERVAL_MS: '30000',
    CATALOG_CONFIG_JSON: JSON.stringify({bootstrap: [{name: 'Album', url: '/album'}], cacheKey: '', url: ''}),
    MEDIA_BROWSER_JS_URL: '/media-browser.js', NETWORK_OBSERVATION_JS_URL: '/observation.js',
};
for (const [name, value] of Object.entries(values)) html = html.replaceAll(`{{${name}}}`, value);

let observationRequested;
const pendingObservation = new Promise(resolve => { observationRequested = resolve; });
const server = http.createServer((request, response) => {
    if (request.url === '/observation.js') {
        // Keep the independent script download pending for the entire test.
        observationRequested();
        return;
    }
    if (request.url === '/media-browser.js') {
        response.setHeader('Content-Type', 'application/javascript');
        response.end(source);
    } else if (request.url.startsWith('/api/v1/media/brand/logo/')) {
        response.setHeader('Content-Type', 'image/svg+xml');
        response.end('<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>');
    } else {
        response.setHeader('Content-Type', 'text/html; charset=utf-8');
        response.end(html);
    }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
let browser;
try {
    browser = await chromium.launch({channel: process.env.PLAYWRIGHT_CHANNEL || 'chrome', headless: true});
    const page = await browser.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(`http://127.0.0.1:${server.address().port}`, {waitUntil: 'domcontentloaded', timeout: 5000});
    await Promise.race([
        pendingObservation,
        new Promise((_, reject) => setTimeout(() => reject(new Error('observation script was not requested')), 2000)),
    ]);
    const card = page.locator('#categoryGrid .card');
    await card.waitFor({state: 'visible', timeout: 2000});
    assert.equal(await card.count(), 1);
    assert.equal(await card.getAttribute('href'), '/album');
    assert.equal(await page.evaluate(() => document.readyState), 'interactive', 'independent script must still be pending');
    assert.deepEqual(errors, []);
    console.log('catalog-startup-browser-ok: directory visible while observation download remains pending');
} finally {
    await browser?.close();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
}
