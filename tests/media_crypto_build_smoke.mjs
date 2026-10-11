import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';

// Check a private copied fixture; never mutate the working crypto modules.
const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'fc-crypto-build-check-'));
try {
    fs.mkdirSync(path.join(fixture, 'scripts'));
    fs.mkdirSync(path.join(fixture, 'static/js'), {recursive: true});
    for (const name of ['package-lock.json', 'scripts/obfuscate-media-crypto.mjs'])
        fs.copyFileSync(name, path.join(fixture, name));
    for (const name of ['media-crypto-common.js', 'media-crypto.js', 'media-crypto-sw.js'])
        fs.copyFileSync(`static/js/${name}`, path.join(fixture, 'static/js', name));
    fs.cpSync('static/js/compiled', path.join(fixture, 'static/js/compiled'), {recursive: true});
    const check = () => spawnSync(process.execPath,
        [path.join(fixture, 'scripts/obfuscate-media-crypto.mjs'), '--check'],
        {cwd: fixture, encoding: 'utf8', timeout: 10000});
    let result = check();
    assert.equal(result.status, 0, result.stderr);
    for (const name of ['static/js/media-crypto-common.js',
        'static/js/compiled/media-crypto-sw.js', 'package-lock.json']) {
        const target = path.join(fixture, name);
        const original = fs.readFileSync(target);
        fs.appendFileSync(target, '\n/* unbuilt change */\n');
        result = check();
        assert.notEqual(result.status, 0, `${name} change bypassed the build check`);
        assert.match(result.stderr, /Stale or changed|configuration changed/);
        fs.writeFileSync(target, original);
    }
    console.log('media-crypto-build-smoke-ok (source, output and lock changes rejected without npm)');
} finally {
	assert.equal(path.dirname(path.resolve(fixture)), path.resolve(os.tmpdir()));
	assert.ok(path.basename(fixture).startsWith('fc-crypto-build-check-'));
    fs.rmSync(fixture, {recursive: true, force: true});
}
