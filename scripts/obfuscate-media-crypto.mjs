#!/usr/bin/env node
// Build-only transformation. Shipped assets contain no obfuscator dependency.
import {createHash} from 'node:crypto';
import {mkdir, readFile, writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import vm from 'node:vm';

const root = fileURLToPath(new URL('../', import.meta.url));
const sourceDirectory = path.join(root, 'static/js');
const outputDirectory = path.join(sourceDirectory, 'compiled');
const files = ['media-crypto-common.js', 'media-crypto.js', 'media-crypto-sw.js'];
const toolVersion = '5.9.0';
const options = {
    compact: true,
    controlFlowFlattening: false,
    deadCodeInjection: false,
    debugProtection: false,
    debugProtectionInterval: 0,
    disableConsoleOutput: false,
    identifierNamesGenerator: 'hexadecimal',
    log: false,
    numbersToExpressions: false,
    renameGlobals: false,
    renameProperties: false,
    reservedNames: ['^FrontierCryptoCommon$', '^FrontierMediaCrypto$'],
    reservedStrings: ['^/static/js/compiled/'],
    selfDefending: false,
    simplify: true,
    sourceMap: false,
    splitStrings: false,
    stringArray: true,
    stringArrayCallsTransform: false,
    stringArrayEncoding: [],
    stringArrayIndexesType: ['hexadecimal-number'],
    stringArrayIndexShift: true,
    stringArrayRotate: false,
    stringArrayShuffle: true,
    stringArrayWrappersCount: 1,
    stringArrayWrappersChainedCalls: false,
    stringArrayWrappersType: 'variable',
    stringArrayThreshold: 0.75,
    target: 'browser-no-eval',
    transformObjectKeys: false,
    unicodeEscapeSequence: false,
};
const hash = value => createHash('sha256').update(value).digest('hex');
const normalized = value => value.replace(/\r\n/g, '\n');
const builderHash = hash(normalized(await readFile(fileURLToPath(import.meta.url), 'utf8')));
const lockHash = hash(normalized(await readFile(path.join(root, 'package-lock.json'), 'utf8')));
const buildHash = hash(JSON.stringify({toolVersion, options, files, builderHash, lockHash}));
const args = process.argv.slice(2);
if (args.length > 1 || args.some(argument => argument !== '--check'))
    throw new Error('Usage: node scripts/obfuscate-media-crypto.mjs [--check]');

async function sources() {
    return Promise.all(files.map(async file => {
        const source = normalized(await readFile(path.join(sourceDirectory, file), 'utf8'));
        return {file, source, source_sha256: hash(source)};
    }));
}

async function verify() {
    const manifest = JSON.parse(await readFile(path.join(outputDirectory, 'media-crypto-build.json'), 'utf8'));
    if (manifest.format !== 'frontiercloud-browser-crypto-build' || manifest.version !== 1
        || manifest.tool?.version !== toolVersion || manifest.build_sha256 !== buildHash)
        throw new Error('Media crypto build configuration changed; rebuild browser assets');
    const input = await sources();
    if (!Array.isArray(manifest.files) || manifest.files.length !== input.length)
        throw new Error('Incomplete media crypto build manifest');
    for (const [index, item] of input.entries()) {
        const record = manifest.files[index];
        const compiled = normalized(await readFile(path.join(outputDirectory, item.file), 'utf8'));
        if (record.file !== item.file || record.source_sha256 !== item.source_sha256
            || record.compiled_sha256 !== hash(compiled)
            || record.source_bytes !== Buffer.byteLength(item.source)
            || record.compiled_bytes !== Buffer.byteLength(compiled))
            throw new Error(`Stale or changed media crypto asset: ${item.file}; rebuild browser assets`);
        new vm.Script(compiled, {filename: item.file});
        if (/\beval\s*\(|\b(?:new\s+)?Function\s*\(|sourceMappingURL\s*=/.test(compiled))
            throw new Error(`CSP-incompatible media crypto asset: ${item.file}`);
    }
    console.log('Media crypto source/build/output hashes and CSP-compatible syntax verified');
}

async function build() {
    const {default: obfuscator} = await import('javascript-obfuscator');
    const installed = JSON.parse(await readFile(path.join(root, 'node_modules/javascript-obfuscator/package.json'), 'utf8'));
    if (installed.version !== toolVersion)
        throw new Error('Unexpected obfuscator version; install the exact locked build dependencies');
    const input = await sources();
    const records = [];
    await mkdir(outputDirectory, {recursive: true});
    for (const item of input) {
        let source = item.source;
        if (item.file === 'media-crypto-sw.js') {
            const from = "importScripts('/static/js/media-crypto-common.js')";
            if (!source.includes(from)) throw new Error('Service worker shared-module import changed');
            const commonHash = records.find(record => record.file === 'media-crypto-common.js').compiled_sha256;
            source = source.replace(from, `importScripts('/static/js/compiled/media-crypto-common.js?v=${commonHash.slice(0, 16)}')`);
        }
        const seed = Number.parseInt(item.source_sha256.slice(0, 8), 16) || 1;
        const identifiersPrefix = `_fc_${item.file.replace(/[^a-z]/g, '_')}_`;
        const body = obfuscator.obfuscate(source, {...options, seed, identifiersPrefix}).getObfuscatedCode();
        const compiled = `/* FrontierCloud browser crypto; source-sha256:${item.source_sha256}; build-sha256:${buildHash} */\n${body}\n`;
        if (Buffer.byteLength(compiled) > 256 * 1024)
            throw new Error(`Media crypto compiled asset exceeds its bounded payload: ${item.file}`);
        new vm.Script(compiled, {filename: item.file});
        await writeFile(path.join(outputDirectory, item.file), compiled);
        records.push({file: item.file, source_sha256: item.source_sha256,
            compiled_sha256: hash(compiled), source_bytes: Buffer.byteLength(item.source),
            compiled_bytes: Buffer.byteLength(compiled)});
    }
    const manifest = {format: 'frontiercloud-browser-crypto-build', version: 1,
        tool: {name: 'javascript-obfuscator', version: toolVersion},
        builder_sha256: builderHash, lock_sha256: lockHash,
        build_sha256: buildHash, options, files: records};
    await writeFile(path.join(outputDirectory, 'media-crypto-build.json'), JSON.stringify(manifest, null, 2) + '\n');
    await verify();
    for (const record of records)
        console.log(`${record.file}: ${record.source_bytes} source bytes -> ${record.compiled_bytes} compiled bytes`);
}

if (args.includes('--check')) await verify(); else await build();
