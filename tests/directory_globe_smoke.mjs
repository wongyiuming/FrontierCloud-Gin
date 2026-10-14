import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

function element() {
    const handlers = new Map(), classes = new Set();
    return {
        handlers, dataset: {}, style: {setProperty() {}, removeProperty() {}},
        classList: {add: n => classes.add(n), remove: n => classes.delete(n),
            toggle(n, on) { on ? classes.add(n) : classes.delete(n); }},
        addEventListener(type, fn) { handlers.set(type, fn); },
        setAttribute() {}, removeAttribute() {}, matches: () => false,
        getBoundingClientRect: () => ({width: 700, height: 500}),
        setPointerCapture() {}, hasPointerCapture: () => false,
    };
}
const stage = element(), grid = element(), toggle = element();
const cards = Array.from({length: 12}, element);
grid.querySelectorAll = () => cards;
const canvas = element();
canvas.getContext = () => ({clearRect() {}, beginPath() {}, arc() {}, fill() {}, stroke() {},
    moveTo() {}, lineTo() {}, setTransform() {}, createRadialGradient: () => ({addColorStop() {}})});
const nodes = new Map([['globeStage', stage], ['categoryGrid', grid], ['globeToggle', toggle],
    ['globeCanvas', canvas], ['globeHint', element()], ['globeCount', element()]]);
const callbacks = [];
const context = {window: {}, document: {hidden: false, getElementById: id => nodes.get(id), addEventListener() {}},
    devicePixelRatio: 1, matchMedia: () => ({matches: false}),
    ResizeObserver: class {observe() {}}, requestAnimationFrame: cb => { callbacks.push(cb); return callbacks.length; }};
vm.runInNewContext(fs.readFileSync(new URL('../static/js/directory-globe.js', import.meta.url), 'utf8'), context);
context.window.FrontierDirectoryGlobe.refresh();
let clock = 0;
function step() {
    assert.equal(callbacks.length, 1, 'only one animation frame may be queued');
    callbacks.shift()(clock += 16.67);
}
step();
assert.equal(stage.dataset.motionState, 'idle');
assert.equal(callbacks.length, 0, 'a stationary globe must stop rendering');
const initial = cards[0].style.transform;
let prevented = false;
stage.handlers.get('wheel')({deltaY: 160, deltaX: 0, deltaMode: 0, preventDefault() { prevented = true; }});
assert.ok(prevented);
assert.equal(cards[0].style.transform, initial, 'wheel events should set a target without jumping');
step();
const intermediate = cards[0].style.transform;
assert.notEqual(intermediate, initial);
assert.equal(stage.dataset.motionState, 'moving');
for (let i = 0; callbacks.length && i < 100; i++) step();
assert.equal(callbacks.length, 0, 'damping must settle');
assert.equal(stage.dataset.motionState, 'idle');
assert.notEqual(cards[0].style.transform, intermediate, 'rotation must interpolate across frames');
const clickable = cards.filter(card => card.style.pointerEvents === 'auto');
assert.ok(clickable.length > 0 && clickable.length <= 8, 'front-facing hit targets must stay sparse');
const boxes = clickable.map(card => {
    const [, x, y, z] = card.style.transform.match(/translate3d\(([-\d.]+)px, ([-\d.]+)px, ([-\d.]+)px\)/);
    const radius = parseFloat(grid.style.perspective) / 4.4;
    const scale = 4.4 / (4.4 - Number(z) / radius);
    return {x: Number(x) * scale, y: Number(y) * scale, w: 116 * scale, h: 152 * scale};
});
for (let i = 0; i < boxes.length; i++) for (let j = i + 1; j < boxes.length; j++) {
    const a = boxes[i], b = boxes[j];
    assert.ok(Math.abs(a.x - b.x) >= (a.w + b.w) / 2 + 13.9 || Math.abs(a.y - b.y) >= (a.h + b.h) / 2 + 13.9,
        'clickable album targets must not overlap');
}
cards[0].handlers.get('focus')();
assert.equal(callbacks.length, 0, 'mouse focus must not jump the globe under a click');
toggle.handlers.get('click')();
assert.equal(canvas.hidden, true);
toggle.handlers.get('click')();
step();
console.log('directory-globe-smoke-ok: smooth interpolation, bounded frames, idle stop, stable pointer focus');
