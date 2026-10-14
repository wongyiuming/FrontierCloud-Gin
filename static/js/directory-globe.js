(() => {
    'use strict';
    let controller;
    window.FrontierDirectoryGlobe = {
        refresh() {
            const stage = document.getElementById('globeStage');
            if (!stage) return;
            if (!controller) controller = createGlobe(stage);
            controller.refresh();
        },
    };

    function createGlobe(stage) {
        const grid = document.getElementById('categoryGrid');
        const canvas = document.getElementById('globeCanvas');
        const ctx = canvas.getContext('2d');
        const toggle = document.getElementById('globeToggle');
        const reduced = matchMedia('(prefers-reduced-motion: reduce)');
        const rings = [];
        for (let lat = -60; lat <= 60; lat += 30) {
            const a = lat * Math.PI / 180, ring = [];
            for (let i = 0; i <= 72; i++) {
                const t = i * Math.PI / 36;
                ring.push([Math.cos(a) * Math.cos(t), Math.sin(a), Math.cos(a) * Math.sin(t)]);
            }
            rings.push(ring);
        }
        for (let lon = 0; lon < 180; lon += 30) {
            const a = lon * Math.PI / 180, ring = [];
            for (let i = 0; i <= 72; i++) {
                const t = i * Math.PI / 36;
                ring.push([Math.cos(t) * Math.cos(a), Math.sin(t), Math.cos(t) * Math.sin(a)]);
            }
            rings.push(ring);
        }
        let cards = [], points = [], width = 0, height = 0, radius = 0, glow;
        let cardWidth = 116, cardHeight = 152;
        let yaw = 0, pitch = -.12, targetYaw = yaw, targetPitch = pitch;
        let frame = 0, lastFrame = 0, velocity = 0, drag = null, moved = false, list = false;
        const clamp = (value, min, max) => Math.max(min, Math.min(max, value));
        const shortest = value => Math.atan2(Math.sin(value), Math.cos(value));

        function schedule() {
            if (!frame && !list && !document.hidden) frame = requestAnimationFrame(draw);
        }
        function draw(now) {
            frame = 0;
            if (list || document.hidden) return;
            const dt = lastFrame ? Math.min(32, now - lastFrame) : 16.67;
            lastFrame = now;
            if (!drag && !reduced.matches && Math.abs(velocity) > .0002) {
                targetYaw += velocity * dt / 16.67;
                velocity *= Math.exp(-dt / 150);
            }
            const blend = reduced.matches ? 1 : 1 - Math.exp(-dt / (drag ? 38 : 78));
            yaw += (targetYaw - yaw) * blend;
            pitch += (targetPitch - pitch) * blend;
            const moving = Math.abs(targetYaw - yaw) + Math.abs(targetPitch - pitch) > .0001 || Math.abs(velocity) > .0002;
            if (!moving) { yaw = targetYaw; pitch = targetPitch; lastFrame = 0; }
            stage.dataset.motionState = moving ? 'moving' : 'idle';

            const sy = Math.sin(yaw), cy = Math.cos(yaw), sp = Math.sin(pitch), cp = Math.cos(pitch);
            const cx = width / 2, centerY = height / 2;
            ctx.clearRect(0, 0, width, height);
            ctx.fillStyle = glow;
            ctx.beginPath(); ctx.arc(cx, centerY, radius * 1.2, 0, Math.PI * 2); ctx.fill();
            for (const ring of rings) {
                let front = null;
                for (const p of ring) {
                    const x = p[0] * cy + p[2] * sy, z = p[2] * cy - p[0] * sy;
                    const y = p[1] * cp - z * sp, side = z * cp + p[1] * sp >= 0;
                    if (side !== front) {
                        if (front !== null) ctx.stroke();
                        ctx.beginPath(); ctx.strokeStyle = side ? '#92d6c92e' : '#55756916';
                        ctx.lineWidth = side ? .8 : .6;
                        ctx.moveTo(cx + x * radius, centerY + y * radius); front = side;
                    } else ctx.lineTo(cx + x * radius, centerY + y * radius);
                }
                ctx.stroke();
            }
            ctx.beginPath(); ctx.arc(cx, centerY, radius, 0, Math.PI * 2);
            ctx.strokeStyle = '#ade8da36'; ctx.lineWidth = 1; ctx.stroke();
            const positions = cards.map((card, i) => {
                const p = points[i], x = p[0] * cy + p[2] * sy, z = p[2] * cy - p[0] * sy;
                const y = p[1] * cp - z * sp, depth = z * cp + p[1] * sp;
                const scale = 4.4 / (4.4 - depth);
                return {card, x, y, depth, scale, focused: card.matches(':focus-visible')};
            });
            const occupied = [];
            const maxFront = width < 460 ? 4 : width < 1000 ? 8 : 12;
            positions.sort((a, b) => Number(b.focused) - Number(a.focused) || b.depth - a.depth);
            positions.forEach(({card, x, y, depth, scale, focused}) => {
                const halfW = cardWidth * scale / 2, halfH = cardHeight * scale / 2;
                // Keep the enlarged sphere without cutting off pole artwork or labels.
                const screenX = clamp(x * radius * scale, -cx + halfW + 8, cx - halfW - 8);
                const screenY = clamp(y * radius * scale, -centerY + halfH + 8, centerY - halfH - 8);
                const box = {left: cx + screenX - halfW, right: cx + screenX + halfW,
                    top: centerY + screenY - halfH, bottom: centerY + screenY + halfH};
                const overlaps = occupied.some(b => box.left < b.right + 14 && box.right > b.left - 14
                    && box.top < b.bottom + 14 && box.bottom > b.top - 14);
                const occluded = !focused && depth >= -.12 && (overlaps || occupied.length >= maxFront);
                if (depth >= -.12 && !occluded) occupied.push(box);
                card.style.transform = `translate(-50%, -50%) translate3d(${screenX / scale}px, ${screenY / scale}px, ${depth * radius}px)`;
                card.style.opacity = String(occluded ? 0 : depth < -.12 ? .09 : .8 + depth * .2);
                card.style.zIndex = String(Math.round((depth + 1) * 100));
                card.style.pointerEvents = depth < -.12 || occluded ? 'none' : 'auto';
                card.classList.toggle('orbit-rear', depth < -.12);
                card.classList.toggle('orbit-occluded', occluded);
            });
            if (moving) schedule();
        }
        function resize() {
            if (list) return;
            const box = stage.getBoundingClientRect(); width = box.width; height = box.height;
            cardWidth = width < 460 ? 100 : 116; cardHeight = cardWidth + 36;
            stage.style.setProperty('--orbit-card-size', `${cardWidth}px`);
            radius = Math.max(68, Math.min(width * .40, height * .43));
            const dpr = Math.min(devicePixelRatio || 1, 2);
            canvas.width = Math.round(width * dpr); canvas.height = Math.round(height * dpr);
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
            grid.style.perspective = `${radius * 4.4}px`;
            glow = ctx.createRadialGradient(width / 2 - radius * .3, height / 2 - radius * .4, 0, width / 2, height / 2, radius * 1.2);
            glow.addColorStop(0, '#172d2a'); glow.addColorStop(.75, '#0d191b'); glow.addColorStop(1, '#0a121600');
            schedule();
        }
        function refresh() {
            cards = Array.from(grid.querySelectorAll('.card'));
            points = cards.map((_, i) => {
                if (cards.length <= 3) {
                    const angle = i * Math.PI * 2 / cards.length;
                    return [Math.sin(angle), 0, Math.cos(angle)];
                }
                const y = 1 - 2 * (i + .5) / cards.length, r = Math.sqrt(1 - y * y), angle = i * 2.399963;
                return [r * Math.sin(angle), y, r * Math.cos(angle)];
            });
            cards.forEach((card, i) => card.addEventListener('focus', () => {
                // Pointer focus must not move a card out from under a click.
                if (list || !card.matches(':focus-visible')) return;
                targetYaw += shortest(-Math.atan2(points[i][0], points[i][2]) - targetYaw);
                targetPitch = Math.asin(points[i][1]); velocity = 0; schedule();
            }));
            const count = document.getElementById('globeCount');
            if (count) count.textContent = `${cards.length.toString().padStart(2, '0')} 个目录`;
            if (list) cards.forEach(card => { card.removeAttribute('style'); card.classList.remove('orbit-rear'); card.classList.remove('orbit-occluded'); });
            resize();
        }
        toggle.addEventListener('click', () => {
            list = !list; velocity = 0; lastFrame = 0;
            toggle.textContent = list ? '前沿UI' : '列表视图'; toggle.setAttribute('aria-pressed', String(list));
            stage.classList.toggle('orbit-list', list); canvas.hidden = list;
            document.getElementById('globeHint').textContent = list ? '选择专辑，开始聆听' : '拖动探索 · 滚轮旋转';
            if (list) { grid.style.removeProperty('perspective'); cards.forEach(card => { card.removeAttribute('style'); card.classList.remove('orbit-rear'); card.classList.remove('orbit-occluded'); }); }
            else resize();
        });
        stage.addEventListener('pointerdown', e => {
            if (list || e.button !== 0) return;
            targetYaw = yaw; targetPitch = pitch;
            drag = {x: e.clientX, y: e.clientY, lastX: e.clientX, time: e.timeStamp, yaw: targetYaw, pitch: targetPitch, id: e.pointerId};
            moved = false; velocity = 0;
        });
        stage.addEventListener('pointermove', e => {
            if (!drag || drag.id !== e.pointerId) return;
            if (Math.hypot(e.clientX - drag.x, e.clientY - drag.y) > 5) {
                moved = true; stage.setPointerCapture(e.pointerId); stage.classList.add('orbit-dragging');
            }
            if (!moved) return;
            targetYaw = drag.yaw + (e.clientX - drag.x) * .006;
            targetPitch = clamp(drag.pitch + (e.clientY - drag.y) * .004, -1.25, 1.25);
            const sample = clamp((e.clientX - drag.lastX) * .006 * 16.67 / Math.max(8, e.timeStamp - drag.time), -.065, .065);
            velocity = velocity * .65 + sample * .35;
            drag.lastX = e.clientX; drag.time = e.timeStamp; schedule();
        });
        function release(e) {
            if (drag?.id !== e.pointerId) return;
            if (e.timeStamp - drag.time > 80 || e.type === 'pointercancel') velocity = 0;
            drag = null; stage.classList.remove('orbit-dragging');
            if (stage.hasPointerCapture(e.pointerId)) stage.releasePointerCapture(e.pointerId);
            schedule();
        }
        stage.addEventListener('pointerup', release); stage.addEventListener('pointercancel', release);
        stage.addEventListener('lostpointercapture', () => { drag = null; stage.classList.remove('orbit-dragging'); });
        stage.addEventListener('click', e => { if (moved && !list && e.detail !== 0) { e.preventDefault(); e.stopPropagation(); moved = false; } }, true);
        stage.addEventListener('wheel', e => {
            if (list) return;
            e.preventDefault(); velocity = 0;
            targetYaw += clamp((e.deltaY + e.deltaX) * .0026 * (e.deltaMode === 1 ? 16 : 1), -.7, .7); schedule();
        }, {passive: false});
        stage.addEventListener('keydown', e => {
            if (list || !['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].includes(e.key)) return;
            e.preventDefault(); velocity = 0;
            targetYaw += e.key === 'ArrowLeft' ? -.22 : e.key === 'ArrowRight' ? .22 : 0;
            targetPitch = clamp(targetPitch + (e.key === 'ArrowUp' ? -.16 : e.key === 'ArrowDown' ? .16 : 0), -1.25, 1.25); schedule();
        });
        new ResizeObserver(resize).observe(stage);
        document.addEventListener('visibilitychange', () => { velocity = 0; lastFrame = 0; if (!document.hidden) schedule(); });
        return {refresh};
    }
})();
