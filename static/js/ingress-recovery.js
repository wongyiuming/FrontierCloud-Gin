'use strict';

(() => {
    const root = document.querySelector('main');
    const form = document.querySelector('#login');
    const restore = document.querySelector('#restore');
    const status = document.querySelector('#status');
    const message = document.querySelector('#message');
    const button = document.querySelector('#restore-button');
    let current = null;

    const csrf = () => {
        const key = root.dataset.csrf + '=';
        const cookie = document.cookie.split('; ').find(value => value.startsWith(key));
        return cookie ? decodeURIComponent(cookie.slice(key.length)) : '';
    };
    const load = async () => {
        const response = await fetch('/api/v1/media/admin/ingress-recovery/state', {credentials: 'same-origin', cache: 'no-store'});
        if (!response.ok) { restore.hidden = true; return; }
        current = await response.json();
        status.textContent = `当前入口 ${current.ingress.public_origin} · 主站 ${current.master_public_origin}`;
        form.hidden = true;
        restore.hidden = false;
    };
    form.addEventListener('submit', async event => {
        event.preventDefault();
        message.textContent = '';
        const body = new URLSearchParams(new FormData(form));
        const response = await fetch('/api/v1/media/admin/elevate', {method: 'POST', credentials: 'same-origin', body});
        form.reset();
        if (!response.ok) { message.textContent = '登录失败，请检查管理密钥。'; return; }
        await load();
    });
    button.addEventListener('click', async () => {
        if (!current?.ingress?.public_origin || !current.master_public_origin ||
            !window.confirm(`确认切回主站？\n\n当前入口 ${current.ingress.public_origin}\n目标入口 ${current.master_public_origin}`)) return;
        button.disabled = true;
        message.textContent = '';
        try {
            const response = await fetch('/api/v1/media/admin/ingress-recovery/restore', {
                method: 'POST', credentials: 'same-origin',
                headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf()},
                body: JSON.stringify({member_id: current.master_id, generation: current.ingress.generation})
            });
            if (!response.ok) { message.textContent = '恢复未完成，请刷新状态后重试。'; await load(); return; }
            window.location.assign('/api/v1/media/admin');
        } catch (_) {
            message.textContent = '连接失败，请刷新状态后重试。';
        } finally { button.disabled = false; }
    });
    load().catch(() => { message.textContent = '恢复页面暂不可用。'; });
})();
