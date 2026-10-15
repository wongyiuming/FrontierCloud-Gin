/* Admin node operations: Storage, Backup and connection state. */
(() => {
    const $ = id => document.getElementById(id);
    const panel = $('nodesPanel');
    if (!panel) return;

    if (!document.querySelector('link[data-node-observability]')) {
        const link = document.createElement('link');
        link.rel = 'stylesheet';
        link.href = '/static/css/nodes-observability.css?v=20260927';
        link.dataset.nodeObservability = '1';
        document.head.append(link);
    }

    let refreshTimer = null;
    let refreshQueue = Promise.resolve();
    const certificateViews = new Map();
    const retirementViews = new Map();
    const migrationViews = new Map();
    let migrationCursor = {time: 0, id: ""};
    let migrationQueueView = true;
    let migrationPlan = null;
    const migrationSelection = {source: '', target: ''};
    const setStatus = text => { $('nodeOperationStatus').textContent = text || ''; };
    const visible = (id, show) => $(id).classList.toggle('hidden', !show);
    const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
    const gib = value => `${(Number(value || 0) / 1073741824).toFixed(2)} GiB`;
    const dataSize = value => {
        const bytes = Math.max(0, Number(value || 0));
        if (bytes >= 1073741824) return `${(bytes / 1073741824).toFixed(2)} GiB`;
        if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(2)} MiB`;
        if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
        return `${Math.round(bytes)} B`;
    };
    const localTime = stamp => stamp ? new Date(Number(stamp) * 1000).toLocaleString() : '从未';
    const shortId = value => value ? String(value).slice(0, 12) : '-';
    const post = (path, value = {}) => api(`/api/v1/media/admin/nodes${path}`, {
        method: 'POST', headers: requestHeaders(), body: JSON.stringify(value),
    });

    function storageFacts(source = {}) {
        const total = Number(source.physical_total_bytes || 0);
        const free = Number(source.physical_free_bytes || 0);
        return {
            total,
            physicalUsed: Math.max(0, total - free),
            allocated: Number(source.current_allocated_bytes ?? source.allocated_bytes ?? 0),
            used: Number(source.project_used_bytes ?? source.used_bytes ?? 0),
        };
    }

    function storageText(source = {}) {
        const facts = storageFacts(source);
        return `物理 used / all ${gib(facts.physicalUsed)} / ${gib(facts.total)} · 已使用 / 已分配 ${gib(facts.used)} / ${gib(facts.allocated)}`;
    }

    function relativeTime(stamp) {
        if (!stamp) return '从未';
        const delta = Math.round(Number(stamp) - Date.now() / 1000);
        const seconds = Math.abs(delta);
        let value;
        if (seconds < 60) value = `${seconds} 秒`;
        else if (seconds < 3600) value = `${Math.floor(seconds / 60)} 分钟`;
        else if (seconds < 86400) value = `${Math.floor(seconds / 3600)} 小时`;
        else value = `${Math.floor(seconds / 86400)} 天`;
        return delta > 0 ? `${value}后` : `${value}前`;
    }

    function duration(seconds) {
        const value = Math.max(0, Number(seconds || 0));
        if (value < 60) return `${Math.round(value)} 秒`;
        if (value < 3600) return `${Math.floor(value / 60)} 分钟`;
        if (value < 86400) return `${Math.floor(value / 3600)} 小时 ${Math.floor((value % 3600) / 60)} 分`;
        return `${Math.floor(value / 86400)} 天 ${Math.floor((value % 86400) / 3600)} 小时`;
    }

    function make(tag, className = '', text = '') {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== '') node.textContent = text;
        return node;
    }

    function pill(text, tone = 'muted') { return make('span', `node-pill ${tone}`, text); }

    function kv(items) {
        const grid = make('div', 'node-kv');
        for (const [label, value] of items) grid.append(make('span', '', label), make('span', '', String(value)));
        return grid;
    }

    function syncLine(value) {
        const labels = {
            effective: ['已生效', 'effective'], syncing: ['同步中', 'syncing'],
            awaiting: ['等待确认', 'syncing'], offline: ['节点离线', 'offline'],
        };
        const [label, tone] = labels[value] || ['未知', ''];
        const row = make('div', `node-sync-line ${tone}`);
        row.append(make('i', 'node-sync-dot'), make('span', '', label));
        return row;
    }

    async function action(work, defaultMessage = '已完成') {
        try {
            setStatus('处理中');
            const result = await work();
            await refresh();
            setStatus(typeof result === 'string' ? result : defaultMessage);
        } catch (error) {
            setStatus(error.message || String(error));
        }
    }

    function button(label, work, className = '', title = '') {
        const result = make('button', className, label);
        result.type = 'button';
        if (title) result.title = title;
        result.onclick = () => action(work);
        return result;
    }

    async function loadData() {
        const node = await api('/api/v1/media/admin/nodes');
        let observability = {members: [], relationships: []};
        try { observability = await api('/api/v1/media/admin/nodes/observability'); }
        catch (error) { console.warn('node observability unavailable', error); }
        let migrations = null;
        if (node.role === 'Master') {
            const query = `?view=${migrationQueueView ? 'queue' : 'history'}${migrationCursor.id ? `&after_time=${migrationCursor.time}&after_id=${encodeURIComponent(migrationCursor.id)}` : ''}`;
            migrations = await api(`/api/v1/media/admin/nodes/migrations${query}`);
            if (migrationPlan && ['observing', 'starting'].includes(migrationPlan.state)) {
                migrationPlan = await api(`/api/v1/media/admin/nodes/migration-plans/${encodeURIComponent(migrationPlan.plan_id)}`);
            }
        }
        return {node, observability, migrations};
    }

    function ensureOverview() {
        let overview = $('nodeFleetOverview');
        if (overview) return overview;
        overview = make('div', 'node-fleet-overview');
        overview.id = 'nodeFleetOverview';
        panel.querySelector('.nodes-table-scroll').before(overview);
        return overview;
    }

    function overviewCard(label, value, detail, tone) {
        const card = make('div', `node-overview-stat ${tone || ''}`);
        card.append(make('small', '', label), make('strong', '', value), make('span', '', detail));
        return card;
    }

    function renderOverview(node, observed) {
        const overview = ensureOverview();
        overview.replaceChildren();
        if (node.role !== 'Master') {
            const online = (node.relationships || []).filter(item => item.status === 'online').length;
            overview.append(
                overviewCard('当前角色', node.role, '资源策略由 Master 控制', 'good'),
                overviewCard('上游关系', String((node.relationships || []).length), `${online} 条在线`, 'storage'),
                overviewCard('协议版本', `v${node.protocol}`, node.app_version, 'storage'),
            );
            return;
        }
        const pool = node.storage_pool || {};
        const followers = (observed.members || []).filter(item => item.member_kind === 'Follower');
        const online = followers.filter(item => item.connection?.status === 'online').length;
        const backupEnabled = followers.filter(item => item.backup?.enabled).length;
        const backupHealthy = followers.filter(item => item.backup?.health === 'healthy').length;
        const poolFacts = storageFacts(pool);
        overview.append(
            overviewCard('存储节点', `${online} / ${followers.length}`, online === followers.length ? '全部在线' : '存在离线或降级节点', 'good'),
            overviewCard('Storage', `${gib(poolFacts.physicalUsed)} / ${gib(poolFacts.total)}`, `物理 used / all · 已使用 / 已分配 ${gib(poolFacts.used)} / ${gib(poolFacts.allocated)}`, 'storage'),
            overviewCard('Backup', `${backupHealthy} / ${backupEnabled}`, backupEnabled ? '健康 / 已启用备份节点' : '尚未启用备份节点', 'backup'),
        );
    }

    function connectionPanel(relation, observed) {
        const connection = observed?.connection || {};
        const state = connection.status || relation?.status || 'local';
        const section = make('section', 'node-resource-panel connection');
        const heading = make('div', 'node-resource-heading');
        heading.append(make('strong', '', '连接状态'), pill(state === 'online' ? 'Online' : state, state === 'online' ? 'good' : state === 'local' ? 'info' : 'bad'));
        const current = Number(connection.current_rtt_ms ?? relation?.rtt_ms ?? 0);
        section.append(heading, make('div', 'node-metric-primary', state === 'local' ? 'Local' : `${current} ms`));
        if (state !== 'local') section.append(kv([
            ['最近心跳', relativeTime(connection.last_heartbeat || relation?.last_heartbeat)],
            ['最近时间', localTime(connection.last_heartbeat || relation?.last_heartbeat)],
            ['1h 平均', `${connection.avg_rtt_ms || current} ms`],
            ['1h 最低 / 最高', `${connection.min_rtt_ms || current} / ${connection.max_rtt_ms || current} ms`],
            ['RTT 样本', `${connection.sample_count || (current ? 1 : 0)} 次`],
            ['连续失败', connection.failures ?? relation?.failures ?? 0],
            ['历史恢复', connection.recoveries ?? relation?.recoveries ?? 0],
        ]));
        section.append(make('div', 'node-note', state === 'local' ? 'Master Local 是本机资源。' : 'RTT 是 Master 到该节点 HTTPS 控制面的往返时间。'));
        return section;
    }

    function storagePanel(member, observed) {
        const section = make('section', 'node-resource-panel storage');
        const heading = make('div', 'node-resource-heading');
        heading.append(make('strong', '', 'Storage'), pill(member.storage_enabled ? 'Enabled' : 'Disabled', member.storage_enabled ? 'info' : 'muted'));
        const facts = storageFacts(member);
        section.append(heading, make('div', 'node-metric-primary', `${gib(facts.physicalUsed)} / ${gib(facts.total)}`), kv([
            ['物理 used / all', `${gib(facts.physicalUsed)} / ${gib(facts.total)}`],
            ['已使用 / 已分配', `${gib(facts.used)} / ${gib(facts.allocated)}`],
        ]), syncLine(observed?.sync?.storage || (member.member_kind === 'MasterLocal' ? 'effective' : 'awaiting')),
        make('div', 'node-note', '物理表示该媒体文件系统已用 / 总容量；已使用 / 已分配表示 FrontierCloud 项目占用 / 分配配额。'));
        return section;
    }

    function backupPanel(member, observed) {
        const backup = observed?.backup || member.backup || {};
        const health = backup.health || 'disabled';
        const labels = {healthy: 'Healthy', running: 'Backing up', failed: 'Failed', stale: 'Stale', 'waiting-first-backup': 'Waiting first backup', disabled: 'Disabled'};
        const tone = health === 'healthy' ? 'good' : (health === 'running' || health === 'waiting-first-backup' ? 'warn' : (health === 'failed' || health === 'stale') ? 'bad' : 'muted');
        const section = make('section', 'node-resource-panel backup');
        const heading = make('div', 'node-resource-heading');
        heading.append(make('strong', '', 'Backup'), pill(labels[health] || backup.raw_state || 'Unknown', tone));
        section.append(heading, make('div', 'node-metric-primary', backup.last_success ? relativeTime(backup.last_success) : (backup.enabled ? '尚未成功' : '未启用')), kv([
            ['最近成功', localTime(backup.last_success)],
            ['距今', backup.last_success ? duration(backup.lag_seconds) : '-'],
            ['最近大小', backup.last_size_bytes ? dataSize(backup.last_size_bytes) : '-'],
            ['恢复点', `${backup.recovery_points || 0} 个`],
            ['最近尝试', backup.last_attempt ? `${localTime(backup.last_attempt)} · ${backup.last_attempt_state || '-'}` : '-'],
            ['下次计划', backup.next_due ? `${localTime(backup.next_due)} · ${relativeTime(backup.next_due)}` : '-'],
            ['最近校验', backup.checksum ? `SHA256 ${shortId(backup.checksum)}…` : '-'],
        ]), syncLine(observed?.sync?.backup || (member.member_kind === 'MasterLocal' ? 'effective' : 'awaiting')),
        make('div', 'node-note', 'Master 每 24 小时向启用 Backup 的存储节点 写入业务恢复点；失败约 5 分钟后重试。'));
        return section;
    }

    function configBox(member) {
        const grid = make('div', 'node-config-grid');
        const storageBox = make('div', 'node-config-box');
        const storageEnabled = document.createElement('input');
        storageEnabled.type = 'checkbox'; storageEnabled.checked = Boolean(member.storage_enabled);
        const capacity = document.createElement('input');
        capacity.type = 'number'; capacity.min = '1'; capacity.max = '10240';
        capacity.value = String(Math.max(1, Math.ceil(Number(member.allocated_bytes || 0) / 1073741824)));
        capacity.disabled = !storageEnabled.checked;
        storageEnabled.onchange = () => { capacity.disabled = !storageEnabled.checked; };
        const storageLabel = make('label'); storageLabel.append(storageEnabled, document.createTextNode(' Storage 承载业务数据'));
        const inputs = make('div', 'node-config-inputs'); inputs.append(capacity, make('span', '', 'GiB 配额'));
        storageBox.append(storageLabel, make('small', '', '关闭后停止新写入；已有数据不会自动迁走。'), inputs);

        const backupBox = make('div', 'node-config-box');
        const backupEnabled = document.createElement('input');
        backupEnabled.type = 'checkbox'; backupEnabled.checked = Boolean(member.backup?.enabled);
        const backupLabel = make('label'); backupLabel.append(backupEnabled, document.createTextNode(' Backup 恢复点'));
        backupBox.append(backupLabel, make('small', '', 'Master 每 24h 发送业务恢复包；失败后约 5 分钟重试。'));
        grid.append(storageBox, backupBox);
        return {grid, storageEnabled, capacity, backupEnabled};
    }

    async function waitForEffective(memberId, timeoutMs = 75000) {
        const deadline = Date.now() + timeoutMs;
        while (Date.now() < deadline) {
            await sleep(2200);
            const data = await api('/api/v1/media/admin/nodes/observability');
            const member = (data.members || []).find(item => item.member_id === memberId);
            if (!member) continue;
            if (member.sync?.storage === 'effective' && member.sync?.backup === 'effective') return `配置已在 存储节点生效 · ${new Date().toLocaleTimeString()}`;
            if (member.connection?.status === 'offline') return 'Master 已保存配置，但 存储节点当前离线，尚未生效';
        }
        return 'Master 已保存配置；存储节点尚未在心跳中确认，请检查连接状态';
    }

    function controls(member, relation) {
        const shell = make('div', 'node-card-controls');
        if (!relation || relation.state !== 'active') {
            if (member.member_kind === 'MasterLocal') {
                const input = document.createElement('input');
                input.type = 'number'; input.min = '1'; input.max = '10240'; input.style.width = '90px';
                input.value = String(Math.max(1, Math.ceil(Number(member.allocated_bytes || 0) / 1073741824)));
                const actions = make('div', 'node-card-actions');
                actions.append(input, button('更新本机配额', () => post(`/${member.member_id}/resources`, {storage_enabled: true, storage_capacity_gib: Number(input.value), backup_enabled: false}), 'apply'));
                shell.append(make('div', 'node-note', 'Master Local 是本机固定资源，仅允许调整 Storage 配额。'), actions);
            }
            return shell;
        }
        const config = configBox(member);
        const actions = make('div', 'node-card-actions');
        const mode = document.createElement('select');
        mode.setAttribute('aria-label', `${member.member_id} 数据传输模式`);
        mode.title = 'Relay 由 Master 中转业务数据；Direct 允许数据面直接访问 存储节点。';
        for (const value of ['Relay', 'Direct']) { const option = document.createElement('option'); option.value = value; option.textContent = value; mode.append(option); }
        mode.value = relation.mode;
        if (relation.summary?.storage_transport) { mode.disabled = true; mode.title = '网络部署类型固定：直连使用 443，中继使用通信高端口；切换需要维护期重新部署。'; }
        mode.onchange = () => action(() => post(`/${relation.relationship_id}/mode`, {mode: mode.value}));
        actions.append(mode, button('应用资源配置', async () => {
            await post(`/${relation.relationship_id}/resources`, {
                storage_enabled: config.storageEnabled.checked,
                storage_capacity_gib: config.storageEnabled.checked ? Number(config.capacity.value) : 0,
                backup_enabled: config.backupEnabled.checked,
            });
            return await waitForEffective(member.member_id);
        }, 'apply', '只有 存储节点回报的 Observed 配置与 Desired 一致才显示已生效。'));
        shell.append(config.grid, actions);
        return shell;
    }

    function memberCard(member, relation, observed, localCertificate) {
        const row = document.createElement('tr'); row.className = 'node-card-row';
        const cell = document.createElement('td'); cell.colSpan = 4;
        const card = make('article', 'node-card');
        const header = make('header', 'node-card-header');
        const title = make('div', 'node-card-title');
        title.append(make('strong', '', member.member_kind === 'MasterLocal' ? 'Master Local' : member.member_id), make('small', '', relation?.peer_endpoint || '本机资源'));
        const badges = make('div', 'node-card-badges');
        badges.append(pill(member.member_kind === 'MasterLocal' ? 'LOCAL' : String(relation?.status || 'UNKNOWN').toUpperCase(), member.member_kind === 'MasterLocal' ? 'info' : relation?.status === 'online' ? 'good' : 'bad'), pill(member.transport || relation?.mode || 'Local', 'muted'));
        header.append(title, badges);
        const grid = make('div', 'node-card-grid');
        grid.append(connectionPanel(relation, observed), storagePanel(member, observed), backupPanel(member, observed));
        if (localCertificate && member.member_kind === 'MasterLocal') grid.append(certificatePanel(localCertificate));
        if (relation?.direction === 'downstream' && relation.state === 'active') grid.append(certificatePanel(relation));
        if (relation?.direction === 'downstream' && ['active', 'retiring', 'revoked'].includes(relation.state)) grid.append(retirementPanel(member, relation));
        card.append(header, grid, controls(member, relation)); cell.append(card); row.append(cell);
        return row;
    }

    function migrationPlanPanel(node) {
        const section = make('section', 'node-resource-panel');
        section.append(make('strong', '', '整节点资源迁出'));
        section.append(make('p', 'node-note', '选择源与目标后生成只读计划。计划包含隐藏、加密及子目录对象；Master Local 暂不支持迁入或迁出。'));
        const members = (node.storage_pool?.members || []).filter(member => member.member_id !== 'auto' && member.member_kind !== 'Auto');
        for (const [key, label] of [['source', '源节点'], ['target', '目标节点']]) {
            const field = make('label', '', label); const select = make('select');
            select.append(make('option', '', '请选择节点'));
            select.children[0].value = '';
            for (const member of members) {
                const reasons = [];
                const relationship = (node.relationships || []).find(value => value.peer_id === member.member_id);
                if (member.member_kind !== 'Follower') reasons.push('Master Local 不支持');
                if (member.member_kind === 'Follower' && relationship?.state !== 'active') reasons.push(relationship?.state === 'retiring' ? '退役处理中' : '节点关系未生效');
                if (member.health !== 'online') reasons.push('离线或不健康');
                if (key === 'target' && (!member.storage_enabled || !member.writable || member.draining)) reasons.push('不可写或排空中');
                const option = make('option', '', `${member.member_id} · ${member.transport || member.member_kind}${reasons.length ? ' · ' + reasons.join('、') : ''}`);
                option.value = member.member_id; option.disabled = member.member_kind !== 'Follower' || relationship?.state !== 'active'; select.append(option);
            }
            select.value = migrationSelection[key];
            select.onchange = () => { migrationSelection[key] = select.value; };
            field.append(select); section.append(field);
        }
        const controls = make('div', 'node-card-actions');
        const generate = button('生成只读迁移计划', async () => {
            if (!migrationSelection.source || !migrationSelection.target || migrationSelection.source === migrationSelection.target) throw new Error('请选择两个不同的 Storage 节点');
            const bytes = crypto.getRandomValues(new Uint8Array(16));
            const request_id = Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');
            migrationPlan = await post('/migration-plans', {request_id, source_id: migrationSelection.source, target_id: migrationSelection.target});
            return '计划观察已开始；等待源文件校验和目标盘点完成';
        });
        generate.disabled = migrationPlan && ['observing', 'starting'].includes(migrationPlan.state);
        controls.append(generate); section.append(controls);
        const plan = migrationPlan;
        if (!plan) return section;
        section.append(kv([['计划', plan.plan_id], ['状态', plan.state], ['源 → 目标类型', `${plan.source.transport || '?'} → ${plan.target.transport || '?'}`], ['归属单元 / 对象', `${plan.unit_count} / ${plan.object_count}`], ['实际字节', dataSize(plan.total_bytes)], ['已校验', `${plan.verified_objects} 个 / ${dataSize(plan.verified_bytes)}`], ['目标已用 / 预留', `${dataSize(plan.target.used_bytes)} / ${dataSize(plan.target.reserved_bytes)}`], ['目标最小可用 / 额外需求', `${dataSize(plan.target_physical_free)} / ${dataSize(plan.additional_target_bytes)}`], ['计划到期', localTime(plan.expires_at)]]));
        section.append(make('p', 'node-note', 'Direct/Relay 可以跨类型迁移，源与目标均须连接同一 Master；迁移数据仅从源节点直传目标节点，任何情况下都不经 Master 中转；无法直连时停止并保留断点。只读盘点不执行写入探测，目标发布仍须通过本机事务。备份和源端残留需单独处理，迁移不会自动退役节点。'));
        if (plan.error_code) {
            const stages = {catalog: '资源清单', source_inventory: '源节点盘点', target_inventory: '目标节点盘点', source_content: '源文件校验', seal: '计划复核', admission: '任务准入'};
            const stage = stages[plan.error_stage] || '计划观察';
            section.append(make('p', 'node-note', `${stage}失败：${plan.error_code}。核对该节点的连接、原生状态和文件版本，处理原因后重新生成计划。`));
        }
        if (plan.blocker_count) section.append(make('p', 'node-note', `阻断总数：${plan.blocker_count}，本页最多显示 64 个。`));
        for (const block of plan.blockers || []) section.append(make('p', 'node-note', `阻断：${block.code} · ${block.resource || ''}`));
        for (const concern of plan.source_residuals || []) section.append(make('p', 'node-note', `源端保留/残留：${concern.code} · ${concern.count} · ${(concern.samples || []).join('、')}`));
        for (const object of plan.objects || []) section.append(make('p', '', `${object.resource_kind} · ${object.physical_path} · ${dataSize(object.size_bytes)} · 归属单元 ${object.parent_path}`));
        controls.append(button('刷新计划', async () => { migrationPlan = await api(`/api/v1/media/admin/nodes/migration-plans/${encodeURIComponent(plan.plan_id)}`); }));
        if (!plan.complete) controls.append(button('下一页计划对象', async () => { migrationPlan = await api(`/api/v1/media/admin/nodes/migration-plans/${encodeURIComponent(plan.plan_id)}?after=${encodeURIComponent(plan.next)}`); }));
        if (plan.state === 'ready') controls.append(button('确认并开始迁移', async () => {
            const confirmation = `${plan.source.member_id} -> ${plan.target.member_id}`;
            if (window.prompt(`请输入 ${confirmation}，确认整节点迁出。\n开始后源节点进入排空，后台重新检查源字节、目标冲突和容量；旧计划变化将被拒绝。`) !== confirmation) return '未发送开始请求';
            migrationPlan = await post(`/migration-plans/${encodeURIComponent(plan.plan_id)}/start`, {review_sha256: plan.review_sha256, confirm_source_id: plan.source.member_id, confirm_target_id: plan.target.member_id});
            return '执行前复核已开始；持久任务创建后将在下方显示';
        }));
        if (plan.task) section.append(make('p', '', `持久任务：${plan.task.task_id} · ${plan.task.state}`));
        return section;
    }

    function migrationPanel(page) {
        const section = make('section', 'node-resource-panel');
        section.append(make('strong', '', migrationQueueView ? '资源迁移任务 · 队列与待处理项' : '资源迁移任务 · 历史'));
        section.append(button(migrationQueueView ? '查看全部历史' : '查看任务队列', async () => { migrationQueueView = !migrationQueueView; migrationCursor = {time: 0, id: ''}; }));
        section.append(make('p', 'node-note', '任务保存在 Master。目标暂存或发布不代表归属已提交；取消保留已提交资源，排空状态需另行明确解除。迁移完成后仍需独立退役检查。'));
        const labels = {queued: '等待执行', copying: '复制中', verifying: '校验中', committing: '归属提交中', cleanup_pending: '清理待办', paused: '已暂停', cancelling: '取消清理中', cancelled: '已取消', failed: '失败', completed: '已完成'};
        for (const task of (page.tasks || []).slice(0, 16)) {
            const card = make('article', 'node-config-box');
            card.append(make('strong', '', `${task.task_id} · ${task.error_code === 'waiting_business_traffic' ? '等待业务低峰' : labels[task.state] || task.state}`));
            card.append(kv([['源节点', task.source_id], ['目标节点', task.target_id], ['对象数', task.object_count], ['已提交 / 全部', `${dataSize(task.committed_bytes)} / ${dataSize(task.total_bytes)}`]]));
            if (task.error_code === 'waiting_business_traffic') card.append(make('p', 'node-note', '正在静默等待业务低峰；断点已保留，持续低流量后自动续跑。手动暂停仍需手动恢复。'));
            else if (task.error_code) card.append(make('p', 'node-note', `失败原因：${task.error_code}。核对节点连接、容量与任务检查点后重试；迁移禁止通过 Master 中转。`));
            const detail = migrationViews.get(task.task_id);
            const load = async after => {
                const value = await api(`/api/v1/media/admin/nodes/migrations/${encodeURIComponent(task.task_id)}${after ? `?after=${encodeURIComponent(after)}` : ''}`);
                migrationViews.set(task.task_id, {at: Date.now(), value});
                if (migrationViews.size > 64) migrationViews.delete(migrationViews.keys().next().value);
            };
            const actions = make('div', 'node-card-actions');
            actions.append(button('更新检查点', () => load('')));
            const control = action => async () => {
                if (action === 'cancel' && !window.confirm(`取消任务 ${task.task_id}？\n源：${task.source_id}\n目标：${task.target_id}\n已提交资源保留在目标，未提交副本通过任务事务清理；不会自动解除排空。`)) return '未发送取消请求';
                await post(`/migrations/${encodeURIComponent(task.task_id)}/control`, {action, revision: task.revision, confirm_source_id: task.source_id, confirm_target_id: task.target_id});
                await load('');
            };
            if (['queued', 'copying', 'verifying', 'committing', 'cleanup_pending'].includes(task.state)) actions.append(button('暂停', control('pause')));
            if (task.state === 'paused') actions.append(button('恢复', control('resume')));
            if (task.state === 'failed' || ['cleanup_pending', 'cancelling'].includes(task.state) && task.error_code) actions.append(button('重试', control('retry')));
            if (!['completed', 'cancelled', 'cancelling'].includes(task.state)) actions.append(button('取消任务', control('cancel'), 'danger'));
            if (['completed', 'cancelled'].includes(task.state)) actions.append(button('明确解除本任务排空', async () => {
                const source = window.prompt(`请输入源 NodeID ${task.source_id}，确认解除任务 ${task.task_id} 的排空限制。其他维护限制保留；此操作不会退役节点。`);
                if (source !== task.source_id) return '未发送排空解除请求';
                await post(`/migrations/${encodeURIComponent(task.task_id)}/release-drain`, {revision: task.revision, confirm_source_id: source, confirm_target_id: task.target_id});
                await load('');
                return '本任务排空已解除；其他维护限制保留';
            }));
            card.append(actions);
            if (detail) {
                const execution = detail.value.execution;
                card.append(kv([['队列位置', detail.value.queue_position || '未排队'], ['调度状态', execution?.state === 'waiting_traffic' ? '等待业务低峰' : labels[detail.value.task?.state] || detail.value.task?.state || ''] ]));
                if (execution) {
                    card.append(kv([['当前对象', execution.object_id || '准备中'], ['当前对象已复制 / 全部', `${dataSize(execution.current_bytes)} / ${dataSize(execution.current_total_bytes)}`], ['当前复制速度', `${dataSize(execution.bytes_per_second)}/s`], ['等待节点', execution.waiting_node_id || '无']]));
                    for (const peer of (execution.traffic || []).slice(0, 3)) {
                        const flow = peer.traffic || {};
                        const role = {master: '主节点', source: '源节点', target: '目标节点'}[peer.role] || peer.role;
                        card.append(make('p', 'node-note', `${role}业务流量：入 ${dataSize(flow.ingress_bytes_per_second)}/s · 出 ${dataSize(flow.egress_bytes_per_second)}/s · 最近 1 秒 ${dataSize(flow.recent_bytes_per_second)}/s；${flow.can_run ? '允许后台执行' : flow.state === 'unavailable' ? '网关流量采样未验证，任务保留在队列' : flow.state === 'high_traffic' ? '业务高峰，等待流量下降' : `等待持续低峰，至少 ${flow.resume_after_seconds || 0} 秒`}。暂停阈值 ${dataSize(flow.high_bytes_per_second)}/s，恢复阈值 ${dataSize(flow.low_bytes_per_second)}/s，须持续 ${flow.low_interval_seconds || 30} 秒。`));
                    }
                }
                card.append(make('p', 'node-note', `检查点观察：${new Date(detail.at).toLocaleString()}，点击更新获取当前事实。`));
                card.append(make('p', 'node-note', `本任务资源清理：${detail.value.retirement_ready ? '已满足' : '尚未满足'}。仍需独立退役检查核对全部资源、备份和读取依赖。`));
                for (const stage of (detail.value.object_stages || []).slice(0, 16)) card.append(make('p', '', `对象 ${stage.state}: ${stage.count} · 已验证 ${dataSize(stage.verified_bytes)} / ${dataSize(stage.size_bytes)}`));
                for (const stage of (detail.value.unit_stages || []).slice(0, 16)) card.append(make('p', '', `归属单元 ${stage.state}: ${stage.count} · ${dataSize(stage.size_bytes)}`));
                for (const object of (detail.value.objects || []).slice(0, 16)) card.append(make('p', '', `${object.physical_path} · ${object.state} · 已验证 ${dataSize(object.verified_bytes)} / ${dataSize(object.size_bytes)}`));
                if (!detail.value.complete) card.append(button('下一页对象', () => load(detail.value.next)));
            }
            section.append(card);
        }
        if (!page.tasks?.length) section.append(make('p', '', '本页没有持久化迁移任务。'));
        const pages = make('div', 'node-card-actions');
        if (!page.complete) pages.append(button('下一页任务', async () => { migrationCursor = {time: page.next_time, id: page.next_id}; }));
        if (migrationCursor.id) pages.append(button('返回最新任务', async () => { migrationCursor = {time: 0, id: ''}; }));
        section.append(pages);
        return section;
    }

    function retirementPanel(member, relation) {
        const section = make('section', 'node-resource-panel');
        if (relation.state === 'revoked' && relation.summary?.retirement?.completed_at) {
            section.append(make('strong', '', '已安全退役'), kv([['NodeID', member.member_id], ['完成时间', localTime(relation.summary.retirement.completed_at)]]));
            section.append(make('p', 'node-note', '旧工作凭据已失效；身份、审计、容器和卷继续保留。物理清理由运维独立处理。'));
            return section;
        }
        section.append(make('strong', '', '退役检查'));
        section.append(make('p', 'node-note', '盘点资源、事务与备份。检查完成后仍需最终复核；不会撤销节点或删除磁盘。'));
        if (relation.state === 'retiring') section.append(make('p', 'node-note', '退役正在对账：持久写入隔离已生效，重启后仍保留。处理阻断项后重试完成退役。'));
        const saved = retirementViews.get(relation.relationship_id);
        if (saved) {
            const report = saved.report;
            section.append(make('p', '', `${report?.observation_complete ? '盘点已完成' : '检查未完成'} · ${new Date(saved.at).toLocaleString()} · 历史观察，需重新检查`));
            if (report) {
                section.append(kv([['物理条目', report.physical_entries], ['逻辑字节', dataSize(report.logical_bytes)], ['预期资源', report.expected_items]]));
                if (Array.isArray(report.volumes)) {
                    for (const volume of report.volumes) {
                        section.append(kv([['盘点范围', volume.scope], ['条目', volume.entries], ['保留原生状态', volume.retained_entries || 0], ['逻辑字节', dataSize(volume.logical_bytes)], ['所在文件系统空闲', dataSize(volume.free_bytes)], ['默认数据目录内', volume.in_data_root ? '是' : '否'], ['写入能力', '未验证']]));
                    }
                    section.append(make('p', 'node-note', '空闲空间为各挂载的观察值；同一文件系统可能共享空间，不能相加作为可用容量。'));
                    section.append(make('p', 'node-note', '保留原生状态应随节点历史保留；盘点完成不代表磁盘可以擦除。'));
                }
                const list = make('ul');
                const steps = {
                    finish_or_reconcile_worker_jobs: '完成或对账后台任务及其有效执行租约。',
                    migrate_or_resolve_media: '迁移受管理媒体，或通过业务恢复流程对账。',
                    migrate_or_resolve_recordings: '迁移录音，或处理未完成录音事务。',
                    finish_or_cancel_uploads: '等待上传安全完成，或取消未完成上传。',
                    reconcile_used_and_reserved_bytes: '核对已用容量、预留容量及对应业务事务。',
                    finish_or_resolve_migration: '完成迁移，或处理失败、取消和清理待办。',
                    wait_for_or_resolve_migration_runner: '等待迁移执行租约结束，或通过任务控制完成对账。',
                    reconcile_terminal_task_unit_and_object_rosters: '核对终态任务、归属单元和对象清单的数量、字节及完成回执。',
                    reconcile_task_scope_receipts: '核对迁移范围锁与双方完成回执。',
                    reconcile_task_reservations: '核对迁移预留与清理回执。',
                    wait_for_or_resolve_read_dependencies: '等待有效读取结束，再重新检查。',
                    retain_or_replace_verified_recovery_points: '保留备份，或验证满足保留要求的替代恢复点。',
                    reconcile_receiving_or_orphan_backup_material: '核对接收中的备份和残留备份分块。',
                    finish_native_file_recovery: '完成节点文件事务恢复。',
                    reconcile_peer_task_and_file_receipts: '核对节点任务、文件事务与双方回执。',
                    verify_replacement_backup_and_stop_delivery: '验证替代备份，并停止向待退役节点继续投递。',
                    restore_connectivity_for_final_reconciliation: '恢复节点连接后执行最终对账。',
                };
                const add = (label, count, samples, advice) => {
                    const item = make('li');
                    item.append(make('strong', '', `${label} · ${count}`), make('p', 'node-note', advice));
                    for (const sample of (samples || []).slice(0, 8)) item.append(make('div', '', String(sample)));
                    list.append(item);
                };
                for (const [label, ledger] of [['Master', report.master], ['Storage', report.peer]]) {
                    for (const block of (ledger?.blockers || []).slice(0, 32)) add(`${label}: ${block.code}`, block.count, block.sample_ids, steps[block.next_step] || '核对阻断对象，处理后重新检查。');
                }
                for (const concern of (report.concerns || []).slice(0, 64)) {
                    let advice = '核对对象与未完成事务，处理后重新检查。不要直接删除未知文件。';
                    if (concern.code.includes('backup')) advice = '先验证替代恢复点与保留要求，再处理备份资源。';
                    else if (concern.code.includes('missing')) advice = '核对挂载和原始数据；缺失文件需要恢复或人工对账。';
                    else if (concern.code.startsWith('physical_managed_')) advice = '受管理资源需通过迁移或业务事务处理。';
                    add(concern.code, concern.count, concern.samples, advice);
                }
                section.append(list);
            }
            if (saved.error) section.append(make('p', 'node-note', saved.error));
        }
        const check = make('button', '', '执行只读退役检查'); check.type = 'button';
        check.onclick = async () => {
            check.disabled = true; setStatus('正在盘点节点资源');
            let report, error;
            try {
                report = await post(`/${encodeURIComponent(relation.relationship_id)}/retire/check`, {member_id: member.member_id});
            } catch (failure) {
                report = failure.responseData?.report; error = failure.message || '退役检查未完成';
            }
            retirementViews.set(relation.relationship_id, {at: Date.now(), report, error});
            section.replaceWith(retirementPanel(member, relation));
            setStatus(error || '盘点完成；结果不代表最终撤销已获准');
        };
        section.append(check);
        const report = saved?.report;
        const clear = report?.observation_complete && report.master?.database_clear && report.peer?.database_clear && report.expected_items === 0 && !report.concerns?.length;
        if (clear || relation.state === 'retiring') {
            section.append(button(relation.state === 'retiring' ? '重试完成安全退役' : '确认安全退役', async () => {
                const confirmation = window.prompt(`输入待退役 NodeID：${member.member_id}\n服务端会重新核验并建立持久隔离；此操作保留容器、卷和历史身份。`);
                if (confirmation !== member.member_id) throw new Error('NodeID 确认不匹配，未执行退役');
                await post(`/${encodeURIComponent(relation.relationship_id)}/retire/apply`, {member_id: member.member_id, confirm_member_id: confirmation});
                return '安全退役已完成；容器、卷和历史身份已保留';
            }, 'danger'));
        }
        return section;
    }

    function certificatePanel(relation) {
        const section = make('section', 'node-resource-panel');
        const heading = make('div', 'node-resource-heading');
        heading.append(make('strong', '', relation.local ? '本机证书' : '存储节点证书'));
        const observed = relation.summary?.certificate || {};
        const queried = certificateViews.get(relation.relationship_id);
        const facts = queried && Date.now() - queried.at < 30000 ? queried.value : observed;
        const labels = {DISABLED: '未启用 TLS', PENDING: '等待证书', VALIDATING: '验证域名', ISSUING: '签发中', ACTIVE: '已生效', RENEWING: '续期中', DEGRADED: '降级，需检查', FAILED: '失败'};
        const codes = {dns: 'DNS 未就绪或解析失败', port80_busy: '80 端口被占用', http01_unreachable: '公网 HTTP-01 不可达', http01_ingress: '等待内部 Challenge 入口就绪', authorization: '域名授权失败', caa: 'CAA 限制', rate_limited: 'CA 限流，自动退避', ca_unavailable: 'CA 暂不可用', ca_timeout: 'CA 请求超时', ca_error: 'CA 请求失败', domain_rejected: 'CA 拒绝域名', system_clock: '系统时间异常', interrupted: '上次操作中断', journal_unwritable: '状态无法持久化', journal_recovered: '已保护损坏记录，等待安全重试', certificate_cache_unreadable: '证书缓存无法读取，保留有效旧证书', certificate_not_yet_valid: '证书尚未生效，请检查系统时间', certificate_cache_unwritable: '签发结果无法保存，保留旧证书', legacy_certificate_invalid: '历史证书无法安全迁移', challenge_listener: 'ACME 验证监听器异常', certificate_validation: '证书完整校验失败', certificate_invalid: '证书已失效或损坏', certificate_expired: '证书已过期', serving_certificate_mismatch: '线上证书尚未与托管证书一致', serving_probe_timeout: '线上 TLS 探测超时，尚未验证当前状态', serving_dns: '线上 TLS 探测 DNS 解析失败', serving_connection: '线上 TLS 探测连接失败', serving_tls_verification: '线上证书信任链、域名或有效期校验失败', serving_tls_handshake: '线上 TLS 握手失败', controller_unavailable: '证书控制器不可用'};
        section.append(heading, kv([
            ['TLS', facts.enabled ? '已启用' : facts.state === 'DISABLED' ? '未启用' : '待查询'],
            ['管理方式', facts.mode === 'automatic' ? '自动托管' : '待查询'],
            ['状态', labels[facts.state] || '待查询'],
            ['域名', facts.hostname || '待查询'],
            ['SAN', Array.isArray(facts.san) ? facts.san.join(', ') : '待查询'],
            ['签发机构', facts.issuer || '待查询'],
            ['生效时间', localTime(facts.not_before)],
            ['有效期至', localTime(facts.not_after)],
            ['剩余有效期', facts.not_after ? duration(facts.remaining_seconds) : '待查询'],
            ['最近续期', facts.last_renewal === 'success' ? '成功' : facts.last_renewal === 'failed' ? '失败' : '尚无续期记录'],
            ['下次计划续期', facts.next_renewal ? localTime(facts.next_renewal) : '待签发或等待 CA 计划'],
            ['最近错误', facts.last_error ? codes[facts.last_error] || '未知错误' : '无'],
            ['HTTPS 服务', facts.https_ready ? '握手已验证' : '尚未验证可用'],
            ['线上证书一致', facts.serving_matches ? '已验证一致' : '尚未验证一致'],
            ['控制器', facts.controller_running ? '运行中' : '尚未确认'],
            ['验证入口', facts.validation === 'temporary_port80' ? 'Go 临时监听 80，完成即释放' : facts.validation === 'http01' ? 'HTTP-01' : '待查询'],
        ]));
        const buttons = make('div', 'node-card-controls');
        const endpoint = `/${encodeURIComponent(relation.relationship_id)}/certificate`;
        const query = button('查询证书', async () => {
            const state = await api(`/api/v1/media/admin/nodes${endpoint}`);
            certificateViews.set(relation.relationship_id, {at: Date.now(), value: state});
            relation.summary = {...relation.summary, certificate: state};
            section.replaceWith(certificatePanel(relation));
            return `证书${labels[state.state] || '待查询'}，有效期至 ${localTime(state.not_after)}`;
        });
        query.disabled = !observed.state;
        buttons.append(query);
        const download = button('下载证书及私钥', () => downloadCertificate(endpoint, facts));
        download.disabled = !facts.enabled || !facts.https_ready || !facts.serving_matches;
        buttons.append(download);
        section.append(buttons);
        return section;
    }

    async function downloadCertificate(endpoint, facts) {
        if (!window.isSecureContext || !crypto.subtle) throw new Error('证书下载需要安全的浏览器环境');
        const encode = bytes => btoa(Array.from(bytes, value => String.fromCharCode(value)).join('')).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
        const decode = value => Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), char => char.charCodeAt(0));
        const keys = await crypto.subtle.generateKey({name: 'ECDH', namedCurve: 'P-256'}, false, ['deriveBits']);
        const browserPublic = encode(new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey)));
        const browserNonce = encode(crypto.getRandomValues(new Uint8Array(32)));
        const state = await post(endpoint, {action: 'download', browser_public_key: browserPublic, browser_nonce: browserNonce});
        const envelope = state.download;
        if (!envelope || envelope.algorithm !== 'P256-HKDF-SHA256-AES256GCM' || envelope.hostname !== facts.hostname || envelope.browser_nonce !== browserNonce || envelope.fingerprint !== state.fingerprint || !/^[a-f0-9]{64}$/.test(envelope.fingerprint) || envelope.ciphertext.length > 120000) throw new Error('证书下载身份校验失败');
        const aad = new TextEncoder().encode(['frontiercloud.certificate.download.v1', envelope.hostname, envelope.fingerprint, browserNonce].join('\n'));
        const peer = await crypto.subtle.importKey('raw', decode(envelope.public_key), {name: 'ECDH', namedCurve: 'P-256'}, false, []);
        const secret = new Uint8Array(await crypto.subtle.deriveBits({name: 'ECDH', public: peer}, keys.privateKey, 256));
        const material = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']); secret.fill(0);
        const wrapping = await crypto.subtle.deriveKey({name: 'HKDF', hash: 'SHA-256', salt: decode(envelope.salt), info: aad}, material, {name: 'AES-GCM', length: 256}, false, ['decrypt']);
        const raw = new Uint8Array(await crypto.subtle.decrypt({name: 'AES-GCM', iv: decode(envelope.iv), additionalData: aad}, wrapping, decode(envelope.ciphertext)));
        let pair;
        try { pair = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(raw)); } finally { raw.fill(0); }
        if (typeof pair.certificate !== 'string' || pair.certificate.length > 65536 || typeof pair.private_key !== 'string' || pair.private_key.length > 16384 || !pair.private_key.includes('PRIVATE KEY-----')) throw new Error('证书下载内容无效');
        const leaf = pair.certificate.match(/-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/\s=]+?)\s*-----END CERTIFICATE-----/);
        if (!leaf) throw new Error('证书下载内容无效');
        const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', decode(leaf[1].replace(/\s/g, ''))));
        if (Array.from(hash, value => value.toString(16).padStart(2, '0')).join('') !== envelope.fingerprint) throw new Error('证书下载指纹不匹配');
        const url = URL.createObjectURL(new Blob([pair.certificate, '\n', pair.private_key], {type: 'application/x-pem-file'}));
        pair = null;
        const anchor = document.createElement('a'); anchor.href = url; anchor.download = `${envelope.hostname}-tls-key-pair.pem`; document.body.append(anchor); anchor.click(); anchor.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        return '已下载此节点的证书及私钥 PEM 文件';
    }

    function renderRows(node, observed, migrations) {
        const body = $('nodeRelationships'); body.replaceChildren();
        const localCertificate = node.certificate ? {local: true, relationship_id: node.node_id, summary: {certificate: node.certificate}} : null;
        const relations = new Map((node.relationships || []).map(item => [item.peer_id, item]));
        const observedMembers = new Map((observed.members || []).map(item => [item.member_id, item]));
        if (node.storage_pool) {
            for (const member of node.storage_pool.members || []) {
                if (member.member_id === 'auto' || member.member_kind === 'Auto') continue;
                body.append(memberCard(member, relations.get(member.member_id), observedMembers.get(member.member_id), localCertificate));
            }

        }
        if (localCertificate && !(node.storage_pool?.members || []).some(member => member.member_kind === 'MasterLocal')) {
            const row = make('tr', 'node-card-row'), cell = make('td'); cell.colSpan = 4;
            const card = make('article', 'node-card'), grid = make('div', 'node-card-grid');
            const header = make('header', 'node-card-header'); header.append(make('strong', '', `${node.role} · ${node.node_id}`));
            grid.append(certificatePanel(localCertificate)); card.append(header, grid); cell.append(card); row.append(cell); body.append(row);
        }
        if (node.role === 'Master' && migrations) {
            const row = make('tr'); const cell = make('td'); cell.colSpan = 4;
            cell.append(migrationPlanPanel(node), migrationPanel(migrations)); row.append(cell); body.append(row);
        }
    }

    async function refresh() {
        const current = refreshQueue.then(async () => {
            const {node, observability, migrations} = await loadData();
            // Poll a bounded number of visible active tasks. This control
            // telemetry is excluded from business-byte load measurement.
            if (node.role === 'Master') {
                const active = (migrations?.tasks || []).filter(task => ['queued', 'copying', 'verifying', 'committing', 'cleanup_pending', 'cancelling'].includes(task.state)).slice(0, 4);
                for (const task of active) {
                    const value = await api(`/api/v1/media/admin/nodes/migrations/${encodeURIComponent(task.task_id)}`);
                    migrationViews.set(task.task_id, {at: Date.now(), value});
                }
                while (migrationViews.size > 64) migrationViews.delete(migrationViews.keys().next().value);
            }
            $('nodeIdentity').textContent = `${node.role} · ${node.node_id} · ${node.app_version} / v${node.protocol}${node.endpoint ? ' · ' + node.endpoint : ''}`;
            visible('nodePromotion', node.role === 'Standalone'); visible('nodePairing', node.role !== 'Standalone');
            visible('nodeImportPair', node.role === 'Master'); visible('nodeReinitialize', node.role !== 'Standalone');
            $('nodePairPackage').readOnly = false;
            const role = $('nodeRole'), capacity = $('masterLocalCapacity'); capacity.disabled = role.value !== 'Master'; role.onchange = () => { capacity.disabled = role.value !== 'Master'; };
            renderOverview(node, observability);
            const pool = node.storage_pool;
            $('storagePoolSummary').textContent = pool ? `Storage Pool · ${storageText(pool)}` : `${node.role} · 资源策略由 Master 管理`;
            renderRows(node, observability, migrations);
        });
        refreshQueue = current.catch(() => {}); return current;
    }

    function startAutoRefresh() {
        if (refreshTimer) return;
        refreshTimer = setInterval(() => { if (panel.classList.contains('expanded')) refresh().catch(error => setStatus(error.message)); }, 10000);
    }
    function stopAutoRefresh() { if (refreshTimer) clearInterval(refreshTimer); refreshTimer = null; }

    $('nodesRefresh').onclick = () => action(async () => {}, '已刷新');
    panel.querySelector('.module-heading').addEventListener('click', () => { if (panel.classList.contains('expanded')) { refresh().catch(error => setStatus(error.message)); startAutoRefresh(); } else stopAutoRefresh(); });
    $('nodePromotion').onsubmit = event => { event.preventDefault(); const role = $('nodeRole').value; action(() => post('/promote', {role, endpoint: $('nodeEndpoint').value, local_capacity_gib: role === 'Master' ? Number($('masterLocalCapacity').value) : null})); };
    $('nodeImportPair').onclick = () => action(() => post('/pair', {package: JSON.parse($('nodePairPackage').value)}));
    $('nodeReinitialize').onsubmit = event => { event.preventDefault(); action(() => post('/reinitialize', {confirmation: $('nodeResetConfirmation').value})); };
})();
