/* Admin node operations: ingress, fleet status and node controls. */
(() => {
    const $ = id => document.getElementById(id);
    const panel = $('nodesPanel');
    if (!panel) return;

    let refreshTimer = null;
    let refreshQueue = Promise.resolve();
    let s3RefreshGeneration = 0;
    let s3Controller = null;
    let s3CreationSummary = null;
    let s3CreationForm = null;
    let inventory = [];
    let retirementInventoryAvailable = false;
    let s3InventoryState = '';
    const certificateViews = new Map();
    const retirementViews = new Map();
    const expandedNodes = new Set();
    const expandedOperations = new Set();
    const modulePanels = [panel, $('nodeRoutingPanel'), $('nodeBackupsPanel'), $('nodeSettingsPanel')].filter(Boolean);
    const setStatus = text => { for (const id of ['nodeOperationStatus','nodeRoutingStatus','nodeBackupsStatus','nodeSettingsStatus']) if ($(id)) $(id).textContent = text || ''; };
    $('nodeRoutingContent')?.append(panel.querySelector('.node-ingress-card'));
    $('nodeSettingsContent')?.append(panel.querySelector('.node-setup'));
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
        const total = Number(source.physical_total_bytes);
        const free = Number(source.physical_free_bytes);
        const physicalKnown = source.physical_capacity_known !== false
            && source.physical_total_bytes != null && source.physical_free_bytes != null
            && Number.isFinite(total) && Number.isFinite(free) && total >= 0 && free >= 0 && free <= total;
        return {
            physicalKnown,
            total,
            physicalUsed: physicalKnown ? total - free : null,
            allocated: Number(source.current_allocated_bytes ?? source.allocated_bytes ?? 0),
            used: Number(source.project_used_bytes ?? source.used_bytes ?? 0),
        };
    }

    function physicalStorageText(facts) {
        return facts.physicalKnown ? `${gib(facts.physicalUsed)} / ${gib(facts.total)}` : '物理容量未知';
    }

    function storageText(source = {}) {
        const facts = storageFacts(source);
        const physical = facts.physicalKnown ? `物理 used / all ${physicalStorageText(facts)}` : physicalStorageText(facts);
        return `${physical} · 已使用 / 已分配 ${gib(facts.used)} / ${gib(facts.allocated)}`;
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

    function nodeHeading(kind, name, detail, memberId) {
        const identity = make('div', 'node-card-identity');
        const icon = make('span', `node-type-icon ${kind}`, {local: '本', follower: '存', s3: 'S3'}[kind]);
        icon.setAttribute('aria-hidden', 'true');
        const title = make('div', 'node-card-title');
        title.append(make('strong', '', name));
        if (detail) title.append(make('small', '', detail));
        if (memberId) title.append(make('small', 'node-member-id', `NodeID ${memberId}`));
        identity.append(icon, title);
        return identity;
    }

    function nodeConnection(relation, observed) {
        const connection = observed?.connection || {};
        const status = connection.status || relation?.status;
        const latency = Number(connection.current_rtt_ms ?? relation?.rtt_ms);
        const retirement = relation?.state === 'retiring' ? '退役中' : relation?.state === 'revoked' ? (relation.summary?.retirement?.completed_at ? '已退役' : '已撤销') : '';
        return {
            category: retirement ? 'attention' : status === 'online' ? 'ready' : status === 'offline' ? 'offline' : 'attention',
            label: retirement || ({online: '在线', offline: '离线', degraded: '降级', pending: '等待连接'}[status] || '状态待确认'),
            latency: Number.isFinite(latency) && latency > 0 ? `${latency} ms` : '未测得',
        };
    }

    function filterInventory() {
        const term = ($('nodeInventorySearch').value || '').trim().toLowerCase();
        const kind = $('nodeInventoryType').value || 'all';
        const status = $('nodeInventoryStatus').value || 'all';
        let shown = 0;
        for (const item of inventory) {
            item.row.hidden = (kind !== 'all' && item.kind !== kind) ||
                (status !== 'all' && item.status !== status) || !item.text.includes(term);
            if (!item.row.hidden) shown++;
        }
        const count = $('nodeInventoryCount');
        const text = `显示 ${shown} / ${inventory.length} 个节点`;
        if (count.textContent !== text) count.textContent = text;
        const empty = $('nodeInventoryEmpty');
        empty.hidden = shown !== 0;
        if (shown === 0) {
            const includesS3 = kind === 'all' || kind === 's3';
            empty.textContent = includesS3 && s3InventoryState === 'loading' ? '正在读取 S3 节点状态' :
                includesS3 && s3InventoryState === 'unavailable' ? 'S3 节点状态暂不可用，请刷新重试' :
                term || kind !== 'all' || status !== 'all' ? '没有符合条件的节点，请调整筛选' : '当前没有节点可显示';
        }
    }

    function addInventoryRow(row, kind, status, ...search) {
        inventory.push({row, kind, status, text: search.filter(Boolean).join(' ').toLowerCase()});
        $('nodeRelationships').append(row);
    }

    function renderIngress(node, routing) {
        const address = routing?.ingress?.public_origin;
        $('nodeIngressAddress').textContent = address || '—';
        $('nodeIngressStatus').textContent = address
            ? (routing.ingress.generation ? `路由版本 ${routing.ingress.generation}` : '入口已登记')
            : node.role === 'Master' ? '入口状态暂不可用' : node.role === 'Follower' ? '公共入口由主站管理' : '当前为单机模式';
    }

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
        retirementInventoryAvailable = node.retirement_inventory_available === true;
        let observability = {members: [], relationships: []};
        try { observability = await api('/api/v1/media/admin/nodes/observability'); }
        catch (error) { console.warn('node observability unavailable', error); }
        let routing = null;
        if (node.role === 'Master') {
            try { routing = await api('/api/v1/media/admin/nodes/public-routing'); }
            catch (error) { console.warn('public routing unavailable', error); }
        }
        return {node, observability, routing};
    }

    function s3Request(path, method, body) {
        return api('/api/v1/media/admin/nodes/s3' + path, {
            method, headers: requestHeaders(), body: JSON.stringify(body),
        });
    }

    function s3Form(member = null, recovery = false) {
        const form = make('form', 'node-s3-form');
        const fields = {};
        const field = (name, label, type = 'text', value = '', required = false) => {
            const wrapper = make('label', 'node-s3-field', label);
            const input = make('input'); input.type = type; input.value = value;
            input.required = required; input.autocomplete = 'off';
            input.setAttribute('aria-label', label);
            fields[name] = input; wrapper.append(input); form.append(wrapper);
            return input;
        };
        if (!recovery) {
            field('name', '显示名称', 'text', member?.name || '', true).maxLength = 100;
            field('endpoint', 'HTTPS 服务地址', 'url', member?.location?.endpoint || '', true);
            field('bucket', '存储桶', 'text', member?.location?.bucket || '', true);
            field('region', '区域', 'text', member?.location?.region || '', true);
            field('prefix', '对象前缀', 'text', member?.location?.prefix || '');
            const styleLabel = make('label', 'node-s3-field', '寻址方式');
            const style = make('select'); fields.style = style;
            for (const [value, label] of [['auto', '自动'], ['path', '路径'], ['virtual', '虚拟主机']]) {
                const option = make('option', '', label); option.value = value; style.append(option);
            }
            style.value = member?.location?.style || 'auto'; styleLabel.append(style); form.append(styleLabel);
            const capacity = field('capacity', '分配配额（GiB）', 'number', String((member?.allocated_bytes || 1073741824) / 1073741824), true);
            capacity.min = '1'; capacity.max = '10240'; capacity.step = '0.01';
            if (member) {
                const enabledLabel = make('label', 'node-s3-enabled');
                const enabled = make('input'); enabled.type = 'checkbox'; enabled.checked = Boolean(member.storage_enabled);
                fields.enabled = enabled; enabledLabel.append(enabled, document.createTextNode('允许新上传（需先通过检查）')); form.append(enabledLabel);
            }
        }
        field('access_key', member && !recovery ? 'Access Key（留空保留）' : 'Access Key', 'password', '', !member || recovery);
        field('secret_key', member && !recovery ? 'Secret Key（留空保留）' : 'Secret Key', 'password', '', !member || recovery);
        field('session_token', '临时会话令牌（可选）', 'password');
        field('expires_at', '临时凭据到期时间（可选）', 'datetime-local');
        form.append(make('p', 'node-note', recovery
            ? '此凭据只用于清理未决对象，不恢复新写入。密钥不会显示或回填。'
            : '密钥仅提交时发送，不会显示或回填。容量是项目配额；供应商物理容量与外部流量未知。'));
        const submit = make('button', 'apply', recovery ? '提交清理凭据' : member ? '保存 S3 配置' : '添加 S3 存储');
        submit.type = 'submit'; form.append(submit);
        form.onsubmit = event => {
            event.preventDefault();
            const credentialsPresent = Boolean(fields.access_key.value || fields.secret_key.value || fields.session_token.value || fields.expires_at.value);
            if (credentialsPresent && (!fields.access_key.value || !fields.secret_key.value)) {
                setStatus('请完整填写 Access Key 和 Secret Key'); return;
            }
            const credentials = credentialsPresent ? {access_key: fields.access_key.value, secret_key: fields.secret_key.value,
                session_token: fields.session_token.value, expires_at: fields.expires_at.value ? Math.floor(new Date(fields.expires_at.value).getTime() / 1000) : 0} : null;
            if (credentials && !Number.isSafeInteger(credentials.expires_at)) {
                setStatus('凭据到期时间无效'); return;
            }
            const payload = recovery ? {revision: member.revision, credentials} : {
                ...(member ? {revision: member.revision} : {}), name: fields.name.value.trim(),
                location: {endpoint: fields.endpoint.value.trim(), bucket: fields.bucket.value.trim(), region: fields.region.value.trim(), prefix: fields.prefix.value.trim(), style: fields.style.value},
                allocated_bytes: Math.round(Number(fields.capacity.value) * 1073741824), enabled: fields.enabled?.checked ?? false,
                ...(credentials ? {credentials} : {}),
            };
            submit.disabled = true;
            // Clear the live password inputs immediately. API responses never populate them.
            for (const name of ['access_key', 'secret_key', 'session_token']) fields[name].value = '';
            action(async () => {
                await s3Request(member ? `/${encodeURIComponent(member.member_id)}${recovery ? '/recovery-credentials' : ''}` : '', recovery ? 'POST' : member ? 'PATCH' : 'POST', payload);
                return recovery ? '清理凭据已提交；未决状态将持续保留至核验完成' : 'S3 配置已保存；新配置需通过连通性检查后启用';
            }).finally(() => { submit.disabled = false; });
        };
        return form;
    }

    function s3Card(member, configurationMode) {
        const row = make('tr', 'node-card-row'), cell = make('td');
        const card = make('article', 'node-card'), header = make('header', 'node-card-header');
        const badges = make('div', 'node-card-badges');
        const legacyConfiguration = configurationMode === 'legacy';
        const state = member.cleanup_only ? '仅清理' : member.probe_state === 'ready' ? (legacyConfiguration ? '检查通过' : '上次检查通过') : member.probe_state === 'running' ? '检查中' : '待检查';
        badges.append(pill('S3', 'muted'), pill(member.storage_enabled ? '已启用' : '未启用', member.storage_enabled ? 'good' : 'muted'), pill(state, member.cleanup_only ? 'warn' : 'muted'));
        header.append(nodeHeading('s3', member.name || member.location?.bucket || 'S3 存储', member.location?.endpoint || '地址不可用'), badges);
        collapsibleNodeCard(card, header, member.member_id, [
            ['已使用 / 已分配', `${gib(member.used_bytes)} / ${gib(member.allocated_bytes)}`],
            ['预留容量', gib(member.reserved_bytes)], ['物理容量', '物理容量未知'],
        ], () => {
                const details = make('div', 'node-s3-details');
                details.append(kv([['存储桶', member.location?.bucket || '-'], ['对象前缀', member.location?.prefix || '/'], ['外部流量', '未知'], ['凭据到期', member.credential_expires_at ? localTime(member.credential_expires_at) : '长期凭据'], ['状态', member.error_code || state]]));
                const actions = make('div', 'node-card-actions');
                actions.append(button('检查连接与读写', async () => {
                    const result = await s3Request(`/${encodeURIComponent(member.member_id)}/test`, 'POST', {revision: member.revision});
                    return result.cleanup_uncertain ? '检查结果包含未决清理，请保留配置并等待核验' : '连通性检查已完成，请查看最新状态';
                }, 'apply'), button('移除配置', async () => {
                    if (!window.confirm('仅在没有对象、上传和未决清理时移除此 S3 配置？')) return '已保留配置';
                    await s3Request(`/${encodeURIComponent(member.member_id)}`, 'DELETE', {revision: member.revision});
                    return 'S3 配置已移除';
                }, 'danger'));
                details.append(actions);
                if (legacyConfiguration) {
                    const configure = make('details'); configure.append(make('summary', '', '配置与凭据'), s3Form(member)); details.append(configure);
                    const recovery = make('details'); recovery.append(make('summary', '', '未决清理凭据'), s3Form(member, true)); details.append(recovery);
                } else if (configurationMode === 'sealed') {
                    const enabled = Boolean(member.storage_enabled);
                    const change = button(enabled ? '停用新上传' : '启用新上传', async () => {
                        await s3Request(`/${encodeURIComponent(member.member_id)}`, 'PATCH', {
                            revision: member.revision, name: member.name, location: member.location,
                            allocated_bytes: member.allocated_bytes, enabled: !enabled,
                        });
                        return enabled ? '已停用新上传' : '已启用新上传';
                    }, 'apply');
                    change.disabled = enabled ? member.used_bytes !== 0 || member.reserved_bytes !== 0 : member.probe_state !== 'ready' || member.cleanup_only;
                    actions.append(change);
                    details.append(make('p', 'node-note', '重启后需重新检查。仅从未使用的节点可停用。当前密文存储暂不支持修改配置或凭据。'));
                } else {
                    details.append(make('p', 'node-note', '配置能力待确认，请刷新后重试。'));
                }
                return [details];
            });
        cell.append(card); row.append(cell); return row;
    }

    function s3Creation(master, state) {
        s3InventoryState = master ? state : '';
        let section = $('nodeS3Creation');
        if (!section) {
            section = make('details', 'node-pairing-details'); section.id = 'nodeS3Creation';
            s3CreationSummary = make('summary');
            s3CreationForm = s3Form();
            section.append(s3CreationSummary, s3CreationForm);
            const anchor = $('nodePairingSetup') || panel.querySelector('.nodes-table-scroll');
            anchor.after(section);
        }
        section.hidden = !master;
        s3CreationSummary.textContent = state === 'loading' ? 'S3 状态加载中' : state === 'unavailable' ? 'S3 状态暂不可用，请刷新后重试' : '添加 S3 存储';
        s3CreationForm.hidden = state !== 'ready';
        filterInventory();
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
        const members = new Map((observed.members || []).map(item => [item.member_id, item]));
        const relations = new Map((node.relationships || []).map(item => [item.relationship_id, item]));
        const followers = (pool.members || []).filter(item => item.member_kind === 'Follower');
        const online = followers.filter(item => nodeConnection(relations.get(item.relationship_id), members.get(item.member_id)).category === 'ready').length;
        const backups = followers.map(item => members.get(item.member_id)?.backup || item.backup);
        const backupEnabled = backups.filter(item => item?.enabled).length;
        const backupHealthy = backups.filter(item => item?.enabled && item.health === 'healthy').length;
        const poolFacts = storageFacts(pool);
        overview.append(
            overviewCard('原生存储节点', `${online} / ${followers.length}`, !followers.length ? '尚未配对存储节点' : online === followers.length ? '全部在线' : '存在离线或待确认节点', online === followers.length ? 'good' : 'compute'),
            overviewCard('Storage', physicalStorageText(poolFacts), `${poolFacts.physicalKnown ? '物理 used / all · ' : ''}已使用 / 已分配 ${gib(poolFacts.used)} / ${gib(poolFacts.allocated)}`, 'storage'),
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
        const usage = observed?.observed?.host_usage;
        if (usage) {
            const facts = [];
            if (Number.isInteger(usage.cpu_percent)) facts.push(['整机 CPU', `${usage.cpu_percent}%`]);
            if (Number.isSafeInteger(usage.memory_used_bytes) && usage.memory_total_bytes > 0) {
                facts.push(['整机内存（已用 / 总量）', `${gib(usage.memory_used_bytes)} / ${gib(usage.memory_total_bytes)}`]);
            }
            if (facts.length) section.append(kv(facts));
        }
        section.append(make('div', 'node-note', state === 'local' ? 'Master Local 是本机资源。' : 'RTT 是 Master 到该节点 HTTPS 控制面的往返时间。'));
        return section;
    }

    function storagePanel(member, observed) {
        const section = make('section', 'node-resource-panel storage');
        const heading = make('div', 'node-resource-heading');
        heading.append(make('strong', '', 'Storage'), pill(member.storage_enabled ? 'Enabled' : 'Disabled', member.storage_enabled ? 'info' : 'muted'));
        const facts = storageFacts(member);
        section.append(heading, make('div', 'node-metric-primary', physicalStorageText(facts)), kv([
            ['物理 used / all', physicalStorageText(facts)],
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
        make('div', 'node-note', 'Master 每 24 小时写入加密状态恢复点，包含数据库与歌词；失败约 5 分钟后重试。恢复仍需保留主站密钥和原媒体资源。'));
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
        actions.append(button('应用资源配置', async () => {
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

    function collapsibleNodeCard(card, header, identity, summary, renderDetails) {
        const details = make('div', 'node-card-details');
        details.id = `node-details-${identity}`;
        const toggle = make('span', 'node-details-toggle');
        toggle.setAttribute('aria-hidden', 'true');
        header.setAttribute('role', 'button');
        header.tabIndex = 0;
        header.setAttribute('aria-controls', details.id);
        let rendered = false;
        const sync = () => {
            const expanded = expandedNodes.has(identity);
            toggle.textContent = expanded ? '收起详情' : '查看详情';
            toggle.setAttribute('aria-expanded', String(expanded));
            header.setAttribute('aria-expanded', String(expanded));
            details.hidden = !expanded;
            if (expanded && !rendered) {
                details.append(...renderDetails());
                rendered = true;
            }
        };
        const changeExpanded = () => {
            if (expandedNodes.has(identity)) expandedNodes.delete(identity);
            else expandedNodes.add(identity);
            sync();
        };
        header.onclick = () => {
            if (window.getSelection()?.toString()) return;
            changeExpanded();
        };
        header.onkeydown = event => {
            if (event.target !== header || event.repeat || !['Enter', ' '].includes(event.key)) return;
            event.preventDefault();
            changeExpanded();
        };
        const facts = make('div', 'node-card-summary');
        for (const [label, value] of summary) {
            const fact = make('div', 'node-row-fact');
            fact.append(make('small', '', label), make('strong', '', value));
            facts.append(fact);
        }
        header.append(facts, toggle);
        card.append(header, details);
        sync();
    }

    function transportPolicyPanel(member, policy, ingress, selectionEnabled = false, targetOrigin = '') {
        const section = make('section', 'node-resource-panel');
        const isMaster = member.member_kind === 'MasterLocal';
        section.append(make('strong', '', '公共资源访问'));
        const labels = {confirmation_required: '历史设置待确认', retained: '当前入口使用 Local，非入口策略已保留', legacy_confirmed: '历史设置已确认，节点应用尚未验证', blocked: '目标策略待应用或条件未就绪', applied: '节点已确认策略', inactive: '关系未激活'};
        const applicationLabels = {pending: '等待节点确认', failed: '节点暂不能应用', applied: '节点已确认'};
        section.append(kv([
            ['当前入口', ingress?.node_id === member.member_id ? '此节点' : '其他节点'],
            ['当前有效访问方式', policy.effective_transport || '未知'],
            ['非入口时的配置策略', policy.configured_transport || '待选择'],
            ['配置版本', String(policy.revision || 0)],
            ['节点确认的策略', policy.applied_transport || '尚未验证'],
            ['节点确认的资源地址', policy.applied_origin || '未适用'],
            ['节点应用状态', isMaster && policy.state === 'retained' ? (policy.applied_transport ? '本机已确认非入口策略' : '非入口时待确认') : applicationLabels[policy.peer_application_status] || '尚未请求'],
            ['历史路由模式', policy.legacy_transport || '未适用'],
            ['状态', labels[policy.state] || '未知'],
        ]));
        const mode = make('select');
        mode.setAttribute('aria-label', '非入口时资源传输策略');
        if (!policy.configured_transport) {
            const empty = make('option', '', '请选择'); empty.value = ''; mode.append(empty);
        }
        for (const value of ['Direct', 'Relay']) {
            const option = make('option', '', value); option.value = value; mode.append(option);
        }
        mode.value = policy.configured_transport || '';
        mode.disabled = policy.state === 'inactive';
        const save = button('保存非入口策略', async () => {
            if (!mode.value) throw new Error('请选择 Direct 或 Relay');
            const result = await post(`/public-routing/transport/${encodeURIComponent(member.member_id)}`, {configured_transport: mode.value, revision: policy.revision});
            return result.state === 'blocked' ? '目标策略已保存但尚未生效；请检查节点应用状态' : result.state === 'legacy_confirmed' ? '已确认当前历史策略；节点应用尚未验证' : '策略已保存；请检查当前状态';
        }, 'apply');
        save.disabled = policy.state === 'inactive';
        section.append(mode, save, make('p', 'node-note', isMaster
            ? '保存策略不会更改当前路径或启用其他入口。'
            : '节点确认表示节点接受了策略；实际访问方式及链路验证仍需分别确认。'));
        if (!isMaster) {
            const check = button('检查入口候选', async () => {
                const result = await post(`/public-routing/candidates/${encodeURIComponent(member.member_id)}/check`, {});
                return result.selection_enabled
                    ? `候选 ${result.origin} 的身份和代理链检查通过；可以显式选择公共入口`
                    : `候选 ${result.origin} 的身份和代理链检查通过；完整能力验证及入口选择尚未开放`;
            });
            check.disabled = policy.state === 'inactive';
            section.append(check);
        }
        const selectIngress = make('button', '', '选择为公共入口');
        selectIngress.type = 'button';
        selectIngress.disabled = !selectionEnabled || !ingress?.generation || !ingress.public_origin || !targetOrigin || ingress.node_id === member.member_id || policy.state === 'inactive';
        selectIngress.onclick = async () => {
            if (selectIngress.disabled || !window.confirm(`确认切换公共入口？\n\n当前入口 ${ingress.public_origin}\n目标入口 ${targetOrigin}`)) return;
            selectIngress.disabled = true;
            try {
                await action(async () => {
                    const result = await post('/public-routing/select', {member_id: member.member_id, generation: ingress.generation, public_origin: targetOrigin});
                    return `已选择公共入口 ${result.public_origin}`;
                });
            } finally { selectIngress.disabled = false; }
        };
        section.append(selectIngress);
        if (!selectionEnabled) section.append(make('p', 'node-note', '入口选择等待完整能力验证。'));
        return section;
    }

    function memberCard(member, relation, observed, localCertificate, policy, ingress, selectionEnabled, masterPublicOrigin) {
        const row = document.createElement('tr'); row.className = 'node-card-row';
        const cell = document.createElement('td');
        const card = make('article', 'node-card');
        const header = make('header', 'node-card-header');
        const local = member.member_kind === 'MasterLocal';
        const endpoint = relation?.peer_endpoint;
        const name = member.name || relation?.summary?.servername;
        const connection = nodeConnection(relation, observed);
        const transport = member.transport || relation?.mode || 'Local';
        const transportTone = {direct: 'transport-direct', relay: 'transport-relay'}[transport.toLowerCase()] || 'muted';
        const badges = make('div', 'node-card-badges');
        badges.append(pill(local ? '本机' : connection.label, local ? 'info' : connection.category === 'ready' ? 'good' : connection.category === 'offline' ? 'bad' : 'warn'), pill(transport, transportTone));
        if (ingress?.node_id === member.member_id) badges.append(pill('当前入口', 'info'));
        header.append(nodeHeading(local ? 'local' : 'follower', local ? 'Master Local' : name || endpoint || '存储节点',
            local ? '主站本机存储' : name && endpoint ? endpoint : '', local ? '' : member.member_id), badges);
        const facts = storageFacts(observed?.storage || member);
        const backup = observed?.backup || member.backup;
        const backupStatus = {healthy: '健康', running: '备份中', failed: '失败', stale: '过期', 'waiting-first-backup': '等待首份备份'};
        collapsibleNodeCard(card, header, member.member_id, [
            ['控制面 RTT', local ? '本机' : connection.latency], ['已使用 / 已分配', `${gib(facts.used)} / ${gib(facts.allocated)}`],
        ], () => {
            const grid = make('div', 'node-card-grid');
            grid.append(connectionPanel(relation, observed), storagePanel(member, observed));
            return [grid];
        });
        cell.append(card); row.append(cell);
        return row;
    }

    function retirementPanel(member, relation) {
        const section = make('section', 'node-resource-panel');
        if (relation.state === 'revoked' && relation.summary?.retirement?.completed_at) {
            section.append(make('strong', '', '已安全退役'), kv([['NodeID', member.member_id], ['完成时间', localTime(relation.summary.retirement.completed_at)]]));
            section.append(make('p', 'node-note', '旧工作凭据已失效；身份、审计、容器和卷继续保留。物理清理由运维独立处理。'));
            return section;
        }
        section.append(make('strong', '', '退役检查'));
        if (!retirementInventoryAvailable) {
            section.append(make('p', 'node-note', '当前部署尚不支持完整退役盘点，检查与退役暂不可用。请保留节点及数据；未知文件不能作为清理依据。'));
            return section;
        }
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
        const labels = {DISABLED: '未启用 TLS', PENDING: '等待证书', VALIDATING: '验证域名 / IP', ISSUING: '签发中', ACTIVE: '已生效', RENEWING: '续期中', DEGRADED: '降级，需检查', FAILED: '失败'};
        const codes = {dns: 'DNS 未就绪或解析失败', port80_busy: '80 端口被占用', http01_unreachable: '公网 HTTP-01 不可达', http01_ingress: '等待内部 Challenge 入口就绪', authorization: '域名 / IP 授权失败', caa: 'CAA 限制', rate_limited: 'CA 限流，自动退避', ca_unavailable: 'CA 暂不可用', ca_timeout: 'CA 请求超时', ca_error: 'CA 请求失败', domain_rejected: 'CA 拒绝域名 / IP', system_clock: '系统时间异常', interrupted: '上次操作中断', journal_unwritable: '状态无法持久化', journal_recovered: '已保护损坏记录，等待安全重试', certificate_cache_unreadable: '证书缓存无法读取，保留有效旧证书', certificate_not_yet_valid: '证书尚未生效，请检查系统时间', certificate_cache_unwritable: '签发结果无法保存，保留旧证书', certificate_issuance_invalid: '签发结果未通过安全校验，自动退避重试', legacy_certificate_invalid: '历史证书无法安全迁移', challenge_listener: 'ACME 验证监听器异常', certificate_validation: '证书完整校验失败', certificate_invalid: '证书已失效或损坏', certificate_expired: '证书已过期', serving_certificate_mismatch: '线上证书尚未与托管证书一致', serving_probe_timeout: '线上 TLS 探测超时，尚未验证当前状态', serving_dns: '线上 TLS 探测 DNS 解析失败', serving_connection: '线上 TLS 探测连接失败', serving_tls_verification: '线上证书信任链、域名 / IP SAN 或有效期校验失败', serving_tls_handshake: '线上 TLS 握手失败', controller_unavailable: '证书控制器不可用'};
        section.append(heading, kv([
            ['TLS', facts.enabled ? '已启用' : facts.state === 'DISABLED' ? '未启用' : '待查询'],
            ['管理方式', facts.mode === 'automatic' ? '自动托管' : '待查询'],
            ['状态', labels[facts.state] || '待查询'],
            ['域名 / IP', facts.hostname || '待查询'],
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

    function renderRows(node, observed, routing) {
        const body = $('nodeRelationships'); body.replaceChildren();
        inventory = [];
        const localCertificate = node.certificate ? {local: true, relationship_id: node.node_id, summary: {certificate: node.certificate}} : null;
        const relations = new Map();
        for (const relation of node.relationships || []) {
            if (!relations.has(relation.peer_id)) relations.set(relation.peer_id, []);
            relations.get(relation.peer_id).push(relation);
        }
        const memberRelation = member => {
            const matches = relations.get(member.member_id) || [];
            const current = member.relationship_id ? matches.filter(item => item.relationship_id === member.relationship_id) : matches;
            return current.length === 1 ? current[0] : null;
        };
        const observedMembers = new Map((observed.members || []).map(item => [item.member_id, item]));
        const policies = new Map((routing?.native_transport_policies || []).map(item => [item.member_id, item]));
        if (node.storage_pool) {
            for (const member of node.storage_pool.members || []) {
                if (member.member_id === 'auto' || member.member_kind === 'Auto' || member.member_kind === 'S3') continue;
                const relation = memberRelation(member);
                const observation = observedMembers.get(member.member_id);
                const local = member.member_kind === 'MasterLocal';
                const row = memberCard(member, relation, observation, localCertificate, policies.get(member.member_id), routing?.ingress, routing?.selection_enabled, routing?.master_public_origin);
                addInventoryRow(row, local ? 'local' : 'follower', local ? 'ready' : nodeConnection(relation, observation).category,
                    local ? 'Master Local 本机' : member.member_id, member.name, relation?.summary?.servername, relation?.peer_endpoint, local ? node.endpoint : '');
            }
        }
        renderOperationalModules(node, observed, routing, memberRelation, localCertificate);
        if (localCertificate && !(node.storage_pool?.members || []).some(member => member.member_kind === 'MasterLocal')) {
            const row = make('tr', 'node-card-row'), cell = make('td');
            const card = make('article', 'node-card');
            const header = make('header', 'node-card-header');
            header.append(nodeHeading('local', node.endpoint || '当前节点', node.role, node.role === 'Follower' ? node.node_id : ''),
                make('div', 'node-card-badges'));
            collapsibleNodeCard(card, header, node.node_id, [['可查看', '本机证书']], () => {
                const grid = make('div', 'node-card-grid'); grid.append(certificatePanel(localCertificate)); return [grid];
            });
            cell.append(card); row.append(cell);
            addInventoryRow(row, 'local', 'ready', node.endpoint, node.role, node.role === 'Follower' ? node.node_id : '', '本机');
        }
    }


    function renderOperationalModules(node, observed, routing, memberRelation, localCertificate) {
        for (const id of ['nodeRoutingCards', 'nodeBackupCards', 'nodeSettingsCards']) $(id)?.remove();
        const targets = {};
        for (const [key, id] of [['routing','nodeRouting'],['backup','nodeBackups'],['settings','nodeSettings']]) {
            const list = make('div', 'node-module-list');
            list.id = key === 'routing' ? 'nodeRoutingCards' : key === 'backup' ? 'nodeBackupCards' : 'nodeSettingsCards';
            $(id + 'Content')?.append(list); targets[key] = list;
        }
        const observations = new Map((observed.members || []).map(item => [item.member_id,item]));
        const policies = new Map((routing?.native_transport_policies || []).map(item => [item.member_id,item]));
        function append(key, member, build) {
            const box = make('details', 'node-module-card');
            const summary = make('summary');
            const relation = memberRelation(member);
            const name = member.name || relation?.summary?.servername || (member.member_kind === 'MasterLocal' ? '主站本机' : '存储节点');
            summary.textContent = `${name} · ${relation?.peer_endpoint || routing?.master_public_origin || ''} · ID ${member.member_id}`;
            if (key === 'backup') {
                const backup = observations.get(member.member_id)?.backup || {};
                summary.append(make('span','node-note', ` · ${backup.enabled ? '已开启' : '未开启'} · 恢复点 ${backup.recovery_points || 0} · ${backup.last_success ? '最近成功 '+localTime(backup.last_success) : '尚无成功备份'}`));
            }
            box.append(summary);
            let rendered = false;
            const stateKey = key + ':' + member.member_id;
            box.ontoggle = () => {
                if (box.open) expandedOperations.add(stateKey); else expandedOperations.delete(stateKey);
                if (box.open && !rendered) { const content=make('div','node-card-grid'); content.append(...build()); box.append(content); rendered=true; }
            };
            box.open = expandedOperations.has(stateKey);
            targets[key].append(box);
        }
        for (const member of node.storage_pool?.members || []) {
            if (['S3','Auto'].includes(member.member_kind) || member.member_id === 'auto') continue;
            const relation=memberRelation(member), observation=observations.get(member.member_id), policy=policies.get(member.member_id);
            if (policy) append('routing', member, () => [transportPolicyPanel(member,policy,routing?.ingress,routing?.selection_enabled,member.member_kind==='MasterLocal'?routing?.master_public_origin:relation?.summary?.public_ingress_candidate_origin)]);
            if (member.member_kind !== 'MasterLocal') append('backup',member,()=>[backupPanel(member,observation)]);
            append('settings',member,()=>{
                const parts=[controls(member,relation)];
                if(member.member_kind==='MasterLocal' && localCertificate) parts.push(certificatePanel(localCertificate));
                if(relation?.direction==='downstream' && relation.state==='active') parts.push(certificatePanel(relation));
                if(relation?.direction==='downstream' && ['active','retiring','revoked'].includes(relation.state)) parts.push(retirementPanel(member,relation));
                return parts;
            });
        }
        if (!targets.backup.children.length) targets.backup.append(make('p','node-note','尚无可配置备份的存储节点。'));
    }
    async function refresh() {
        const generation = ++s3RefreshGeneration;
        if (s3Controller) s3Controller.abort();
        s3Controller = null;
        const current = refreshQueue.then(async () => {
            const {node, observability, routing} = await loadData();
            if (generation !== s3RefreshGeneration) return;
            $('nodeIdentity').textContent = `${node.role} · ${node.app_version} / v${node.protocol}${node.endpoint ? ' · ' + node.endpoint : ''}`;
            visible('nodePromotion', node.role === 'Standalone'); visible('nodePairing', node.role !== 'Standalone');
            visible('nodeImportPair', node.role === 'Master'); visible('nodeReinitialize', node.reinitialize_available === true);
            $('nodePairPackage').readOnly = false;
            const role = $('nodeRole'), capacity = $('masterLocalCapacity'); capacity.disabled = role.value !== 'Master'; role.onchange = () => { capacity.disabled = role.value !== 'Master'; };
            renderIngress(node, routing);
            renderOverview(node, observability);
            const pool = node.storage_pool;
            $('storagePoolSummary').textContent = pool ? `Storage Pool · ${storageText(pool)}` : `${node.role} · 资源策略由 Master 管理`;
            renderRows(node, observability, routing);
            const master = node.role === 'Master';
            s3Creation(master, master ? 'loading' : 'ready');
            if (master) {
                const controller = new AbortController();
                s3Controller = controller;
                api('/api/v1/media/admin/nodes/s3', {signal: controller.signal}).then(data => {
                    if (generation !== s3RefreshGeneration) return;
                    const members = Array.isArray(data) ? data : (data.members || data.items || []);
                    if (!Array.isArray(members)) throw new Error('S3 状态无效');
                    for (const member of members) {
                        const category = member.storage_enabled && !member.cleanup_only && member.probe_state === 'ready' ? 'ready' : 'attention';
                        addInventoryRow(s3Card(member, data.configuration_mode), 's3', category, 'S3', member.name, member.location?.endpoint, member.location?.bucket);
                    }
                    s3Creation(true, 'ready');
                }).catch(() => {
                    if (generation === s3RefreshGeneration) s3Creation(true, 'unavailable');
                }).finally(() => {
                    if (s3Controller === controller) s3Controller = null;
                });
            }
        });
        refreshQueue = current.catch(() => {}); return current;
    }

    function startAutoRefresh() {
        if (refreshTimer) return;
        refreshTimer = setInterval(() => {
            const active = document.activeElement;
            const editing = active && (active.matches('input, select, textarea') || active.isContentEditable)
                && !['nodeInventorySearch', 'nodeInventoryType', 'nodeInventoryStatus'].includes(active.id)
                && modulePanels.some(item => item.contains(active));
            if (modulePanels.some(item => item.classList.contains('expanded')) && !editing) refresh().catch(error => setStatus(error.message));
        }, 10000);
    }
    function stopAutoRefresh() { if (refreshTimer) clearInterval(refreshTimer); refreshTimer = null; }

    $('nodesRefresh').onclick = () => action(async () => {}, '已刷新');
    $('nodeInventorySearch').oninput = filterInventory;
    $('nodeInventoryType').onchange = filterInventory;
    $('nodeInventoryStatus').onchange = filterInventory;
    for (const item of modulePanels) item.querySelector('.module-heading').addEventListener('click', () => { if (item.classList.contains('expanded')) { refresh().catch(error => setStatus(error.message)); startAutoRefresh(); } else if (!modulePanels.some(other => other.classList.contains('expanded'))) stopAutoRefresh(); });
    $('nodePromotion').onsubmit = event => { event.preventDefault(); const role = $('nodeRole').value; action(() => post('/promote', {role, endpoint: $('nodeEndpoint').value, local_capacity_gib: role === 'Master' ? Number($('masterLocalCapacity').value) : null})); };
    $('nodeImportPair').onclick = () => action(() => post('/pair', {package: JSON.parse($('nodePairPackage').value)}));
    $('nodeReinitialize').onsubmit = event => { event.preventDefault(); action(() => post('/reinitialize', {confirmation: $('nodeResetConfirmation').value})); };
})();
