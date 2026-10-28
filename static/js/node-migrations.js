/* Independent Admin resource migration module; transfer authority remains on Master. */
(() => {
    const $ = id => document.getElementById(id);
    const panel = $('migrationsPanel');
    if (!panel) return;
    let refreshTimer = null;
    let refreshQueue = Promise.resolve();
    const migrationViews = new Map();
    let migrationCursor = {time: 0, id: ''};
    let migrationQueueView = true;
    let migrationPlan = null;
    const migrationSelection = {source: '', target: ''};
    const setStatus = text => { $('migrationOperationStatus').textContent = text || ''; };
    const post = (path, value = {}) => api(`/api/v1/media/admin/nodes${path}`, {
        method: 'POST', headers: requestHeaders(), body: JSON.stringify(value),
    });
    const dataSize = value => {
        const bytes = Math.max(0, Number(value || 0));
        if (bytes >= 1073741824) return `${(bytes / 1073741824).toFixed(2)} GiB`;
        if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(2)} MiB`;
        if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
        return `${Math.round(bytes)} B`;
    };
    const localTime = stamp => stamp ? new Date(Number(stamp) * 1000).toLocaleString() : '从未';
    function make(tag, className = '', text = '') {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== '') node.textContent = text;
        return node;
    }

    function kv(items) {
        const grid = make('div', 'node-kv');
        for (const [label, value] of items) grid.append(make('span', '', label), make('span', '', String(value)));
        return grid;
    }

    // A historical task may outlive a node relationship. Resolve an endpoint
    // only when it is unambiguously bound to the member's current identity.
    function memberRelationship(node, member) {
        if (!member || typeof member.member_id !== 'string') return null;
        const matches = (node?.relationships || []).filter(item => item.peer_id === member.member_id);
        const current = member.relationship_id ? matches.filter(item => item.relationship_id === member.relationship_id) : matches;
        return current.length === 1 ? current[0] : null;
    }

    function memberLabel(node, id) {
        const member = (node?.storage_pool?.members || []).find(item => item.member_id === id);
        if (member?.member_kind === 'S3') return `S3 · ${id}`;
        if (member?.member_kind === 'MasterLocal') return `Master Local · ${id}`;
        if (member?.member_kind !== 'Follower') return `NodeID ${id}`;
        const relation = memberRelationship(node, member);
        let host = '';
        if (typeof relation?.peer_endpoint === 'string') {
            try {
                const endpoint = new URL(relation.peer_endpoint);
                if (endpoint.protocol === 'https:' && !endpoint.username && !endpoint.password) host = endpoint.host;
            } catch (_) { /* A missing or malformed endpoint is not an identity. */ }
        }
        return host ? `${host} · ${id}` : `NodeID ${id}`;
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
                const relationship = memberRelationship(node, member);
                if (member.member_kind !== 'Follower') reasons.push('Master Local 不支持');
                if (member.member_kind === 'Follower' && relationship?.state !== 'active') reasons.push(relationship?.state === 'retiring' ? '退役处理中' : '节点关系未生效');
                if (member.health !== 'online') reasons.push('离线或不健康');
                if (key === 'target' && (!member.storage_enabled || !member.writable || member.draining)) reasons.push('不可写或排空中');
                const option = make('option', '', `${memberLabel(node, member.member_id)} · ${member.transport || member.member_kind}${reasons.length ? ' · ' + reasons.join('、') : ''}`);
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
        section.append(kv([['计划', plan.plan_id], ['状态', plan.state], ['源节点', memberLabel(node, plan.source.member_id)], ['目标节点', memberLabel(node, plan.target.member_id)], ['源 → 目标类型', `${plan.source.transport || '?'} → ${plan.target.transport || '?'}`], ['归属单元 / 对象', `${plan.unit_count} / ${plan.object_count}`], ['实际字节', dataSize(plan.total_bytes)], ['已校验', `${plan.verified_objects} 个 / ${dataSize(plan.verified_bytes)}`], ['目标已用 / 预留', `${dataSize(plan.target.used_bytes)} / ${dataSize(plan.target.reserved_bytes)}`], ['目标最小可用 / 额外需求', `${dataSize(plan.target_physical_free)} / ${dataSize(plan.additional_target_bytes)}`], ['计划到期', localTime(plan.expires_at)]]));
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
            if (window.prompt(`请输入 True，确认整节点迁出。\n源：${memberLabel(node, plan.source.member_id)}\n目标：${memberLabel(node, plan.target.member_id)}\n开始后源节点进入排空，后台重新检查源字节、目标冲突和容量；旧计划变化将被拒绝。`) !== 'True') return '未发送开始请求';
            migrationPlan = await post(`/migration-plans/${encodeURIComponent(plan.plan_id)}/start`, {review_sha256: plan.review_sha256, confirm_source_id: plan.source.member_id, confirm_target_id: plan.target.member_id});
            return '执行前复核已开始；持久任务创建后将在下方显示';
        }));
        if (plan.task) section.append(make('p', '', `持久任务：${plan.task.task_id} · ${plan.task.state}`));
        return section;
    }

    function migrationPanel(page, node) {
        const section = make('section', 'node-resource-panel');
        section.append(make('strong', '', migrationQueueView ? '资源迁移任务 · 队列与待处理项' : '资源迁移任务 · 历史'));
        section.append(button(migrationQueueView ? '查看全部历史' : '查看任务队列', async () => { migrationQueueView = !migrationQueueView; migrationCursor = {time: 0, id: ''}; }));
        section.append(make('p', 'node-note', '任务保存在 Master。目标暂存或发布不代表归属已提交；取消保留已提交资源，排空状态需另行明确解除。迁移完成后仍需独立退役检查。'));
        const labels = {queued: '等待执行', copying: '复制中', verifying: '校验中', committing: '归属提交中', cleanup_pending: '清理待办', paused: '已暂停', cancelling: '取消清理中', cancelled: '已取消', failed: '失败', completed: '已完成'};
        for (const task of (page.tasks || []).slice(0, 16)) {
            const card = make('article', 'node-config-box');
            card.append(make('strong', '', `${task.task_id} · ${task.error_code === 'waiting_business_traffic' ? '等待业务低峰' : labels[task.state] || task.state}`));
            card.append(kv([['源节点', memberLabel(node, task.source_id)], ['目标节点', memberLabel(node, task.target_id)], ['对象数', task.object_count], ['已提交 / 全部', `${dataSize(task.committed_bytes)} / ${dataSize(task.total_bytes)}`]]));
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

    async function refresh() {
        const current = refreshQueue.then(async () => {
            const node = await api('/api/v1/media/admin/nodes');
            if (node.role !== 'Master') {
                $('migrationContent').replaceChildren(make('p', 'node-note', '请在主节点管理资源迁移。'));
                return;
            }
            const query = `?view=${migrationQueueView ? 'queue' : 'history'}${migrationCursor.id ? `&after_time=${migrationCursor.time}&after_id=${encodeURIComponent(migrationCursor.id)}` : ''}`;
            const migrations = await api(`/api/v1/media/admin/nodes/migrations${query}`);
            if (migrationPlan && ['observing', 'starting'].includes(migrationPlan.state)) {
                migrationPlan = await api(`/api/v1/media/admin/nodes/migration-plans/${encodeURIComponent(migrationPlan.plan_id)}`);
            }
            // At most four visible active tasks per refresh; no data-plane traffic.
            const active = (migrations.tasks || []).filter(task => ['queued', 'copying', 'verifying', 'committing', 'cleanup_pending', 'cancelling'].includes(task.state)).slice(0, 4);
            for (const task of active) {
                const value = await api(`/api/v1/media/admin/nodes/migrations/${encodeURIComponent(task.task_id)}`);
                migrationViews.set(task.task_id, {at: Date.now(), value});
            }
            while (migrationViews.size > 64) migrationViews.delete(migrationViews.keys().next().value);
            $('migrationContent').replaceChildren(migrationPlanPanel(node), migrationPanel(migrations, node));
        });
        refreshQueue = current.catch(() => {});
        return current;
    }

    $('migrationsRefresh').onclick = () => action(async () => {}, '已刷新');
    panel.querySelector('.module-heading').addEventListener('click', () => {
        if (panel.classList.contains('expanded')) {
            refresh().catch(error => setStatus(error.message));
            if (!refreshTimer) refreshTimer = setInterval(() => {
                if (panel.classList.contains('expanded')) refresh().catch(error => setStatus(error.message));
            }, 10000);
        } else {
            clearInterval(refreshTimer);
            refreshTimer = null;
        }
    });
})();
