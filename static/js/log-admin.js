/* Explicit-query log viewer; keys and plaintext stay in memory only. */
(() => {
    const $ = id => document.getElementById(id), panel = $('logsPanel');
    if (!panel) return;
    const root = '/api/v1/media/admin/logs';
    const labels = {application:'应用',access:'访问',error:'错误',audit:'审计',security:'IP安全',webrtc:'WebRTC',node:'节点',certificate:'证书',job:'后台任务',browser:'浏览器诊断'};
    let status = null, worker = null, generation = 0, run = 0, loaded = false;
    const serverNow = () => status ? status.now_ms + (performance.now() - status.loadedAt) : Date.now();
    function windowRange() {
        const end = Math.floor(serverNow());
        if ($('logWindow').value !== 'custom') return {start:end - Number($('logWindow').value)*3600000,end};
        const start = new Date(`${$('logStart').value}T00:00:00`).getTime();
        const finish = new Date(`${$('logEnd').value}T00:00:00`);finish.setDate(finish.getDate()+1);
        return {start,end:Math.min(finish.getTime(),end)};
    }
    function syncQuery() {
        for(const id of ['logWindow','logStart','logEnd','logType'])$(id).disabled=!!worker;
        const custom = $('logWindow').value === 'custom';$('logStartLabel').hidden = !custom;$('logEndLabel').hidden = !custom;
        const range = windowRange();const keyword = !!$('logType').value && range.end>range.start && range.end-range.start<43200000;
        $('logKeyword').disabled = !keyword;if(!keyword)$('logKeyword').value='';
        $('logQuery').disabled = !status?.configuration?.enabled || !range.start || range.start>=range.end || !$('logType').value || !!worker;
    }
    async function refresh() {
        const [current,nodes,routing] = await Promise.all([api(root+'/status'),api('/api/v1/media/admin/nodes'),api('/api/v1/media/admin/nodes/public-routing')]);
        status = {...current,loadedAt:performance.now()};generation = current.configuration.generation;
        const selector = $('logDestination');selector.replaceChildren(new Option('请选择直连日志节点',''));
        const policies = new Map(routing.native_transport_policies.map(p=>[p.member_id,p]));
        for(const member of nodes.storage_pool?.members||[]){
            const relation = nodes.relationships?.find(r=>r.peer_id===member.member_id),policy=policies.get(member.member_id);
            if(member.member_kind!=='Follower'||relation?.state!=='active'||relation?.status!=='online'||policy?.configured_transport!=='Direct'||policy?.applied_transport!=='Direct')continue;
            selector.add(new Option(`${relation.peer_endpoint} · ${member.member_id}`,member.member_id));
        }
        const selected = current.configuration.target?.member_id;
        if(selected&&!Array.from(selector.options).some(o=>o.value===selected)){const option=new Option(`${current.configuration.target.origin}（当前不可选，已有日志保留）`,selected);option.disabled=true;selector.add(option)}
        selector.value=selected||'';$('logConfigure').textContent=current.configuration.enabled?'移动日志节点':'启用日志节点';
        const q=current.queue,c=current.capture;
        $('logHealth').textContent=`${current.configuration.enabled?'已启用':'未启用；现有日志周期保持原样'} · 加密块 ${q.records} · 加密缓冲 ${q.durable_pending} 类 · 主站日志预算 ${(q.used_bytes/1048576).toFixed(1)} / 128 MiB · 待归档/移动 ${q.pending} · 失败待重试 ${q.failed} · 本进程丢弃 ${c.dropped_this_process} · ${c.last_error||'状态正常'} · ${current.idle.can_run?'闲时可执行':'等待业务空闲'}`;
        const type=$('logType'),chosen=type.value;type.replaceChildren(new Option('请选择日志类型',''));for(const kind of current.types)type.add(new Option(labels[kind]||kind,kind));type.value=chosen||'access';syncQuery();
    }
    $('logConfigure').onclick=async()=>{
        const member=$('logDestination').value;if(!member){$('logHealth').textContent='请选择已准备好的直连节点';return}
        if(!confirm(`确认${status.configuration.enabled?'移动':'启用'}日志节点？\n${$('logDestination').selectedOptions[0].text}\n仅在闲时传输密文，验证完成前保留来源。`))return;
        $('logConfigure').disabled=true;try{await api(root+'/configure',{method:'POST',headers:requestHeaders(),body:JSON.stringify({member_id:member,generation,confirm:true})});await refresh()}catch(e){$('logHealth').textContent=e.message}finally{$('logConfigure').disabled=false}
    };
    function cancel(clear=true){run++;worker?.terminate();worker=null;$('logCancel').disabled=true;if(clear)$('logResults').textContent='';syncQuery()}
    $('logCancel').onclick=()=>{cancel();$('logQueryStatus').textContent='已取消，查询结果与临时密钥已清空'};
    $('logRefresh').onclick=()=>refresh().catch(e=>$('logHealth').textContent=e.message);
    for(const id of ['logWindow','logStart','logEnd','logType'])$(id).onchange=syncQuery;
    $('logQueryForm').onsubmit=async event=>{
        event.preventDefault();cancel();const thisRun=run,range=windowRange(),kind=$('logType').value,keyword=$('logKeyword').value;
        if(!kind||!range.start||range.start>=range.end||keyword&&range.end-range.start>=43200000){$('logQueryStatus').textContent='日期或关键字窗口无效';return}
        worker=new Worker(root+'/worker.js');$('logCancel').disabled=false;syncQuery();$('logQueryStatus').textContent='正在读取密文，由浏览器解密与筛选…';
        let after='',more=true,scanned=0,bytes=0,rows=[];
        try{
            while(more&&run===thisRun){
                const page=await api(root+'/query',{method:'POST',headers:requestHeaders(),body:JSON.stringify({start_ms:range.start,end_ms:range.end,type:kind,keyword_filter:!!keyword,after})});if(run!==thisRun)return;
                const result=await new Promise((resolve,reject)=>{worker.onmessage=e=>e.data.error?reject(new Error(e.data.error)):resolve(e.data);worker.onerror=()=>reject(new Error('浏览器日志解密任务失败'));worker.postMessage({blocks:page.blocks,start:range.start,end:range.end,keyword})});
                scanned=result.scanned;bytes=result.bytes;rows.push(...result.rows);more=page.more&&!result.limited;after=page.after;
                $('logResults').textContent=rows.map(row=>JSON.stringify(row,null,2)).join('\n\n');
                $('logQueryStatus').textContent=`已在浏览器检查 ${scanned} 条，匹配 ${rows.length} 条，读取 ${(bytes/1048576).toFixed(2)} MiB${result.limited?'；已达到本次上限，请缩小日期窗口':more?'；继续读取…':'；查询完成'}`;
                if(result.limited)break;
            }
        }catch(e){if(run===thisRun)$('logQueryStatus').textContent=`查询未完成：${e.message}`}finally{if(run===thisRun){worker?.terminate();worker=null;$('logCancel').disabled=false;syncQuery()}}
    };
    new MutationObserver(()=>{if(panel.classList.contains('expanded')&&!loaded){loaded=true;refresh().catch(e=>{loaded=false;$('logHealth').textContent=e.message})}else if(!panel.classList.contains('expanded'))cancel()}).observe(panel,{attributes:true,attributeFilter:['class']});
    window.addEventListener('pagehide',()=>cancel());
})();
