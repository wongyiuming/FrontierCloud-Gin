"""Real Chromium interaction with the shipped node module and deterministic API replies.

This covers browser rendering, dialogs, pagination and request payloads. It does
not claim native byte transfer or server authentication; those have separate
TLS, Redis, database and native fleet acceptance gates.
"""
import argparse
import json
import os
from pathlib import Path
import re

from playwright.sync_api import sync_playwright, expect


def run(output):
    source = Path(__file__).resolve().parents[1]
    markup = (source / 'static/media/admin.html').read_text()
    markup = re.sub(r'<script\b[^>]*>.*?</script>', '', markup, flags=re.S)
    markup = re.sub(r'<link\b[^>]*>', '', markup)
    fixture = r"""
    window.calls=[]; window.clearRetirement=false;
    window.sourceID='2'.repeat(32); window.targetID='3'.repeat(32);
    window.task={task_id:'1'.repeat(32),source_id:sourceID,target_id:targetID,
      revision:3,state:'failed',error_code:'target_unavailable',object_count:20,total_bytes:200,committed_bytes:100};
    window.plan={plan_id:'5'.repeat(32),state:'ready',source:{member_id:sourceID,transport:'Direct'},
      target:{member_id:targetID,transport:'Relay'},review_sha256:'a'.repeat(64),unit_count:2,
      object_count:20,total_bytes:200,verified_objects:20,verified_bytes:200,objects:[],
      blockers:[],source_residuals:[],complete:false,next:'b'.repeat(64)};
    window.nodes={role:'Master',node_id:'4'.repeat(32),protocol:2,app_version:'fixture',certificate:{state:'ready',mode:'automatic',hostname:'fixture.localhost'},
      relationships:[{relationship_id:'6'.repeat(32),peer_id:sourceID,state:'active',status:'online',direction:'downstream',peer_endpoint:'https://source.example:8443'},
      {relationship_id:'7'.repeat(32),peer_id:targetID,state:'active',status:'online',direction:'downstream',peer_endpoint:'https://target.example'},
      {relationship_id:'0'.repeat(32),peer_id:sourceID,state:'revoked',status:'offline',direction:'downstream',peer_endpoint:'https://old.example'}],
      storage_pool:{members:[{member_id:'auto',member_kind:'Auto',transport:'Automatic'}, {member_id:sourceID,relationship_id:'6'.repeat(32),member_kind:'Follower',transport:'Direct',health:'online',storage_enabled:1,writable:1},
      {member_id:targetID,member_kind:'Follower',transport:'Relay',health:'online',storage_enabled:1,writable:1},
      {member_id:'8'.repeat(32),member_kind:'MasterLocal',transport:'Local',health:'online'}]}};
    window.requestHeaders=()=>({'X-CSRF-Token':'browser-fixture'});
    window.api=async (path,options={})=>{
      calls.push({path,options});
      if(window.failMigrationList && path.includes('/nodes/migrations?')) throw Error('migration queue unavailable');
      if(path.endsWith('/retire/check')) return {observation_complete:true,expected_items:0,
        master:{database_clear:true,blockers:[]},peer:{database_clear:true,blockers:[]},
        concerns:clearRetirement?[]:[{code:'backup_retention_required',count:1,samples:['<img src=x onerror=alert(1)>']}]};
      if(path.endsWith('/retire/apply')) {
        nodes.relationships[0].state='revoked';nodes.relationships[0].summary={retirement:{completed_at:1}};
        return {completed_at:1};
      }
      if(path.includes('/migration-plans')) {
        if(path.endsWith('/start')) plan.state='started';
        return {...plan,objects:[{resource_kind:'media',physical_path:'<img src=x onerror=alert(1)>',parent_path:'music/unit',size_bytes:10}],
          complete:path.includes('?after=')};
      }
      if(path.endsWith('/control')) {
        const action=JSON.parse(options.body).action;task.revision++;
        task.state=action==='pause'?'paused':action==='cancel'?'cancelled':'queued';task.error_code='';return {...task};
      }
      if(path.includes('/migrations/'+task.task_id)) return {task:{...task},objects:[],object_stages:[],unit_stages:[],complete:true};
      if(path.includes('/nodes/migrations')) return {tasks:[{...task}],complete:true};
      if(path.endsWith('/observability')) return {members:[],relationships:[]};
      if(path==='/api/v1/media/admin/nodes/s3' && !options.method) return {members:[]};
      if(path==='/api/v1/media/admin/nodes') return nodes;
      throw Error('unexpected fixture API '+path);
    };
    """
    output.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as runtime:
        browser = runtime.chromium.launch(executable_path=os.environ['PLAYWRIGHT_CHROMIUM_EXECUTABLE'],
                                          headless=True, args=['--no-sandbox'])
        page = browser.new_page(viewport={'width': 1360, 'height': 1000})
        errors = []
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.route('**/*', lambda route: route.fulfill(status=200, content_type='text/html', body=markup)
                   if route.request.url == 'https://node-ui.fixture.invalid/' else route.fulfill(status=404, body=''))
        page.goto('https://node-ui.fixture.invalid/')
        page.evaluate('() => {' + fixture + '}')
        page.add_script_tag(content=(source / 'static/js/nodes.js').read_text())
        page.add_script_tag(content=(source / 'static/js/node-migrations.js').read_text())
        original_order = page.locator('[data-admin-module]').evaluate_all('(x)=>x.map(e=>e.dataset.adminModule)')
        page.locator('#nodesRefresh').click()
        expect(page.locator('#nodeOperationStatus')).to_have_text('已刷新')
        expect(page.locator('#nodeRelationships')).not_to_contain_text('target_unavailable')
        assert not page.evaluate("calls.some(x=>x.path.includes('/nodes/migrations'))")
        page.locator('#migrationsRefresh').click()
        expect(page.locator('#migrationContent')).to_contain_text('target_unavailable')
        expect(page.locator('#nodesPanel')).not_to_contain_text('生成只读迁移计划')
        expect(page.locator('.node-card-title strong').filter(has_text='auto')).to_have_count(0)
        expect(page.locator('#nodeRelationships')).not_to_contain_text('Automatic')
        expect(page.locator('#nodeRelationships .node-card-grid')).to_have_count(0)
        source_card = page.locator('#nodeRelationships .node-card').filter(has=page.locator('.node-card-title strong', has_text='source.example'))
        expect(source_card.locator('.node-member-id')).to_have_text('NodeID ' + '2' * 32)
        target_card = page.locator('#nodeRelationships .node-card').filter(has=page.locator('.node-card-title strong', has_text='target.example'))
        expect(target_card.locator('.node-member-id')).to_have_text('NodeID ' + '3' * 32)
        expect(page.locator('#nodeIdentity')).not_to_contain_text('4' * 32)
        expect(page.locator('#nodeRelationships')).not_to_contain_text('old.example')
        toggles = page.locator('#nodeRelationships .node-details-toggle')
        for index in range(toggles.count()):
            expect(toggles.nth(index)).to_have_attribute('aria-expanded', 'false')
            toggles.nth(index).click()
        page.locator('#nodesRefresh').click()
        expect(page.locator('#nodeRelationships .node-details-toggle[aria-expanded="false"]')).to_have_count(0)
        local_card = page.locator('.node-card').filter(has=page.locator('.node-card-title strong', has_text='Master Local'))
        expect(local_card.locator('.node-member-id')).to_have_count(0)
        expect(local_card).not_to_contain_text('8' * 32)
        expect(local_card.locator('.node-card-grid')).to_contain_text('本机证书')
        expect(local_card.locator('.node-card-grid > .node-resource-panel')).to_have_count(4)
        planner = page.locator('.node-resource-panel').filter(has=page.get_by_text('整节点迁移计划', exact=True))
        if planner.count() == 0:
            planner = page.locator('.node-resource-panel').filter(has=page.get_by_role('button', name='生成只读迁移计划', exact=True))
        expect(planner).to_contain_text('Master Local 不支持')
        expect(planner.locator('select').nth(0).locator('option[value="' + '2' * 32 + '"]')).to_have_text('source.example:8443 · ' + '2' * 32 + ' · Direct')
        expect(planner.locator('select').nth(1).locator('option[value="' + '3' * 32 + '"]')).to_have_text('target.example · ' + '3' * 32 + ' · Relay')
        planner.locator('select').nth(0).select_option('2' * 32)
        planner.locator('select').nth(1).select_option('3' * 32)
        planner.get_by_role('button', name='生成只读迁移计划', exact=True).click()
        expect(planner).to_contain_text('Direct → Relay')
        expect(planner.locator('img')).to_have_count(0)
        planner.get_by_role('button', name='下一页计划对象', exact=True).click()
        page.once('dialog', lambda dialog: dialog.accept('wrong'))
        planner.get_by_role('button', name='确认并开始迁移', exact=True).click()
        assert page.evaluate("calls.filter(x=>x.path.endsWith('/start')).length") == 0
        page.once('dialog', lambda dialog: dialog.accept('true'))
        planner.get_by_role('button', name='确认并开始迁移', exact=True).click()
        assert page.evaluate("calls.filter(x=>x.path.endsWith('/start')).length") == 0
        def confirm_migration(dialog):
            assert '请输入 True' in dialog.message
            assert 'source.example:8443 · ' + '2' * 32 in dialog.message
            assert 'target.example · ' + '3' * 32 in dialog.message
            dialog.accept('True')
        page.once('dialog', confirm_migration)
        planner.get_by_role('button', name='确认并开始迁移', exact=True).click()
        expect(planner).to_contain_text('started')
        page.get_by_role('button', name='重试', exact=True).click()
        page.get_by_role('button', name='暂停', exact=True).click()
        page.get_by_role('button', name='恢复', exact=True).click()
        before = page.evaluate('calls.length')
        page.once('dialog', lambda dialog: dialog.dismiss())
        page.get_by_role('button', name='取消任务', exact=True).click()
        assert not page.evaluate('(n)=>calls.slice(n).some(x=>x.options.body&&JSON.parse(x.options.body).action==="cancel")', before)
        page.once('dialog', lambda dialog: dialog.accept())
        page.get_by_role('button', name='取消任务', exact=True).click()
        expect(page.get_by_role('button', name='明确解除本任务排空', exact=True)).to_be_visible()
        page.get_by_role('button', name='执行只读退役检查', exact=True).first.click()
        expect(page.locator('#nodeRelationships')).to_contain_text('backup_retention_required')
        expect(page.get_by_role('button', name='确认安全退役', exact=True)).to_have_count(0)
        page.evaluate('clearRetirement=true')
        page.get_by_role('button', name='执行只读退役检查', exact=True).first.click()
        try:
            expect(page.get_by_role('button', name='确认安全退役', exact=True)).to_be_visible(timeout=5000)
        except Exception:
            (output / 'failure.json').write_text(json.dumps(page.evaluate('({calls,clearRetirement,text:document.querySelector("#nodeRelationships").textContent,status:document.querySelector("#nodeOperationStatus").textContent})'), ensure_ascii=False, indent=2))
            raise
        page.once('dialog', lambda dialog: dialog.accept('wrong'))
        page.get_by_role('button', name='确认安全退役', exact=True).click()
        assert page.evaluate("calls.filter(x=>x.path.endsWith('/retire/apply')).length") == 0
        page.once('dialog', lambda dialog: dialog.accept('2' * 32))
        page.get_by_role('button', name='确认安全退役', exact=True).click()
        expect(page.locator('#nodeRelationships')).to_contain_text('已安全退役')
        assert original_order == page.locator('[data-admin-module]').evaluate_all('(x)=>x.map(e=>e.dataset.adminModule)')
        posts = page.evaluate("calls.filter(x=>x.options.method==='POST')")
        assert all(item['options']['headers']['X-CSRF-Token'] == 'browser-fixture' for item in posts)
        start = next(item for item in posts if item['path'].endswith('/start'))
        assert json.loads(start['options']['body']) == {'review_sha256': 'a' * 64,
            'confirm_source_id': '2' * 32, 'confirm_target_id': '3' * 32}
        assert not errors, errors
        page.evaluate('failMigrationList=true')
        page.locator('#migrationsRefresh').click()
        expect(page.locator('#migrationOperationStatus')).to_have_text('migration queue unavailable')
        before = page.evaluate('calls.length')
        page.locator('#nodesRefresh').click()
        expect(page.locator('#nodeOperationStatus')).to_have_text('已刷新')
        assert not page.evaluate('(n)=>calls.slice(n).some(x=>x.path.includes("/nodes/migrations"))', before)
        page.evaluate('failMigrationList=false')
        for stylesheet in ('admin.css', 'nodes-observability.css'):
            page.add_style_tag(content=(source / 'static/css' / stylesheet).read_text())
        page.locator('#nodesPanel').evaluate("""panel => {
            for (const other of document.querySelectorAll('[data-admin-module]')) if (other!==panel) other.style.display='none';
            panel.classList.remove('hidden'); panel.classList.add('expanded');
            Object.assign(panel.style,{display:'block',position:'fixed',inset:'0',height:'100vh',maxHeight:'none',overflow:'auto',zIndex:'100'});
        }""")
        expect(local_card).to_be_visible()
        panel_tops=local_card.locator('.node-card-grid > .node-resource-panel').evaluate_all('(panels)=>panels.map(p=>p.getBoundingClientRect().top)')
        assert max(panel_tops)-min(panel_tops)<1, panel_tops
        local_card.screenshot(path=str(output / 'node-local-certificate-master.png'))
        page.locator('#nodesPanel').screenshot(path=str(output / 'node-operations.png'))
        page.evaluate("() => { nodes.role='Follower'; nodes.storage_pool={members:[]}; }")
        page.locator('#nodesRefresh').evaluate('button => button.click()')
        page.locator('#nodeRelationships .node-details-toggle').click()
        expect(page.locator('#nodeRelationships .node-card-grid')).to_contain_text('本机证书')
        expect(page.locator('#nodeRelationships .node-card')).to_have_count(1)
        expect(page.locator('#nodeRelationships .node-member-id')).to_have_text('NodeID ' + '4' * 32)
        page.locator('#migrationsRefresh').evaluate('button => button.click()')
        expect(page.locator('#migrationContent')).to_contain_text('请在主节点管理资源迁移')
        page.locator('#nodeRelationships .node-card').screenshot(path=str(output / 'node-local-certificate-follower-card.png'))
        page.locator('#nodesPanel').screenshot(path=str(output / 'node-local-certificate-follower.png'))
        (output / 'evidence.json').write_text(json.dumps({'real_chromium': True, 'backend': 'deterministic fixture',
            'unmodified_node_module': True, 'independent_migration_errors': True, 'master_role_required': True,
            'plan_paging_and_typed_confirmation': True,
            'task_controls': True, 'backup_blocks_retirement': True, 'retirement_confirmation_and_history': True,
            'csrf_headers': True, 'html_injection_rejected': True, 'module_order_preserved': True}, indent=2) + '\n')
        browser.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    run(parser.parse_args().output)
    print('PASS: real Chromium node operations UI; deterministic API fixture, no native-server claim')
