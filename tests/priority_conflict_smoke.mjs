import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const elements = new Map();
const controls = [{disabled:false}, {disabled:false}];
const element = id => {
    if (!elements.has(id)) elements.set(id, {
        value:'', disabled:false, textContent:'', title:'', dataset:{},
        classList:{add(){}, remove(){}, toggle(){}, contains(){return false;}},
        querySelectorAll:()=>controls, children:[], append(){}, appendChild(){}, setAttribute(){},
    });
    return elements.get(id);
};
const calls = [], rendered = [], activated = [];
let failure = {kind:'directory',status:409};
const data = {scope:'music', searching:false, directories:[
    {path:'music/one',name:'one',preference:0},
    {path:'music/two',name:'two',preference:0},
    {path:'music/three',name:'three',preference:0},
    {path:'music/four',name:'four',preference:0},
], items:[{media_path:'music/one.mp3',preference:0}], pagination:{page:1,pages:1}, catalog_total:1185};
const context = {
    document:{cookie:'admin_csrf=test',hidden:false,getElementById:element,createElement:()=>element('created'),querySelectorAll:()=>[],addEventListener(){}},
    location:{href:'',protocol:'https:'},URL,URLSearchParams,Blob,FormData:class{},XMLHttpRequest:class{},
    setInterval:()=>1,clearInterval(){},console,alert(message){throw new Error(message);},
    fetch:async (url,options={})=>{
        calls.push({url,method:options.method||'GET'});
        let status=200,body={};
        if (url.includes('/status')) body={csrf_cookie_name:'admin_csrf',limits:{}};
        else if (url.includes('/tree')) body={path:'',items:[]};
        else if (url.includes('/media-priority?')) body=JSON.parse(JSON.stringify(data));
        else if (url.includes('/priority-order?')) {
            const kind=new URL(url,'https://example.test').searchParams.get('kind');
            if (failure?.kind===kind) {status=failure.status;body={detail:'节点状态或存储操作冲突'};}
            else body={scope:'music',items:kind==='directory'
                ? data.directories.slice(0,2).map(d=>({path:d.path,preference:7}))
                : [{path:'music/one.mp3',preference:8}]};
        }
        return {status,ok:status===200,json:async()=>body};
    },
};
context.window=context;
context.FrontierPriorityDrag={cancel(){},activate(_,orders){activated.push(JSON.parse(JSON.stringify(orders)));}};
vm.createContext(context);
vm.runInContext(fs.readFileSync('static/js/admin.js','utf8'),context);
await new Promise(resolve=>setTimeout(resolve,0));
context.renderMediaPriority = value => {rendered.push(JSON.parse(JSON.stringify(value)));controls.forEach(c=>{c.disabled=false;});};
vm.runInContext(fs.readFileSync('static/js/directory-admin.js','utf8'),context);
vm.runInContext("priorityScope='music'",context);
for (const kind of ['directory','media']) {
    failure={kind,status:409};
    await vm.runInContext('loadMediaPriority(true)',context);
    assert.equal(rendered.at(-1).directories.length,4,'conflict must preserve the full readable listing, including when an earlier order succeeded');
    assert(rendered.at(-1).directories.every(d=>d.preference===0));
    assert.deepEqual(activated.at(-1),{},'conflict must not activate drag ordering');
    assert(controls.every(c=>c.disabled),'numeric and range priority controls must be disabled');
    assert(element('prioritySaveState').textContent.includes('可继续浏览'));
}
const count=rendered.length;
for (const status of [403,500]) {
    failure={kind:'directory',status};
    await assert.rejects(vm.runInContext('loadMediaPriority(true)',context));
    assert.equal(rendered.length,count,'authentication/server failures must not be disguised as a usable ordering snapshot');
}
failure=null;
await vm.runInContext('loadMediaPriority(true)',context);
assert(controls.every(c=>!c.disabled),'refresh after the conflict clears must restore normal ordering');
assert.equal(rendered.at(-1).directories.length,2);
assert(activated.at(-1).directory);
assert.equal(element('prioritySaveState').textContent,'');
assert(calls.every(c=>c.method==='GET'),'browsing conflicts must not cancel uploads or change priorities');
console.log('priority-conflict-smoke-ok: readable listing, disabled ordering, recovery refresh, no mutation');
