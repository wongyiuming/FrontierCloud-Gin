/* Bounded WebCrypto reader. No storage, caching, eval or server-side search. */
let bytes=0,scanned=0,matches=0;
const maxBytes=8*1024*1024,maxRecords=4000,maxMatches=500,magic=[70,67,76,71,49,0];
const decode=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
const hex=b=>Array.from(new Uint8Array(b),v=>v.toString(16).padStart(2,'0')).join('');
async function readBounded(response,n){
    if(!response.ok||n>262200||n<35)throw Error('日志节点拒绝读取或块大小无效');
    const reader=response.body.getReader(),parts=[];let size=0;
    while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>n){await reader.cancel();throw Error('日志节点返回的数据超出授权大小')}parts.push(value)}
    if(size!==n)throw Error('日志块传输未完成');const out=new Uint8Array(size);let at=0;for(const part of parts){out.set(part,at);at+=part.length}return out;
}
self.onmessage=async({data})=>{
    const rows=[];let limited=false;
    try{
        for(const block of data.blocks){
            if(bytes+block.reference.bytes>maxBytes||scanned>=maxRecords||matches>=maxMatches){limited=true;break}
            if(block.expires<=Date.now()/1000)throw Error('临时日志授权已过期，请重新查询');
            const url=new URL(block.source.url,self.location.origin);if(url.protocol!=='https:'||url.username||url.password)throw Error('日志来源地址无效');
            const options={cache:'no-store',redirect:'error',credentials:block.source.local?'same-origin':'omit'};
            if(!block.source.local){options.method='POST';options.headers={'Content-Type':'application/json'};options.body=JSON.stringify(block.source.grant)}
            const p=await readBounded(await fetch(url,options),block.reference.bytes);bytes+=p.length;
            if(hex(await crypto.subtle.digest('SHA-256',p))!==block.reference.sha256||!magic.every((v,i)=>p[i]===v))throw Error('日志密文校验失败');
            const h=block.header;if(h.id!==block.reference.id||![h.start_ms,h.end_ms].every(Number.isSafeInteger))throw Error('日志清单无效');
            const aad=new TextEncoder().encode(JSON.stringify({id:h.id,master_id:h.master_id,kind:h.kind,start_ms:h.start_ms,end_ms:h.end_ms}));
            const raw=decode(block.key);if(raw.length!==32)throw Error('日志临时密钥无效');
            const key=await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['decrypt']);raw.fill(0);block.key='';
            let plain;try{plain=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:p.slice(6,18),additionalData:aad,tagLength:128},key,p.slice(18)))}catch(_){throw Error('日志解密或清单认证失败')}
            let values;try{values=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plain))}finally{plain.fill(0)}
            if(!Array.isArray(values))values=[values];
            for(const value of values){if(scanned>=maxRecords||matches>=maxMatches){limited=true;break}scanned++;const stamp=value.received_at_ms??h.start_ms;if(stamp<data.start||stamp>=data.end)continue;if(data.keyword&&!JSON.stringify(value).toLocaleLowerCase().includes(data.keyword.toLocaleLowerCase()))continue;rows.push(value);matches++}
            if(limited)break;
        }
        self.postMessage({rows,bytes,scanned,limited});
    }catch(e){self.postMessage({error:e.message||'日志读取失败'})}
};
