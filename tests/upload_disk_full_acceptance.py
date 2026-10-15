"""Real ENOSPC and retry on a disposable, bounded Compose filesystem."""
import argparse
import hashlib
import http.cookiejar
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


def run(args):
    assert re.fullmatch(r'[a-z0-9][a-z0-9./:@_-]+',args.image)
    project='fc-upload-disk-full-'+uuid.uuid4().hex
    work=Path(tempfile.mkdtemp(prefix='fc-upload-disk-full-'))
    definition={'services':{
        'redis':{'image':'redis:7.4.11-alpine','mem_limit':'96m','cpus':0.25},
        'web':{'image':args.image,'user':'0:0','entrypoint':['/bin/sh','-ec'],
               'command':['/app/frontiercloud init-secrets; /app/frontiercloud init-media; exec /app/frontiercloud serve'],
               'environment':{'DATA_ROOT':'/app/data','SECRETS_DIR':'/run/frontiercloud-secrets','DB_TYPE':'sqlite','SQLITE_PATH':'/app/data/frontiercloud.db','HTTP_ADDR':'0.0.0.0:8000','TLS_ENABLED':'false','REDIS_URL':'redis://redis:6379/0','GOMAXPROCS':'1','NGINX_MEDIA_ACCEL':'false'},
               'tmpfs':['/app/data:rw,size=16m','/run/frontiercloud-secrets:rw,size=1m'],
               'mem_limit':'512m','memswap_limit':'512m','cpus':1,
               'ports':['127.0.0.1::8000'],'depends_on':['redis'],
               'healthcheck':{'test':['CMD','/app/frontiercloud','healthcheck'],'interval':'1s','timeout':'3s','retries':60}}}}
    compose=work/'compose.json';compose.write_text(json.dumps(definition))
    command=['docker','compose','--env-file','/dev/null','-p',project,'-f',str(compose)]
    def execute(*arguments):
        return subprocess.check_output(command+list(arguments),text=True,stderr=subprocess.STDOUT,timeout=150)
    output=Path(args.output);output.mkdir(parents=True,exist_ok=True)
    proof={'project':project,'isolated_tmpfs_bytes':16*1024*1024,'web_cpus':1,'web_memory_mib':512,'fixture_user':'root for disposable tmpfs initialization; not a production configuration','transport':'isolated loopback publication with trusted-proxy fixture headers; not a TLS acceptance claim'}
    try:
        execute('up','-d','--no-build','--pull','never','--wait','--wait-timeout','90')
        address=execute('port','web','8000').strip();assert re.fullmatch(r'127\.0\.0\.1:[0-9]+',address),address
        base='http://'+address
        secret=execute('exec','-T','web','cat','/run/frontiercloud-secrets/admin_key').strip()
        jar=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        def request(method,path,data=None,headers=None):
            try:
                with opener.open(urllib.request.Request(base+path,data=data,headers={'X-Real-IP':'127.0.0.1','X-Forwarded-Proto':'https',**(headers or {})},method=method),timeout=30) as response:return response.status,response.read()
            except urllib.error.HTTPError as error:return error.code,error.read()
        login=request('POST','/api/v1/media/admin/elevate',urllib.parse.urlencode({'token':secret}).encode(),{'Content-Type':'application/x-www-form-urlencoded'})
        assert login[0]==200,login
        status=json.loads(request('GET','/api/v1/media/admin/status')[1]);csrf=next(c.value for c in jar if c.name==status['csrf_cookie_name'])
        relative='disk-full-'+uuid.uuid4().hex+'/retry.mp3'
        def upload(payload):
            boundary='fc-disk-'+uuid.uuid4().hex
            fields={'storage_mode':'plain','target_dir':'music','relative_path':relative}
            prefix=b''.join(('--'+boundary+'\r\nContent-Disposition: form-data; name="'+key+'"\r\n\r\n'+value+'\r\n').encode() for key,value in fields.items())
            prefix+=('--'+boundary+'\r\nContent-Disposition: form-data; name="file"; filename="retry.mp3"\r\nContent-Type: audio/mpeg\r\n\r\n').encode()
            return request('POST','/api/v1/media/admin/upload/item',prefix+payload+('\r\n--'+boundary+'--\r\n').encode(),{'X-CSRF-Token':csrf,'Content-Type':'multipart/form-data; boundary='+boundary})
        disk_code=None
        client_error=None
        try:
            disk_code,body=upload(b'ID3\x03\0\0\0\0\0\0'+bytes(32*1024*1024))
            assert disk_code>=500,(disk_code,body[:200])
        except urllib.error.URLError as error:
            # An early server rejection can close the socket while the client
            # is still sending. Require independent server ENOSPC evidence.
            client_error=str(error.reason)
        logs=execute('logs','web')
        assert 'no space left on device' in logs.lower(), 'failure was not ENOSPC'
        (output/'server-enospc.log').write_text(logs)
        proof.update(server_enospc_logged=True,server_log_sha256=hashlib.sha256(logs.encode()).hexdigest())
        stages=execute('exec','-T','web','/bin/sh','-ec','for p in /app/data/media/.upload-*; do [ ! -e "$p" ] || printf "%s\\n" "$p"; done').strip()
        assert not stages,stages
        category='music/'+relative.rsplit('/',1)[0]
        catalog_status,_=request('GET','/api/v1/media/catalog/media?'+urllib.parse.urlencode({'media_type':'music','path':category,'playback_session_id':str(uuid.uuid4())}))
        assert catalog_status==404,catalog_status
        small=b'ID3\x03\0\0\0\0\0\0'+bytes(16384)
        retry_code,retry_body=upload(small);assert retry_code==200,(retry_code,retry_body)
        code,actual=request('GET','/api/v1/media/stream?'+urllib.parse.urlencode({'file_path':'music/'+relative}))
        assert code==200 and actual==small,(code,len(actual),actual[:200],retry_body)
        proof.update(disk_full_status=disk_code,client_error=client_error)
        proof.update(disk_full_rejected=True,stage_files_after_failure=0,catalog_after_failure=404,retry_status=retry_code,retry_original_sha256=hashlib.sha256(actual).hexdigest())
        idle=[]
        container=execute('ps','-q','web').strip()
        for _ in range(5):
            sample=json.loads(subprocess.check_output(['docker','stats','--no-stream','--format','{{json .}}',container],text=True))
            idle.append(float(sample['CPUPerc'].rstrip('%')));time.sleep(1)
        assert all(value<20 for value in idle),idle
        proof['five_idle_cpu_samples']=idle
        print(json.dumps(proof),flush=True)
    finally:
        execute('stop','web')
        execute('down','--volumes','--remove-orphans')
        remaining=subprocess.check_output(['docker','ps','-aq','--filter','label=com.docker.compose.project='+project],text=True).strip()
        assert not remaining,remaining
        proof['owned_containers_removed']=True
        (output/'evidence.json').write_text(json.dumps(proof,indent=2)+'\n')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',required=True)
    parser.add_argument('--output',required=True)
    run(parser.parse_args())
