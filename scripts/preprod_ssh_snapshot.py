"""Bounded, read-only SSH collection for preproduction import.

No production action is performed merely by importing this module. Callers
must supply an already authenticated SSH client, independently pinned host
fingerprint and collector key, and a preproduction receiver public key. Only
the encrypted envelope is returned; paths and rows never reach logs or files.
This attests an SSH collection, not a source-application signature.
"""
import base64
import hashlib
import hmac
import json
import math
import re
import shlex
import time
import os
import pathlib
import stat
import threading
from contextlib import contextmanager

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_MAX = 16 * 1024 * 1024
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_DB = "/opt/frontiercloud/data/frontiercloud.db"
_PROCESS_BUDGET = threading.Lock()


@contextmanager
def _single_collector():
    """One cooperating collector process per trusted controller, fail busy."""
    if not _PROCESS_BUDGET.acquire(blocking=False):
        raise ValueError("collector busy")
    fd = None
    try:
        directory = pathlib.Path.home() / ".codex" / "tmp" / "preproduction-clone-20261104"
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = directory / ".source-collector-budget.lock"
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(path), flags, 0o600)
        opened, current = os.fstat(fd), os.lstat(path)
        if not stat.S_ISREG(opened.st_mode) or stat.S_ISLNK(current.st_mode) or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError("collector lock identity")
        if os.fstat(fd).st_size == 0:
            os.write(fd, b"1")
            os.fsync(fd)
        if os.name == "nt":
            import msvcrt
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        def check_identity():
            opened, current = os.fstat(fd), os.lstat(path)
            if not stat.S_ISREG(opened.st_mode) or stat.S_ISLNK(current.st_mode) or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
                raise ValueError("collector lock identity")
        check_identity()
        yield check_identity
        check_identity()
    except OSError:
        raise ValueError("collector busy or lock unavailable") from None
    finally:
        if fd is not None:
            os.close(fd)
        _PROCESS_BUDGET.release()

# The root cgroup has no cpu.max; nested groups may have several active
# ancestor quotas. Fail closed when the process cgroup cannot be located.
_REMOTE_CPU = '''def cpu_budget():
 root=pathlib.Path('/sys/fs/cgroup')
 lines=pathlib.Path('/proc/self/cgroup').read_text().splitlines()
 entry=next((line[3:] for line in lines if line.startswith('0::')),None)
 if entry is None or not entry.startswith('/') or '..' in pathlib.PurePosixPath(entry).parts:raise ValueError('cgroup')
 group=root.joinpath(entry.lstrip('/'))
 if not group.is_dir():raise ValueError('cgroup')
 cpus=float(max(1,len(os.sched_getaffinity(0))))
 while True:
  path=group/'cpu.max'
  if path.is_file():
   quota,period=path.read_text().split()
   if quota!='max':cpus=min(cpus,int(quota)/int(period))
  elif group!=root:raise ValueError('cgroup quota')
  if group==root:break
  group=group.parent
 if cpus<=0:raise ValueError('cgroup quota')
 return cpus
'''

# This is fixed code, not source-provided shell. All source rows are read in
# one SQLite transaction; SQL bounds cells and row counts before transfer.
_REMOTE = r'''import hashlib,json,os,pathlib,select,signal,sqlite3,stat,sys,time,urllib.parse
# CPU_BUDGET_HELPER
signal.alarm(25)
budget=json.loads(sys.stdin.readline());p=pathlib.Path('/opt/frontiercloud/data/frontiercloud.db');last=0
def healthy():
 global last
 if select.select([0],[],[],0)[0] and not os.read(0,1):raise ValueError('cancelled')
 now=time.monotonic()
 if now-last<0.5:return
 last=now
 cpus=cpu_budget()
 line=next(x for x in open('/proc/pressure/io') if x.startswith('some '))
 psi=float(next(x.split('=',1)[1] for x in line.split() if x.startswith('avg10=')))
 if os.getloadavg()[0]/cpus>budget['max_load_ratio'] or psi>budget['max_io_psi']:raise ValueError('source busy')
healthy()
if not all(stat.S_ISREG(os.lstat(x).st_mode) for x in (p,pathlib.Path(str(p)+'-wal'),pathlib.Path(str(p)+'-shm'))):raise SystemExit(1)
c=sqlite3.connect('file:'+urllib.parse.quote(str(p))+'?mode=ro',uri=True,timeout=3)
try:
 c.set_progress_handler(lambda: (healthy(),0)[1],10000)
 c.execute('PRAGMA query_only=ON');c.execute('BEGIN')
 identity=c.execute('SELECT node_id,role FROM node_identity WHERE singleton=1').fetchone()
 if not identity or identity[1]!='Master':raise ValueError('identity')
 specs=[
  ('objects',['media_id','object_kind','media_path','path_locator','created_at','updated_at'],'media_objects','media_id',''),
  ('placements',['media_id','storage_member_id','object_id','media_path','object_kind','size_bytes','etag','state','created_at','updated_at'],'global_media_objects','media_id',''),
  ('visibility',['relative_path','hidden','updated_at'],'media_visibility','relative_path',''),
  ('playback',['media_id','media_path','preference','play_score','created_at','updated_at'],'media_playback_stats','media_id',''),
  ('lyric_links',['media_id','media_path','lyric_id','lyric_path','created_at','updated_at'],'media_lyric_links','media_id',''),
  ('encryption',['object_kind','object_id','file_id','descriptor_json','created_at'],'media_encryption','object_kind,object_id'," WHERE object_kind='media'"),
  ('members',['member_id','relationship_id','member_kind','transport','storage_enabled','allocated_bytes','used_bytes','reserved_bytes','physical_free_bytes','health','writable','updated_at'],'cluster_storage_members','member_id',''),
  ('relationships',['relationship_id','peer_id','peer_endpoint','peer_key','direction','mode','state','created_at'],'node_relationships','relationship_id',''),
  ('crypto_key_id',['singleton','key_id','created_at'],'media_crypto_keys','singleton','')]
 sections=[];remaining=25000;total=0
 for name,columns,table,order,where in specs:
  selected=columns+(['path_locator'] if name=='placements' else [])
  q='SELECT '+','.join('SUBSTR('+col+',1,65537)' for col in selected)+' FROM '+table+where+' ORDER BY '+order+' LIMIT ?'
  result=[]
  for row in c.execute(q,(remaining+1,)):
   healthy()
   if remaining<=0:raise ValueError('rows')
   remaining-=1;cells=[]
   for value in row:
    if value is None:cells.append(None);continue
    text=str(value);length=len(text.encode('utf-8'))
    if length>65536 or '\x00' in text:raise ValueError('cell')
    total+=length
    if total>16*1024*1024:raise ValueError('size')
    cells.append(text)
   for index in {'objects':(2,), 'placements':(3,), 'visibility':(0,), 'playback':(1,), 'lyric_links':(1,3)}.get(name,()):
    value=cells[index]
    if value is None or len(value)>1024 or len(value.encode('utf-8'))>4096:raise ValueError('path length')
   if name=='objects' and (cells[2] is None or cells[3]!=hashlib.sha256(cells[2].encode('utf-8')).hexdigest()):raise ValueError('locator')
   if name=='placements':
    if cells[3] is None or cells[-1]!=hashlib.sha256(cells[3].encode('utf-8')).hexdigest():raise ValueError('locator')
    cells.pop()
   result.append(cells)
  sections.append({'name':name,'columns':columns,'rows':result})
 result={'node':identity[0],'sections':sections}
 encoded=json.dumps(result,ensure_ascii=False,separators=(',',':')).encode('utf-8')
 if len(encoded)>16*1024*1024:raise ValueError('encoded size')
 # Do not retain a source SQLite read snapshot while the rate-limited
 # transport drains; the complete bounded result already exists in memory.
 c.rollback();c.close()
 signal.alarm((len(encoded)+budget['bytes_per_second']-1)//budget['bytes_per_second']+30)
 for offset in range(0,len(encoded),65536):
  healthy()
  start=time.monotonic();chunk=encoded[offset:offset+65536]
  sys.stdout.buffer.write(chunk);sys.stdout.buffer.flush()
  delay=len(chunk)/budget['bytes_per_second']-(time.monotonic()-start)
  if delay>0:time.sleep(delay)
finally:c.close()
'''

_REMOTE_FACTS = r'''import hashlib,json,os,pathlib,select,signal,sqlite3,stat,sys,time,urllib.parse
# CPU_BUDGET_HELPER
signal.alarm(25)
q=json.loads(sys.stdin.readline());p=pathlib.Path('/opt/frontiercloud/data/frontiercloud.db');last=0
def healthy():
 global last
 if select.select([0],[],[],0)[0] and not os.read(0,1):raise ValueError('cancelled')
 now=time.monotonic()
 if now-last<0.5:return
 last=now
 line=next(x for x in open('/proc/pressure/io') if x.startswith('some '))
 psi=float(next(x.split('=',1)[1] for x in line.split() if x.startswith('avg10=')))
 if os.getloadavg()[0]/cpu_budget()>q['max_load_ratio'] or psi>q['max_io_psi']:raise ValueError('source busy')
healthy()
if not all(stat.S_ISREG(os.lstat(x).st_mode) for x in (p,pathlib.Path(str(p)+'-wal'),pathlib.Path(str(p)+'-shm'))):raise SystemExit(1)
c=sqlite3.connect('file:'+urllib.parse.quote(str(p))+'?mode=ro',uri=True,timeout=3)
try:
 c.set_progress_handler(lambda: (healthy(),0)[1],10000)
 c.execute('PRAGMA query_only=ON');c.execute('BEGIN')
 def one(cols,table,where,args):
  rows=list(c.execute('SELECT '+','.join('SUBSTR('+x+',1,65537)' for x in cols)+' FROM '+table+' WHERE '+where+' LIMIT 2',args))
  if len(rows)>1:raise ValueError('duplicate')
  return None if not rows else [None if x is None else str(x) for x in rows[0]]
 node=c.execute('SELECT node_id,role FROM node_identity WHERE singleton=1').fetchone()
 if not node or node[1]!='Master':raise ValueError('identity')
 obj=one(['media_id','object_kind','media_path','path_locator','created_at','updated_at'],'media_objects','media_id=?',(q['media_id'],))
 place=one(['media_id','storage_member_id','object_id','media_path','object_kind','size_bytes','etag','state','created_at','updated_at','path_locator'],'global_media_objects','media_id=?',(q['media_id'],))
 if obj is not None and (obj[2] is None or obj[3]!=hashlib.sha256(obj[2].encode('utf-8')).hexdigest()):raise ValueError('locator')
 if place is not None:
  if place[3] is None or place[-1]!=hashlib.sha256(place[3].encode('utf-8')).hexdigest():raise ValueError('locator')
  place.pop()
 enc=one(['object_kind','object_id','file_id','descriptor_json','created_at'],'media_encryption',"object_kind='media' AND object_id=?",(q['media_id'],))
 member=one(['member_id','relationship_id','member_kind','transport','storage_enabled','allocated_bytes','used_bytes','reserved_bytes','physical_free_bytes','health','writable','updated_at'],'cluster_storage_members','member_id=?',(q['owner_id'],))
 if member is None:raise ValueError('member')
 rel=None if member[1] is None else one(['relationship_id','peer_id','peer_endpoint','peer_key','direction','mode','state','created_at'],'node_relationships','relationship_id=?',(member[1],))
 if place is not None:path=place[3]
 elif obj is not None and obj[1]=='lyric' and q['owner_id']==node[0]:path=obj[2]
 else:raise ValueError('object')
 if place is not None and place[1]!=q['owner_id']:raise ValueError('owner')
 parts=pathlib.PurePosixPath(path).parts
 if len(path)>1024 or len(path.encode('utf-8'))>4096 or path.startswith('/') or str(pathlib.PurePosixPath(path))!=path or len(parts)<2 or len(parts)>4 or parts[0] not in ('music','vido','lyrics') or any(x in ('','.','..') or x.startswith('.') or ':' in x or '\\' in x for x in parts):raise ValueError('path')
 ext=pathlib.PurePosixPath(path).suffix.lower()
 if (parts[0]=='music' and (len(parts)<3 or ext not in ('.mp3','.m4a','.flac','.wav'))) or (parts[0]=='vido' and (len(parts)<3 or ext not in ('.mp4','.webm','.mkv'))) or (parts[0]=='lyrics' and ext!='.lrc'):raise ValueError('path')
 prefixes=['/'.join(parts[:i]) for i in range(1,len(parts)+1)]
 rows=[];seen=0
 for row in c.execute('SELECT SUBSTR(relative_path,1,65537),SUBSTR(hidden,1,65537),SUBSTR(updated_at,1,65537) FROM media_visibility WHERE relative_path IN ('+','.join('?' for _ in prefixes)+') ORDER BY relative_path LIMIT 25001',prefixes):
  healthy()
  seen+=1
  if seen>25000:raise ValueError('rows')
  item=[None if x is None else str(x) for x in row]
  if item[0] is None or len(item[0].encode())>65536:raise ValueError('path')
  if path==item[0] or path.startswith(item[0]+'/'):rows.append(item)
 facts={'object':obj,'placement':place,'encryption':enc,'member':member,'relationship':rel,'visibility':rows}
 for row in [obj,place,enc,member,rel]+rows:
  if row is not None and any(x is not None and (len(x.encode('utf-8'))>65536 or '\x00' in x) for x in row):raise ValueError('cell')
 result=json.dumps({'node':node[0],'path':path,'facts':facts},ensure_ascii=False,separators=(',',':')).encode()
 if len(result)>1024*1024:raise ValueError('size')
 for offset in range(0,len(result),65536):
  healthy()
  start=time.monotonic();chunk=result[offset:offset+65536]
  sys.stdout.buffer.write(chunk);sys.stdout.buffer.flush()
  delay=len(chunk)/q['bytes_per_second']-(time.monotonic()-start)
  if delay>0:time.sleep(delay)
finally:c.close()
'''

_REMOTE_HASH = r'''import fcntl,hashlib,json,os,pathlib,select,signal,stat,sys,time
# CPU_BUDGET_HELPER
q=json.loads(sys.stdin.readline());name=q['path'];expected=int(q['size']);rate=int(q['rate']);master=bool(q['master'])
if not 0<=expected<=10*1024*1024*1024 or not 65536<=rate<=1024*1024:raise SystemExit(1)
signal.alarm(int(expected/rate)+180)
parts=pathlib.PurePosixPath(name).parts
if len(name)>1024 or len(name.encode('utf-8'))>4096 or name.startswith('/') or str(pathlib.PurePosixPath(name))!=name or len(parts)<2 or len(parts)>4 or parts[0] not in ('music','vido','lyrics') or any(x in ('','.','..') or x.startswith('.') or ':' in x for x in parts) or '\\' in name:raise SystemExit(1)
ext=pathlib.PurePosixPath(name).suffix.lower()
if (parts[0]=='music' and (len(parts)<3 or ext not in ('.mp3','.m4a','.flac','.wav'))) or (parts[0]=='vido' and (len(parts)<3 or ext not in ('.mp4','.webm','.mkv'))) or (parts[0]=='lyrics' and ext!='.lrc'):raise SystemExit(1)
base='/opt/frontiercloud/data/media' if master else '/opt/frontiercloud-storage/data/media'
flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK
fds=[]
def cancelled():
 readable,_,_=select.select([sys.stdin],[],[],0)
 if readable and not os.read(sys.stdin.fileno(),1):raise ValueError('cancelled')
def idle():
 end=time.monotonic()+60
 while True:
  cancelled()
  cpus=cpu_budget()
  with open('/proc/pressure/io','r') as f:line=f.readline()
  psi=float(next(x.split('=',1)[1] for x in line.split() if x.startswith('avg10=')))
  if os.getloadavg()[0]/cpus<=q['max_load_ratio'] and psi<=q['max_io_psi']:return
  if time.monotonic()>=end:raise ValueError('busy')
  time.sleep(1)
def walk_root():
 fd=os.open('/',flags);fds.append(fd)
 for part in pathlib.PurePosixPath(base).parts[1:]:
  fd=os.open(part,flags,dir_fd=fd);fds.append(fd)
 return fd
def lock(root):
 fd=os.open('.media-mutation.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=root)
 st=os.fstat(fd)
 if not stat.S_ISREG(st.st_mode):raise ValueError('lock')
 end=time.monotonic()+0.25
 while True:
  try:fcntl.flock(fd,fcntl.LOCK_SH|fcntl.LOCK_NB);break
  except BlockingIOError:
   if time.monotonic()>=end:raise ValueError('busy')
   time.sleep(.01)
 cur=os.stat('.media-mutation.lock',dir_fd=root,follow_symlinks=False)
 if (st.st_dev,st.st_ino)!=(cur.st_dev,cur.st_ino):raise ValueError('lock changed')
 return fd,(st.st_dev,st.st_ino)
def unlock(fd):fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)
def open_path(root):
 fd=root;parents=[]
 for part in parts[:-1]:
  fd=os.open(part,flags,dir_fd=fd);fds.append(fd);st=os.fstat(fd);parents.append((st.st_dev,st.st_ino))
 f=os.open(parts[-1],os.O_RDONLY|os.O_NOATIME|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd);fds.append(f)
 s=os.fstat(f);cur=os.stat(parts[-1],dir_fd=fd,follow_symlinks=False)
 if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or (s.st_dev,s.st_ino)!=(cur.st_dev,cur.st_ino):raise ValueError('file')
 return f,parents,s
def version(s):return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
try:
 root=walk_root();rootstat=os.fstat(root);lk,lockid=lock(root)
 try:f,parents,before=open_path(root)
 finally:unlock(lk)
 if before.st_size!=expected:raise ValueError('size')
 h=hashlib.sha256();count=0
 while True:
  idle()
  started=time.monotonic()
  chunk=os.read(f,65536)
  if not chunk:break
  count+=len(chunk)
  if count>expected:raise ValueError('size')
  h.update(chunk);delay=len(chunk)/rate-(time.monotonic()-started)
  while delay>0:
   cancelled();time.sleep(min(delay,.25));delay=len(chunk)/rate-(time.monotonic()-started)
 if count!=expected:raise ValueError('short')
 root2=walk_root();rootstat2=os.fstat(root2);lk,lockid2=lock(root2)
 try:
  f2,parents2,after=open_path(root2)
  if (rootstat.st_dev,rootstat.st_ino)!=(rootstat2.st_dev,rootstat2.st_ino) or lockid!=lockid2 or parents!=parents2 or version(before)!=version(os.fstat(f)) or version(before)!=version(after):raise ValueError('changed')
 finally:unlock(lk)
 print(json.dumps({'sha256':h.hexdigest(),'size':expected,'device':before.st_dev,'inode':before.st_ino,'mtime_ns':before.st_mtime_ns,'ctime_ns':before.st_ctime_ns},separators=(',',':')))
finally:
 for fd in reversed(fds):os.close(fd)
'''

_REMOTE_HEALTH = r'''import json,os,pathlib
# CPU_BUDGET_HELPER
cpus=cpu_budget()
with open('/proc/pressure/io','r') as f:line=f.readline()
psi=float(next(x.split('=',1)[1] for x in line.split() if x.startswith('avg10=')))
print(json.dumps({'load_ratio':os.getloadavg()[0]/cpus,'io_psi':psi},separators=(',',':')))
'''

_REMOTE = _REMOTE.replace('# CPU_BUDGET_HELPER', _REMOTE_CPU)
_REMOTE_FACTS = _REMOTE_FACTS.replace('# CPU_BUDGET_HELPER', _REMOTE_CPU)
_REMOTE_HASH = _REMOTE_HASH.replace('# CPU_BUDGET_HELPER', _REMOTE_CPU)
_REMOTE_HEALTH = _REMOTE_HEALTH.replace('# CPU_BUDGET_HELPER', _REMOTE_CPU)


def _verify_ssh(client, expected):
    if not isinstance(expected, str) or not _HEX64.fullmatch(expected):
        raise ValueError("invalid SSH pin")
    transport = client.get_transport()
    if transport is None or not transport.is_active() or not transport.is_authenticated():
        raise ValueError("SSH session unavailable")
    got = hashlib.sha256(transport.get_remote_server_key().asbytes()).hexdigest()
    if not hmac.compare_digest(got, expected):
        raise ValueError("SSH host key mismatch")


def _remote_json(client, script, payload, limit, timeout, cancel, keep_input=False):
    channel = None
    try:
        channel = client.get_transport().open_session(timeout=15)
        channel.exec_command("python3 -B -c " + shlex.quote(script))
        if payload is not None:
            channel.sendall(_go_json(payload) + b"\n")
        if not keep_input:
            channel.shutdown_write()
        end = time.monotonic() + timeout
        data = bytearray()
        stderr_seen = False
        while True:
            if cancel.is_set() or time.monotonic() >= end:
                raise ValueError("collection cancelled or timed out")
            while channel.recv_ready():
                data.extend(channel.recv(min(65536, limit + 1 - len(data))))
                if len(data) > limit:
                    raise ValueError("source response exceeds bound")
            while channel.recv_stderr_ready():
                channel.recv_stderr(1024)
                raise ValueError("source operation failed")
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                if channel.recv_exit_status() != 0 or stderr_seen:
                    raise ValueError("source operation failed")
                return json.loads(data)
            time.sleep(.05)
    except Exception:
        raise ValueError("source operation failed or cancelled") from None
    finally:
        if channel is not None:
            channel.close()
        if 'data' in locals():
            data[:] = b"\x00" * len(data)


def _check_health(client, limits, cancel):
    state = _remote_json(client, _REMOTE_HEALTH, None, 1024, 10, cancel)
    if (set(state) != {"load_ratio", "io_psi"} or
            not isinstance(state["load_ratio"], (int, float)) or
            not isinstance(state["io_psi"], (int, float)) or
            not math.isfinite(state["load_ratio"]) or not math.isfinite(state["io_psi"]) or
            state["load_ratio"] > limits["max_load_ratio"] or
            state["io_psi"] > limits["max_io_psi"]):
        raise ValueError("source busy")


def _go_json(value, *, sort_keys=False):
    raw = json.dumps(value, ensure_ascii=False, sort_keys=sort_keys,
                     separators=(",", ":"), allow_nan=False)
    for old, new in (("&", r"\u0026"), ("<", r"\u003c"), (">", r"\u003e"),
                     ("\u2028", r"\u2028"), ("\u2029", r"\u2029")):
        raw = raw.replace(old, new)
    return raw.encode("utf-8")


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _collect_unlocked(client, expected_host_sha256, source_node, source_key_id,
            target_node, target_receiver, challenge, collector_key, limits, cancel):
    """Collect into RAM, attest with collector key, return encrypted envelope.

    `expected_host_sha256` is lowercase hex SHA-256 of the independently
    authenticated SSH host key blob. No SSH key or session is sent onward.
    The caller must provision the collector public key and this fingerprint
    independently on the trusted target before accepting the envelope.
    """
    if not (_HEX64.fullmatch(expected_host_sha256) and _HEX32.fullmatch(source_node)
            and _HEX64.fullmatch(source_key_id) and _HEX32.fullmatch(target_node)
            and source_node != target_node and _HEX64.fullmatch(challenge)
            and isinstance(target_receiver, bytes) and len(target_receiver) == 32
            and any(target_receiver) and isinstance(collector_key, ed25519.Ed25519PrivateKey)):
        raise ValueError("invalid collection parameters")
    transport = client.get_transport()
    if transport is None or not transport.is_active() or not transport.is_authenticated():
        raise ValueError("SSH session unavailable")
    actual = hashlib.sha256(transport.get_remote_server_key().asbytes()).hexdigest()
    if not hmac.compare_digest(actual, expected_host_sha256):
        raise ValueError("SSH host key mismatch")
    try:
        timeout = math.ceil(_MAX / limits["bytes_per_second"]) + 65
        data = _remote_json(client, _REMOTE, limits, _MAX, timeout, cancel, keep_input=True)
    except Exception:
        raise ValueError("source snapshot failed") from None
    if not isinstance(data, dict) or set(data) != {"node", "sections"} or data["node"] != source_node:
        raise ValueError("source identity mismatch")
    sections = data["sections"]
    if not isinstance(sections, list) or len(sections) != 9:
        raise ValueError("source sections missing")
    keys = sections[-1]
    if keys.get("name") != "crypto_key_id" or len(keys.get("rows", [])) != 1 or keys["rows"][0][1] != source_key_id:
        raise ValueError("source media key identity mismatch")
    public = collector_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    now = int(time.time())
    snapshot = {"version": 1, "authority_kind": "ssh-collector-v1",
                "source_ssh_host_key_sha256": actual, "source_node": source_node,
                "source_public": _b64url(public), "target_node": target_node,
                "target_receiver": base64.b64encode(target_receiver).decode("ascii"),
                "challenge": challenge, "issued_unix": now, "expires_unix": now + 300,
                "sections": sections}
    digest = hashlib.sha256(_go_json(snapshot)).hexdigest()
    statement = {"kind": "frontiercloud-preprod-media-source-v1", "sha256": digest,
                 "source_node": source_node, "target_node": target_node, "challenge": challenge}
    signature = _b64url(collector_key.sign(_go_json(statement, sort_keys=True)))
    plain = bytearray(_go_json({"snapshot": snapshot, "signature": signature}))
    if len(plain) > _MAX + 4096:
        raise ValueError("source snapshot exceeds bound")
    try:
        ephemeral = x25519.X25519PrivateKey.generate()
        ephemeral_public = ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        target = x25519.X25519PublicKey.from_public_bytes(target_receiver)
        shared = ephemeral.exchange(target)
        aad = b"frontiercloud:preprod-source-envelope:v1\x00" + ephemeral_public + target_receiver
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=hashlib.sha256(aad).digest(), info=b"preprod-source-envelope-key-v1").derive(shared)
        import os
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, bytes(plain), aad)
        return ({"version": 1, "ephemeral": base64.b64encode(ephemeral_public).decode("ascii"),
                 "nonce": base64.b64encode(nonce).decode("ascii"), "cipher": base64.b64encode(ciphertext).decode("ascii")}, digest)
    finally:
        plain[:] = b"\x00" * len(plain)


def collect(client, expected_host_sha256, source_node, source_key_id,
            target_node, target_receiver, challenge, collector_key, limits, cancel):
    with _single_collector() as check_lock:
        _validate_limits(limits, cancel)
        _verify_ssh(client, expected_host_sha256)
        _check_health(client, limits, cancel)
        check_lock()
        return _collect_unlocked(client, expected_host_sha256, source_node,
                                 source_key_id, target_node, target_receiver,
                                 challenge, collector_key, limits, cancel)


def _validate_limits(limits, cancel):
    if (not isinstance(limits, dict) or set(limits) != {"bytes_per_second", "max_load_ratio", "max_io_psi"} or
            type(limits["bytes_per_second"]) is not int or not 65536 <= limits["bytes_per_second"] <= 1024 * 1024 or
            not isinstance(limits["max_load_ratio"], (int, float)) or not math.isfinite(limits["max_load_ratio"]) or not 0 < limits["max_load_ratio"] <= 1 or
            not isinstance(limits["max_io_psi"], (int, float)) or not math.isfinite(limits["max_io_psi"]) or not 0 <= limits["max_io_psi"] <= 100 or
            cancel is None or not callable(getattr(cancel, "is_set", None)) or cancel.is_set()):
        raise ValueError("invalid collector budget")


def collect_object(master_client, owner_client, source_host_pin, owner_host_pin,
                   source_node, source_key_id, owner_id, media_id, object_id,
                   expected_size, expected_sha256, target_node, target_owner_id,
                   target_blob_id, target_read_alias, target_receiver,
                   snapshot_challenge, object_challenge, collector_key, limits, cancel):
    """Return fresh encrypted SQL snapshot and one encrypted SSH byte proof.

    Hashing occurs on the pinned owner; only a small digest/stat response is
    transferred. Existing stage SHA is checked, never retransferred. The
    source can still change through uncooperative writes or ABA; this is not
    an atomic cluster snapshot and is not a deployment permission.
    """
    with _single_collector() as check_lock:
        _validate_limits(limits, cancel)
        if (not all(_HEX32.fullmatch(x) for x in (source_node, owner_id, target_node, target_owner_id)) or
                not all(_HEX64.fullmatch(x) for x in (source_host_pin, owner_host_pin, source_key_id, media_id, object_id,
                                                      expected_sha256, target_blob_id, target_read_alias, snapshot_challenge, object_challenge)) or
                target_blob_id in (media_id, object_id, target_read_alias, object_challenge) or
                target_read_alias in (media_id, object_id, object_challenge) or object_challenge in (media_id, object_id) or
                source_node == target_node or type(expected_size) is not int or not 0 <= expected_size <= 10 * 1024 * 1024 * 1024 or
                not isinstance(target_receiver, bytes) or len(target_receiver) != 32 or not any(target_receiver) or
                not isinstance(collector_key, ed25519.Ed25519PrivateKey)):
            raise ValueError("invalid source object scope")
        _verify_ssh(master_client, source_host_pin)
        _verify_ssh(owner_client, owner_host_pin)
        _check_health(master_client, limits, cancel)
        _check_health(owner_client, limits, cancel)
        query = {"media_id": media_id, "owner_id": owner_id, **limits}
        check_lock()
        before = _remote_json(master_client, _REMOTE_FACTS, query, _MAX, 30, cancel, keep_input=True)
        if set(before) != {"node", "path", "facts"} or before["node"] != source_node:
            raise ValueError("source identity mismatch")
        facts = before["facts"]
        if not isinstance(facts, dict) or set(facts) != {"object", "placement", "encryption", "member", "relationship", "visibility"}:
            raise ValueError("source object facts")
        member, placement, obj = facts["member"], facts["placement"], facts["object"]
        if not isinstance(member, list) or len(member) != 12 or member[0] != owner_id:
            raise ValueError("source owner mismatch")
        master = member[2] == "MasterLocal" and member[3] == "Local" and member[1] is None and owner_id == source_node
        follower = member[2] == "Follower" and member[3] in ("Direct", "Relay") and member[1] is not None
        if follower:
            relation = facts["relationship"]
            follower = (isinstance(relation, list) and len(relation) == 8 and relation[0] == member[1] and
                        relation[1] == owner_id and relation[4] == "downstream" and relation[6] == "active")
        if not (master or follower):
            raise ValueError("source owner unavailable")
        if placement is None:
            if not (master and isinstance(obj, list) and len(obj) == 6 and obj[0] == media_id and obj[1] == "lyric" and object_id == media_id):
                raise ValueError("source lyric identity")
        elif (not isinstance(placement, list) or len(placement) != 10 or placement[0] != media_id or
              placement[1] != owner_id or placement[2] != object_id or placement[3] != before["path"] or
              placement[4] not in ("audio", "video") or placement[5] != str(expected_size) or placement[7] != "active"):
            raise ValueError("source media identity")
        timeout = expected_size / limits["bytes_per_second"] + 180
        observed = _remote_json(owner_client, _REMOTE_HASH,
                                {"path": before["path"], "size": expected_size, "rate": limits["bytes_per_second"],
                                 "master": master, "max_load_ratio": limits["max_load_ratio"], "max_io_psi": limits["max_io_psi"]},
                                4096, timeout, cancel, keep_input=True)
        if (set(observed) != {"sha256", "size", "device", "inode", "mtime_ns", "ctime_ns"} or
                observed["sha256"] != expected_sha256 or observed["size"] != expected_size or
                any(type(observed[k]) is not int for k in ("device", "inode", "mtime_ns", "ctime_ns")) or observed["inode"] <= 0):
            raise ValueError("source bytes changed")
        _verify_ssh(master_client, source_host_pin)
        _verify_ssh(owner_client, owner_host_pin)
        check_lock()
        _check_health(master_client, limits, cancel)
        after = _remote_json(master_client, _REMOTE_FACTS, query, _MAX, 30, cancel, keep_input=True)
        if before != after:
            raise ValueError("source facts changed")
        source_envelope, source_digest = _collect_unlocked(master_client, source_host_pin, source_node, source_key_id,
                                                             target_node, target_receiver, snapshot_challenge, collector_key,
                                                             limits, cancel)
        facts_digest = hashlib.sha256(_go_json(facts)).hexdigest()
        now = int(time.time())
        proof = {"version": 1, "source_node": source_node, "source_owner_id": owner_id,
                 "owner_ssh_host_key_sha256": owner_host_pin, "source_snapshot_digest": source_digest,
                 "before_facts_sha256": facts_digest, "after_facts_sha256": facts_digest,
                 "media_id": media_id, "source_object_id": object_id, "path": before["path"],
                 "sha256": expected_sha256, "size": expected_size, "device": observed["device"], "inode": observed["inode"],
                 "mtime_ns": observed["mtime_ns"], "ctime_ns": observed["ctime_ns"], "target_node": target_node,
                 "target_owner_id": target_owner_id, "target_blob_id": target_blob_id, "target_read_alias": target_read_alias,
                 "challenge": object_challenge, "issued_unix": now, "expires_unix": now + 240}
        digest = hashlib.sha256(_go_json(proof)).hexdigest()
        statement = {"kind": "frontiercloud-preprod-ssh-object-proof-v1", "sha256": digest}
        signature = _b64url(collector_key.sign(_go_json(statement, sort_keys=True)))
        raw = bytearray(_go_json({"proof": proof, "signature": signature}))
        try:
            ephemeral = x25519.X25519PrivateKey.generate()
            eph = ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            shared = ephemeral.exchange(x25519.X25519PublicKey.from_public_bytes(target_receiver))
            aad = b"frontiercloud:preprod-source-object-proof:v1\x00" + eph + target_receiver
            key = HKDF(algorithm=hashes.SHA256(), length=32, salt=hashlib.sha256(aad).digest(), info=b"preprod-source-envelope-key-v1").derive(shared)
            nonce = os.urandom(12)
            encrypted = AESGCM(key).encrypt(nonce, bytes(raw), aad)
            proof_envelope = {"version": 1, "ephemeral": base64.b64encode(eph).decode("ascii"),
                              "nonce": base64.b64encode(nonce).decode("ascii"), "cipher": base64.b64encode(encrypted).decode("ascii")}
            return source_envelope, proof_envelope
        finally:
            raw[:] = b"\x00" * len(raw)
