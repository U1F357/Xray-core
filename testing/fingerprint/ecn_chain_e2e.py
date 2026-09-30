#!/usr/bin/env python3
"""Nine profile/ECN offers through three VLESS nodes, verified on actual SYNs."""
from capture_ready import wait_capture
import concurrent.futures
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time
ROOT=Path(__file__).resolve().parents[2]
BINARY=Path(sys.argv[1]).resolve()
V6='--ipv6' in sys.argv[2:]
DELAY='--handshake-delay' in sys.argv[2:]
FIRST='2001:db8:11::2' if V6 else '198.18.0.2'
DEST='2001:db8:22::2' if V6 else '192.0.2.2'
OUT=ROOT/'testing/fingerprint/artifacts'/(('ecn-chain-v6' if V6 else 'ecn-chain')+('-delay' if DELAY else ''));OUT.mkdir(parents=True,exist_ok=True)
PREFIX=f'xfpecn-{os.getpid()}'
CLIENT,SERVER,PEER=[PREFIX+x for x in ('c','s','p')]
spaces=[];processes=[];logs=[]
UUID='8e023ca4-6e4d-47ab-9f38-233a67d95671'
PROFILES=['windows','macos','linux'];MODES=['none','classic','accecn']
COMBOS=[(p,m) for p in PROFILES for m in MODES]
def run(args,ns=None,**kwargs):
 return subprocess.run((['ip','netns','exec',ns] if ns else [])+args,check=True,**kwargs)
def launch(args,ns,name):
 f=(OUT/(name+'.log')).open('w');logs.append(f)
 p=subprocess.Popen(['ip','netns','exec',ns]+args,stdout=f,stderr=f);processes.append(p);return p
def ready(p,name,needle):
 for _ in range(300):
  if needle in (OUT/(name+'.log')).read_text():return
  if p.poll() is not None:raise RuntimeError((name,p.returncode,(OUT/(name+'.log')).read_text()))
  time.sleep(.05)
 raise RuntimeError('startup timeout '+name)
def core(ns,name,config):
 path=OUT/(name+'.json');path.write_text(json.dumps(config))
 p=launch([str(BINARY),'run','-config',str(path)],ns,name);ready(p,name,'started');return p
def pair(a,namea,ipa,b,nameb,ipb):
 run(['ip','link','add',namea,'type','veth','peer','name','tmppeer'],a)
 run(['ip','link','set','tmppeer','netns',b],a);run(['ip','link','set','tmppeer','name',nameb],b)
 for ns,name,ip in [(a,namea,ipa),(b,nameb,ipb)]:
  run(['ip','addr','add',ip+('/64' if V6 else '/24'),'dev',name]+(['nodad'] if V6 else []),ns);run(['ip','link','set',name,'up'],ns)
def inbound(port,email,source):
 x={'listen':('::' if V6 and port==12345 else '0.0.0.0'),'port':port,'protocol':'vless','settings':{'clients':[{'id':UUID,'email':email}],'decryption':'none'},'tcpFingerprint':{'source':source}}
 if source=='vless':x['tcpFingerprint'].update(trustedUsers=[email],onMissing='unknown')
 return x
def outbound(port):return {'protocol':'vless','settings':{'tcpFingerprintForward':True,'vnext':[{'address':'127.0.0.1','port':port,'users':[{'id':UUID,'encryption':'none'}]}]}}
def config(ins,outs):return {'log':{'loglevel':'info'},'inbounds':ins,'outbounds':outs}
def syns(path,ports):
 b=path.read_bytes();endian='<' if b[:4]==bytes.fromhex('d4c3b2a1') else '>';pos=24;found=[]
 while pos<len(b):
  _,_,n,_=struct.unpack_from(endian+'IIII',b,pos);pos+=16;f=b[pos:pos+n];pos+=n
  if f[12:14] not in (b'\x08\x00',b'\x86\xdd'):continue
  ip=f[14:]
  if ip[0]>>4==6:
   if ip[6]!=6:continue
   h=ip[40:];traffic=(ip[0]&15)<<4|ip[1]>>4
  else:
   if ip[9]!=6:continue
   h=ip[(ip[0]&15)*4:];traffic=ip[1]
  port=int.from_bytes(h[2:4],'big')
  if h[13]&0x17!=2 or port not in ports:continue
  kinds=[];i=20;mss=ws=None
  while i<(h[12]>>4)*4:
   k=h[i];kinds.append(str(k))
   if k==0:break
   if k==1:i+=1;continue
   n=h[i+1];assert n>=2
   if k==2:mss=int.from_bytes(h[i+2:i+4],'big')
   if k==3:ws=h[i+2]
   i+=n
  found.append({'port':port,'flags':(h[12]&1)<<8|h[13],'ecn':traffic&3,'options':'-'.join(kinds),'ws':ws,'window':int.from_bytes(h[14:16],'big')})
 return found
try:
 for ns in [CLIENT,SERVER,PEER]:run(['ip','netns','add',ns]);spaces.append(ns);run(['ip','link','set','lo','up'],ns)
 pair(CLIENT,'eth0','2001:db8:11::1' if V6 else '198.18.0.1',SERVER,'client0',FIRST)
 pair(SERVER,'eth0','2001:db8:22::1' if V6 else '192.0.2.1',PEER,'eth0',DEST)
 run(['ip','route','add','default','via',FIRST],CLIENT)
 run(['ip','route','add','default','via',DEST],SERVER)
 if V6:
  for ns in spaces:run(['sysctl','-qw','net.ipv6.conf.all.forwarding=1'],ns)
 http='''import http.server,threading,signal,socket,sys,ssl
v6=sys.argv[1]=="1"
if v6:http.server.ThreadingHTTPServer.address_family=socket.AF_INET6
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  b=b"x"*131072;self.send_response(200);self.send_header("Content-Length",str(len(b)));self.end_headers();self.wfile.write(b)
 def log_message(self,*a):pass
for port in range(18080,18089):
 s=http.server.ThreadingHTTPServer(("::" if v6 else "0.0.0.0",port),H)
 if len(sys.argv)>2:
  ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(sys.argv[2],sys.argv[3]);s.socket=ctx.wrap_socket(s.socket,server_side=True)
 threading.Thread(target=s.serve_forever,daemon=True).start()
print("ready",flush=True);signal.pause()
'''
 tlsargs=[]
 if DELAY:
  cert=OUT/'cert.pem';key=OUT/'key.pem'
  run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-keyout',str(key),'-out',str(cert)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  tlsargs=[str(cert),str(key)]
 p=launch(['python3','-u','-c',http,'1' if V6 else '0']+tlsargs,PEER,'http');ready(p,'http','ready')
 core(SERVER,'exit',config([inbound(12500,'middle','vless')],[{'protocol':'freedom','settings':{'tcpFingerprint':'auto','tcpECN':'auto',**({'tcpHandshakeDelay':{'minMs':200,'maxMs':300}} if DELAY else {}),'finalRules':[{'action':'allow','ip':[DEST],'port':'18080-18088'}]}}]))
 core(SERVER,'middle',config([inbound(12400,'entry','vless')],[outbound(12500)]))
 core(SERVER,'entry',config([inbound(12345,'client','syn')],[outbound(12400)]))
 ins=[];outs=[];rules=[]
 for i,(profile,mode) in enumerate(COMBOS):
  tag=str(i);ins.append({'listen':'127.0.0.1','port':10800+i,'tag':tag,'protocol':'socks','settings':{'auth':'noauth'}})
  outs.append({'tag':tag,'protocol':'freedom','settings':{'tcpFingerprint':profile,'tcpECN':mode}})
  rules.append({'type':'field','inboundTag':[tag],'outboundTag':tag})
 clientconfig=config(ins,outs);clientconfig['routing']={'rules':rules};core(CLIENT,'client',clientconfig)
 captures=[]
 for ns,iface,name in [(SERVER,'client0','ingress'),(PEER,'eth0','egress')]:
  p=launch(['tcpdump','--immediate-mode','-U','-nn','-i',iface,'-s','128','-w',str(OUT/(name+'.pcap')),'ip6 and tcp' if V6 else 'tcp'],ns,name);wait_capture(p,OUT/(name+'.log'));captures.append(p)
 fetch='''import socket,struct,uuid,sys,ssl
idx=int(sys.argv[1]);v6=sys.argv[2]=="1"
first="2001:db8:11::2" if v6 else "198.18.0.2";dest="2001:db8:22::2" if v6 else "192.0.2.2"
pack=lambda a:socket.inet_pton(socket.AF_INET6 if v6 else socket.AF_INET,a)
s=socket.create_connection(("127.0.0.1",10800+idx),timeout=20)
def exact(n):
 b=b""
 while len(b)<n:
  a=s.recv(n-len(b));assert a;b+=a
 return b
s.sendall(b"\\x05\\x01\\x00");assert exact(2)==b"\\x05\\x00"
s.sendall(b"\\x05\\x01\\x00"+bytes([4 if v6 else 1])+pack(first)+struct.pack("!H",12345));reply=exact(4);assert reply[:3]==b"\\x05\\x00\\x00";exact(18 if reply[3]==4 else 6)
s.sendall(b"\\x00"+uuid.UUID("8e023ca4-6e4d-47ab-9f38-233a67d95671").bytes+b"\\x00\\x01"+struct.pack("!H",18080+idx)+bytes([3 if v6 else 1])+pack(dest))
request=b"GET / HTTP/1.0\\r\\nHost: test\\r\\n\\r\\n"
if sys.argv[3]=="1":
 incoming=ssl.MemoryBIO();outgoing=ssl.MemoryBIO();tls=ssl._create_unverified_context().wrap_bio(incoming,outgoing,server_side=False,server_hostname="localhost")
 try:tls.do_handshake()
 except ssl.SSLWantReadError:pass
 s.sendall(outgoing.read());assert exact(2)==b"\\x00\\x00"
 while True:
  try:tls.do_handshake();break
  except ssl.SSLWantReadError:
   s.sendall(outgoing.read());a=s.recv(65536);assert a;incoming.write(a)
 s.sendall(outgoing.read());tls.write(request);s.sendall(outgoing.read());b=b""
 while len(b.split(b"\\r\\n\\r\\n",1)[-1])<131072:
  try:b+=tls.read(65536)
  except ssl.SSLWantReadError:
   s.sendall(outgoing.read());a=s.recv(65536);assert a;incoming.write(a)
else:
 s.sendall(request);assert exact(2)==b"\\x00\\x00";b=b""
 while True:
  a=s.recv(65536)
  if not a:break
  b+=a
assert b.split(b"\\r\\n\\r\\n",1)[1]==b"x"*131072
s.close()
'''
 with concurrent.futures.ThreadPoolExecutor(max_workers=9) as pool:
  list(pool.map(lambda i:run(['python3','-c',fetch,str(i),'1' if V6 else '0','1' if DELAY else '0'],CLIENT),range(9)))
 time.sleep(.2)
 for p in captures:p.send_signal(signal.SIGINT);p.wait(timeout=10)
 observed=syns(OUT/'egress.pcap',range(18080,18089));assert len(observed)==9,observed
 expected_options={'windows':('2-1-3-1-1-4',64240,8),'macos':('2-1-3-1-1-8-4-0',65535,6),'linux':('2-4-8-1-3',65535,9)}
 for row in observed:
  profile,mode=COMBOS[row['port']-18080];assert (row['options'],row['window'],row['ws'])==expected_options[profile],row
  assert row['flags']=={'none':2,'classic':0xc2,'accecn':0x1c2}[mode],row
  expected_ecn=0 if mode=='none' else 2 if profile=='windows' else 1 if profile=='macos' and mode=='accecn' else 0
  assert row['ecn']==expected_ecn,row
 if DELAY:
  from handshake_delay_capture import verify
  verify(OUT/'egress.pcap',OUT/'exit.log',OUT/'timing.json')
 text=(OUT/'exit.log').read_text()
 for mode in MODES:assert f'selected={mode} source=vless fallback=false' in text,text
 (OUT/'verification.json').write_text(json.dumps(observed,indent=2)+'\n')
 print(('IPv6 ' if V6 else 'IPv4 ')+'PASS: nine concurrent profile/ECN combinations, saved SYN -> VLESS -> VLESS -> freedom, 128 KiB each')
finally:
 for p in reversed(processes):
  if p.poll() is None:
   p.terminate()
   try:p.wait(timeout=15)
   except subprocess.TimeoutExpired:p.kill();p.wait()
 for f in logs:f.close()
 for ns in reversed(spaces):subprocess.run(['ip','netns','del',ns],check=False)
