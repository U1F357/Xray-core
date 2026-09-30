#!/usr/bin/env python3
"""Verify route/interface MTU selection, concurrent isolation and bidirectional data."""
from capture_ready import wait_capture
import concurrent.futures
import ipaddress
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[2];BINARY=Path(sys.argv[1]).resolve()
OUT=ROOT/'testing/fingerprint/artifacts/mtu';OUT.mkdir(parents=True,exist_ok=True)
LAB=f'xfpmtu-{os.getpid()}a';PEER=f'xfpmtu-{os.getpid()}b'
processes=[];logs=[];spaces=[];BODY=bytes(range(256))*512
profiles=['windows','macos','linux','auto']
templates=[('64240','2-1-3-1-1-4','8'),('65535','2-1-3-1-1-8-4-0-0','6'),('65535','2-4-8-1-3','9'),('65535','2-4-8-1-3','9')]
def run(args,ns=LAB,**kwargs):return subprocess.run(['ip','netns','exec',ns]+args,check=True,**kwargs)
def output(args):return subprocess.check_output(['ip','netns','exec',LAB]+args)
def launch(args,name,ns=LAB):
 f=(OUT/(name+'.log')).open('w');logs.append(f)
 p=subprocess.Popen(['ip','netns','exec',ns]+args,stdout=f,stderr=f);processes.append(p);return p
def ready(p,name):
 for _ in range(200):
  text=(OUT/(name+'.log')).read_text()
  if p.poll() is not None:raise RuntimeError(text)
  if 'ready' in text or 'started' in text:return
  time.sleep(.05)
 raise RuntimeError('startup timeout')
def fetch(task):
 i,target=task;host=f'[{target}]' if ':' in target else target
 p=run(['curl','--noproxy','','--socks5-hostname',f'127.0.0.1:{1080+i}','-gfsS','--max-time','20','--data-binary','@-',f'http://{host}:{18080+i}/'],input=BODY,stdout=subprocess.PIPE)
 assert p.stdout==BODY

def capture_check(path,limits):
 data=path.read_bytes();endian='<' if data[:4]==bytes.fromhex('d4c3b2a1') else '>';pos=24;syns={};payloads=0
 while pos<len(data):
  _,_,size,_=struct.unpack_from(endian+'IIII',data,pos);pos+=16;f=data[pos:pos+size];pos+=size
  ip=f[14:]
  if f[12:14]==b'\x08\x00':
   target=str(ipaddress.IPv4Address(ip[16:20]));header=(ip[0]&15)*4;length=int.from_bytes(ip[2:4],'big');proto=ip[9];overhead=40
  elif f[12:14]==b'\x86\xdd':
   target=str(ipaddress.IPv6Address(ip[24:40]));header=40;length=40+int.from_bytes(ip[4:6],'big');proto=ip[6];overhead=60
  else:continue
  if target not in limits:continue
  assert proto!=44,'unexpected IPv6 fragmentation'
  if proto!=6:continue
  if overhead==40:assert int.from_bytes(ip[6:8],'big')&0x3fff==0,'unexpected IPv4 fragmentation'
  tcp=ip[header:length];port=int.from_bytes(tcp[2:4],'big')
  if not 18080<=port<18084:continue
  mtu=limits[target];assert length<=mtu,(target,length,mtu)
  if tcp[13]&0x12==2:
   p=20;kinds=[];mss=ws=None
   while p<(tcp[12]>>4)*4:
    k=tcp[p];kinds.append(str(k))
    if k in [0,1]:p+=1;continue
    n=tcp[p+1];assert n>=2
    if k==2:mss=int.from_bytes(tcp[p+2:p+4],'big')
    if k==3:ws=tcp[p+2]
    p+=n
   i=port-18080;expected=templates[i]
   assert (str(int.from_bytes(tcp[14:16],'big')),'-'.join(kinds),str(ws))==expected
   assert mss==mtu-overhead,(target,i,mss,mtu-overhead)
   syns[(target,i)]=mss
  elif length>header+(tcp[12]>>4)*4:payloads+=1
 assert len(syns)==len(limits)*len(profiles),(syns,limits)
 assert payloads>20,payloads
 return {'syn_mss':{f'{a}/{profiles[i]}':m for (a,i),m in syns.items()},'payload_packets':payloads}
try:
 for ns in [LAB,PEER]:
  subprocess.run(['ip','netns','add',ns],check=True);spaces.append(ns);run(['ip','link','set','lo','up'],ns)
 run(['ip','link','add','eth0','type','veth','peer','name','peer0']);run(['ip','link','set','peer0','netns',PEER]);run(['ip','link','set','peer0','name','eth0'],PEER)
 for ns,last in [(LAB,'1'),(PEER,'2')]:
  run(['ip','link','set','eth0','mtu','9000','up'],ns)
  run(['ip','addr','add',f'192.0.2.{last}/24','dev','eth0'],ns)
  run(['ip','-6','addr','add',f'2001:db8:99::{last}/64','dev','eth0','nodad'],ns)
 run(['ip','addr','add','192.0.2.3/24','dev','eth0'],PEER);run(['ip','-6','addr','add','2001:db8:99::3/64','dev','eth0','nodad'],PEER)
 run(['sysctl','-qw','net.ipv6.conf.all.forwarding=1'])
 server='''import http.server,socket,threading,signal,time
class H(http.server.BaseHTTPRequestHandler):
 def do_POST(self):
  b=self.rfile.read(int(self.headers['Content-Length']));time.sleep(.5);self.send_response(200);self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
 def log_message(self,*a):pass
class S(http.server.ThreadingHTTPServer):
 address_family=socket.AF_INET6
 def server_bind(self):self.socket.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0);super().server_bind()
for p in range(18080,18084):
 s=S(('::',p),H);threading.Thread(target=s.serve_forever,daemon=True).start()
print('ready',flush=True);signal.pause()
'''
 peer=launch(['python3','-u','-c',server],'peer',PEER);ready(peer,'peer')
 c={'log':{'loglevel':'info'},'inbounds':[],'outbounds':[],'routing':{'rules':[]}}
 for i,profile in enumerate(profiles):
  c['inbounds'].append({'tag':profile,'listen':'127.0.0.1','port':1080+i,'protocol':'socks','settings':{'auth':'noauth'}})
  c['outbounds'].append({'tag':profile,'protocol':'freedom','settings':{'tcpFingerprint':profile}})
  c['routing']['rules'].append({'type':'field','inboundTag':[profile],'outboundTag':profile})
 (OUT/'config.json').write_text(json.dumps(c));p=launch([str(BINARY),'run','-c',str(OUT/'config.json')],'xrui');ready(p,'xrui')
 targets=['192.0.2.2','192.0.2.3','2001:db8:99::2','2001:db8:99::3'];report={}
 for label,interface,route_limits in [('jumbo',9000,[9000]*4),('interface1492',1492,[9000]*4),('mixed-routes',1500,[1280,1400,1280,1400]),('interface1280',1280,[9000]*4),('route-advmss',1500,[1500]*4)]:
  run(['ip','link','set','eth0','mtu',str(interface)])
  limits={}
  for target,mtu in zip(targets,route_limits):
   family='-6' if ':' in target else '-4';prefix='/128' if ':' in target else '/32'
   metric = (1220 if ':' in target else 1000) if label == 'route-advmss' else 0
   args = ['advmss', str(metric)] if metric else []
   run(['ip',family,'route','replace',target+prefix,'dev','eth0','mtu',str(mtu)]+args)
   limits[target]=min(1500,interface,mtu,metric+(60 if ':' in target else 40) if metric else 9000)
  cap=launch(['tcpdump','--immediate-mode','-i','eth0','-s','128','-B','8192','-U','-w',str(OUT/(label+'.pcap')),'ip or ip6'],'capture-'+label,PEER)
  wait_capture(cap,OUT/('capture-'+label+'.log'))
  with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:list(pool.map(fetch,[(i,t) for i in range(4) for t in targets]))
  cap.send_signal(signal.SIGINT);cap.wait(timeout=5)
  report[label]=capture_check(OUT/(label+'.pcap'),limits)
  print(label+': IPv4/IPv6, all profiles, MSS and upload/download packet lengths PASS',flush=True)
 p.terminate();p.wait(timeout=15);assert p.returncode==0
 (OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
finally:
 for p in reversed(processes):
  if p.poll() is None:
   p.terminate()
   try:p.wait(timeout=10)
   except subprocess.TimeoutExpired:p.kill();p.wait()
 for ns in reversed(spaces):subprocess.run(['ip','netns','delete',ns],check=False)
 for f in logs:f.close()
