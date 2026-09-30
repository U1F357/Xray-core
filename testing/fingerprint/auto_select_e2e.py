#!/usr/bin/env python3
"""Run real Xray VLESS clients inside three gVisor runtimes; verify ingress/egress SYNs.
All links, NAT rules and forwarding changes are confined to disposable netns.
"""
from capture_ready import wait_capture
import concurrent.futures
import json
import os
from pathlib import Path
import shutil
import signal
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
BINARY = Path(sys.argv[1]).resolve() if len(sys.argv)>1 else ROOT/'dist/xrui'
MULTI_HOP = os.environ.get('XRAY_FP_MULTI_HOP') == '1'
OUT = ROOT/'testing/fingerprint/artifacts'/('multi-hop' if MULTI_HOP else 'auto-selection')
OUT.mkdir(parents=True, exist_ok=True)
PROFILES = ['windows','macos','linux']
EXPECTED = ['64240_2-1-3-1-1-4_1460_8','65535_2-1-3-1-1-8-4-0_1460_6','65535_2-4-8-1-3_1460_9']
RUNTIMES = Path(os.environ.get('XRAY_FP_RUNSC_DIR', str(ROOT.parent/'dist')))
UUID = '8e023ca4-6e4d-47ab-9f38-233a67d95671'
PREFIX=f'xfpsel-{os.getpid()}'
SERVER, RECEIVER = PREFIX+'s', PREFIX+'r'
namespaces,processes,logs,containers=[],[],[],[]

def cmd(args,ns=None,**kwargs):
 return subprocess.run((['ip','netns','exec',ns] if ns else [])+args,check=True,**kwargs)
def launch(args,name,ns=None):
 log=(OUT/(name+'.log')).open('w');logs.append(log)
 p=subprocess.Popen((['ip','netns','exec',ns] if ns else [])+args,stdout=log,stderr=log);processes.append(p);return p

def pair(left, lname, lip, right, rname, rip):
 # Temporary names exist only inside their owning namespaces.
 cmd(['ip','link','add',lname,'type','veth','peer','name','tmppeer'],left)
 cmd(['ip','link','set','tmppeer','netns',right],left)
 cmd(['ip','link','set','tmppeer','name',rname],right)
 for ns,name,ip in [(left,lname,lip),(right,rname,rip)]:
  cmd(['ip','addr','add',ip+'/24','dev',name],ns);cmd(['ip','link','set',name,'up'],ns)

def wait_log(p,name,text):
 for _ in range(300):
  if p.poll() is not None: raise RuntimeError((OUT/(name+'.log')).read_text())
  if text in (OUT/(name+'.log')).read_text():return
  time.sleep(.1)
 raise RuntimeError('startup timeout: '+(OUT/(name+'.log')).read_text())

def fingerprints(path):
 data=path.read_bytes();endian='<' if data[:4]==bytes.fromhex('d4c3b2a1') else '>'
 assert struct.unpack_from(endian+'I',data,20)[0]==1
 pos=24; result=[]
 while pos<len(data):
  _,_,size,_=struct.unpack_from(endian+'IIII',data,pos);pos+=16;frame=data[pos:pos+size];pos+=size
  if frame[12:14]!=b'\x08\x00':continue
  ip=frame[14:]; tcp=ip[(ip[0]&15)*4:]
  if ip[9]!=6 or tcp[13]&0x12!=2:continue
  win=int.from_bytes(tcp[14:16],'big');end=(tcp[12]>>4)*4;p=20;kinds=[];mss=ws=None
  while p<end:
   kind=tcp[p];kinds.append(str(kind))
   if kind==0:
    assert not any(tcp[p+1:end]), "nonzero EOL padding"
    break
   if kind==1:p+=1;continue
   length=tcp[p+1]
   if kind==2:mss=int.from_bytes(tcp[p+2:p+4],'big')
   if kind==3:ws=tcp[p+2]
   assert length>=2;p+=length
  result.append({'port':int.from_bytes(tcp[2:4],'big'),'fingerprint':f'{win}_{"-".join(kinds)}_{mss}_{ws}'})
 return result

def fetch(task):
 i,mode=task
 body=subprocess.check_output(['ip','netns','exec',SERVER,'curl','--noproxy','','--socks5-hostname',f'10.77.{i}.2:{1080+mode}','-fsS','--max-time','20',f'http://192.0.2.2:{18080+i}/'])
 assert body==bytes(range(256))*1024,len(body)

try:
 for ns in [SERVER,RECEIVER]+[PREFIX+str(i) for i in range(3)]:
  cmd(['ip','netns','add',ns]);namespaces.append(ns);cmd(['ip','link','set','lo','up'],ns)
 pair(SERVER,'eth0','192.0.2.1',RECEIVER,'eth0','192.0.2.2')
 for i in range(3):pair(SERVER,'client'+str(i),f'10.77.{i}.1',PREFIX+str(i),'eth0',f'10.77.{i}.2')
 cmd(['sysctl','-qw','net.ipv4.ip_forward=0'],SERVER)
 for iface in ['eth0','client0','client1','client2']:cmd(['sysctl','-qw',f'net.ipv4.conf.{iface}.forwarding=0'],SERVER)
 cmd(['ip','route','add','default','via','192.0.2.2'],SERVER)
 cmd(['nft','-f','-'],SERVER,input='table inet administrator { chain forward { type filter hook forward priority 0; policy drop; }\n }\n',text=True)
 baseline=subprocess.check_output(['ip','netns','exec',SERVER,'nft','list','ruleset'])
 server_config={'log':{'loglevel':'info'},'inbounds':[{'port':12345,'listen':'0.0.0.0','protocol':'vless','settings':{'clients':[{'id':UUID}],'decryption':'none'},'streamSettings':{'network':'tcp'}}],'outbounds':[{'protocol':'freedom','settings':{'tcpFingerprint':'auto','tcpFingerprintFallback':'macos','finalRules':[{'action':'allow','ip':['192.0.2.2'],'port':'18080-18082'}]}}],'policy':{'system':{'statsInboundUplink':True,'statsInboundDownlink':True}},'stats':{}}
 cmd(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(OUT/'key.pem'),'-out',str(OUT/'cert.pem'),'-days','1','-subj','/CN=fp.test','-addext','subjectAltName=DNS:fp.test'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 tls_inbound=json.loads(json.dumps(server_config['inbounds'][0]));tls_inbound['port']=12346
 tls_inbound['streamSettings'].update({'security':'tls','tlsSettings':{'certificates':[{'certificateFile':str(OUT/'cert.pem'),'keyFile':str(OUT/'key.pem')}]}})
 server_config['inbounds'].append(tls_inbound)
 # Unix HTTP ingress has no TCP SYN and must use the explicit macos fallback.
 unix_path=str(OUT/'fallback.sock')
 server_config['inbounds'].append({'listen':unix_path,'protocol':'http','settings':{}})
 server_config['outbounds'][0]['settings']['finalRules'][0]['port']='18080-18083'
 if MULTI_HOP:
  # First ingress chooses the physically observed SYN, never a client claim.
  for inbound in server_config['inbounds']:
   if inbound['protocol']=='vless':inbound['tcpFingerprint']={'source':'syn'}
  freedom=server_config['outbounds'][0]
  def relay_out(port):
   return {'protocol':'vless','settings':{'tcpFingerprintForward':True,'vnext':[{'address':'127.0.0.1','port':port,'users':[{'id':UUID,'encryption':'none'}]}]},'streamSettings':{'network':'tcp'}}
  def relay_in(port,email):
   return {'listen':'127.0.0.1','port':port,'protocol':'vless','settings':{'clients':[{'id':UUID,'email':email}],'decryption':'none'},'tcpFingerprint':{'source':'vless','trustedUsers':[email],'onMissing':'unknown'}}
  server_config['outbounds']=[relay_out(12400)]
  for name,config in [('exit',{'log':{'loglevel':'info'},'inbounds':[relay_in(12500,'middle@relay')],'outbounds':[freedom]}),('middle',{'log':{'loglevel':'info'},'inbounds':[relay_in(12400,'entry@relay')],'outbounds':[relay_out(12500)]})]:
   path=OUT/(name+'.json');path.write_text(json.dumps(config));p=launch([str(BINARY),'run','-config',str(path)],name,SERVER);wait_log(p,name,'started')
   if name=='exit':exit_process=p
   else:middle_process=p
 (OUT/'server.json').write_text(json.dumps(server_config))
 server=launch([str(BINARY),'run','-config',str(OUT/'server.json')],'xray-server',SERVER)
 wait_log(server,'xray-server','started')
 http_code='''import http.server,threading,signal
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  b=bytes(range(256))*1024;self.send_response(200);self.send_header("Content-Length",str(len(b)));self.end_headers();self.wfile.write(b)
 def log_message(self,*a):pass
for p in range(18080,18084):
 s=http.server.ThreadingHTTPServer(("0.0.0.0",p),H);threading.Thread(target=s.serve_forever,daemon=True).start()
print("ready",flush=True);signal.pause()
'''
 http=launch(['python3','-u','-c',http_code],'http',RECEIVER);wait_log(http,'http','ready')
 captures=[]
 for i in range(3):captures.append(launch(['tcpdump','--immediate-mode','-i','client'+str(i),'-U','-w',str(OUT/f'inbound-{PROFILES[i]}.pcap'),'(tcp dst port 12345 or tcp dst port 12346) and tcp[tcpflags] & 0x12 == 2'],'capture-in-'+PROFILES[i],SERVER))
 captures.append(launch(['tcpdump','--immediate-mode','-i','eth0','-U','-w',str(OUT/'outbound.pcap'),'tcp[tcpflags] & 0x12 == 2'],'capture-out',RECEIVER))
 for i,profile in enumerate(PROFILES):wait_capture(captures[i], OUT/('capture-in-'+profile+'.log'))
 wait_capture(captures[-1], OUT/'capture-out.log')
 for i,profile in enumerate(PROFILES):
  bundle=OUT/profile;rootfs=bundle/'rootfs';rootfs.mkdir(parents=True,exist_ok=True)
  shutil.copy2(BINARY,rootfs/'xrui')
  for path in ['proc','dev','tmp']: (rootfs/path).mkdir(exist_ok=True)
  client={'log':{'loglevel':'info'},'inbounds':[],'outbounds':[],'routing':{'rules':[]}}
  for mode in range(3):
   mux=mode==1
   tag=['plain','mux','tls'][mode]
   client['inbounds'].append({'tag':tag,'listen':'0.0.0.0','port':1080+mode,'protocol':'socks','settings':{'auth':'noauth'}})
   client['outbounds'].append({'tag':tag,'protocol':'vless','settings':{'vnext':[{'address':f'10.77.{i}.1','port':12345,'users':[{'id':UUID,'encryption':'none'}]}]},'streamSettings':{'network':'tcp'},'mux':{'enabled':mux,'concurrency':8}})
   if mode==2:
    client['outbounds'][-1]['settings']['vnext'][0]['port']=12346
    client['outbounds'][-1]['streamSettings'].update({'security':'tls','tlsSettings':{'serverName':'fp.test','certificates':[{'certificate':(OUT/'cert.pem').read_text().splitlines(),'usage':'verify'}]}})
   client['routing']['rules'].append({'type':'field','inboundTag':[tag],'outboundTag':tag})
  (rootfs/'client.json').write_text(json.dumps(client))
  spec={'ociVersion':'1.0.2','root':{'path':str(rootfs),'readonly':True},'process':{'terminal':False,'user':{'uid':0,'gid':0},'args':['/xrui','run','-config','/client.json'],'env':['PATH=/','GOMAXPROCS=2'],'cwd':'/','noNewPrivileges':True},'mounts':[{'destination':'/proc','type':'proc','source':'proc'},{'destination':'/dev','type':'tmpfs','source':'tmpfs'},{'destination':'/tmp','type':'tmpfs','source':'tmpfs'}],'linux':{'namespaces':[{'type':'network','path':'/var/run/netns/'+PREFIX+str(i)},{'type':'pid'},{'type':'ipc'},{'type':'uts'},{'type':'mount'}]}}
  (bundle/'config.json').write_text(json.dumps(spec))
  runtime=[str(RUNTIMES/profile/'runsc'),'--root='+str(bundle/'state'),'--ignore-cgroups','--network=sandbox','--platform=systrap']
  name=PREFIX+profile;containers.append((runtime,name))
  p=launch(runtime+['run','--bundle='+str(bundle),name],'client-'+profile)
  wait_log(p,'client-'+profile,'started')
  for mode in range(3):fetch((i,mode))
  print(profile+' runsc Xray client: plain + mux + TLS PASS',flush=True)
 with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:list(pool.map(fetch,[(i,m) for _ in range(3) for i in range(3) for m in range(3)]))
 print('concurrent profiles, TLS and multiplexed streams PASS',flush=True)
 fallback_code="import socket,http.client,sys; s=socket.socket(socket.AF_UNIX);s.settimeout(10);s.connect(sys.argv[1]);s.sendall(b'GET http://192.0.2.2:18083/ HTTP/1.0\\r\\nHost: 192.0.2.2:18083\\r\\nConnection: close\\r\\n\\r\\n');r=http.client.HTTPResponse(s);r.begin();assert r.status==200,r.status;sys.stdout.buffer.write(r.read());s.close()"
 fallback_body=subprocess.check_output(['ip','netns','exec',SERVER,'python3','-c',fallback_code,unix_path])
 assert fallback_body==bytes(range(256))*1024
 print('Unix ingress without SYN: fallback request PASS',flush=True)
 for p in captures:p.send_signal(signal.SIGINT);p.wait(timeout=5)
 outbound=fingerprints(OUT/'outbound.pcap');report={}
 for i,profile in enumerate(PROFILES):
  incoming=fingerprints(OUT/f'inbound-{profile}.pcap');outgoing=[v for v in outbound if v['port']==18080+i]
  assert incoming and outgoing,(profile,incoming,outgoing)
  assert all(v['fingerprint']==EXPECTED[i] for v in incoming),(profile,incoming)
  assert all(v['fingerprint']==EXPECTED[i] for v in outgoing),(profile,outgoing)
  report[profile]={'inbound':incoming,'outbound':outgoing}
 fallback=[v for v in outbound if v['port']==18083]
 assert fallback and all(v['fingerprint']==EXPECTED[1] for v in fallback),fallback
 report['fallback']=fallback
 if MULTI_HOP:
  for process in [server,middle_process,exit_process]:process.terminate();process.wait(timeout=15)
  for name in ['middle','exit']:
   log=(OUT/(name+'.log')).read_text()
   for profile in PROFILES:assert 'status=accepted source=vless category='+profile in log,(name,profile)
  assert 'detected=unknown selected=macos fallback=true source=vless' in (OUT/'exit.log').read_text()
  report['multi_hop']={'nodes':3,'trusted_metadata':True,'unknown_preserved':True}
 else:
  server.terminate();server.wait(timeout=15)
 for _ in range(100):
  now=subprocess.check_output(['ip','netns','exec',SERVER,'nft','list','ruleset'])
  if now==baseline:break
  time.sleep(.05)
 else:raise AssertionError('firewall cleanup failed')
 assert subprocess.check_output(['ip','netns','exec',SERVER,'cat','/proc/sys/net/ipv4/conf/eth0/forwarding']).strip()==b'0'
 report['checks']=['real gVisor runsc Xray clients','VLESS TCP and TLS','Unix ingress fallback','inbound statistics enabled','mux inheritance','256KiB payload per request','concurrent profile isolation','ingress and receiver egress packet capture','automatic network cleanup']
 (OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
 print('all ingress/egress fingerprints match; cleanup PASS',flush=True)
finally:
 for runtime,name in reversed(containers):subprocess.run(runtime+['delete','--force',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
 for p in reversed(processes):
  if p.poll() is None:
   p.terminate()
   try:p.wait(timeout=10)
   except subprocess.TimeoutExpired:p.kill();p.wait()
 for ns in reversed(namespaces):subprocess.run(['ip','netns','delete',ns],check=False)
 for log in logs:log.close()
 # Keep reproducible configs/captures, not duplicate binaries or runtime state.
 for profile in PROFILES:
  (OUT/profile/'rootfs/xrui').unlink(missing_ok=True)
