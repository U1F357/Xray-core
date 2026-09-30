#!/usr/bin/env python3
"""Exercise the original TUN inbound -> native freedom for TCP and UDP in isolated netns."""
import json,os,signal,socket,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];OUT=ROOT/'testing/fingerprint/artifacts/legacy-tun';OUT.mkdir(parents=True,exist_ok=True)
BINARY=Path(sys.argv[1]).resolve();LAB=f'xfltun-{os.getpid()}';PEER=LAB+'p';namespaces=[];processes=[];logs=[]
def cmd(args,ns=None,**kw):return subprocess.run((['ip','netns','exec',ns] if ns else [])+args,check=True,**kw)
def launch(args,name,ns):
 log=(OUT/(name+'.log')).open('w');logs.append(log);p=subprocess.Popen(['ip','netns','exec',ns]+args,stdout=log,stderr=log);processes.append(p);return p
try:
 for ns in [LAB,PEER]:cmd(['ip','netns','add',ns]);namespaces.append(ns);cmd(['ip','link','set','lo','up'],ns)
 cmd(['ip','link','add','eth0','type','veth','peer','name','tmppeer'],LAB);cmd(['ip','link','set','tmppeer','netns',PEER],LAB);cmd(['ip','link','set','tmppeer','name','eth0'],PEER)
 for ns,ip in [(LAB,'192.0.2.1/24'),(PEER,'192.0.2.2/24')]:cmd(['ip','addr','add',ip,'dev','eth0'],ns);cmd(['ip','link','set','eth0','up'],ns)
 code='''import http.server,socket,threading,signal
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  b=bytes(range(256))*1024;self.send_response(200);self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
 def log_message(self,*a):pass
h=http.server.ThreadingHTTPServer(('0.0.0.0',18080),H);threading.Thread(target=h.serve_forever,daemon=True).start()
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',18081))
print('ready',flush=True)
while True:
 b,a=s.recvfrom(65535);s.sendto(b,a)
'''
 server=launch(['python3','-u','-c',code],'receiver',PEER)
 config={'log':{'loglevel':'info'},'inbounds':[{'protocol':'tun','settings':{'name':'xfptun','mtu':1500,'gateway':['10.203.10.1/30']}}],'outbounds':[{'protocol':'freedom','settings':{'redirect':'192.0.2.2:0'}}]}
 path=OUT/'config.json';path.write_text(json.dumps(config));xray=launch([str(BINARY),'run','-config',str(path)],'xray',LAB)
 for _ in range(100):
  if xray.poll()!=None:raise RuntimeError((OUT/'xray.log').read_text())
  if 'started' in (OUT/'xray.log').read_text() and 'ready' in (OUT/'receiver.log').read_text():break
  time.sleep(.1)
 else:raise RuntimeError('startup timeout')
 cmd(['ip','route','add','198.51.100.2/32','dev','xfptun'],LAB)
 for _ in range(3):
  got=subprocess.check_output(['ip','netns','exec',LAB,'curl','--noproxy','*','-fsS','--max-time','10','http://198.51.100.2:18080/'])
  assert got==bytes(range(256))*1024
 code="import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(10);b=bytes(range(256))*4;s.sendto(b,('198.51.100.2',18081));assert s.recv(65535)==b;s.close()"
 cmd(['python3','-c',code],LAB)
 assert 'TCP fingerprint inbound:' not in (OUT/'xray.log').read_text()
 xray.terminate();xray.wait(timeout=10)
 assert 'xfptun' not in subprocess.check_output(['ip','netns','exec',LAB,'ip','-j','link']).decode()
 (OUT/'verification.json').write_text(json.dumps({'binary':str(BINARY),'tcp_256KiB':True,'udp_1024B':True,'tun_cleanup':True},indent=2)+'\n')
 print('Original TUN inbound -> native freedom: TCP, UDP and cleanup PASS')
finally:
 for p in reversed(processes):
  if p.poll() is None:
   p.terminate()
   try:p.wait(timeout=10)
   except subprocess.TimeoutExpired:p.kill();p.wait()
 for ns in reversed(namespaces):subprocess.run(['ip','netns','delete',ns],check=False)
 for log in logs:log.close()
