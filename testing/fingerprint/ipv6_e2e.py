#!/usr/bin/env python3
"""IPv6 NAT66/fingerprint regression in disposable namespaces; no Internet."""
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

ROOT=Path(__file__).resolve().parents[2]
BINARY=Path(sys.argv[1]).resolve()
OUT=ROOT/'testing/fingerprint/artifacts/ipv6';OUT.mkdir(parents=True,exist_ok=True)
LAB=f'xfp6-{os.getpid()}a';PEER=f'xfp6-{os.getpid()}b'
processes=[];logs=[];spaces=[]
BODY=bytes(range(256))*1024

def cmd(args,ns=None,**kwargs):return subprocess.run((['ip','netns','exec',ns] if ns else [])+args,check=True,**kwargs)
def output(args,ns=LAB):return subprocess.check_output(['ip','netns','exec',ns]+args)
def launch(args,name,ns=LAB):
 log=(OUT/(name+'.log')).open('w');logs.append(log)
 p=subprocess.Popen(['ip','netns','exec',ns]+args,stdout=log,stderr=log);processes.append(p);return p
def ready(p,name):
 for _ in range(100):
  text=(OUT/(name+'.log')).read_text()
  if p.poll() is not None:raise RuntimeError(text)
  if 'started' in text or 'ready' in text:return
  time.sleep(.1)
 raise RuntimeError('startup timeout '+name)
def fetch(port):
 result=output(['curl','--noproxy','','--socks5-hostname',f'127.0.0.1:{port}','-gfsS','--max-time','15','http://[2001:db8:66::2]:18080/'])
 assert result==BODY,len(result)
def check_packets(path):
 data=path.read_bytes();endian='<' if data[:4]==bytes.fromhex('d4c3b2a1') else '>';pos=24;found=[]
 while pos<len(data):
  _,_,size,_=struct.unpack_from(endian+'IIII',data,pos);pos+=16;frame=data[pos:pos+size];pos+=size
  if frame[12:14]!=b'\x86\xdd':continue
  ip=frame[14:]
  if ip[6]!=6:continue
  tcp=ip[40:40+int.from_bytes(ip[4:6],'big')]
  if len(tcp)<20 or tcp[13]&0x12!=2 or int.from_bytes(tcp[2:4],'big')!=18080:continue
  assert ipaddress.IPv6Address(ip[8:24])==ipaddress.IPv6Address('2001:db8:66::1')
  pseudo=ip[8:40]+len(tcp).to_bytes(4,'big')+b'\0\0\0\6'+tcp
  if len(pseudo)%2:pseudo+=b'\0'
  total=sum(struct.unpack('!'+str(len(pseudo)//2)+'H',pseudo))
  while total>>16:total=(total&65535)+(total>>16)
  assert total==65535,'bad IPv6 TCP checksum'
  options=[];mss=ws=None;p=20
  while p<(tcp[12]>>4)*4:
   k=tcp[p];options.append(str(k))
   if k in [0,1]:p+=1;continue
   n=tcp[p+1];assert n>=2
   if k==2:mss=int.from_bytes(tcp[p+2:p+4],'big')
   if k==3:ws=tcp[p+2]
   p+=n
  found.append(f'{int.from_bytes(tcp[14:16],"big")}_{"-".join(options)}_{mss}_{ws}')
 return found
try:
 for ns in [LAB,PEER]:cmd(['ip','netns','add',ns]);spaces.append(ns);cmd(['ip','link','set','lo','up'],ns)
 cmd(['ip','link','add','eth0','type','veth','peer','name','peer0'],LAB)
 cmd(['ip','link','set','peer0','netns',PEER],LAB);cmd(['ip','link','set','peer0','name','eth0'],PEER)
 for ns,last in [(LAB,'1'),(PEER,'2')]:
  cmd(['ip','link','set','eth0','up'],ns)
  cmd(['ip','-6','addr','add',f'2001:db8:66::{last}/64','dev','eth0','nodad'],ns)
 cmd(['sysctl','-qw','net.ipv6.conf.all.forwarding=0'],LAB)
 cmd(['nft','-f','-'],LAB,input='table inet administrator { chain forward { type filter hook forward priority 0; policy drop; }\n }\n',text=True)
 baseline=output(['nft','list','ruleset']);route_before=output(['ip','-6','route'])
 servercode='''import http.server,socket,signal
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  b=bytes(range(256))*1024;self.send_response(200);self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
 def log_message(self,*a):pass
class S(http.server.ThreadingHTTPServer):address_family=socket.AF_INET6
s=S(('2001:db8:66::2',18080),H)
import threading
threading.Thread(target=s.serve_forever,daemon=True).start()
print('ready',flush=True);signal.pause()
'''
 server=launch(['python3','-u','-c',servercode],'http',PEER);ready(server,'http')
 config={'dns':{'hosts':{'ipv6.test':'2001:db8:66::2'}},'log':{'loglevel':'info'},'inbounds':[],'outbounds':[],'routing':{'rules':[]}}
 profiles=['windows','macos','linux','auto']
 for i,name in enumerate(profiles):
  config['inbounds'].append({'tag':name,'listen':'127.0.0.1','port':1080+i,'protocol':'socks','settings':{'auth':'noauth'}})
  config['outbounds'].append({'tag':name,'protocol':'freedom','settings':{'tcpFingerprint':name},'streamSettings':{'sockopt':{'domainStrategy':'ForceIPv6'}}})
  config['routing']['rules'].append({'type':'field','inboundTag':[name],'outboundTag':name})
 (OUT/'config.json').write_text(json.dumps(config))
 xray=launch([str(BINARY),'run','-c',str(OUT/'config.json')],'xrui');ready(xray,'xrui')
 result=subprocess.run(['ip','netns','exec',LAB,'curl','--noproxy','','--socks5-hostname','127.0.0.1:1080','-gfsS','--max-time','4','http://[2001:db8:66::2]:18080/'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 assert result.returncode!=0,'silently bypassed IPv6 forwarding requirement'
 assert 'net.ipv6.conf.all.forwarding=1' in (OUT/'xrui.log').read_text()
 assert output(['cat','/proc/sys/net/ipv6/conf/all/forwarding']).strip()==b'0'
 cmd(['sysctl','-qw','net.ipv6.conf.all.forwarding=1'],LAB)
 expected=['64240_2-1-3-1-1-4_1440_8','65535_2-1-3-1-1-8-4-0-0_1440_6','65535_2-4-8-1-3_1440_9','65535_2-4-8-1-3_1440_9']
 report={}
 for i,name in enumerate(profiles):
  path=OUT/(name+'.pcap');cap=launch(['tcpdump','--immediate-mode','-i','eth0','-U','-w',str(path),'ip6 and tcp'],'capture-'+name,PEER)
  wait_capture(cap,OUT/('capture-'+name+'.log'))
  with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(fetch,[1080+i]*4))
  resolved=output(['curl','--noproxy','','--socks5-hostname',f'127.0.0.1:{1080+i}','-fsS','--max-time','15','http://ipv6.test:18080/'])
  assert resolved==BODY
  cap.send_signal(signal.SIGINT);cap.wait(timeout=5)
  packets=check_packets(path);assert packets and set(packets)=={expected[i]},(name,packets)
  report[name]=packets;print(name+' IPv6 NAT66, fingerprint, checksum and 256KiB payload PASS',flush=True)
 # Stop all six v4/v6 profiles and verify no networking state leaked.
 xray.terminate();xray.wait(timeout=20);assert xray.returncode==0
 for _ in range(100):
  if output(['nft','list','ruleset'])==baseline:break
  time.sleep(.05)
 else:raise AssertionError('IPv6 firewall cleanup')
 assert output(['ip','-6','route'])==route_before
 assert output(['cat','/proc/sys/net/ipv6/conf/all/forwarding']).strip()==b'1'
 # Manual IPv6 TUN with the minimum IPv6 MTU exercises configuration and MSS.
 cmd(['ip','tuntap','add','dev','manual6','mode','tun'],LAB)
 cmd(['ip','link','set','manual6','mtu','1280','up'],LAB)
 cmd(['ip','-6','addr','add','fd66:1234::1/126','dev','manual6','nodad'],LAB)
 cmd(['nft','-f','-'],LAB,input='table ip6 manual6 { chain post { type nat hook postrouting priority 100; ip6 saddr fd66:1234::2 masquerade; }\n }\nadd rule inet administrator forward iifname "manual6" accept\nadd rule inet administrator forward oifname "manual6" accept\n',text=True)
 manual={'log':{'loglevel':'info'},'inbounds':[{'port':1089,'listen':'127.0.0.1','protocol':'socks','settings':{'auth':'noauth'}}],'outbounds':[{'protocol':'freedom','settings':{'tcpFingerprint':'windows','tcpFingerprintSettings':{'tun':'manual6','address':'fd66:1234::2'}}}]}
 (OUT/'manual.json').write_text(json.dumps(manual))
 process=launch([str(BINARY),'run','-c',str(OUT/'manual.json')],'manual');ready(process,'manual')
 cap=launch(['tcpdump','--immediate-mode','-i','eth0','-U','-w',str(OUT/'manual.pcap'),'ip6 and tcp'],'capture-manual',PEER)
 wait_capture(cap,OUT/'capture-manual.log');fetch(1089)
 cap.send_signal(signal.SIGINT);cap.wait(timeout=5)
 packets=check_packets(OUT/'manual.pcap');assert packets and set(packets)=={'64240_2-1-3-1-1-4_1220_8'},packets
 report['manual_mtu1280']=packets
 process.terminate();process.wait(timeout=15)
 cmd(['ip','tuntap','del','dev','manual6','mode','tun'],LAB)
 cmd(['nft','delete','table','ip6','manual6'],LAB)
 cmd(['nft','flush','chain','inet','administrator','forward'],LAB)
 print('Manual IPv6 TUN, MTU 1280 / MSS 1220 PASS',flush=True)
 # SIGKILL of the parent still lets the separate helpers restore their rules.
 process=launch([str(BINARY),'run','-c',str(OUT/'config.json')],'crash');ready(process,'crash');fetch(1082)
 process.kill();process.wait(timeout=5)
 for _ in range(100):
  if output(['nft','list','ruleset'])==baseline and output(['ip','-6','route'])==route_before:break
  time.sleep(.05)
 else:raise AssertionError('IPv6 SIGKILL cleanup')
 report['parent_sigkill_cleanup']=True
 print('IPv6 parent SIGKILL helper cleanup PASS',flush=True)
 (OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
 print('IPv6 automatic network cleanup and unchanged global forwarding PASS',flush=True)
finally:
 for p in reversed(processes):
  if p.poll() is None:
   p.terminate()
   try:p.wait(timeout=10)
   except subprocess.TimeoutExpired:p.kill();p.wait()
 for ns in reversed(spaces):subprocess.run(['ip','netns','delete',ns],check=False)
 for log in logs:log.close()
