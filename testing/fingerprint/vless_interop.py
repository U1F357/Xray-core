#!/usr/bin/env python3
"""Local real-process VLESS interop; optional second argument is stock Xray.
No root, TUN, runsc or external network required. Tests plain/TLS/Vision TLS.
"""
import http.server, json, socket, subprocess, sys, threading, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT/'testing/fingerprint/artifacts/vless-interop'
OUT.mkdir(parents=True, exist_ok=True)
CUSTOM = str(Path(sys.argv[1]).resolve())
STOCK = str(Path(sys.argv[2]).resolve()) if len(sys.argv)>2 else None
UUID = '8e023ca4-6e4d-47ab-9f38-233a67d95671'
processes, logs, report = [], [], []
class HTTP(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  body=bytes(range(256))*1024; self.send_response(200); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
 def log_message(self,*a):pass
http = http.server.ThreadingHTTPServer(('127.0.0.1',0),HTTP)
threading.Thread(target=http.serve_forever,daemon=True).start()
def port():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def start(binary,name,config):
 path=OUT/(name+'.json');path.write_text(json.dumps(config));log=(OUT/(name+'.log')).open('w');logs.append(log)
 p=subprocess.Popen([binary,'run','-config',str(path)],stdout=log,stderr=log);processes.append(p)
 for _ in range(100):
  text=(OUT/(name+'.log')).read_text()
  if p.poll() is not None:raise RuntimeError(text)
  if 'started' in text:return
  time.sleep(.05)
 raise RuntimeError(name+' startup timeout')
def inbound(p,mode,custom):
 account={'id':UUID,'email':'relay@test'}
 if mode=='vision':account['flow']='xtls-rprx-vision'
 i={'listen':'127.0.0.1','port':p,'protocol':'vless','settings':{'clients':[account],'decryption':'none'},'streamSettings':{'network':'tcp'}}
 if custom:i['tcpFingerprint']={'source':'vless','trustedUsers':['relay@test']}
 if mode!='plain':i['streamSettings'].update({'security':'tls','tlsSettings':{'certificates':[{'certificateFile':str(OUT/'cert.pem'),'keyFile':str(OUT/'key.pem')}]}})
 return i
def outbound(p,mode,custom):
 account={'id':UUID,'encryption':'none'}
 if mode=='vision':account['flow']='xtls-rprx-vision'
 o={'protocol':'vless','settings':{'vnext':[{'address':'127.0.0.1','port':p,'users':[account]}]},'streamSettings':{'network':'tcp'}}
 if custom:o['settings']['tcpFingerprintForward']=True
 if mode!='plain':o['streamSettings'].update({'security':'tls','tlsSettings':{'serverName':'fp.test','fingerprint':'chrome','certificates':[{'certificate':(OUT/'cert.pem').read_text().splitlines(),'usage':'verify'}]}})
 return o
try:
 subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(OUT/'key.pem'),'-out',str(OUT/'cert.pem'),'-days','1','-subj','/CN=fp.test','-addext','subjectAltName=DNS:fp.test'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 cases=[('custom-chain',True,True)]
 if STOCK:cases += [('custom-stock',True,False),('stock-custom',False,True)]
 for mode in ['plain','tls','vision']:
  for label,client_custom,server_custom in cases:
   name=mode+'-'+label;server_port=port();socks_port=port()
   native={'protocol':'freedom','settings':{'finalRules':[{'action':'allow','ip':['127.0.0.1'],'port':str(http.server_address[1])}]}}
   start(CUSTOM if server_custom else STOCK,name+'-server',{'log':{'loglevel':'info'},'inbounds':[inbound(server_port,mode,server_custom)],'outbounds':[native]})
   destination=server_port
   if label=='custom-chain':
    destination=port()
    start(CUSTOM,name+'-relay',{'log':{'loglevel':'info'},'inbounds':[inbound(destination,mode,True)],'outbounds':[outbound(server_port,mode,True)]})
   socks={'listen':'127.0.0.1','port':socks_port,'protocol':'socks','settings':{'auth':'noauth'}}
   if client_custom:socks['tcpFingerprint']={'source':'syn'}
   start(CUSTOM if client_custom else STOCK,name+'-client',{'log':{'loglevel':'info'},'inbounds':[socks],'outbounds':[outbound(destination,mode,client_custom)]})
   body=subprocess.check_output(['curl','--noproxy','','--socks5-hostname',f'127.0.0.1:{socks_port}','-fsS','--max-time','15',f'http://127.0.0.1:{http.server_address[1]}/'])
   assert body==bytes(range(256))*1024
   if server_custom:
    expected='status=accepted source=vless category=linux' if client_custom else 'status=missing source=unknown category=unknown'
    assert expected in (OUT/(name+'-server.log')).read_text(),name
   report.append(name);print(name+' PASS',flush=True)
 (OUT/'verification.json').write_text(json.dumps({'passed':report,'stock_binary':STOCK,'scope':'plain, TLS, Vision TLS; no REALITY handshake coverage'},indent=2)+'\n')
finally:
 for p in reversed(processes):
  p.terminate()
  try:p.wait(timeout=5)
  except subprocess.TimeoutExpired:p.kill();p.wait()
 http.shutdown();http.server_close()
 for log in logs:log.close()
