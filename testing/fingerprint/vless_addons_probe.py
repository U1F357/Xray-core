#!/usr/bin/env python3
"""Compatibility research: inject an unknown protobuf Addons field into STOCK VLESS.
This does not implement or enable a fingerprint propagation feature.
All servers bind loopback. Usage: python3 .../vless_addons_probe.py /path/to/upstream-xray
"""
import http.server,json,socket,ssl,subprocess,sys,threading,time,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];OUT=ROOT/'testing/fingerprint/artifacts/vless-addons-probe';OUT.mkdir(parents=True,exist_ok=True)
BINARY=Path(sys.argv[1]).resolve();UUID=uuid.UUID('8e023ca4-6e4d-47ab-9f38-233a67d95671');processes=[];logs=[];listeners=[]
def freeport():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def varint(x):
 out=bytearray()
 while x>127:out.append((x&127)|128);x>>=7
 out.append(x);return bytes(out)
# Arbitrary experimental field number; not a claimed upstream protocol allocation.
value=b'xray-fp-probe:v1:windows';extension=varint((65001<<3)|2)+varint(len(value))+value
class HTTP(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  body=b'VLESS Addons compatibility';self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def log_message(self,*args):pass
http=http.server.ThreadingHTTPServer(('127.0.0.1',0),HTTP);threading.Thread(target=http.serve_forever,daemon=True).start();target=http.server_address[1]
def start(name,port,tls=False,outbound=None):
 inbound={'listen':'127.0.0.1','port':port,'protocol':'vless','settings':{'clients':[{'id':str(UUID)}],'decryption':'none'},'streamSettings':{'network':'tcp'}}
 if tls:inbound['streamSettings'].update({'security':'tls','tlsSettings':{'certificates':[{'certificateFile':str(OUT/'cert.pem'),'keyFile':str(OUT/'key.pem')}]}})
 config={'log':{'loglevel':'info'},'inbounds':[inbound],'outbounds':[outbound or {'protocol':'freedom','settings':{'finalRules':[{'action':'allow','ip':['127.0.0.1'],'port':str(target)}]}}]}
 path=OUT/(name+'.json');path.write_text(json.dumps(config));log=(OUT/(name+'.log')).open('w');logs.append(log)
 p=subprocess.Popen([str(BINARY),'run','-config',str(path)],stdout=log,stderr=log);processes.append(p)
 for _ in range(100):
  if p.poll()!=None:raise RuntimeError((OUT/(name+'.log')).read_text())
  if 'started' in (OUT/(name+'.log')).read_text():return
  time.sleep(.05)
 raise RuntimeError('start timeout')
def request(port,extra,tls=False):
 with socket.create_connection(('127.0.0.1',port),timeout=10) as raw:
  conn=raw
  if tls:conn=ssl.create_default_context(cafile=str(OUT/'cert.pem')).wrap_socket(raw,server_hostname='fp.test')
  header=b'\0'+UUID.bytes+bytes([len(extra)])+extra+b'\1'+target.to_bytes(2,'big')+b'\1'+socket.inet_aton('127.0.0.1')
  conn.sendall(header+b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n')
  data=b''
  while True:
   b=conn.recv(65535)
   if not b:break
   data+=b
  if conn is not raw:conn.close()
  assert data[:2]==b'\0\0' and b'VLESS Addons compatibility' in data,data
try:
 subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(OUT/'key.pem'),'-out',str(OUT/'cert.pem'),'-days','1','-subj','/CN=fp.test','-addext','subjectAltName=DNS:fp.test'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 report={}
 for tls in [False,True]:
  port=freeport();name='tls' if tls else 'plain';start(name,port,tls)
  request(port,b'',tls);request(port,extension,tls);report[name+'_unknown_field_accepted']=True
 # Stock relay reconstructs Addons instead of forwarding unknown fields.
 sink=socket.socket();sink.bind(('127.0.0.1',0));sink.listen();sink.settimeout(10);listeners.append(sink);seen=[];errors=[]
 def readn(c,n):
  data=b''
  while len(data)<n:
   b=c.recv(n-len(data))
   if not b:raise EOFError()
   data+=b
  return data
 def receive():
  try:
   c,_=sink.accept()
   with c:
    c.settimeout(10);header=readn(c,18);assert header[:17]==b'\0'+UUID.bytes
    seen.append(readn(c,header[17]));addr=readn(c,4);assert addr[0]==1 and addr[3]==1;readn(c,4)
    data=b''
    while b'\r\n\r\n' not in data:data+=c.recv(1024)
    body=b'VLESS Addons compatibility';c.sendall(b'\0\0HTTP/1.0 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body)
  except Exception as e:errors.append(repr(e))
 t=threading.Thread(target=receive,daemon=True);t.start();port=freeport()
 outbound={'protocol':'vless','settings':{'vnext':[{'address':'127.0.0.1','port':sink.getsockname()[1],'users':[{'id':str(UUID),'encryption':'none'}]}]},'streamSettings':{'network':'tcp'}}
 start('relay',port,outbound=outbound);request(port,extension);t.join(timeout=10);assert not t.is_alive() and not errors,errors;assert seen==[b''],seen
 report['stock_relay_drops_unknown_field']=True
 report['binary']=str(BINARY);report['experimental_field']=65001;report['scope']='plain VLESS and TLS, no Vision or REALITY handshake test'
 (OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
finally:
 for p in processes:
  p.terminate()
  try:p.wait(timeout=10)
  except subprocess.TimeoutExpired:p.kill();p.wait()
 for l in listeners:l.close()
 http.shutdown();http.server_close()
 for log in logs:log.close()
