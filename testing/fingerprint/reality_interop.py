#!/usr/bin/env python3
"""Local nginx REALITY interoperability matrix; requires nginx, openssl, curl and mihomo.
All handshake and application traffic stays on loopback. Does not change system services.
Usage: reality_interop.py MIHOMO LABEL=BINARY [LABEL=BINARY ...]
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
MLKEM = os.environ.get('REALITY_MLKEM', '1') == '1'
OUT = ROOT / ('testing/fingerprint/artifacts/reality-interop-mlkem' if MLKEM else 'testing/fingerprint/artifacts/reality-interop')
OUT = OUT / os.environ.get('REALITY_RUN', 'matrix')
OUT.mkdir(parents=True, exist_ok=True)
MIHOMO = str(Path(sys.argv[1]).resolve())
SERVERS = [(s.split('=', 1)[0], str(Path(s.split('=', 1)[1]).resolve())) for s in sys.argv[2:]]
UUID = '8e023ca4-6e4d-47ab-9f38-233a67d95671'
processes, logs, results = [], [], []
def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]
def launch(args, name, env=None):
    log = (OUT / (name + '.log')).open('w'); logs.append(log)
    p = subprocess.Popen(args, stdout=log, stderr=log, env=env); processes.append(p)
    return p
def ready(p, name, needle):
    for _ in range(150):
        text = (OUT / (name + '.log')).read_text()
        if p.poll() is not None: raise RuntimeError(name + ': ' + text)
        if needle in text: return
        time.sleep(.05)
    raise RuntimeError(name + ' startup timed out: ' + text)
def stop(p):
    if p.poll() is None:
        p.terminate()
        try: p.wait(timeout=5)
        except subprocess.TimeoutExpired: p.kill(); p.wait()
try:
    cert, key = OUT / 'cert.pem', OUT / 'key.pem'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','2','-subj','/CN=reality.test','-addext','subjectAltName=DNS:reality.test,IP:127.0.0.1'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    body = bytes(range(256)) * 1024
    (OUT / 'payload').write_bytes(body)
    tls_port = port()
    nginx_conf = OUT / 'nginx.conf'
    nginx_conf.write_text(f'''daemon off;
master_process off;
pid {OUT}/nginx.pid;
error_log stderr info;
events {{ worker_connections 128; }}
http {{ access_log off; server {{
 listen 127.0.0.1:{tls_port} ssl;
 http2 on;
 server_name reality.test;
 ssl_certificate {cert}; ssl_certificate_key {key};
 ssl_protocols TLSv1.3; ssl_session_tickets on; ssl_ecdh_curve X25519;
 location / {{ root {OUT}; }}
}} }}
''')
    ng = launch(['nginx','-p',str(OUT),'-c',str(nginx_conf)],'nginx')
    for _ in range(100):
        try:
            with socket.create_connection(('127.0.0.1', tls_port), .1): break
        except OSError: time.sleep(.05)
    assert ng.poll() is None
    keys = subprocess.check_output([SERVERS[0][1], 'x25519'],text=True).splitlines()
    private = keys[0].split(': ',1)[1]; public = keys[1].split(': ',1)[1]
    env = dict(os.environ, SSL_CERT_FILE=str(cert))
    for label, binary in SERVERS:
      for capture in (['off'] if label == 'stock' else ['off','syn']):
       for flow in ['', 'xtls-rprx-vision']:
        name = f'{label}-{capture}-{flow or "plain"}'
        listen = port()
        account = {'id':UUID,'email':'test@example.test','flow':flow}
        inbound = {'listen':'127.0.0.1','port':listen,'protocol':'vless','settings':{'clients':[account],'decryption':'none'},'streamSettings':{'network':'tcp','security':'reality','realitySettings':{'show':True,'target':f'127.0.0.1:{tls_port}','serverNames':['reality.test'],'privateKey':private,'shortIds':['0123456789abcdef']}}}
        if label != 'stock': inbound['tcpFingerprint']={'source':capture}
        config = {'log':{'loglevel':'debug'},'inbounds':[inbound],'outbounds':[{'protocol':'freedom','settings':{'finalRules':[{'action':'allow','ip':['127.0.0.1'],'port':str(tls_port)}]}}]}
        path = OUT / (name+'.json'); path.write_text(json.dumps(config))
        server = launch([binary,'run','-c',str(path)],name,env); ready(server,name,'started')
        time.sleep(.5)
        for fingerprint in os.environ.get('REALITY_FINGERPRINTS', 'chrome').split(','):
            clientname = name+'-'+fingerprint
            socks = port()
            node = {'name':'local','type':'vless','server':'127.0.0.1','port':listen,'uuid':UUID,'network':'tcp','tls':True,'servername':'reality.test','client-fingerprint':fingerprint,'reality-opts':{'public-key':public,'short-id':'0123456789abcdef'}}
            if MLKEM: node['reality-opts']['support-x25519mlkem768']=True
            if flow: node['flow']=flow
            config={'mixed-port':socks,'bind-address':'127.0.0.1','mode':'rule','log-level':'debug','proxies':[node],'rules':['MATCH,local']}
            path=OUT/(clientname+'.json');path.write_text(json.dumps(config))
            homedir=OUT/clientname;homedir.mkdir(exist_ok=True)
            client=launch([MIHOMO,'-d',str(homedir),'-f',str(path)],clientname,env)
            ready(client,clientname,'Mixed(http+socks) proxy listening')
            # Mihomo opens listeners before switching its tunnel from Suspend to Running.
            time.sleep(.5)
            r=subprocess.run(['curl','--noproxy','','--socks5',f'127.0.0.1:{socks}','--cacert',str(cert),'-fsS','--max-time','8',f'https://127.0.0.1:{tls_port}/payload'],capture_output=True)
            ok=r.returncode==0 and r.stdout==body
            result={'case':clientname,'passed':ok,'curl_error':r.stderr.decode(),'bytes':len(r.stdout),'support_x25519mlkem768':MLKEM}
            results.append(result);print(clientname, 'PASS' if ok else 'FAIL '+result['curl_error'],flush=True)
            stop(client)
        stop(server)
    (OUT/'verification.json').write_text(json.dumps({'mihomo':subprocess.check_output([MIHOMO,'-v'],text=True).strip(),'results':results},indent=2)+'\n')
finally:
    for p in reversed(processes): stop(p)
    for log in logs: log.close()
if not all(r['passed'] for r in results): sys.exit(1)
