#!/usr/bin/env python3
"""Exercise packaged assets, container permissions, process name and gVisor egress."""
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time

image = sys.argv[1]
name = f'xrui-smoke-{os.getpid()}'
network = name + '-net'
def docker(*args):
    return subprocess.check_output(['docker', *args], text=True, stderr=subprocess.STDOUT).strip()
assert docker('run', '--rm', image, 'version').startswith('xrui ')
server = None
try:
    docker('network', 'create', network)
    gateway = json.loads(docker('network', 'inspect', network))[0]['IPAM']['Config'][0]['Gateway']
    class HTTP(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'xrui container TCP fingerprint smoke\n' * 4096
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *args): pass
    server = http.server.ThreadingHTTPServer((gateway, 0), HTTP)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    with tempfile.TemporaryDirectory(prefix='xrui-docker-') as tmp:
        path = Path(tmp)/'config.json'
        path.write_text(json.dumps({
            'log': {'loglevel': 'info'},
            'inbounds': [{'listen': '0.0.0.0', 'port': 1080, 'protocol': 'socks', 'settings': {'auth': 'noauth'}}],
            'outbounds': [{'tag': 'direct', 'protocol': 'freedom', 'settings': {'tcpFingerprint': 'auto'}}],
            'routing': {'rules': [
                {'type': 'field', 'domain': ['geosite:private'], 'outboundTag': 'direct'},
                {'type': 'field', 'ip': ['geoip:private'], 'outboundTag': 'direct'}]}
        }))
        docker('run', '-d', '--name', name, '--network', network,
               '--cap-add=NET_ADMIN', '--device=/dev/net/tun',
               '--sysctl=net.ipv4.ip_forward=1', '--sysctl=net.ipv4.conf.default.forwarding=1',
               '-p', '127.0.0.1::1080', '-v', f'{path}:/usr/local/etc/xrui/config.json:ro', image)
        for _ in range(100):
            state = json.loads(docker('inspect', name))[0]['State']
            if not state['Running']: raise RuntimeError(docker('logs', name))
            if 'started' in docker('logs', name): break
            time.sleep(.1)
        else: raise RuntimeError('Container startup timeout')
        if Path('/proc', str(state['Pid']), 'comm').exists():
            assert Path('/proc', str(state['Pid']), 'comm').read_text().strip() == 'xrui'
        address = docker('port', name, '1080/tcp')
        body = subprocess.check_output(['curl', '--noproxy', '', '--socks5-hostname', address,
            '-fsS', '--max-time', '20', f'http://{gateway}:{server.server_port}/'])
        assert body == b'xrui container TCP fingerprint smoke\n' * 4096
        assert 'TCP fingerprint freedom: mode=auto' in docker('logs', name)
        docker('stop', '--time', '15', name)
        assert json.loads(docker('inspect', name))[0]['State']['ExitCode'] == 0
        print('Docker: xrui process, geosite/geoip loading, auto gVisor egress and clean stop PASS')
finally:
    subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['docker', 'network', 'rm', network], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if server: server.shutdown(); server.server_close()
