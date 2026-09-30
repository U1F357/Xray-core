#!/usr/bin/env python3
"""Exercise packaged assets, container permissions, process name and gVisor egress."""
import http.server
import errno
import json
import os
import socket
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time

image = sys.argv[1]
ipv6 = "--ipv6" in sys.argv[2:]
name = f'xrui-smoke-{os.getpid()}'
network = name + '-net'
def docker(*args):
    return subprocess.check_output(['docker', *args], text=True, stderr=subprocess.STDOUT).strip()
assert docker('run', '--rm', image, 'version').startswith('xrui ')
server = None
# Docker itself can enable host IPv6 forwarding while creating an IPv6 bridge.
# Snapshot it before our temporary network and restore it after deleting that network.
forwarding_before = {p: p.read_text() for p in Path('/proc/sys/net/ipv6/conf').glob('*/forwarding')} if ipv6 else {}
try:
    netargs = ['--ipv6', '--subnet', f'fd64:1234:{os.getpid() & 65535:x}::/64', '--gateway', f'fd64:1234:{os.getpid() & 65535:x}::1'] if ipv6 else []
    docker('network', 'create', *netargs, network)
    # A bridge without attached endpoints has no carrier: IPv6 DAD cannot finish.
    if ipv6: docker('run', '-d', '--name', name+'-anchor', '--network', network, image)
    configs = json.loads(docker('network', 'inspect', network))[0]['IPAM']['Config']
    gateway = next(c['Gateway'] for c in configs if c.get('Gateway') and (':' in c['Gateway']) == ipv6)
    class HTTP(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'xrui container TCP fingerprint smoke\n' * 4096
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *args): pass
    class Server(http.server.ThreadingHTTPServer):
        address_family = socket.AF_INET6 if ipv6 else socket.AF_INET
    # Docker IPv6 bridge addresses may still be undergoing DAD.
    for attempt in range(100):
        try:
            server = Server((gateway, 0), HTTP)
            break
        except OSError as e:
            if not ipv6 or e.errno != errno.EADDRNOTAVAIL or attempt == 99: raise
            time.sleep(.1)
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
        v6args = ['--sysctl=net.ipv6.conf.all.forwarding=1'] if ipv6 else []
        docker('run', '-d', *v6args, '--name', name, '--network', network,
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
            '-fsS', '--max-time', '20', f'http://[{gateway}]:{server.server_port}/' if ipv6 else f'http://{gateway}:{server.server_port}/'])
        assert body == b'xrui container TCP fingerprint smoke\n' * 4096
        assert 'TCP fingerprint freedom: mode=auto' in docker('logs', name)
        docker('stop', '--time', '15', name)
        assert json.loads(docker('inspect', name))[0]['State']['ExitCode'] == 0
        print(('IPv6 ' if ipv6 else 'IPv4 ')+'Docker: xrui process, geosite/geoip loading, auto gVisor egress and clean stop PASS')
finally:
    subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['docker', 'rm', '-f', name+'-anchor'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['docker', 'network', 'rm', network], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if server: server.shutdown(); server.server_close()
    global_path = Path('/proc/sys/net/ipv6/conf/all/forwarding')
    if global_path in forwarding_before and global_path.read_text() != forwarding_before[global_path]:
        global_path.write_text(forwarding_before[global_path])
        for path, value in forwarding_before.items():
            if path != global_path and path.exists() and path.read_text() != value:
                path.write_text(value)
