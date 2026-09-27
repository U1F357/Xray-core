#!/usr/bin/env python3
"""Root-only local SOCKS -> freedom -> gVisor -> TUN test; no public network.

Creates three temporary TUNs without changing forwarding/firewall settings.
Run: python3 testing/fingerprint/e2e.py ../dist/xray-fingerprint
"""
import concurrent.futures
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'testing/fingerprint/artifacts'
OUT.mkdir(exist_ok=True)
BINARY = Path(sys.argv[1]).resolve()
PROFILES = {
    'windows': '64240_2-1-3-1-1-4_1460_8',
    'macos': '65535_2-1-3-1-1-8-4-0-0_1460_6',
    'linux': '65535_2-4-8-1-3_1460_9',
}
BODY = bytes(range(256)) * 1024
TARGET = '10.204.237.1'

def run(args, **kw):
    return subprocess.run(args, check=True, **kw)

def freeport():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

class HTTP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)
    def log_message(self, *_):
        pass

def recv_exact(s, n):
    data = b''
    while len(data) < n:
        chunk = s.recv(n-len(data))
        if not chunk:
            raise RuntimeError('unexpected SOCKS EOF')
        data += chunk
    return data

def udp_roundtrip(socksport):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as echo, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        echo.bind(('127.0.0.1', 0))
        echo.settimeout(3)
        udp.settimeout(3)
        def reflect():
            data, addr = echo.recvfrom(4096)
            echo.sendto(data, addr)
        thread = threading.Thread(target=reflect, daemon=True)
        thread.start()
        with socket.create_connection(('127.0.0.1', socksport), timeout=3) as control:
            control.sendall(b'\x05\x01\x00')
            assert recv_exact(control, 2) == b'\x05\x00'
            control.sendall(b'\x05\x03\x00\x01' + b'\0'*6)
            reply = recv_exact(control, 10)
            assert reply[:4] == b'\x05\x00\x00\x01', reply
            relay = (socket.inet_ntoa(reply[4:8]), struct.unpack('!H', reply[8:])[0])
            packet = b'\0\0\0\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', echo.getsockname()[1]) + b'udp-kernel-path'
            udp.sendto(packet, relay)
            answer = udp.recv(4096)
            assert answer.endswith(b'udp-kernel-path'), answer
        thread.join(timeout=3)

def read_fingerprints(path):
    data = path.read_bytes()
    endian = '<' if data[:4] == bytes.fromhex('d4c3b2a1') else '>'
    link = struct.unpack_from(endian+'I', data, 20)[0]
    offset = {101: 0, 228: 0, 1: 14, 113: 16, 276: 20}[link]
    pos = 24
    results = []
    while pos < len(data):
        _, _, size, _ = struct.unpack_from(endian+'IIII', data, pos)
        pos += 16
        ip = data[pos+offset:pos+size]
        pos += size
        if not ip or ip[0] >> 4 != 4 or ip[9] != 6:
            continue
        tcp = ip[(ip[0]&15)*4:struct.unpack_from('!H', ip, 2)[0]]
        if tcp[13]&0x12 != 2:
            continue
        pseudo = ip[12:20] + b'\0\x06' + struct.pack('!H', len(tcp))
        checked = pseudo + tcp
        checked += b'\0' * (len(checked)%2)
        total = sum(struct.unpack('!%dH' % (len(checked)//2), checked))
        while total >> 16:
            total = (total&65535)+(total>>16)
        assert total == 65535, 'invalid SYN checksum'
        options = tcp[20:(tcp[12]>>4)*4]
        kinds, mss, scale, p = [], None, None, 0
        while p < len(options):
            kind = options[p]
            kinds.append(kind)
            if kind in (0, 1):
                p += 1
                continue
            length = options[p+1]
            assert length >= 2 and p+length <= len(options)
            if kind == 2:
                mss = struct.unpack_from('!H', options, p+2)[0]
            if kind == 3:
                scale = options[p+2]
            p += length
        results.append(f'{struct.unpack_from("!H", tcp, 14)[0]}_{"-".join(map(str, kinds))}_{mss}_{scale}')
    return results

interfaces, captures, logs = [], [], []
xray = server = None
try:
    subnet = ipaddress.ip_network('10.204.237.0/28')
    for route in json.loads(subprocess.check_output(['ip', '-j', 'route'])):
        dst = route.get('dst', 'default')
        if dst != 'default' and subnet.overlaps(ipaddress.ip_network(dst)):
            raise RuntimeError('test subnet overlaps existing route: '+dst)
    config = {
        'log': {'loglevel': 'warning'},
        'dns': {'hosts': {'fingerprint.test': TARGET}},
        'inbounds': [], 'outbounds': [], 'routing': {'rules': []},
    }
    ports = {}
    for index, name in enumerate([*PROFILES, 'native']):
        port = freeport()
        ports[name] = port
        config['inbounds'].append({'tag': name, 'listen': '127.0.0.1', 'port': port, 'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': True}})
        settings = {}
        if name in PROFILES:
            interface = f'xf{os.getpid()}{index}'
            run(['ip', 'tuntap', 'add', 'dev', interface, 'mode', 'tun'])
            interfaces.append(interface)
            run(['ip', 'addr', 'add', f'10.204.237.{index*4+1}/30', 'dev', interface])
            run(['ip', 'link', 'set', interface, 'mtu', '1500', 'up'])
            settings = {'tcpFingerprint': name, 'tcpFingerprintSettings': {'tun': interface, 'address': f'10.204.237.{index*4+2}'}}
            log = (OUT/f'{name}-capture.log').open('w')
            logs.append(log)
            captures.append(subprocess.Popen(['tcpdump', '--immediate-mode', '-i', interface, '-s', '0', '-U', '-w', str(OUT/f'{name}.pcap'), 'tcp[tcpflags] & 0x12 == 2'], stdout=log, stderr=log))
        config['outbounds'].append({'tag': name, 'protocol': 'freedom', 'settings': settings, 'streamSettings': {'sockopt': {'domainStrategy': 'ForceIPv4'}}})
        config['routing']['rules'].append({'type': 'field', 'inboundTag': [name], 'outboundTag': name})
    server = http.server.ThreadingHTTPServer(('0.0.0.0', 0), HTTP)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    httpport = server.server_port
    path = OUT/'config.json'
    path.write_text(json.dumps(config, indent=2)+'\n')
    log = (OUT/'xray.log').open('w')
    logs.append(log)
    xray = subprocess.Popen([str(BINARY), 'run', '-config', str(path)], stdout=log, stderr=log)
    for _ in range(100):
        if xray.poll() is not None:
            raise RuntimeError((OUT/'xray.log').read_text())
        try:
            with socket.create_connection(('127.0.0.1', ports['native']), timeout=.1):
                break
        except OSError:
            time.sleep(.05)
    else:
        raise RuntimeError('Xray did not start')
    time.sleep(.2)
    def fetch(name, domain=False):
        host = 'fingerprint.test' if domain else TARGET
        result = subprocess.check_output(['curl', '--noproxy', '', '--socks5-hostname', f'127.0.0.1:{ports[name]}', '-fsS', '--max-time', '10', f'http://{host}:{httpport}/'])
        assert result == BODY, (name, len(result))
        return name
    for name in [*PROFILES, 'native']:
        fetch(name)
        fetch(name, True)
        udp_roundtrip(ports[name])
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        list(pool.map(lambda name: fetch(name, True), list(PROFILES)*4))
    xray.terminate()
    xray.wait(timeout=5)
    assert xray.returncode == 0, xray.returncode
    xray = None
    for cap in captures:
        cap.send_signal(signal.SIGINT)
        cap.wait(timeout=5)
    captures.clear()
    if go := os.environ.get('XRAY_FP_GO'):
        env = dict(os.environ, XRAY_FP_TEST_TUN=interfaces[0], XRAY_FP_TEST_ADDRESS='10.204.237.2', XRAY_FP_TEST_HOST=TARGET)
        run([go, 'test', '-race', './proxy/freedom', '-run', '^TestFingerprintLifecycle$', '-count=1', '-timeout', '30s'], cwd=ROOT, env=env)
    report = {}
    for name, expected in PROFILES.items():
        fingerprints = read_fingerprints(OUT/f'{name}.pcap')
        assert len(fingerprints) >= 6, (name, fingerprints)
        assert set(fingerprints) == {expected}, (name, fingerprints)
        report[name] = {'ja4t': expected, 'syn_count': len(fingerprints), 'checksums_valid': True, 'http_ip_and_domain': True, 'concurrent_http': True, 'udp_unchanged': True}
        print(name, expected, 'PASS', flush=True)
    # Reopen the same TUN and ensure finalRules still prevent the TCP SYN.
    config['inbounds'] = [config['inbounds'][0]]
    config['outbounds'] = [config['outbounds'][0]]
    config['routing']['rules'] = [config['routing']['rules'][0]]
    config['outbounds'][0]['settings']['finalRules'] = [{'action': 'block', 'network': 'tcp', 'ip': [TARGET], 'blockDelay': '0'}]
    path = OUT/'blocked-config.json'
    path.write_text(json.dumps(config, indent=2)+'\n')
    caplog = (OUT/'blocked-capture.log').open('w')
    logs.append(caplog)
    captures.append(subprocess.Popen(['tcpdump', '--immediate-mode', '-i', interfaces[0], '-s', '0', '-U', '-w', str(OUT/'blocked.pcap'), 'tcp[tcpflags] & 0x12 == 2'], stdout=caplog, stderr=caplog))
    xray = subprocess.Popen([str(BINARY), 'run', '-config', str(path)], stdout=log, stderr=log)
    time.sleep(.5)
    blocked = subprocess.run(['curl', '--noproxy', '', '--socks5-hostname', f'127.0.0.1:{ports["windows"]}', '-fsS', '--max-time', '3', f'http://fingerprint.test:{httpport}/'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert xray.poll() is None and blocked.returncode != 0 and not blocked.stdout
    xray.terminate()
    xray.wait(timeout=5)
    assert xray.returncode == 0
    xray = None
    captures[0].send_signal(signal.SIGINT)
    captures[0].wait(timeout=5)
    captures.clear()
    assert read_fingerprints(OUT/'blocked.pcap') == [], 'blocked request emitted a SYN'
    report['controls'] = {'native_http': True, 'native_udp': True, 'final_rules_block': True, 'shutdown_and_reopen': True, 'payload_sha256': hashlib.sha256(BODY).hexdigest()}
    report['controls']['lifecycle_race_test'] = bool(os.environ.get('XRAY_FP_GO'))
    (OUT/'verification.json').write_text(json.dumps(report, indent=2)+'\n')
    print('native TCP/UDP, finalRules, clean shutdown and TUN reopen PASS', flush=True)
finally:
    if xray and xray.poll() is None:
        xray.terminate()
        try:
            xray.wait(timeout=5)
        except subprocess.TimeoutExpired:
            xray.kill()
            xray.wait()
    for cap in captures:
        if cap.poll() is None:
            cap.send_signal(signal.SIGINT)
            cap.wait(timeout=5)
    if server:
        server.shutdown()
        server.server_close()
    for log in logs:
        log.close()
    for interface in reversed(interfaces):
        run(['ip', 'tuntap', 'del', 'dev', interface, 'mode', 'tun'])
