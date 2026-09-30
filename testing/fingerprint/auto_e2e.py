#!/usr/bin/env python3
"""Isolated, offline automatic-networking integration test (Linux root).

The host's routes, firewall and forwarding flags are never modified. Two network
namespaces simulate Xray and an external server; captures are at the receiver.
"""
from capture_ready import wait_capture
import concurrent.futures
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT/'testing/fingerprint/artifacts/automatic'
OUT.mkdir(parents=True, exist_ok=True)
BINARY = Path(sys.argv[1]).resolve()
LAB, PEER = f'xfplab-{os.getpid()}', f'xfppeer-{os.getpid()}'
EXPECTED = ['64240_2-1-3-1-1-4_1460_8', '65535_2-1-3-1-1-8-4-0_1460_6', '65535_2-4-8-1-3_1460_9']
PROFILES = ['windows', 'macos', 'linux']
processes, logs, namespaces = [], [], []

def command(args, ns=None, **kw):
    return subprocess.run((['ip','netns','exec',ns] if ns else [])+args, check=True, **kw)

def output(args, ns=LAB):
    return subprocess.check_output(['ip','netns','exec',ns]+args).decode()

def launch(args, name, ns=LAB):
    log = (OUT/f'{name}.log').open('w')
    logs.append(log)
    env = dict(os.environ)
    if args[0] == str(BINARY): env['PATH'] = '/no-external-network-tools'
    p = subprocess.Popen([shutil.which('ip'),'netns','exec',ns]+args, stdout=log, stderr=log, env=env)
    processes.append(p)
    return p

def nft_snapshot():
    return output(['nft','list','ruleset'])

def links():
    return [v['ifname'] for v in json.loads(output(['ip','-j','link','show']))]

def forwarding():
    return output(['cat','/proc/sys/net/ipv4/conf/eth0/forwarding']).strip()

def wait_clean(baseline):
    for _ in range(100):
        if sorted(links()) == ['eth0','lo'] and forwarding() == '0' and nft_snapshot() == baseline:
            assert output(['cat','/proc/sys/net/ipv4/ip_forward']).strip() == '0'
            return
        time.sleep(.05)
    raise AssertionError({'links': links(), 'forwarding': forwarding(), 'nft': nft_snapshot()})

def config(name, baseport=10800):
    c = {'log': {'loglevel': 'warning'}, 'inbounds': [], 'outbounds': [], 'routing': {'rules': []}}
    for i, profile in enumerate(PROFILES):
        c['inbounds'].append({'tag':profile, 'listen':'127.0.0.1', 'port':baseport+i, 'protocol':'socks', 'settings':{'auth':'noauth'}})
        c['outbounds'].append({'tag':profile, 'protocol':'freedom', 'settings':{'tcpFingerprint':profile}})
        c['routing']['rules'].append({'type':'field','inboundTag':[profile],'outboundTag':profile})
    path = OUT/f'{name}.json'
    path.write_text(json.dumps(c, indent=2)+'\n')
    return path

def start(name, baseport=10800):
    p = launch([str(BINARY),'run','-config',str(config(name, baseport))], name)
    for _ in range(120):
        if p.poll() is not None: raise RuntimeError((OUT/f'{name}.log').read_text())
        listening = output(['ss','-lnt'])
        if f':{baseport+2} ' in listening: return p
        time.sleep(.05)
    raise RuntimeError('Xray did not start')

def fetch(index, baseport=10800):
    result = subprocess.check_output(['ip','netns','exec',LAB,'curl','--noproxy','','--socks5-hostname',f'127.0.0.1:{baseport+index}','-fsS','--max-time','10',f'http://192.0.2.2:{18080+index}/'])
    assert result == bytes(range(256))*1024, len(result)

def stop(p, kill=False):
    p.send_signal(signal.SIGKILL if kill else signal.SIGTERM)
    p.wait(timeout=15)
    if not kill: assert p.returncode == 0, p.returncode

def capture_check(path):
    data = path.read_bytes()
    endian = '<' if data[:4] == bytes.fromhex('d4c3b2a1') else '>'
    assert struct.unpack_from(endian+'I', data, 20)[0] == 1
    pos, observed = 24, {i:[] for i in range(3)}
    while pos < len(data):
        _,_,size,_ = struct.unpack_from(endian+'IIII', data, pos)
        pos += 16
        frame = data[pos:pos+size]
        pos += size
        if frame[12:14] != b'\x08\x00': continue
        ip = frame[14:]
        if ip[9] != 6: continue
        tcp = ip[(ip[0]&15)*4:struct.unpack_from('!H',ip,2)[0]]
        if tcp[13]&0x12 != 2: continue
        index = struct.unpack_from('!H',tcp,2)[0]-18080
        if index not in observed: continue
        # Receiver sees host egress address, not the automatically allocated guest.
        assert ip[12:16] == socket.inet_aton('192.0.2.1'), socket.inet_ntoa(ip[12:16])
        checked = ip[12:20]+b'\0\x06'+struct.pack('!H',len(tcp))+tcp
        checked += b'\0'*(len(checked)%2)
        checksum = sum(struct.unpack('!%dH'%(len(checked)//2),checked))
        while checksum>>16: checksum = (checksum&65535)+(checksum>>16)
        assert checksum == 65535, 'invalid checksum after NAT'
        options, kinds, cursor, mss, scale = tcp[20:(tcp[12]>>4)*4], [], 0, None, None
        while cursor < len(options):
            kind = options[cursor]
            kinds.append(kind)
            if kind == 0:
                assert not any(options[cursor+1:]), "nonzero EOL padding"
                break
            if kind == 1: cursor += 1; continue
            length = options[cursor+1]
            assert length >= 2 and cursor+length <= len(options)
            if kind == 2: mss = struct.unpack_from('!H',options,cursor+2)[0]
            if kind == 3: scale = options[cursor+2]
            cursor += length
        fp = f'{struct.unpack_from("!H",tcp,14)[0]}_{"-".join(map(str,kinds))}_{mss}_{scale}'
        assert fp == EXPECTED[index], (index, fp)
        observed[index].append(fp)
    assert all(observed.values()), observed
    return {PROFILES[i]: {'ja4t':EXPECTED[i], 'syn_count':len(v), 'nat_source':'192.0.2.1', 'checksum_valid':True} for i,v in observed.items()}

try:
    for ns in [LAB,PEER]:
        command(['ip','netns','add',ns]); namespaces.append(ns)
        command(['ip','link','set','lo','up'],ns)
    command(['ip','link','add','eth0','type','veth','peer','name','eth0','netns',PEER],LAB)
    for ns, address in [(LAB,'192.0.2.1/30'),(PEER,'192.0.2.2/30')]:
        command(['ip','addr','add',address,'dev','eth0'],ns)
        command(['ip','link','set','eth0','up'],ns)
    command(['ip','route','add','default','via','192.0.2.2'],LAB)
    # Force allocation away from the first pools to exercise conflict avoidance.
    command(['ip','route','add','198.18.0.0/15','dev','eth0'],LAB)
    command(['ip','route','add','10.203.0.0/16','dev','eth0','table','100'],LAB)
    command(['sysctl','-qw','net.ipv4.ip_forward=0'],LAB)
    command(['sysctl','-qw','net.ipv4.conf.eth0.forwarding=0'],LAB)
    command(['nft','-f','-'],LAB,input='table inet administrator {\n chain forward {\n type filter hook forward priority 0; policy drop;\n counter comment "keep-existing-rule"\n }\n}\n',text=True)
    baseline = nft_snapshot()
    (OUT/'firewall-before.txt').write_text(baseline)
    routes_before = output(['ip','-j','route'])
    server_code = '''import http.server,threading,signal
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  b=bytes(range(256))*1024;self.send_response(200);self.send_header("Content-Length",str(len(b)));self.end_headers();self.wfile.write(b)
 def log_message(self,*a): pass
for p in range(18080,18083):
 s=http.server.ThreadingHTTPServer(("0.0.0.0",p),H);threading.Thread(target=s.serve_forever,daemon=True).start()
print("ready",flush=True)
signal.pause()
'''
    server = launch(['python3','-u','-c',server_code],'server',PEER)
    capture = launch(['tcpdump','--immediate-mode','-i','eth0','-s','0','-U','-w',str(OUT/'receiver.pcap'),'tcp[tcpflags] & 0x12 == 2'],'capture',PEER)
    wait_capture(capture, OUT/'capture.log')
    first = start('automatic')
    assert len([x for x in links() if x.startswith('xfp')]) == 3
    addresses = json.loads(output(['ip','-j','addr']))
    assert all(a['local'].startswith('172.31.') for l in addresses if l['ifname'].startswith('xfp') for a in l['addr_info'] if a['family']=='inet')
    for i in range(3): fetch(i)
    assert forwarding() == '1'
    assert output(['cat','/proc/sys/net/ipv4/ip_forward']).strip() == '0'
    with concurrent.futures.ThreadPoolExecutor(max_workers=9) as pool: list(pool.map(fetch,list(range(3))*3))
    # Enabling per-interface forwarding must not accidentally make Xray a
    # router for unrelated traffic, even if the administrator uses ACCEPT.
    command(['nft','-f','-'],LAB,input='add chain inet administrator forward { policy accept; }\n',text=True)
    command(['ip','route','add','198.51.100.2/32','via','192.0.2.1'],PEER)
    guard_capture = launch(['tcpdump','--immediate-mode','-i','eth0','-Q','in','-U','-w',str(OUT/'unrelated.pcap'),'udp and src host 192.0.2.2 and dst host 198.51.100.2'],'unrelated-capture',PEER)
    wait_capture(guard_capture, OUT/'unrelated-capture.log')
    command(['python3','-c','import socket;socket.socket(socket.AF_INET,socket.SOCK_DGRAM).sendto(b"unrelated",("198.51.100.2",38499))'],PEER)
    time.sleep(.2)
    guard_capture.send_signal(signal.SIGINT);guard_capture.wait(timeout=5)
    assert (OUT/'unrelated.pcap').stat().st_size == 24, 'automatic networking forwarded unrelated traffic'
    command(['nft','-f','-'],LAB,input='add chain inet administrator forward { policy drop; }\n',text=True)
    command(['ip','route','del','198.51.100.2/32'],PEER)
    second = start('second-instance',10900)
    for i in range(3): fetch(i,10900)
    stop(first)
    assert forwarding() == '1', 'first process restored a flag still needed by second'
    for i in range(3): fetch(i,10900)
    stop(second)
    wait_clean(baseline)
    assert output(['ip','-j','route']) == routes_before
    print('automatic three profiles, NAT, parallel instances, normal cleanup PASS',flush=True)
    victim = start('killed-parent')
    fetch(0)
    stop(victim,True)
    wait_clean(baseline)
    print('SIGKILL of parent: helper cleaned all resources PASS',flush=True)
    # Fail after earlier outbounds have created their automatic resources.
    live = start('live-instance')
    fetch(0)
    failure_path = config('startup-failure',11000)
    failure_config = json.loads(failure_path.read_text())
    failure_config['outbounds'][-1]['settings']['tcpFingerprintSettings'] = {'tun':'missingfp0','address':'10.250.0.2'}
    failure_path.write_text(json.dumps(failure_config))
    failed = launch([str(BINARY),'run','-config',str(failure_path)],'startup-failure')
    failed.wait(timeout=20)
    assert failed.returncode != 0
    for _ in range(100):
        if len([x for x in links() if x.startswith('xfp')]) == 3: break
        time.sleep(.05)
    else: raise AssertionError('startup failure leaked interfaces')
    fetch(0)
    stop(live)
    wait_clean(baseline)
    print('startup failure cleanup and other instance survival PASS',flush=True)
    # If both the parent and its helper are SIGKILLed, the next startup recovers
    # journaled rules and interface flags without confusing reused PIDs.
    crashed = start('killed-all')
    fetch(0)
    children = set()
    for task in Path(f'/proc/{crashed.pid}/task').iterdir():
        try: children.update(map(int,(task/'children').read_text().split()))
        except FileNotFoundError: pass
    assert len(children) == 3, children
    for child in children: os.kill(child,signal.SIGKILL)
    stop(crashed,True)
    recovered = start('recovery')
    for i in range(3): fetch(i)
    stop(recovered)
    wait_clean(baseline)
    print('killed helper journal recovery PASS',flush=True)
    # Exhaust the remaining allocation pools; no partial network may remain.
    for prefix in ['10.203.0.0/16','172.31.0.0/16']: command(['ip','route','add',prefix,'dev','eth0'],LAB)
    exhausted = launch([str(BINARY),'run','-config',str(config('no-addresses'))],'no-addresses')
    exhausted.wait(timeout=20)
    assert exhausted.returncode != 0
    wait_clean(baseline)
    for prefix in ['10.203.0.0/16','172.31.0.0/16']: command(['ip','route','del',prefix],LAB)
    capture.send_signal(signal.SIGINT); capture.wait(timeout=5)
    report = capture_check(OUT/'receiver.pcap')
    report['checks'] = {'automatic_config_only':True,'global_forwarding_unchanged':True,'existing_firewall_restored':True,'routes_restored':True,'multiple_instances':True,'parent_sigkill_cleanup':True,'startup_failure_cleanup':True,'subnet_conflict_avoidance':True,'subnet_exhaustion_rollback':True,'killed_helper_recovery':True}
    report['checks']['unrelated_forwarding_stays_blocked'] = True
    report['checks']['no_runtime_network_commands'] = True
    (OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
    (OUT/'firewall-after.txt').write_text(nft_snapshot())
    print(json.dumps(report,indent=2),flush=True)
finally:
    for p in reversed(processes):
        if p.poll() is None:
            p.terminate()
            try: p.wait(timeout=5)
            except subprocess.TimeoutExpired: p.kill();p.wait()
    for log in logs: log.close()
    for ns in reversed(namespaces):
        # Catch a failed test's orphaned helpers before deleting the namespace.
        for pid in output(['ip','netns','pids',ns],ns).split():
            try: os.kill(int(pid),signal.SIGTERM)
            except ProcessLookupError: pass
        time.sleep(.1)
        command(['ip','netns','del',ns])
