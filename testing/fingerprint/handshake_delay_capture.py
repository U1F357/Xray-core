"""Validate handshake-only delay in a receiver-side Ethernet pcap."""
import json
import re
import struct


def verify(path, log, report):
    raw = path.read_bytes()
    endian = '<' if raw[:4] == bytes.fromhex('d4c3b2a1') else '>'
    pos = 24
    flows = {}
    while pos < len(raw):
        sec, usec, size, _ = struct.unpack_from(endian+'IIII', raw, pos)
        pos += 16
        f = raw[pos:pos+size]
        pos += size
        if f[12:14] not in (b'\x08\x00', b'\x86\xdd'):
            continue
        p = f[14:]
        offset = 40 if p[0] >> 4 == 6 else (p[0] & 15)*4
        total = 40+int.from_bytes(p[4:6], 'big') if p[0] >> 4 == 6 else int.from_bytes(p[2:4], 'big')
        h = p[offset:]
        src, dst = struct.unpack_from('!HH', h)
        outbound = 18080 <= dst <= 18088
        port = dst if outbound else src
        if not 18080 <= port <= 18088:
            continue
        row = flows.setdefault(port, {})
        at = sec+usec/1e6
        flags = h[13]
        length = (h[12] >> 4)*4
        payload = total-offset-length
        if not outbound and flags & 0x12 == 0x12:
            row.setdefault('synack', at)
        if outbound and flags & 0x12 == 0x10:
            row.setdefault('ack', at)
            if payload:
                if 'hello' not in row:
                    assert h[length:length+2] == b'\x16\x03', (port, h.hex())
                row.setdefault('hello', at)
        if not outbound and payload and flags & 2 == 0:
            # Wait for enough server TLS data to require an ordinary ACK.
            row.setdefault('data', at)
        if outbound and 'data' in row and flags & 0x10:
            row.setdefault('data_ack', at)
    selected = {int(port): int(ms) for ms, port in re.findall(r'TCP handshake delay: selectedMs=(\d+) target=.*?:(1808[0-8])', log.read_text())}
    assert len(flows) == len(selected) == 9, (flows, selected)
    timings = []
    for port, row in sorted(flows.items()):
        delay = (row['ack']-row['synack'])*1000
        hello = (row['hello']-row['ack'])*1000
        data_ack = (row['data_ack']-row['data'])*1000
        assert 200 <= selected[port] <= 300
        assert selected[port]-5 <= delay <= selected[port]+150, (port, delay, selected[port])
        assert 0 <= hello < 150, (port, hello)
        assert 0 <= data_ack < 150, (port, data_ack)
        timings.append(dict(port=port, selected_ms=selected[port], synack_ack_ms=delay, ack_clienthello_ms=hello, data_ack_ms=data_ack))
    span = max(r['ack'] for r in flows.values())-min(r['synack'] for r in flows.values())
    assert span < .8, ('serialized handshakes', span)
    report.write_text(json.dumps(timings, indent=2)+'\n')
    print('Handshake delay PASS: 9 concurrent TLS connections, configured range, prompt ClientHello/data ACKs')
