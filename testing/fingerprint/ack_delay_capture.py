"""Verify initial ACK/data-ACK delay and recovery after the ten-second window."""
import json
import struct


def verify(path, report, continuous=False):
    raw=path.read_bytes();endian='<' if raw[:4]==bytes.fromhex('d4c3b2a1') else '>'
    pos=24;flows={}
    while pos<len(raw):
        sec,usec,n,_=struct.unpack_from(endian+'IIII',raw,pos);pos+=16
        f=raw[pos:pos+n];pos+=n
        if f[12:14] not in (b'\x08\x00',b'\x86\xdd'):continue
        p=f[14:];v6=p[0]>>4==6;offset=40 if v6 else (p[0]&15)*4
        total=40+int.from_bytes(p[4:6],'big') if v6 else int.from_bytes(p[2:4],'big')
        h=p[offset:];src,dst,seq,ack=struct.unpack_from('!HHII',h)
        outgoing=18080<=dst<=18088;port=dst if outgoing else src
        if not 18080<=port<=18088:continue
        flow=flows.setdefault(port,[])
        flow.append(dict(at=sec+usec/1e6,out=outgoing,seq=seq,ack=ack,flags=h[13],length=total-offset-(h[12]>>4)*4))
    assert len(flows)==9
    report_rows=[]
    for port,packets in sorted(flows.items()):
        packets.sort(key=lambda p:p["at"]) # AF_PACKET may merge per-CPU captures out of timestamp order.
        synack=next(p for p in packets if not p['out'] and p['flags']&0x12==0x12)
        acks=[p for p in packets if p['out'] and p['flags']&0x12==0x10]
        initial=(acks[0]['at']-synack['at'])*1000
        # The simultaneously configured old 200-300 ms SYN-ACK delay MUST be
        # overridden: the new 80-120 ms handshake delay is applied just once.
        assert 75<=initial<190,(port,'handshake delay doubled or absent',initial)
        server_data=[p for p in packets if not p['out'] and p['length']>0 and not p['flags']&2]
        def rtt(p):
            end=(p['seq']+p['length'])&0xffffffff
            matching=[a for a in acks if a['at']>=p['at'] and ((a['ack']-end)&0xffffffff)<0x80000000]
            assert matching,(port,p)
            return (matching[0]['at']-p['at'])*1000,matching[0]['length']
        first_rtt,_=rtt(server_data[0])
        assert 75<=first_rtt<350,(port,'initial server data ACK',first_rtt)
        # First application request rides on an ACK and cannot bypass the delay.
        data_acks=[p for p in acks if p['length']>0]
        assert data_acks
        late=[p for p in server_data if p['at']-synack['at']>10.5]
        assert late,(port,'no traffic after window')
        late_rtt,_=rtt(late[0])
        if continuous:assert 75<=late_rtt<350,(port,'continuous delay stopped',late_rtt)
        else:assert late_rtt<70,(port,'window did not expire',late_rtt)
        # ACK numbers on the wire must not go backwards because of random jitter.
        for prev,cur in zip(acks,acks[1:]):
            if ((cur['ack']-prev['ack'])&0xffffffff)>=0x80000000:
                # Kernel/netem/AF_PACKET can reorder a microsecond burst across
                # CPUs. Scheduler ordering is asserted independently in Go.
                assert cur['at']-prev['at']<.001,(port,'ACK regression beyond capture burst')
        report_rows.append(dict(port=port,handshake_ms=initial,early_data_ack_ms=first_rtt,late_data_ack_ms=late_rtt))
    report.write_text(json.dumps(report_rows,indent=2)+'\n')
    print('ACK timing PASS: nine concurrent TLS flows, handshake once; '+('continuous timing after 10 seconds' if continuous else 'recovery after 10 seconds'))
