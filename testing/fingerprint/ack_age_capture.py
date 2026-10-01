"""Compare TCP ACK RTT and TLS client response across a 100 ms proxy path."""
import json
import struct


def verify(path, report, legacy=False):
    raw=path.read_bytes();endian='<' if raw[:4]==bytes.fromhex('d4c3b2a1') else '>'
    pos=24;flows={}
    while pos<len(raw):
        sec,usec,n,_=struct.unpack_from(endian+'IIII',raw,pos);pos+=16
        frame=raw[pos:pos+n];pos+=n
        if frame[12:14] not in (b'\x08\x00',b'\x86\xdd'):continue
        p=frame[14:];v6=p[0]>>4==6;off=40 if v6 else (p[0]&15)*4
        total=40+int.from_bytes(p[4:6],'big') if v6 else int.from_bytes(p[2:4],'big')
        h=p[off:];src,dst,seq,ack=struct.unpack_from('!HHII',h)
        outgoing=18080<=dst<=18088;port=dst if outgoing else src
        if not 18080<=port<=18088:continue
        length=(h[12]>>4)*4;payload=h[length:];at=sec+usec/1e6
        f=flows.setdefault(port,{})
        if outgoing and total>off+length and 'server' not in f:
            seen=f.setdefault('early_segments',set());segment=(seq,total-off-length)
            if segment in seen:f['early_duplicates']=f.get('early_duplicates',0)+1
            seen.add(segment)
        if not outgoing and total>off+length and 'server' not in f:
            f['server']=at;f['end']=(seq+total-off-length)&0xffffffff
        if outgoing and 'server' in f and h[13]&16:
            if ((ack-f['end'])&0xffffffff)<0x80000000:f.setdefault('ack',at)
            # OpenSSL's first encrypted client TLS 1.3 record contains Finished;
            # skip an optional compatibility CCS record in the same TCP segment.
            i=0
            while i+5<=len(payload):
                kind=payload[i]
                if kind==23 and payload[i+1:i+3]==b'\x03\x03':
                    f.setdefault('response',at);break
                i+=5+int.from_bytes(payload[i+3:i+5],'big')
    rows=[]
    for port,f in sorted(flows.items()):
        ack_ms=(f['ack']-f['server'])*1000
        tls_ms=(f['response']-f['server'])*1000
        assert 95<=ack_ms<170,(port,'ACK',ack_ms)
        if legacy:assert tls_ms>=185,(port,'legacy control',tls_ms)
        else:
            assert 95<=tls_ms<175 and abs(tls_ms-ack_ms)<70,(port,'TLS reply delayed again',ack_ms,tls_ms)
            assert f.get('early_duplicates',0)==0,(port,'premature ClientHello retransmission')
        rows.append(dict(port=port,tcp_ack_ms=ack_ms,tls_client_response_ms=tls_ms,gap_ms=tls_ms-ack_ms,early_duplicates=f.get('early_duplicates',0)))
    assert len(rows)==9
    report.write_text(json.dumps(rows,indent=2)+'\n')
    print(('Legacy baseline' if legacy else 'ACK age compensation')+' PASS: client RTT 100 ms, exit RTT 1 ms, 9 TLS flows')
