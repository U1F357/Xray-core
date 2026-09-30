#!/usr/bin/env python3
"""Extended fixed-profile validation on real IPv4/IPv6 NAT egress packets.
Reuses the MTU/parallel echo harness; passes only after all profile checks.
"""
import collections
import json
from pathlib import Path
import struct
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[2]
if len(sys.argv)>1:
 subprocess.run([sys.executable,str(ROOT/'testing/fingerprint/mtu_e2e.py'),sys.argv[1]],check=True)
OUT=ROOT/'testing/fingerprint/artifacts/mtu'
report={}
for path in sorted(OUT.glob('*.pcap')):
 data=path.read_bytes();order='<' if data[:4]==bytes.fromhex('d4c3b2a1') else '>';pos=24
 flows={};windows_ids=[];syns=collections.Counter();flags=collections.Counter();clocks=0
 while pos<len(data):
  sec,usec,size,_=struct.unpack_from(order+'IIII',data,pos);pos+=16;f=data[pos:pos+size];pos+=size
  p=f[14:];version=p[0]>>4 if p else 0
  if version==4 and f[12:14]==b'\x08\x00':
   h=(p[0]&15)*4
   if p[9]!=6:continue
   tcp=p[h:];src=p[12:16];dst=p[16:20];ttl=p[8];total=int.from_bytes(p[2:4],'big')
  elif version==6 and f[12:14]==b'\x86\xdd':
   h=40
   if p[6]!=6:continue
   tcp=p[40:];src=p[8:24];dst=p[24:40];ttl=p[7];total=40+int.from_bytes(p[4:6],'big')
  else:continue
  port=int.from_bytes(tcp[2:4],'big')
  if not 18080<=port<18084:continue
  profile=['windows','macos','linux','linux'][port-18080]
  sourceport=int.from_bytes(tcp[:2],'big');low,high=(32768,60999) if profile=='linux' else (49152,65535)
  assert low<=sourceport<=high,(profile,sourceport)
  assert ttl==(127 if profile=='windows' else 63),(profile,ttl)
  assert tcp[12]&15==0 and tcp[13]&0xe0==0,'reserved/ECN/URG bits unexpectedly set'
  assert tcp[18:20]==b'\x00\x00','unexpected urgent pointer'
  flags[(profile,tcp[13])]+=1
  key=(version,src,dst,sourceport,port)
  flow=flows.setdefault(key,{'ids':[],'labels':set(),'timestamps':[]})
  if version==4:
   assert h==20 and p[1]==0
   assert int.from_bytes(p[6:8],'big')==0x4000
   checksum=sum(struct.unpack('!10H',p[:20]));checksum=(checksum&65535)+(checksum>>16);checksum=(checksum&65535)+(checksum>>16)
   assert checksum==65535,'IPv4 checksum'
   ident=int.from_bytes(p[4:6],'big');flow['ids'].append(ident)
   if profile=='windows':windows_ids.append(ident)
   if profile=='macos':assert ident==0
  else:
   assert (int.from_bytes(p[:4],'big')>>20)&255==0,'traffic class'
   label=int.from_bytes(p[:4],'big')&0xfffff
   if profile!='windows':assert label!=0
   flow['labels'].add(label)
  end=(tcp[12]>>4)*4;i=20;ts=None
  while i<end:
   kind=tcp[i]
   if kind in (0,1):i+=1;continue
   n=tcp[i+1];assert n>=2
   if kind==8:ts=struct.unpack('!II',tcp[i+2:i+10]);flow['timestamps'].append((sec+usec/1e6,ts[0]))
   i+=n
  if profile=='windows':assert ts is None,'Windows unexpectedly negotiated timestamps'
  if tcp[13]&2:
   assert tcp[13]==2 and tcp[8:12]==b'\0'*4 and total==h+end,'malformed SYN flags/ACK/payload'
   if profile!='windows':assert ts is not None and ts[1]==0,'initial timestamp echo'
   syns[(version,profile)]+=1
 for key,f in flows.items():
  profile=['windows','macos','linux','linux'][key[-1]-18080]
  assert len(f['labels'])<=1,'flow label changed within a connection'
  if profile=='linux':
   ids=f['ids'];assert all((b-a)&65535==1 for a,b in zip(ids,ids[1:])),'Linux IP ID progression'
  times=f['timestamps']
  if times:
   start,val=times[0];end,last=times[-1]
   if end-start>=.3:
    assert abs(((last-val)&0xffffffff)-(end-start)*1000)<120,'timestamp clock differs from 1 kHz'
    clocks+=1
 assert all((b-a)&65535==1 for a,b in zip(windows_ids,windows_ids[1:])),'Windows shared ID progression'
 assert len(syns)==6 and clocks>=4,(syns,clocks)
 report[path.stem]={'syns':{f'IPv{v}/{p}':n for (v,p),n in syns.items()},'timestamp_clocks_verified':clocks,'flags':{f'{p}/0x{f:02x}':n for (p,f),n in flags.items()},'connections':len(flows)}
 print(path.stem+': TTL/hop-limit, ports, DF, IP ID, flow label, flags, timestamps, checksum PASS',flush=True)
(OUT/'platform-verification.json').write_text(json.dumps(report,indent=2)+'\n')
