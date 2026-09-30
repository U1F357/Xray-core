#!/usr/bin/env python3
"""Fetch the pinned geodata snapshot and verify every downloaded byte."""
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
manifest = ROOT/'scripts/geodata-source.json'
source = json.loads(manifest.read_text())
out = ROOT/'dist/geodata'
out.mkdir(parents=True, exist_ok=True)
files = [(name, source['commit'], digest) for name, digest in source['sha256'].items()]
files.append(('LICENSE', source['source_commit'], source['license_sha256']))
for name, revision, digest in files:
    target = out/name
    if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest() == digest:
        continue
    url = f"https://raw.githubusercontent.com/{source['repository']}/{revision}/{name}"
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != digest:
        raise RuntimeError(f'Geodata checksum mismatch: {name}')
    temporary = target.with_suffix('.download')
    temporary.write_bytes(data)
    temporary.replace(target)
(out/'SOURCE.json').write_bytes(manifest.read_bytes())
print('Verified pinned geoip.dat, geosite.dat and license.')
