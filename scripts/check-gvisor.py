#!/usr/bin/env python3
"""Offline integrity check for the pinned, regenerated gVisor export."""
import hashlib,json
from pathlib import Path
root=Path(__file__).resolve().parents[1]
meta=json.loads((root/'third_party/gvisor-source.json').read_text())
manifest=json.loads((root/'third_party/gvisor-export.sha256.json').read_text())
source=root/'third_party/gvisor'
actual={str(p.relative_to(source)):hashlib.sha256(p.read_bytes()).hexdigest() for p in source.rglob('*') if p.is_file()}
changed=[n for n in sorted(actual.keys()|manifest.keys()) if actual.get(n)!=manifest.get(n)]
if changed:raise SystemExit('gVisor export differs from manifest: '+', '.join(changed))
if hashlib.sha256((root/'third_party/gvisor-tcp-fingerprints.patch').read_bytes()).hexdigest()!=meta['patch_sha256']:raise SystemExit('gVisor source patch digest mismatch')
if 'gvisor.dev/gvisor '+meta['module_version'] not in (root/'go.mod').read_text():raise SystemExit('gVisor module version mismatch')
if meta['default_profile']!='native':raise SystemExit('Shared netstack must default to native')
print(f"Verified {len(actual)} gVisor source files, patch and module version.")
