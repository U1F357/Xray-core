#!/usr/bin/env python3
"""Rebuild the checked-in gVisor source export from pinned upstream + patch.
Requires git, Bazel 8.3.1 (or Bazelisk), and Linux amd64. Default is verify only.
--source may name a local upstream Git clone to avoid downloading it again.
"""
import argparse,hashlib,json,os,platform,shutil,subprocess,tempfile,zipfile
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parents[1]
META=json.loads((ROOT/'third_party/gvisor-source.json').read_text())
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--source',default=META['upstream'])
p.add_argument('--bazel',default='bazel')
p.add_argument('--output-user-root',help='Optional shared Bazel cache directory')
p.add_argument('--update',action='store_true',help='Replace the vendored snapshot after successful generation')
a=p.parse_args()
patch_hash=hashlib.sha256((ROOT/'third_party/gvisor-tcp-fingerprints.patch').read_bytes()).hexdigest()
if not a.update and META.get('patch_sha256')!=patch_hash:raise SystemExit('Patch hash differs from source metadata')
if platform.system()!='Linux' or platform.machine() not in ('x86_64','amd64'):raise SystemExit('Regenerate on Linux amd64; other builds can consume the snapshot.')
def run(args,**kw):return subprocess.run(args,check=True,**kw)
def hashes(folder):return {str(f.relative_to(folder)):hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(folder.rglob('*')) if f.is_file()}
bazel=[a.bazel]+(['--output_user_root='+str(Path(a.output_user_root).resolve())] if a.output_user_root else [])
with tempfile.TemporaryDirectory(prefix='xray-gvisor-export-') as tmp:
 tmp=Path(tmp);src=tmp/'source';stage=tmp/'export';stage.mkdir()
 run(['git','clone','--quiet','--no-checkout',a.source,str(src)])
 run(['git','checkout','--quiet','--detach',META['commit']],cwd=src)
 version=subprocess.check_output([a.bazel,'--version'],cwd=src,text=True).strip()
 if version!='bazel '+META['bazel_version']:raise SystemExit('Required Bazel '+META['bazel_version']+', got '+version)
 run(['git','apply','--check',str(ROOT/'third_party/gvisor-tcp-fingerprints.patch')],cwd=src)
 run(['git','apply',str(ROOT/'third_party/gvisor-tcp-fingerprints.patch')],cwd=src)
 try:
  run(bazel+['build',META['export_target'],'--jobs=4'],cwd=src)
  with zipfile.ZipFile(src/'bazel-bin/netstack_gopath.zip') as archive:
   prefix='src/gvisor.dev/gvisor/'
   for name in archive.namelist():
    if not name.startswith(prefix) or name.endswith('/'):continue
    relative=PurePosixPath(name[len(prefix):])
    if relative.is_absolute() or '..' in relative.parts:raise ValueError(name)
    target=stage/str(relative);target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(archive.read(name))
  for name in ['go.mod','go.sum','LICENSE','AUTHORS']:shutil.copyfile(src/name,stage/name)
  (stage/'CUSTOM_FINGERPRINT.txt').write_text(f'''Generated gVisor netstack source; export platform: {META['export_platform']}.
Upstream: {META['upstream']}
Upstream commit: {META['commit']}
Module version: {META['module_version']}
Profiles: native (default), windows, macos, linux. Freedom selects profiles explicitly.
Custom modifications and integration were implemented entirely by AI (OpenAI Codex).
Original upstream copyright and Apache-2.0 license remain applicable; see LICENSE and AUTHORS.
Regenerate/verify: python3 scripts/update-gvisor.py [--update] from the repository root.
See ../gvisor-source.json, ../gvisor-tcp-fingerprints.patch and ../../README.tcp-fingerprint.zh-CN.md.
''')
  actual=hashes(stage);current=hashes(ROOT/'third_party/gvisor')
  changed=[name for name in sorted(actual.keys()|current.keys()) if actual.get(name)!=current.get(name)]
  manifest=ROOT/'third_party/gvisor-export.sha256.json'
  if a.update:
   # Only replace after clone, patch application, build and extraction all succeed.
   shutil.rmtree(ROOT/'third_party/gvisor');shutil.copytree(stage,ROOT/'third_party/gvisor')
   manifest.write_text(json.dumps(actual,indent=2)+'\n')
   META['patch_sha256']=patch_hash
   (ROOT/'third_party/gvisor-source.json').write_text(json.dumps(META,indent=2)+'\n')
   print(f'Updated {len(actual)} source files; {len(changed)} changed.')
  else:
   if changed:raise SystemExit('Export differs: '+', '.join(changed))
   if not manifest.exists() or json.loads(manifest.read_text())!=actual:raise SystemExit('Export manifest differs')
   print(f'Verified all {len(actual)} files against pinned upstream + patch.')
 finally:
  run(bazel+['shutdown'],cwd=src)
