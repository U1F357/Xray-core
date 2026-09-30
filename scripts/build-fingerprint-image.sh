#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
image=${1:-xrui:local}
version=${2:-local}
python3 scripts/fetch-geodata.py
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
cp dist/xrui "$stage/xrui"
mkdir -p "$stage/geodata" "$stage/config" "$stage/licenses/gvisor" "$stage/licenses/geodata"
cp dist/geodata/*.dat dist/geodata/SOURCE.json "$stage/geodata/"
cp LICENSE "$stage/licenses/LICENSE-Xray"
cp third_party/gvisor/LICENSE third_party/gvisor/AUTHORS "$stage/licenses/gvisor/"
cp dist/geodata/LICENSE dist/geodata/SOURCE.json "$stage/licenses/geodata/"
printf '%s\n' '{"log":{"loglevel":"warning"}}' > "$stage/config/00_log.json"
docker build --platform linux/amd64 -f .github/docker/Dockerfile \
  --build-arg "SOURCE_REVISION=$(git rev-parse HEAD)" \
  --build-arg "VERSION=$version" -t "$image" "$stage"
