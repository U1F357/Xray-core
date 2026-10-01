#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "$(go env GOOS)/$(go env GOARCH)" != linux/amd64 ]]; then
  echo 'This release currently supports Linux amd64 only.' >&2
  exit 1
fi
python3 scripts/check-gvisor.py
mkdir -p dist
python3 scripts/fetch-geodata.py
go test ./proxy/vless/... ./proxy/freedom/... ./proxy/wireguard ./proxy/tun ./transport/internet ./transport/internet/tcp ./app/proxyman/inbound ./app/proxyman/outbound ./infra/conf \
  -run 'TestFreedom|TestOutbound|TestTCP|TestFingerprint|TestCanceledReply|TestProcessIdentity' -count=1
go test ./testing/fingerprint/ecn -count=1
CGO_ENABLED=0 go build -trimpath -o dist/xrui ./main
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
cp dist/geodata/*.dat "$stage/"
mkdir -p "$stage/licenses/geodata"
cp dist/geodata/LICENSE dist/geodata/SOURCE.json "$stage/licenses/geodata/"
cp dist/xrui README.md README.tcp-fingerprint.zh-CN.md LICENSE "$stage/"
cp testing/fingerprint/example{,-auto}.json "$stage/"
mkdir -p "$stage/licenses/gvisor" "$stage/docs"
cp docs/tcp-ack-delay.zh-CN.md docs/tcp-handshake-delay.zh-CN.md docs/tcp-ecn.zh-CN.md docs/tcp-platform-presets.zh-CN.md docs/reality-mihomo.zh-CN.md docs/ipv6-fingerprint.zh-CN.md docs/docker.zh-CN.md docs/vless-fingerprint.zh-CN.md "$stage/docs/"
cp -r testing/fingerprint/example-chain "$stage/"
cp third_party/gvisor/LICENSE third_party/gvisor/AUTHORS third_party/gvisor/CUSTOM_FINGERPRINT.txt "$stage/licenses/gvisor/"
git rev-parse HEAD > "$stage/SOURCE_COMMIT"
go version > "$stage/BUILD_TOOLCHAIN"
tar -czf dist/xrui-linux-amd64.tar.gz -C "$stage" .
(cd dist && sha256sum xrui xrui-linux-amd64.tar.gz > SHA256SUMS)
