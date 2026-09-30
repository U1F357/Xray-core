# IPv6 TCP 指纹出口

此功能从 **fp-v0.3.0** 起提供；旧版 fp-v0.2.1 只有 IPv4 指纹出口。

三种固定模式及 auto 均支持 IPv4/IPv6；VLESS 类别传递方式不变。IPv6 TCP SYN 仍使用原来的窗口、选项顺序和窗口缩放模板；MSS 根据 IP 头长度及 MTU 确定，MTU 1500 时 IPv6 MSS 为 1440，MTU 1280 时为 1220。

## 自动模式

原配置无需新增 JSON 字段：

```json
{
  "protocol": "freedom",
  "settings": { "tcpFingerprint": "auto", "tcpFingerprintFallback": "linux" }
}
```

每个模板启动时准备原有 IPv4 网络，首次连接 IPv6 目标时才额外创建该模板独立的 IPv6 栈、TUN、ULA /126 和 NAT66。只使用 IPv4 的主机不需要为此启用 IPv6。

IPv6 出口需要当前网络命名空间满足：

- 内核启用 IPv6，存在可用的 IPv6 地址和到目标的路由。
- `net.ipv6.conf.all.forwarding=1`，以及可用的 nftables IPv6 NAT/conntrack。
- 原有 root、TUN、网络管理权限要求。

程序不自动修改宿主的全局 IPv6 转发或默认路由。未开启上述转发设置时，IPv6 请求明确报错，IPv4 仍可用，不会回退到系统 TCP 绕过指纹。宿主直接运行时由管理员结合现有路由及 RA 配置决定是否开启；容器中则在容器创建时设置其独立网络空间的 sysctl。

NAT66 使用宿主为对应出口选择的 IPv6 地址，不要求给 gVisor 分配公网前缀或配置 NDP 代理。保留原有防火墙策略，仅增加本程序 TUN 流量的规则；正常停止或主进程被强杀时由管理进程清理。

## 解析与目标范围

- IPv6 字面地址直接使用；支持公网及可路由的 ULA 单播地址。
- 默认系统 DNS 同时查询 A/AAAA，优先 IPv4，没有 IPv4 时使用 IPv6，保持原有 IPv4 偏好。
- 可通过原有 `streamSettings.sockopt.domainStrategy: "ForceIPv6"` 配合 Xray DNS 选择 IPv6；`ForceIPv4` 仍有效。
- 此实现没有新增 Happy Eyeballs 并发竞速，也不保证某一地址连接失败后自动轮换另一地址族。
- 自动 IPv6 出口不支持 link-local、带 zone 的目标、multicast、unspecified 或 IPv6 loopback 目标。

## Docker

使用 `ghcr.io/u1f357/xrui:fp-v0.3.0`，也可按 [Docker 构建说明](docker.zh-CN.md) 自行构建。容器所在 Docker 网络必须支持 IPv6 并能路由到目标；仅增加 sysctl 不会自动获得公网 IPv6。

例如创建一个不与现有网络冲突的双栈网络后：

```bash
docker network create --ipv6 --subnet fd66:1234:5678::/64 xrui-net
docker run -d --name xrui --network xrui-net \
  --cap-add=NET_ADMIN --device=/dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 \
  --sysctl net.ipv4.conf.default.forwarding=1 \
  --sysctl net.ipv6.conf.all.forwarding=1 \
  -p 127.0.0.1:1080:1080 \
  -v "$PWD/config:/usr/local/etc/xrui:ro" \
  ghcr.io/u1f357/xrui:fp-v0.3.0
```

Docker 守护进程在创建 IPv6 bridge 网络时可能自行开启宿主 IPv6 转发；这是 Docker 的网络管理行为，与 xrui 仅配置内部 TUN/NAT 的行为分开。不要将上述命令改为 host 网络。

## 手动 TUN

原有 `tcpFingerprintSettings.address` 现在也接受 IPv6 单播地址：

```json
{
  "tcpFingerprint": "windows",
  "tcpFingerprintSettings": { "tun": "manual6", "address": "fd66:1234::2" }
}
```

地址属于 gVisor，须不同于宿主 TUN 地址。使用者自行配置 TUN、IPv6 路由、转发和必要的 NAT；MTU 至少为 1280。手动模式单个栈只配置一个地址族，要同时支持两者可使用自动模式或分别配置出站。auto 仍不能与手动设置同时使用。

## 验证

```bash
sudo python3 testing/fingerprint/ipv6_e2e.py dist/xrui
sudo python3 testing/fingerprint/docker_smoke.py xrui:local --ipv6
```

已验证三模板及 auto 的 IPv6 NAT66 出口 SYN、TCP 校验和、并发 256 KiB 负载、ForceIPv6 域名解析、转发关闭时拒绝且保持原设置、MTU 1280 手动 TUN、正常退出及主进程 SIGKILL 清理。IPv4 自动联网、异常恢复和 race 回归也已通过。
