# Xray-core：TCP 指纹可选 / 自动匹配版本

**本 fork 的全部自定义修改、gVisor 集成、测试、文档和 GitHub Actions 工作流，完全由 AI（OpenAI Codex）实现。**
**All custom changes in this fork were implemented entirely by AI (OpenAI Codex).**
原始 Xray-core、gVisor 及第三方依赖由各自上游作者开发；上述声明仅指本 fork 的新增修改。
本项目不是 XTLS 官方发行版。保留上游许可证和作者声明。

基于 [XTLS/Xray-core](https://github.com/XTLS/Xray-core) 的
`3519dfecbd65022ba71d9bc73e94063d0cbc8636`，将自定义 gVisor TCP/IP 栈集成到 freedom 出站。
[下载 Release](https://github.com/U1F357/Xray-core/releases) · [详细使用说明](README.tcp-fingerprint.zh-CN.md) · [上游 README](README.upstream.md)

## 做了哪些修改

- freedom 增加 `tcpFingerprint`：支持 `windows`、`macos`、`linux`、`auto`。
- 自定义 gVisor 控制 TCP SYN 的初始窗口、选项顺序及窗口缩放；三种模板使用独立栈。
- `auto` 通过 Linux `TCP_SAVE_SYN` / `TCP_SAVED_SYN` 获取入站 SYN、进行保守分类，
  随会话传递给 freedom；Mux 逻辑流继承物理连接类别。
- 自动准备内部 TUN、路由、nftables NAT 和必要的接口转发设置，退出时清理；
  无需手工配置网络，也不需要安装 runsc 或运行 gVisor 容器。
- INFO 日志显示入站识别类别、freedom 所选模板以及是否使用备用类别。
- 不配置指纹时仍使用原生 freedom；UDP 保留原有路径。现有 WireGuard/TUN 入站显式使用
  gVisor native profile，避免被自定义默认模板影响。
- 修改过的网络栈源码包含在 `third_party/gvisor`，可独立克隆构建。
  上游通用工作流归档在 `docs/upstream-workflows`，本 fork 使用专用 Linux amd64 发布流程。

| 设置 | SYN 指纹模板 |
| --- | --- |
| `windows` | `64240_2-1-3-1-1-4_*_8` |
| `macos` | `65535_2-1-3-1-1-8-4-0-0_*_6` |
| `linux` | `65535_2-4-8-1-3_*_9` |

`*` 是根据出站链路确定的 MSS。MTU 1500 时实测 MSS 为 1460。
这些名称代表指纹模板，不是对真实操作系统身份的保证。

## 使用

当前发行包仅支持 **Linux amd64、IPv4 出站**。需要 root、可用的 `/dev/net/tun`、
网络管理权限，以及内核 nftables/NAT/conntrack 支持。普通宿主 Linux 可直接运行；
受限制容器或 VPS 可能需要宿主授予相应能力。运行时不调用 ip/nft/iptables 命令。

下载 `xray-fingerprint-linux-amd64.tar.gz` 和 `SHA256SUMS`，核验并解压：

```bash
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf xray-fingerprint-linux-amd64.tar.gz
sudo ./xray-fingerprint run -config example-auto.json
```

示例监听 `127.0.0.1:1080` SOCKS；部署代理服务器时，请在自己的入站配置中配置认证，
并将其出站改为以下 freedom 设置。

自动匹配入站类别：

```json
{
  "log": { "loglevel": "info" },
  "outbounds": [{
    "protocol": "freedom",
    "settings": {
      "tcpFingerprint": "auto",
      "tcpFingerprintFallback": "linux"
    }
  }]
}
```

上面是用于合并进现有配置的片段；完整可运行配置见 `example-auto.json`。
无法识别或读取 SYN 时使用 `tcpFingerprintFallback`，可选三种模板，默认 `linux`。
固定指纹只需将 settings 改为 `{"tcpFingerprint":"windows"}`，并删除 fallback 设置。
`example.json` 是固定 Windows 模板的完整示例。
自动网络模式不需要 `tcpFingerprintSettings`；该字段仅用于手动配置的 TUN，不能与 `auto` 同用。

日志级别设为 `info` 或 `debug` 后可看到：

```text
TCP fingerprint inbound: detected=windows peer=...
TCP fingerprint freedom: mode=auto detected=windows selected=windows fallback=false template=64240_2-1-3-1-1-4_*_8 dialing=tcp:...
TCP fingerprint freedom: mode=auto detected=unknown selected=linux fallback=true template=65535_2-4-8-1-3_*_9 dialing=tcp:...
```

日志带会话 ID；`dialing` 表示拨号尝试，连接结果看后续成功/失败日志。

## 识别范围与限制

- 分类匹配 TCP options 顺序，允许正常变化的 MSS、初始窗口和合法缩放值；
  正常 MTU 变化通常不影响分类。未知排列使用备用模板，不会复制任意客户端指纹。
- 当前自动采集覆盖 TCP/raw 传输入站及其 TLS/REALITY 包装；已实测 VLESS TCP、TLS 和 Mux。
  WebSocket、XHTTP、QUIC、Unix socket、PROXY protocol 等无法取得 SYN 的路径使用备用类别。
- 识别的是直接建立 TCP 的最后一跳；CDN/代理如果重建连接，观察到的是中转栈。
  多个用户共用同一条物理 TCP 连接时，不能分别识别原始用户的系统。
- freedom 指纹出站不支持链式 dialerProxy、sendThrough、transport TLS/REALITY、
  出站 mux、finalmask、TCP transport headers 或多数自定义 sockopt；连接中的 HTTPS 负载不受影响。
- 不修改整机默认路由或全局 IPv4 forwarding。会暂时管理相关接口的转发设置及专属规则。
  正常退出和仅主进程被杀均有清理机制；主进程及管理子进程全被强杀时，部分规则可能
  留到下次启动按记录恢复。防火墙服务重载等环境变化需配合重启。
- 未完成完整 WireGuard 隧道回归和吞吐基准测试。完整边界见[详细说明](README.tcp-fingerprint.zh-CN.md)。

## 构建与发布

需要 Go 1.27。网络栈源码和生成后的 protobuf 均已包含，不需要 Bazel 或 protoc：

```bash
git clone https://github.com/U1F357/Xray-core.git
cd Xray-core
bash scripts/build-fingerprint-release.sh
```

输出在 `dist/`。GitHub Actions 会运行相关测试、编译静态二进制并进行隔离网络抓包测试。
推送 `fp-v*` 标签会在成功后创建 GitHub Release，附带二进制、压缩包和 SHA256 校验文件；
普通分支推送和手动触发仅构建测试，不发布。

本地已用三种定制 runsc 沙箱运行 Xray 客户端，验证服务端自动匹配、TLS、Mux、
并发与备用路径，并对入站/出站 SYN 抓包核对。此完整沙箱测试需要额外的三种 runsc
运行时，未包含在本仓库或 Release 中；复现步骤见详细说明。

## 来源与许可证

- Xray-core：[MPL-2.0](LICENSE)，原始作者信息见上游文件。
- 提取的 gVisor：[Apache-2.0](third_party/gvisor/LICENSE)，提交
  `95eb5d5930b0e7736826cc2cb949ba9d2c4d5d29`，保留 [AUTHORS](third_party/gvisor/AUTHORS)。
- gVisor 自定义 TCP 修改的源补丁见 [third_party/gvisor-tcp-fingerprints.patch](third_party/gvisor-tcp-fingerprints.patch)。
