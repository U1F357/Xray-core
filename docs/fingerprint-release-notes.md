本 fork 的全部自定义修改、gVisor 集成、测试、文档和发布工作流完全由 AI（OpenAI Codex）实现。原始 Xray-core 和 gVisor 由各自上游作者开发；这不是 XTLS 官方发行版。

本次新增 VLESS 多跳 TCP 指纹类别传递：入口观测 SYN，各可信中转通过 VLESS Addons 传递 windows / macos / linux / unknown，末端 freedom auto 选择对应栈。功能默认关闭，按入站认证账户 email 显式信任。未知类别不会被中转自身指纹覆盖。

- 原版 Xray 可以处理新增字段的流量，但不会继续传递类别。已验证固定上游版本的双向普通 VLESS、TLS、Vision over TLS 互通；REALITY 握手尚未完成端到端验证。
- 节点间启用转发的出站必须关闭 Mux；用户到入口的 Mux 可继承物理连接类别。
- INFO 日志包含入口识别、VLESS 收发类别及 freedom 选择结果。
- 统一共享 gVisor 库默认 native，按实例开启自定义指纹；修正依赖版本并提供完整可复现导出脚本及源文件校验。
- SYN 采集和 MPTCP 默认调整仅作用于需要采集的监听器，普通配置保留原行为。
- 增加真实 WireGuard TCP/UDP、原有 TUN 入站、三节点传播、信任策略和互通测试。

最终指纹出口仅支持 Linux amd64、IPv4，需要 root、TUN、nftables/NAT/conntrack 和网络管理权限。中转类别本身不需要 TUN。外层代理若重建 TCP，最终线上指纹仍可能被改写。

下载压缩包及 SHA256SUMS，校验后解压：

```bash
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf xray-fingerprint-linux-amd64.tar.gz
sudo ./xray-fingerprint run -config example-auto.json
```

`example-auto.json` 为本机 SOCKS 自动模式，`example.json` 为固定 Windows 模板。
`example-chain/` 提供本地三节点示例，部署时应替换认证及链路配置。
完整参数与限制见 README.tcp-fingerprint.zh-CN.md 和 docs/vless-fingerprint.zh-CN.md。
GitHub Actions 编译静态二进制，并执行相关测试、race 检测、VLESS/TLS/Vision 集成和隔离网络抓包验证。
