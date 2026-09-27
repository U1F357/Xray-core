本 fork 的全部自定义修改、gVisor 集成、测试、文档和发布工作流完全由 AI（OpenAI Codex）实现。
原始 Xray-core 和 gVisor 由各自上游作者开发；这不是 XTLS 官方发行版。

新增 freedom TCP 指纹：windows / macos / linux / auto。自动模式读取入站 SYN 分类，
按会话选择独立的 gVisor 栈，未知类别使用 tcpFingerprintFallback；INFO 日志显示识别与选择结果。
内部 TUN、路由和 nftables 规则自动管理，正常退出清理，不需手动配置或安装 runsc。

仅支持 Linux amd64、IPv4；需要 root、TUN、nftables/NAT/conntrack 和网络管理权限。
下载压缩包及 SHA256SUMS，校验后解压，以 root 运行：

```bash
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf xray-fingerprint-linux-amd64.tar.gz
sudo ./xray-fingerprint run -config example-auto.json
```

example-auto.json 默认监听本机 SOCKS 1080；部署时请按 README 合并自己的入站及认证配置。
example.json 使用固定 Windows 模板。日志设为 info 可查看选择结果。

GitHub Actions 编译并执行相关测试、race 检测及隔离网络抓包验证。
分类只能观察最后一跳 TCP 发起端，外层代理重建 TCP 时无法保留原始用户指纹。
完整配置、兼容性与清理边界参见仓库 README 和 README.tcp-fingerprint.zh-CN.md。
