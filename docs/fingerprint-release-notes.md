本 fork 的全部自定义修改、测试、文档和发布流程完全由 AI（OpenAI Codex）实现。上游 Xray-core、gVisor、基础镜像及地理数据由各自作者开发；本项目不是 XTLS 官方发行版。

## fp-v0.5.0

- freedom 新增 `tcpHandshakeDelay: {"minMs": 80, "maxMs": 120}`，默认关闭，要求使用 `tcpFingerprint`。每次连接均匀抽取闭区间内整数毫秒，支持固定值及 0，最大 10000 ms。
- 收到目标 SYN-ACK 后按连接异步暂存，到期交给 gVisor，再正常发送第三次握手 ACK 和应用数据；不在共享读包循环中睡眠。
- 重复 SYN-ACK 共用截止时间，队列有上限；取消、超时和关闭时清理。后续 TLS 数据、普通 ACK 与 RST 不添加延迟。
- 支持 IPv4/IPv6 及现有三平台、ECN 自动选择；新增九条并发 TLS 连接的双栈抓包时序测试及取消/竞态测试。

延迟会增加连接建立时间并影响初始 RTT；过大可能触发重传或 ECN 回退。分片 SYN-ACK 直接交给栈，不保证延迟。不能保证消除所有代理特征。详细配置见 `docs/tcp-handshake-delay.zh-CN.md`。

保留 fp-v0.4.0 的 ECN/AccECN 核心反馈、入口模式识别及可信 VLESS 传递；不包含 L4S 拥塞控制，节点间元数据转发仍需关闭 Mux。

## 使用与镜像

自动跟随入口需在 freedom 中同时配置 `tcpFingerprint: "auto"` 和 `tcpECN: "auto"`。入口/中转策略及固定模式见 `docs/tcp-ecn.zh-CN.md`。
Linux amd64 镜像：`ghcr.io/u1f357/xrui:fp-v0.5.0`，同时更新 `latest`。
配置目录：`/usr/local/etc/xrui/`；镜像及普通压缩包内置固定版本、经校验的 geoip/geosite。
指纹出口仍需 NET_ADMIN、TUN 和转发能力；IPv6 还需实际可用的 IPv6 网络。

详情见压缩包和仓库中的 `docs/docker.zh-CN.md`、`docs/ipv6-fingerprint.zh-CN.md`、`docs/tcp-platform-presets.zh-CN.md`、`docs/reality-mihomo.zh-CN.md`。

## 附件与验证

- `xrui`：静态可执行文件。
- `xrui-linux-amd64.tar.gz`：程序、geodata、配置示例和文档。
- `xrui-docker-linux-amd64.tar.gz`：可通过 `docker load -i` 导入。
- `IMAGE_DIGEST`、`SHA256SUMS`：镜像 digest 及文件校验。

发布流水线执行单元/race 测试、VLESS TLS/Vision、多模板 IPv4/IPv6 抓包、MTU/平台特征、异常清理及真实 Docker 双栈 smoke 测试。平台模板尚未与真实 Windows/macOS 系统做全面逐包对照，不能保证绕过所有系统识别。
