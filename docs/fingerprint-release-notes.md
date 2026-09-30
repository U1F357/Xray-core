本 fork 的全部自定义修改、测试、文档和发布流程完全由 AI（OpenAI Codex）实现。上游 Xray-core、gVisor、基础镜像及地理数据由各自作者开发；本项目不是 XTLS 官方发行版。

## fp-v0.4.0

- 新增经典 ECN 和 AccECN 核心实现：协商与回退、CE 反馈、ACE 计数器回绕及拥塞窗口响应；不只是设置 SYN 标志。
- freedom 新增 `tcpECN: template|auto|none|classic|accecn`，逐连接选择，与平台类别独立。省略时 Windows/macOS 默认请求经典 ECN，Linux 默认不请求 ECN；需要旧版行为可显式设置 `none`。
- 入口识别 SYN 请求的 ECN 模式，沿用现有可信用户策略，通过独立 VLESS 私有字段跨节点传递。出站 `tcpFingerprintForward: true` 同时转发平台及 ECN；转发仍需关闭 Mux。原版可忽略扩展，但不保留元数据。
- 完善 Windows/macOS/iPhone 样本对应的 SYN 标志和 IP ECN 标记；修正 Apple JA4T 展示，将 EOL 后的零填充排除在选项列表之外。MSS 仍随有效 MTU 调整。
- 增加 IPv4/IPv6 三平台 × 三 ECN 模式的三层 VLESS 并发抓包测试，以及协商、回退、拥塞反馈、重传和 D-SACK 测试。

AccECN 使用 ACE 核心反馈，不包含可选字节计数 TCP 选项或 L4S 拥塞控制。入口识别代表收到的 SYN 声明，不证明客户端完整实现能力；出口独立协商。不保证完整复制某一操作系统的 TCP 行为。

## 使用与镜像

自动跟随入口需在 freedom 中同时配置 `tcpFingerprint: "auto"` 和 `tcpECN: "auto"`。入口/中转策略及固定模式见 `docs/tcp-ecn.zh-CN.md`。
Linux amd64 镜像：`ghcr.io/u1f357/xrui:fp-v0.4.0`，同时更新 `latest`。
配置目录：`/usr/local/etc/xrui/`；镜像及普通压缩包内置固定版本、经校验的 geoip/geosite。
指纹出口仍需 NET_ADMIN、TUN 和转发能力；IPv6 还需实际可用的 IPv6 网络。

详情见压缩包和仓库中的 `docs/docker.zh-CN.md`、`docs/ipv6-fingerprint.zh-CN.md`、`docs/tcp-platform-presets.zh-CN.md`、`docs/reality-mihomo.zh-CN.md`。

## 附件与验证

- `xrui`：静态可执行文件。
- `xrui-linux-amd64.tar.gz`：程序、geodata、配置示例和文档。
- `xrui-docker-linux-amd64.tar.gz`：可通过 `docker load -i` 导入。
- `IMAGE_DIGEST`、`SHA256SUMS`：镜像 digest 及文件校验。

发布流水线执行单元/race 测试、VLESS TLS/Vision、多模板 IPv4/IPv6 抓包、MTU/平台特征、异常清理及真实 Docker 双栈 smoke 测试。平台模板尚未与真实 Windows/macOS 系统做全面逐包对照，不能保证绕过所有系统识别。
