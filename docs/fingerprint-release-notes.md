本 fork 的全部自定义修改、测试、文档和发布流程完全由 AI（OpenAI Codex）实现。上游 Xray-core、gVisor、基础镜像及地理数据由各自作者开发；本项目不是 XTLS 官方发行版。

## fp-v0.7.0

- 可选入口 RTT 自动采样：Linux 原生 TCP/TLS/REALITY 入站配置 `tcpFingerprint: {"source":"syn","rtt":true}`，接受连接时读取一次 TCP_INFO。
- freedom 增加 `tcpAckDelay.autoRTT`，默认回退100 ms、限幅0–1000 ms；按连接固定。手动 `minMs`/`maxMs` 显式配置优先。所有自动功能默认关闭。
- 初始 RTT 可通过私有 VLESS Addons 字段65003经可信中转继承，沿用 `tcpFingerprintForward`、显式 `trustedUsers` 及 `rtt:true`。普通客户端无需修改；普通服务端忽略扩展，普通中转不能保留元数据。Mux 转发限制不变。
- **修正 v0.6 延迟语义**：从“每个 ACK 生成后完整追加等待”改为“所确认服务器数据首次到达后达到最小年龄”。客户端回复已经消耗的时间被抵扣，减少 TLS 二次增加100 ms的问题；原字段保留但行为改变。
- 新增 `continuous:true` 全连接生效，避免窗口结束后网站测得的 TCP RTT 回落。默认仍为10秒窗口。
- SYN-ACK 和第三次握手 ACK 共享截止时间，使 gVisor 初始 RTT/RTO 包含等待，避免过早重传 ClientHello；不叠加旧握手延迟。
- 处理累计 ACK、SACK、重传、序号回绕、keepalive、连接关闭和队列/区间上限；新增 race、双栈、多级 VLESS/Vision 和模拟100 ms客户端链路的真实TLS抓包验证。

配置和局限见 `docs/tcp-rtt.zh-CN.md`、`docs/tcp-ack-delay.zh-CN.md` 和 `docs/tcp-timing-design.zh-CN.md`。
只估计入口TCP对端初始RTT，不累加中转距离、不动态跟随网络变化、不承诺网站所有测量精确一致。
持续延迟可能影响吞吐；仅指纹TCP出口生效，UDP/QUIC不受影响。

## 使用与镜像

自动跟随入口需在 freedom 中同时配置 `tcpFingerprint: "auto"` 和 `tcpECN: "auto"`。入口/中转策略及固定模式见 `docs/tcp-ecn.zh-CN.md`。
Linux amd64 镜像：`ghcr.io/u1f357/xrui:fp-v0.7.0`，同时更新 `latest`。
配置目录：`/usr/local/etc/xrui/`；镜像及普通压缩包内置固定版本、经校验的 geoip/geosite。
指纹出口仍需 NET_ADMIN、TUN 和转发能力；IPv6 还需实际可用的 IPv6 网络。

详情见压缩包和仓库中的 `docs/docker.zh-CN.md`、`docs/ipv6-fingerprint.zh-CN.md`、`docs/tcp-platform-presets.zh-CN.md`、`docs/reality-mihomo.zh-CN.md`。

## 附件与验证

- `xrui`：静态可执行文件。
- `xrui-linux-amd64.tar.gz`：程序、geodata、配置示例和文档。
- `xrui-docker-linux-amd64.tar.gz`：可通过 `docker load -i` 导入。
- `IMAGE_DIGEST`、`SHA256SUMS`：镜像 digest 及文件校验。

发布流水线执行单元/race 测试、VLESS TLS/Vision、多模板 IPv4/IPv6 抓包、MTU/平台特征、异常清理及真实 Docker 双栈 smoke 测试。平台模板尚未与真实 Windows/macOS 系统做全面逐包对照，不能保证绕过所有系统识别。
