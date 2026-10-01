本 fork 的全部自定义修改、测试、文档和发布流程完全由 AI（OpenAI Codex）实现。上游 Xray-core、gVisor、基础镜像及地理数据由各自作者开发；本项目不是 XTLS 官方发行版。

## fp-v0.6.0

- freedom 新增 `tcpAckDelay: {"minMs": 80, "maxMs": 120, "windowMs": 10000}`，默认关闭，要求使用 `tcpFingerprint`。
- 从第三次握手 ACK 进入调度器起计时，前 10 秒内所有出站 ACK（包括数据、重传、FIN 和 ECN 反馈）逐包抽取随机延迟。窗口可配置，默认 10000 ms。
- 同连接保持发送顺序；到期后排空原队列再恢复直接发送，不对每包串行累加延迟。不同连接独立，由每栈一个计时调度器管理。
- **握手也包括在窗口和随机范围内**：新模式替代旧 `tcpHandshakeDelay` 的 SYN-ACK 等待，不会叠加两次。只使用旧选项时行为不变。
- 有界队列、RST/元组复用清理和关闭取消；新增有序性、竞态、窗口切换、资源上限测试，以及持续超过 10 秒的 IPv4/IPv6 九连接并发 TLS 抓包验证。

仅指纹 TCP 出口生效，不支持 UDP/QUIC。RST 直接发送；异常/分片报文不保证调度。延迟含数据的 ACK 会影响应用性能，窗口结束后网站测得的 RTT 也可能下降。详细边界见 `docs/tcp-ack-delay.zh-CN.md`。

## 使用与镜像

自动跟随入口需在 freedom 中同时配置 `tcpFingerprint: "auto"` 和 `tcpECN: "auto"`。入口/中转策略及固定模式见 `docs/tcp-ecn.zh-CN.md`。
Linux amd64 镜像：`ghcr.io/u1f357/xrui:fp-v0.6.0`，同时更新 `latest`。
配置目录：`/usr/local/etc/xrui/`；镜像及普通压缩包内置固定版本、经校验的 geoip/geosite。
指纹出口仍需 NET_ADMIN、TUN 和转发能力；IPv6 还需实际可用的 IPv6 网络。

详情见压缩包和仓库中的 `docs/docker.zh-CN.md`、`docs/ipv6-fingerprint.zh-CN.md`、`docs/tcp-platform-presets.zh-CN.md`、`docs/reality-mihomo.zh-CN.md`。

## 附件与验证

- `xrui`：静态可执行文件。
- `xrui-linux-amd64.tar.gz`：程序、geodata、配置示例和文档。
- `xrui-docker-linux-amd64.tar.gz`：可通过 `docker load -i` 导入。
- `IMAGE_DIGEST`、`SHA256SUMS`：镜像 digest 及文件校验。

发布流水线执行单元/race 测试、VLESS TLS/Vision、多模板 IPv4/IPv6 抓包、MTU/平台特征、异常清理及真实 Docker 双栈 smoke 测试。平台模板尚未与真实 Windows/macOS 系统做全面逐包对照，不能保证绕过所有系统识别。
