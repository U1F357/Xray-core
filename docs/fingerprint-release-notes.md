本 fork 的全部自定义修改、测试、文档和发布流程完全由 AI（OpenAI Codex）实现。上游 Xray-core、gVisor、基础镜像及地理数据由各自作者开发；本项目不是 XTLS 官方发行版。

## fp-v0.3.0

- 新增 IPv6 指纹出口：三模板及 auto、NAT66、IPv6 字面地址与 ForceIPv6 解析。IPv6 自动联网要求当前网络空间已开启全局 IPv6 转发；程序不会代为开启。
- 新增按目标路由/出口接口 MTU 和 advmss 自动限制 MSS 与发包大小，每条新连接重新读取；不等于主动探测全路径 MTU，隐藏瓶颈及 ICMP 黑洞仍有局限。
- 扩展固定平台预设：Windows 初始 TTL/Hop Limit 128，macOS/Linux 64；平台源端口范围；Windows/Linux IPv4 ID 序列与现代 XNU 原子包 ID=0；Linux/macOS 每流 IPv6 Flow Label。正常转发仍减跳数。
- 增加 TCP Flags、DF、保留位、头长度、timestamp 时钟、IP ID/flow label、校验和及不同 MTU 的抓包验证。未新增动态特征探测，也未声称模拟完整操作系统的 ECN/拥塞恢复/异常探测行为。
- 补充 mihomo REALITY 兼容说明及本地 nginx 测试：使用 `client-fingerprint: chrome`，在 `reality-opts` 中设置 `support-x25519mlkem768: true`。对应较新上游 REALITY 的握手要求；同基线原版也有此要求。
- 保留 xrui 文件/进程名、三种 JA4T、入口分类、可信 VLESS 多跳类别传递和 INFO 日志。节点间类别转发仍不支持出站 Mux。

## 使用与镜像

现有 `tcpFingerprint: windows|macos|linux|auto` 配置直接应用扩展模板，无需增加字段。
Linux amd64 镜像：`ghcr.io/u1f357/xrui:fp-v0.3.0`，同时更新 `latest`。
配置目录：`/usr/local/etc/xrui/`；镜像及普通压缩包内置固定版本、经校验的 geoip/geosite。
指纹出口仍需 NET_ADMIN、TUN 和转发能力；IPv6 还需实际可用的 IPv6 网络。

详情见压缩包和仓库中的 `docs/docker.zh-CN.md`、`docs/ipv6-fingerprint.zh-CN.md`、`docs/tcp-platform-presets.zh-CN.md`、`docs/reality-mihomo.zh-CN.md`。

## 附件与验证

- `xrui`：静态可执行文件。
- `xrui-linux-amd64.tar.gz`：程序、geodata、配置示例和文档。
- `xrui-docker-linux-amd64.tar.gz`：可通过 `docker load -i` 导入。
- `IMAGE_DIGEST`、`SHA256SUMS`：镜像 digest 及文件校验。

发布流水线执行单元/race 测试、VLESS TLS/Vision、多模板 IPv4/IPv6 抓包、MTU/平台特征、异常清理及真实 Docker 双栈 smoke 测试。平台模板尚未与真实 Windows/macOS 系统做全面逐包对照，不能保证绕过所有系统识别。
