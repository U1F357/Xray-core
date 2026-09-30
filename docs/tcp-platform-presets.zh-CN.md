# TCP/IP 平台预设：范围、依据与验证

本次仅扩展 `windows`、`macos`、`linux` 三个固定模板，不新增动态特征探测、
不传递原始 SYN。原有 auto 分类和 VLESS 类别传递保持原有语义。
这里模拟的是平台家族的一组常见行为，**不是特定版本操作系统的完整 TCP/IP 栈**。
这些扩展从 fp-v0.3.0 起提供，旧版 fp-v0.2.1 不包含。

## 三套模板的具体取值

| 特征 | windows | macos | linux |
| --- | --- | --- | --- |
| SYN JA4T | `64240_2-1-3-1-1-4_*_8` | `65535_2-1-3-1-1-8-4-0-0_*_6` | `65535_2-4-8-1-3_*_9` |
| 初始 IPv4 TTL / IPv6 Hop Limit | 128 | 64 | 64 |
| 主动 TCP IPv4 DF | 1 | 1 | 1 |
| 原子 IPv4 包 IP ID | 随机初值、每个栈递增 | 0（当前 XNU RFC 6864 模式） | 每条流随机初值、递增 |
| IPv4 Options / IPv6 Extension Headers | 普通 TCP 包不添加 | 普通 TCP 包不添加 | 普通 TCP 包不添加 |
| IPv6 Flow Label | 保留原栈的 0，未模拟 Windows 各版本差异 | 非零、每条流固定 | 非零、每条流固定 |
| 默认 ToS / Traffic Class | 0 | 0 | 0 |
| SYN Flags | SYN (`0x02`)，不主动协商 ECN | SYN (`0x02`)，选择非 ECN 变体 | SYN (`0x02`)，不主动协商 ECN |
| SYN ACK number / urgent pointer / reserved bits | 0 | 0 | 0 |
| TCP timestamp | 不主动提供 | 提供，1 kHz | 提供，1 kHz |
| 初始 TSecr | 无 timestamp | 0 | 0 |
| 源端口范围（NAT 前） | 49152–65535 | 49152–65535 | 32768–60999 |
| SYN TCP 头长度 | 32 字节 | 44 字节 | 40 字节 |
| SYN payload | 无 | 无 | 无 |

MSS 仍按有效 MTU 和 IPv4/IPv6 头长度计算，不写死 1460。前三项 JA4T 模板
保留用户指定值，因此不能声称所有值都来自某个具体 OS 版本的默认配置。

**TTL 是栈发包时的初始值。** 自动 TUN 在宿主转发时仍正常减 1，因此本机物理
出口抓包通常为 Windows 127、macOS/Linux 63。后续路由还会继续递减；不能把
接收端观测到的 TTL 与初始 TTL 混为一谈，也不主动篡改路由器的跳数语义。

IPv4 ID 的“递增”是预设策略：Windows 在单个 freedom 栈内共享计数器，
不保证复刻 Windows 内核所有场景的分组/随机化算法；Linux 按 NAT 前四元组
维护计数器，最多缓存 65536 条流，LRU 淘汰后重新建立序列。每个新 SYN 的初始
序列号变化也会重置该流的 IP ID 初值。16 位 IP ID 正常回绕可以经过 0。
只处理 DF=1、MF=0、offset=0 的原子 TCP 包，不改动可分片包/分片的 ID。

IPv6 Flow Label 使用栈内随机密钥对流四元组散列，固定为非零值，避免全部
为零及每包变化；这模拟字段性质，不复刻 Linux/XNU 的具体散列算法。
NAT 可能重写源端口，中间网络也可能改写 DSCP/TTL；跨 TCP 终止代理则会重新生成
整条连接，因此不能保证本地抓包特征在远端完全保留。

## 对照完整指纹清单

| 项目 | 本次处理 | 边界 |
| --- | --- | --- |
| TTL / Hop Limit | 新增平台预设 | 转发正常减跳数 |
| DF / IP Options / IPv6 扩展头 | 保留正确的已有行为并抓包断言 | 不干扰分片、ICMP 或扩展头处理 |
| IP ID | 新增上述策略及校验和重算 | 不模仿所有 Windows 版本；Mac 选用当前 XNU 行为 |
| IPv6 Flow Label | 新增 Linux/macOS 每流标签 | Windows 更细差异暂不模拟 |
| ToS / DSCP / ECN | 默认 0，不主动 ECN | 应用、网络策略会改变此项，并非独有 OS 标志 |
| Window / MSS / WS / Option 顺序 | 保留 JA4T 预设和 MTU 适配 | 不动态复制入口窗口 |
| Flags / NOP / EOL / padding / header length | 保留已有模板及 TCP 状态机，增加抓包验证 | 不能把所有包都强行写成 SYN 或固定 flags |
| Timestamp | Windows 不提供；另外两类 1 kHz；验证初始 echo=0 | 保留 gVisor timestamp offset/回显/PAWS，不复制 OS 的随机偏移算法 |
| Source Port | 新增平台范围 | 端口选择顺序/散列仍由 gVisor 分配器决定 |
| ISN / Sequence Number | 保留安全的 gVisor 生成与状态管理 | 不为外观改成可预测序号，不复刻平台 ISN 算法 |
| SYN/SYN-ACK 重传次数及 RTO | 暂不模拟平台差异 | 当前 freedom 是主动客户端；超时/重传仍由原有栈管理 |
| ACK / SACK / 拥塞恢复 | 暂不模拟平台差异 | 更改会影响可靠性和吞吐，不能仅改头部字段 |
| 异常 Flags / 非法 Options / ECN probe | 暂不模拟平台差异 | 涉及完整 TCP 状态机及拥塞反馈，不能仅添加 ECE/CWR |
| Closed Port RST / ICMP / UDP→ICMP | 暂不模拟平台差异 | 公开入站通常由宿主 Linux 处理；freedom 模板不覆盖整台主机 |

现代 macOS 的 ECN/AccECN/L4S 会受版本、网络接口、系统配置和启发式策略影响。
当前模板明确选择非 ECN 变体，不宣称与所有现代 macOS 默认 SYN Flags 相同。
仅添加 ECE/CWR 而不实现 CE 标记反馈、拥塞窗口调整及回退会制造协议不一致，
因此没有采用这种做法。旧 p0f 数据库中的 macOS 常见 `id+`，而当前 XNU 默认
原子包 ID=0；不能为了命中旧数据库就声称它是所有现代 Mac 的行为。

## 实现位置与隔离

TTL、Hop Limit、端口范围通过现有 gVisor stack API 配置。
`proxy/freedom/fingerprint_headers_linux.go` 在自定义 freedom 栈的出包边界处理
IP ID 和 Flow Label，复用已有 TUN write pump；不引入第二套 TCP 实现。
IPv4 只重算 IP 头校验和；TCP 报文、序号、选项及校验和均不改动。
IPv6 Flow Label 不在 TCP 伪头内，不需要更改 TCP 校验和。

该逻辑不作用于普通 freedom、WireGuard、原有 TUN 入站或宿主系统的全局参数。
没有改动第三方 gVisor 导出文件及其校验清单；这里的网络头预设属于 Xray
freedom 集成，独立 runsc 二进制不会因此自动具备这些新增行为。

## 验证

```sh
python3 testing/fingerprint/platform_e2e.py dist/xrui
```

隔离的 network namespace 中覆盖 IPv4/IPv6、三模板及 auto fallback、NAT、
16 条并发连接、1280/1492/1500 MTU、9000 MTU 的保守上限、不同目标路由 MTU
和 advmss。检查 SYN 指纹、flags、TTL、DF、源端口、IP ID 序列、IPv6 flow label、
保留位、urgent pointer、header length、timestamp echo/时钟、IPv4 校验和及
双向 128 KiB 正文完整性。抓包是在宿主转发/NAT 之后的对端接口进行。

另有单元测试验证截断输入、可分片包不改动、IP 头改写不改变 TCP、缓存有界、
各栈默认值；IPv4/IPv6 自动联网、异常退出清理和 race 检查也需要通过。
这些是本实现行为的验证，**并非与真实 Windows/macOS 机器逐包对照的认证**。

## 调研依据（2026-09-30）

- [FoxIO JA4T 设计](https://blog.foxio.io/ja4t-tcp-fingerprinting)：JA4T 的字段范围。
- [Nmap 指纹方法](https://nmap.org/book/osdetect-methods.html)：IP ID、ISN、timestamp、ECN、异常 flags 等跨包/主动探测的区别。
- [p0f 数据库](https://github.com/p0f/p0f/blob/master/p0f.fp)：平台家族 TTL/DF/选项及 quirks 的历史样本，不能代表所有新版本。
- [Linux IP 头生成](https://github.com/torvalds/linux/blob/master/include/net/ip.h)：`ip_select_ident_segs` 的 TCP socket 私有 ID 计数器。
- [Linux 网络参数文档](https://kernel.org/doc/html/latest/networking/ip-sysctl.html)：端口范围、ECN、flow label 等可配置行为。
- [Apple IPv4 输出](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/ip_output.c)：`rfc6864=1` 和原子包 ID=0。
- [Apple TCP 输出](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/tcp_output.c)：DF 与 ECN/L4S 条件。
- [Apple PCB 初始化](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/in_pcb.c)：自动端口范围。
- [Apple IPv6 配置](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet6/in6_proto.c)：自动 flow label 默认开启。
- [Apple TCP 时钟](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/tcp_subr.c)：毫秒 TCP clock。
- [Microsoft 动态端口文档](https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/tcp-ip-port-exhaustion-troubleshooting)：49152–65535。
- [Microsoft IPv6 默认 Hop Limit](https://learn.microsoft.com/en-us/powershell/module/nettcpip/set-netipv6protocol?view=windowsserver2025-ps)：128。
- [RFC 6864](https://www.rfc-editor.org/rfc/rfc6864.html)：IPv4 ID 的原子/非原子包语义。
