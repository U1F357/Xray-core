# Freedom TCP 指纹版本

**本 fork 的自定义修改、网络栈集成、测试、文档及发布工作流完全由 AI（OpenAI Codex）实现。
这不表示原始 Xray-core 或 gVisor 项目由 AI 实现。**

基于 Xray-core `3519dfecbd65022ba71d9bc73e94063d0cbc8636`，将相邻目录
`third_party/gvisor` 中提取的自定义 gVisor TCP/IP 网络栈作为 Go 库编入 Xray。
不依赖 runsc、gVisor 沙箱或另外安装的网络工具。已构建的程序是 Linux amd64 静态二进制：
`dist/xray-fingerprint`，不依赖 glibc（本次 Xray 集成测试在本机 Linux 完成）。

## 配置

使用发行包时，解压后运行 `./xray-fingerprint run -config example.json`。
下面的路径和构建命令均以本仓库根目录为工作目录。

在 freedom 的 `settings` 中只需添加 `tcpFingerprint`。以 root 启动程序，
网络接口、内部地址、转发和 NAT 会自动准备好，无需 `tcpFingerprintSettings`：

```json
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "listen": "127.0.0.1",
    "port": 1080,
    "protocol": "socks",
    "settings": {"auth": "noauth", "udp": true}
  }],
  "outbounds": [{
    "tag": "fingerprint-exit",
    "protocol": "freedom",
    "settings": {
      "tcpFingerprint": "windows"
    }
  }]
}
```

| `tcpFingerprint` | TCP SYN 指纹 |
| --- | --- |
| `windows` | `64240_2-1-3-1-1-4_*_8` |
| `macos` | `65535_2-1-3-1-1-8-4-0-0_*_6` |
| `linux` | `65535_2-4-8-1-3_*_9` |

`*` 为 MSS，由链路 MTU 决定；MTU 1500 时本次抓包为 1460。
不填 `tcpFingerprint` 时使用原来的 freedom 系统拨号。UDP 仍使用原路径。
三个选项可同时用于不同出站；程序为各出站自动分配独占接口和不同地址。

每个出站的 TCP 握手、选项、重传和窗口管理由自己的 gVisor TCP 栈执行。
应用 TLS 数据原样穿过该连接，HTTPS 可用；这里配置的是 TCP 指纹，不是 TLS 指纹。
Xray 出站的流量统计、freedom redirect、fragment、PROXY protocol 和 finalRules
仍位于原处理路径。DNS 结果在 finalRules 检查前确定，拨号使用同一个 IP。

## 按入站 SYN 自动选择指纹

发行包可直接运行 `./xray-fingerprint run -config example-auto.json`。
在 freedom 中配置：

```json
{
  "protocol": "freedom",
  "settings": {
    "tcpFingerprint": "auto",
    "tcpFingerprintFallback": "linux"
  }
}
```

`tcpFingerprintFallback` 可为 `windows`、`macos`、`linux`，省略时为 `linux`；
仅可与 `auto` 一起使用。`auto` 自动创建三套独立的网络栈和网络管理子进程，
按每条会话选择，不修改共享栈的指纹。不能同时指定手动 `tcpFingerprintSettings`。

按实例及入站策略启用采集时，Linux 监听 socket 启用 `TCP_SAVE_SYN`，TCP 传输在 accept 后、TLS/REALITY
包装前用 `TCP_SAVED_SYN` 读取初始 IP/TCP 头。默认分类结果在本机入站会话中传递，不相信客户端声明的操作系统。
可显式启用[可信 VLESS 多跳传递](docs/vless-fingerprint.zh-CN.md)。入站流量统计不会丢失分类；Mux
逻辑流继承物理连接的分类。临时的元数据包装在入站 worker 开始处理时就会
移除，后续仍获得原本的 TCP/TLS/REALITY 连接对象。

分类识别当前三种模板的 TCP options 排列，允许 MSS、窗口和合法窗口缩放值
变化；未知排列不猜测。它是粗分类，不能证明真实操作系统，也不会逐字节
复制所有入站报文特征。macOS 的 EOL 后零填充按终止填充处理。

当前支持 TCP（raw）传输入站，包括在其上包装的 TLS/REALITY；已经实测
VLESS TCP、VLESS TCP+TLS 及 Mux。WebSocket、XHTTP、QUIC、Unix socket、
PROXY protocol 包装或其他无法读取底层 socket 的路径使用备用类别。
旧内核、不支持这些 socket 选项的运行环境、SYN cookies 导致未保存 SYN、
显式开启 MPTCP 等情况下也可能读不到 SYN，此时同样使用备用类别。
仅启用 SYN 采集的 TCP 监听显式关闭 Go 隐式启用的 MPTCP；`sockopt.tcpMptcp: true` 仍保留。

观察到的总是最后一跳 TCP 发起端。如果 CDN/中转重新建立了 TCP，识别到的是
它的协议栈；单个复用连接内不同原始用户无法凭这个 SYN 再区分。
出站仍受本文所述 Linux、IPv4、TUN/nftables 和权限限制。

端到端验证（需 root、ip、nft、tcpdump、curl、openssl、Python，以及外部准备的
三种自定义 runsc 完整运行时；设置 `XRAY_FP_RUNSC_DIR` 指向包含
`windows/runsc`、`macos/runsc`、`linux/runsc` 及配套 sidecar 的目录；这些运行时不包含在本发行包中）：

```bash
python3 testing/fingerprint/auto_select_e2e.py dist/xray-fingerprint
```

测试建立隔离网络命名空间，在三种 runsc 沙箱内运行不启用出站指纹设置的
Xray VLESS 客户端，再经服务端 `freedom auto` 访问隔离 HTTP 接收端。
分别捕获服务端入站与接收端出站 SYN，对比三种模板，同时验证 TLS、Mux、
并发传输、无 SYN 的 Unix 入站备用路径，以及自动网络清理。
结果位于 `testing/fingerprint/artifacts/auto-selection/verification.json` 和同目录 pcap。

### 指纹日志

设置 `"log": {"loglevel": "info"}`（或 `debug`）后，日志会显示入站分类以及
freedom 每次实际拨号选择的模板，包含 Xray 的会话 ID，便于关联：

```text
TCP fingerprint inbound: detected=windows peer=...
TCP fingerprint freedom: mode=auto detected=windows selected=windows fallback=false template=64240_2-1-3-1-1-4_*_8 dialing=tcp:...
TCP fingerprint freedom: mode=auto detected=unknown selected=linux fallback=true template=65535_2-4-8-1-3_*_9 dialing=tcp:...
TCP fingerprint freedom: mode=fixed selected=macos template=65535_2-1-3-1-1-8-4-0-0_*_6 dialing=tcp:...
```

`unknown` 表示无法识别或无法获取 SYN；`fallback=true` 表示使用备用类别。
`template` 显示配置模板，`*` 为由链路决定的 MSS，并非实际抓包值。
`dialing` 记录拨号尝试，不代表已经连通；连接结果继续看原有连接成功/失败日志。
Mux 的物理入站只识别一次，每次 freedom 拨号仍记录所选类别。
不使用自定义指纹的原生 freedom 出站不产生模板选择日志。

## 网络包如何出机器

网络栈输出的是 IP 报文，需要一个收发通道。本版本自动管理 Linux TUN：

```text
Xray 入站 → freedom → gonet.DialContextTCP → 自定义 gVisor TCP/IP 栈
                                                    ↕ IP 报文
                                            channel / Linux TUN
                                                    ↕
                                          宿主路由、NAT → 真实网卡
```

TUN 只搬运 IP 报文；它不负责 TCP 指纹，也不接管整机默认路由。

自动模式的实现如下：

1. 从候选地址池中挑选不与现有地址、所有路由表及其他实例冲突的 `/30` 子网。
2. 创建非持久 TUN，设置接口地址和内部路由。最后一个描述符关闭时，内核自动删除接口。
3. 使用 Go 的 Netlink API 原子安装 nftables NAT 和只匹配本出站接口的转发规则。
   不调用 `ip`、`iptables`、`nft` 或 shell，不替换已有规则或默认策略。
4. 每次连接按宿主路由查询出口接口，按需启用该接口的 IPv4 forwarding。
   不写全局 `net.ipv4.ip_forward`；其修改可能重置其他网络参数，见
   [Linux 内核说明](https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html)。
5. 多出站、多进程通过加锁的资源记录共享接口 forwarding 的使用权；最后一个使用者退出时恢复原值。

如果某个真实接口原本关闭转发，临时启用时还会添加范围受限的防护规则：只允许
返回本程序用户态栈的已建立连接报文转发，其他流量继续保持原先不能转发的行为。

每个自动出站由同一个 Xray 二进制启动一个网络管理子进程。它不处理代理数据，
只管理网络资源，通过继承的私有 Unix socket 向主进程传递 TUN 描述符。
正常关闭或配置初始化失败会撤销本出站的规则；主进程被 `SIGKILL` 时，子进程
检测到控制通道断开，仍能完成清理。子进程使用独立会话，避免主进程组信号直接跳过清理。

若整个进程组/服务的所有进程都被 `SIGKILL`，非持久接口自动消失，但防火墙规则和
forwarding 可能暂时保留；下次启动会根据 `/run/xray-fingerprint/` 中按网络命名空间
保存的记录清理。资源归属同时检查 PID 与进程启动时间，避免误认复用的 PID。
该目录本身及空的记录文件会保留，权限为 root 私有。

自动模式要求 Linux root、可访问的 `/dev/net/tun`、可写的相关 `/proc/sys` 项，
以及内核 nftables/NAT/conntrack 支持。只获得容器内 root、但缺少 CAP_NET_ADMIN
等宿主授权时仍不可用，程序会报错，不会悄悄回退到系统 TCP。
支持 nftables 和 iptables-nft 的常规 IPv4/inet FORWARD 规则；检测到活动 legacy
iptables 表时拒绝自动模式。外部工具在运行期间重建防火墙、修改路由/接口设置时，
需要协调这些资源或重启本实例；不保证兼容任意第三方网络管理策略。

## 可选的手动网络模式

已有自己的网络配置时，可显式提供以下设置，此时 Xray 不自动修改网络：

```json
"settings": {
  "tcpFingerprint": "windows",
  "tcpFingerprintSettings": {
    "tun": "xrfp0",
    "address": "10.203.10.2"
  }
}
```

以下手动示例假设 `10.203.10.0/30` 未被占用、出口为 `eth0`。
宿主 TUN 地址 `.1` 和用户态栈地址 `.2` 必须不同，不能把 `.2` 配给宿主网卡。

```bash
ip tuntap add dev xrfp0 mode tun
ip addr add 10.203.10.1/30 dev xrfp0
ip link set xrfp0 mtu 1500 up

# 公网转发要求宿主已启用 IPv4 forwarding；未启用时按部署需要设置。
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -I POSTROUTING 1 -s 10.203.10.2/32 -o eth0 -j MASQUERADE
iptables -I FORWARD 1 -i xrfp0 -o eth0 -s 10.203.10.2/32 -j ACCEPT
iptables -I FORWARD 1 -i eth0 -o xrfp0 -d 10.203.10.2/32 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 使用包含上面 tcpFingerprintSettings 的手动模式配置启动 Xray。
```

创建/打开 TUN 需要相应权限，通常使用 root 或 CAP_NET_ADMIN。
手动模式只打开已有设备，不修改系统路由、NAT 或 sysctl；停止时关闭连接、网络栈和
TUN 描述符，持久 TUN 及管理员配置的规则保留。

停止 Xray 后撤销上面示例的规则：

```bash
iptables -t nat -D POSTROUTING -s 10.203.10.2/32 -o eth0 -j MASQUERADE
iptables -D FORWARD -i xrfp0 -o eth0 -s 10.203.10.2/32 -j ACCEPT
iptables -D FORWARD -i eth0 -o xrfp0 -d 10.203.10.2/32 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip tuntap del dev xrfp0 mode tun
```

如修改过全局 forwarding，应结合其他服务需求恢复原值。

## 当前范围

- 当前实现验证了 Linux amd64、IPv4。IPv6 目标会报错，不会回退成系统 TCP。
- 默认域名通过宿主解析器解析 IPv4；也可用 `streamSettings.sockopt.domainStrategy`
  选择 Xray DNS，例如 `ForceIPv4`。不支持自定义 Happy Eyeballs 参数。
- 指纹出站只支持普通 TCP transport；拒绝链式 `dialerProxy`、`sendThrough`、mux、
  transport TLS/REALITY、finalmask、TCP transport headers 和其他 sockopt。
  用户连接内的 HTTPS/TLS 不受这个限制。
- egress 网卡由宿主路由决定；自动模式自行准备所需的接口转发和 NAT。
- 共享 gVisor 库默认 native；原有 WireGuard 和 TUN 入站也显式选择 native。
  已通过真实 WireGuard 隧道 TCP/UDP、原有 TUN 入站 TCP/UDP 回归；未做吞吐基准。
- 外层若终止 TCP 再重新连接，最终指纹仍由外层决定；此次验收只比较本机发出的 SYN。

## 构建与测试

`go.mod` 用 `replace gvisor.dev/gvisor => ./third_party/gvisor` 指向提取出的网络库。
网络库源码已包含在仓库内，克隆本仓库即可构建；运行二进制不需要源码。
构建需要 Go 1.27，使用 Go 工具链自动下载功能时应允许联网。

```bash
bash scripts/build-fingerprint-release.sh
```

修改 protobuf 后重新生成（正常构建不需要 protoc）：

```bash
protoc --go_out=. --go_opt=paths=source_relative proxy/freedom/config.proto
```

本地端到端测试需要 root、`ip`、`tcpdump`、`curl`、Python 3 和 `/dev/net/tun`：

```bash
XRAY_FP_GO="$(command -v go)" python3 testing/fingerprint/e2e.py dist/xray-fingerprint
```

自动模式有独立的离线测试（测试工具还需要 `nft` 命令，但 Xray 本身不需要）：

```bash
python3 testing/fingerprint/auto_e2e.py dist/xray-fingerprint
```

它在两个临时网络命名空间内运行 Xray 和接收端，以关闭全局转发、管理员设置
FORWARD 默认 DROP 为起点，只给 Xray 一个指纹选项。接收端抓包验证 NAT 后的
三种 SYN 指纹、源地址和校验和，覆盖并发实例、正常清理、主进程 SIGKILL、
启动中途失败、子进程也被杀后的恢复、路由表地址冲突和地址池耗尽回滚。
Xray 的 PATH 被设置为空工具目录，验证运行时不依赖网络管理命令。
测试不会修改宿主网络规则，报告在 `testing/fingerprint/artifacts/automatic/`。

测试使用临时 `10.204.237.0/28` 内的三个 TUN 和本机 HTTP 服务，不访问公网，
不修改全局 forwarding/防火墙，结束后删除临时设备。
它通过 SOCKS 发起 IP/域名请求及并发连接，传输并核对 256 KiB 数据，检查三种
SYN 的窗口、选项顺序、MSS、WS 和 TCP 校验和，并测试 UDP 原路径、未启用指纹的
freedom、finalRules 阻断、关闭重开和文件描述符释放。提供 `XRAY_FP_GO` 时，
还在 race detector 下测试重复关闭和活动连接中断。

抓包、日志和报告写入 `testing/fingerprint/artifacts/`。

## 共享网络库与可复现来源

WireGuard、TUN 入站和 freedom 共享唯一的 `gvisor.dev/gvisor` 模块，没有再嵌入第二份网络栈。
模块版本与源码提交一致，默认 native；三个自定义模板在独立栈实例上选择。
WireGuard 原本通过加密隧道搬运网络包，TUN 入站原本就从接口收包；普通 freedom 则只有宿主 TCP socket。
因此自定义 freedom 需要额外的报文出口，本实现自动创建内部 TUN/NAT。它复用同一 TCP/IP 库，
但不能复用一个并不存在的 WireGuard 隧道。无需使用者手动配置，仍需要操作系统授权相关网络操作。

`third_party/gvisor-source.json` 固定上游提交、Bazel 版本和补丁哈希。
`third_party/gvisor-export.sha256.json` 记录全部导出文件；构建先离线校验来源一致性。
正常构建不需要 Bazel。维护者需要重新导出时：

```bash
python3 scripts/check-gvisor.py
# 需要 Git、Bazel 8.3.1 及网络；不带 --update 时重新生成并比较
python3 scripts/update-gvisor.py --bazel /path/to/bazel
# 修改补丁并确认来源后更新导出源码与清单
python3 scripts/update-gvisor.py --bazel /path/to/bazel --update
```

已实际重新运行导出并核对全部 526 个文件。替换的 gVisor 版本仍较原版 Xray 的依赖更新；
native 保留该版本原生行为，并不意味着恢复旧版本全部内部实现。
