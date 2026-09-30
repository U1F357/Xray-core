# 指纹出口的随机 TCP 握手延迟（fp-v0.5.0）

在 freedom 的 `settings` 中配置：

```json
{
  "protocol": "freedom",
  "settings": {
    "tcpFingerprint": "auto",
    "tcpECN": "auto",
    "tcpHandshakeDelay": {
      "minMs": 80,
      "maxMs": 120
    }
  }
}
```

也支持固定的 `windows`、`macos`、`linux` 指纹。此功能只作用于使用自定义
gVisor 的 TCP 出口，不作用于普通系统 TCP 出口、UDP 或入口连接。

- 默认关闭；省略配置或两端均为 0 即关闭。
- `minMs`、`maxMs` 为非负整数毫秒，要求 `0 <= minMs <= maxMs <= 10000`。
  两端相等表示固定延迟，例如 `100/100`；不同则每次拨号在闭区间内均匀抽取整数。
- 从收到目标的第一个 SYN-ACK 起计时，到期后交给 gVisor，由栈正常发送第三次
  握手 ACK，随后上层继续发送 ClientHello 或其他数据。不是在发出 SYN 前等待。
- 每连接独立计时；共享 TUN 读包循环不会等待该计时器。等待期间重复 SYN-ACK
  共用同一截止时间，不重新抽样或累加延迟；每连接最多暂存 8 包、65535 字节，
  超出部分丢弃，由 TCP 正常重传恢复。
- 建连后的 TLS 数据、普通 ACK、重传 SYN-ACK 和 RST 不添加此延迟。RST 在等待
  期间也直接交给栈。取消、拨号超时或关闭 core 时清理待交付报文。
- IPv4、IPv6 均支持；可解析常见 IPv6 扩展头。分片 SYN-ACK 不在该调度器内
  重组，会直接交给 gVisor，因而不保证对分片握手施加延迟。

INFO 日志的 `TCP handshake delay: selectedMs=... target=...` 表示该次拨号
抽取的延迟，不是实际端到端 RTT；操作系统调度可能使实际交付更晚。

这会增加连接建立时间，并影响 TCP 栈测得的初始 RTT。数值过大还可能触发
SYN/SYN-ACK 重传或 ECN 回退，因此建议从几十至一百多毫秒开始测试。
此功能仅调整时序，不保证消除 TCP 终止、多跳代理或网络路径产生的所有特征。
不把该配置放进 VLESS 元数据，避免中转逐跳自动叠加；只在需要延迟的 freedom
出口上显式配置。

发布测试使用 IPv4/IPv6、三平台 × 三 ECN 模式的九条并发 TLS 连接，在目标侧
抓包核对 SYN-ACK → ACK 延迟、ACK → ClientHello 间隔和后续数据 ACK，另有
队列上限、取消、元组复用及竞态测试。
