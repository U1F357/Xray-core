# 可选入口 RTT 自动采样（fp-v0.7.0）

默认关闭。首入口在接受原生 TCP 连接时读取 Linux `TCP_INFO.tcpi_rtt`，在 TLS/REALITY
包装和应用层处理之前保存一次。无需修改普通 Xray 客户端，也不主动发送探测报文。
微秒值随会话保存；freedom 将其向上取整到毫秒，作为这一连接固定的最小确认年龄。

## 单节点

在真正接受远端用户连接的入站对象中加入：

```json
"tcpFingerprint": {
  "source": "syn",
  "rtt": true
}
```

freedom 的 `settings` 示例：

```json
{
  "tcpFingerprint": "auto",
  "tcpFingerprintFallback": "windows",
  "tcpECN": "auto",
  "tcpAckDelay": {
    "continuous": true,
    "autoRTT": {
      "fallbackMs": 100,
      "minMs": 0,
      "maxMs": 1000
    }
  }
}
```

平台指纹不必使用 auto，也可固定 windows/macos/linux。`continuous: true` 全连接生效；
省略时保留默认 10000 ms 窗口，也可指定 `windowMs`，不能和 continuous 同时指定非零窗口。

## 多级 VLESS

第一入口使用上面的 `source: "syn", rtt: true`。每级发送节点的 VLESS 出站
`settings` 保留 `tcpFingerprintForward: true`。每级接收节点在入站对象显式开启：

```json
"tcpFingerprint": {
  "source": "vless",
  "trustedUsers": ["previous-hop@example.test"],
  "onMissing": "unknown",
  "rtt": true
}
```

`trustedUsers` 必须对应这一入站已认证用户的 email，不能用通配符。
该策略同时控制指纹、ECN 和可选 RTT 元数据。出口使用同样的 freedom 配置。

RTT 独立存放在私有 Addons 字段 65003：`XRTT`、版本字节 1、4 字节大端微秒值。
0 表示明确未知。仅在已开启转发且本地有 RTT 元数据策略的 TCP 请求中发送；
不改变 VLESS 的流标识和数据边界。普通上游服务端忽略未知字段，普通客户端无需发送它。
所有参与保留元数据的中转必须支持本扩展并显式开启；普通中转会丢失元数据，最后出口使用回退值。
Mux 仍不能启用 `tcpFingerprintForward`，不把多个逻辑流误当成独立物理连接采样。

缺失、非法或不可信字段默认变为未知，不能用近端中转 RTT 冒充原始入口 RTT。
显式设置 `onMissing: "syn"` 才允许回退到当前连接的本地观测；收到有效的“明确未知”
仍保持未知。某级未开启 `rtt` 不会使用收到的 RTT 字段。**不会累加中转链路 RTT**。

## 手动覆盖与上下限

- `autoRTT: {}` 等价于 `fallbackMs: 100, minMs: 0, maxMs: 1000`。
- 要求 `0 <= minMs <= fallbackMs <= maxMs <= 1000`。观测超界时截断；0/不可用采用回退值。
- 上下限属于 `autoRTT` 对象时是自动估计的限幅；不是随机区间。
- 如果 `tcpAckDelay` 本层显式写了 `minMs` 或 `maxMs`，则**手动模式优先**，
  即使同一对象还有 `autoRTT`。手动方式仍要求 `0 <= minMs <= maxMs <= 1000`。
- 手动 `minMs: 100, maxMs: 100` 固定100 ms；`80, 120` 随接收数据段随机抽样。
  手动上下限均为0关闭 ACK 调度；此时若保留旧 `tcpHandshakeDelay`，旧握手延迟仍独立有效。
- 只开启入口采样不会自动启用出口延迟；自动采样和自动使用都需要显式配置。

## 日志

INFO 日志包含入口 `TCP RTT inbound: rttUs=... source=tcp_info`，VLESS 接收/转发
的 `rttUs`、来源，以及出口 `TCP ACK timing selection: mode=autoRTT source=...
observedUs=... selectedMs=...`。`source=fallback` 表示使用本地回退值。
每条连接独立固定，运行中不根据共享栈或其他用户的新测量改变。

## 能测到什么

只测到入口 TCP 对端的初始平滑 RTT。原生 TCP、TCP+TLS、TCP+REALITY 的 Linux
入口可用；IPv4/IPv6 均支持。非 Linux、WebSocket/HTTP 等其他传输、PROXY protocol、
非原生 socket、失败/零采样没有本次支持，使用回退值。不要在本机浏览器连接的
loopback SOCKS 入站估算远端用户 RTT。

如果前置代理终止了 TCP，测到的是前置代理的 RTT；不会自动恢复原始用户距离。
初始握手重传、拥塞和内核的采样可用性会影响结果。这是一次初始估计，不是实时
带宽/抖动探测，也不读取客户端私有状态。之后客户端线路变化不会更新当前连接。

目标网站测到的 TCP RTT 预期接近“出口实际 RTT + 最小确认年龄”，不是精确的总 RTT
控制器。客户端/中转往返更慢时，无法让 TLS 回复提前；过高估计仍可能增加应用等待。
本次改为按服务器数据首次到达时间约束 ACK，抵扣客户端回复已经经历的等待，
不再给每个 TLS 回复完整追加一次延迟。持续模式仍会影响拥塞控制和吞吐。
详细行为见 [ACK 调度](tcp-ack-delay.zh-CN.md) 和 [时序设计](tcp-timing-design.zh-CN.md)。
