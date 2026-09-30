# TCP ECN 模板、入口识别与 VLESS 传递

本功能使用自定义 gVisor TCP 栈，需与 freedom 的 `tcpFingerprint` 一起配置。
它识别并转发客户端 **SYN 请求的 ECN 模式**，不是对客户端系统版本的识别，
也不是入口 TCP 最终协商结果的证明。出口仍需与目标服务器独立协商。

## 配置

同时自动选择平台类别和 ECN 模式：

```json
{
  "protocol": "freedom",
  "settings": {
    "tcpFingerprint": "auto",
    "tcpFingerprintFallback": "linux",
    "tcpECN": "auto"
  }
}
```

固定 Apple 指纹并主动请求 AccECN：

```json
{
  "protocol": "freedom",
  "settings": {
    "tcpFingerprint": "macos",
    "tcpECN": "accecn"
  }
}
```

`tcpECN` 支持以下取值：

| 配置值 | 行为 |
| --- | --- |
| 省略或 `template` | Windows、macOS 使用经典 ECN；Linux 不主动请求 ECN |
| `auto` | 根据有效入口元数据选择；未知时使用选中平台的默认值 |
| `none` | 不主动请求 ECN |
| `classic` | 请求经典 ECN |
| `accecn` | 请求 AccECN；兼容经典 ECN 和不支持 ECN 的对端 |

平台和 ECN 是两个独立选择。例如，`tcpFingerprint: "windows"` 与
`tcpECN: "auto"` 会固定 Windows 的窗口/选项布局，只跟随入口的 ECN 模式。
即使平台布局无法分类，仍可单独识别有效 SYN 上的 ECN 请求。

ECN 选项在每个 endpoint 的 Connect 前设置，建连后禁止修改；不会为 ECN
组合创建额外 TUN，也不会在并发拨号时修改共享栈的 ECN 参数。
普通未启用 `tcpFingerprint` 的 freedom、WireGuard 和 TUN 入站保持原有默认行为。

## 入口与中转

SYN 标志对应关系：

| AE / CWR / ECE | 元数据 |
| --- | --- |
| 0 / 0 / 0 | `none` |
| 0 / 1 / 1 | `classic` |
| 1 / 1 / 1 | `accecn` |
| 不可读取、格式错误或其他组合 | unknown |

AE 是一些抓包页面仍标为 NS 的位。`none` 与 unknown 不同：明确观察到没有 ECN
请求时，自动出口也不请求 ECN；unknown 才使用模板默认值。中间设备可能更改 SYN，
因此识别结果仅代表入口实际收到的报文。

沿用现有入站 `tcpFingerprint` 策略：首入口使用 `source: "syn"`；可信 VLESS
中转使用 `source: "vless"` 并设置 `trustedUsers`。`onMissing` 同样作用于 ECN
字段，且平台类别和 ECN 独立处理。显式传来的 unknown 不会被误替换为中转链路
自身的 SYN 特征。固定出口 ECN 配置不受传入声明覆盖。

VLESS 出站开启已有的 `tcpFingerprintForward: true` 即同时传递两项元数据。
平台字段 65001 的编码保持不变；ECN 使用独立的私有 protobuf bytes 字段 65002，
内容为 `XECN`、版本字节 1、模式字节（0 unknown、1 none、2 classic、3 accecn）。
这些字段不是上游分配的标准扩展。

原版 VLESS 可忽略未知字段；旧版自定义 core 仍可读取平台类别，但不会传递 ECN
模式。经过不支持该扩展的中转后，下游须按缺失元数据策略处理，不能保证模式继续保留。
转发仍要求关闭 VLESS 出站 Mux；不能让多个不同来源的流共享一个连接级声明。

日志中入口显示 `ecn`；VLESS 中转显示字段接受状态与来源；freedom 显示
`selected`、`source`、`fallback` 和平台。这里的选择表示出口请求的模式，
不等于目标服务器一定接受了该模式。

## 指纹和实现边界

Windows 经典 ECN SYN 使用 ECE+CWR 和 ECT(0)，对应用户提供的 Windows 样本；
Apple 经典 ECN SYN 使用 ECE+CWR 和 Not-ECT，对应提供的 macOS 样本；
Apple AccECN SYN 使用 AE+ECE+CWR 和 ECT(1)，对应提供的 iPhone 样本。
MSS 始终由有效 MTU 决定，不复制样本里的固定数值。

AccECN 实现以 RFC 9768 的 ACE 计数器反馈为核心；不实现可选的 AccECN 字节计数
TCP 选项，不宣称具备 Apple 的 L4S 拥塞控制算法。建立连接后的新数据使用 ECT(0)
和现有 Reno/CUBIC 拥塞响应；重传和纯控制包使用 Not-ECT。初始 SYN 上的 ECT(1)
不意味着后续数据采用 L4S。

实现必须处理协商/回退、握手特殊编码、CE 反馈、计数器回绕与陈旧 ACK、接收侧
反馈触发，以及拥塞窗口调整。仅设置 AE/ECE/CWR 而不维护协议状态不属于支持 AccECN。
这也不是对某一 Windows/macOS/iOS 版本完整 TCP 行为的复制。

参考：[经典 ECN（RFC 3168）](https://www.rfc-editor.org/rfc/rfc3168.html)、
[AccECN（RFC 9768）](https://www.rfc-editor.org/rfc/rfc9768.html)。
