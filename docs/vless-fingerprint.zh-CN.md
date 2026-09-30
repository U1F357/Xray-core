# VLESS 多跳传递 TCP 指纹类别

此扩展完全由 AI（OpenAI Codex）实现，不是 XTLS 官方协议扩展。默认不发送、不信任远端类别。只传递 `windows`、`macos`、`linux`、`unknown` 四种状态，不传用户地址或完整 SYN。

路径：用户 → 入口（读取用户 SYN）→ VLESS 中转（传递类别）→ VLESS 出口 → freedom auto。
中转节点只转发元数据，无需 TUN 或 root；最后的 freedom 指纹出口仍需要 Linux、root、TUN 和 nftables。

## 配置

以下片段需合并到各节点现有配置，继续使用自己的地址、UUID、TLS/REALITY 和路由设置。可运行的本地三节点示例在 `testing/fingerprint/example-chain/`；它们仅监听本机，正式部署应替换认证及传输配置。

第一入口的入站顶层设置：

```json
"tcpFingerprint": { "source": "syn" }
```

它只认实际观测的 SYN，忽略客户端在 VLESS 中携带的声明。适用于 TCP/raw 入站，包括 TLS/REALITY 包装；无法观测时为 unknown。

入口及每个继续中转的 **VLESS 出站 settings** 增加：

```json
"tcpFingerprintForward": true
```

对应出站必须关闭 `mux.enabled`。该开关按路由实际选择的出站生效，仅为 TCP 请求写入类别，UDP 保留原路径。不要配置 reverse；运行时也拒绝转发 Mux/反向命令。

每个后续节点的 **VLESS 入站**，为上一跳配置独立账户并设置 email：

```json
{
  "protocol": "vless",
  "settings": {
    "clients": [{
      "id": "请替换为上一跳专用的 UUID",
      "email": "entry@relay"
    }],
    "decryption": "none"
  },
  "tcpFingerprint": {
    "source": "vless",
    "trustedUsers": ["entry@relay"],
    "onMissing": "unknown"
  }
}
```

`trustedUsers` 精确匹配本节点认证账户的 email；不是客户端任意填写的邮件字段。不能为空或使用 `*`。独立账户应仅交给可信上一跳，避免与普通终端用户共用。TLS/REALITY 用来保护链路；类别声明本身不是操作系统身份证明。

最后节点的 freedom 出站：

```json
{
  "protocol": "freedom",
  "settings": {
    "tcpFingerprint": "auto",
    "tcpFingerprintFallback": "linux"
  }
}
```

固定模式仍优先使用固定模板；只有 auto 按会话类别选择。

## 入站策略和缺失处理

| 入站 source | 行为 |
| --- | --- |
| 未配置 | 保持自动采集行为：实例启动时存在 auto freedom 或开启转发的 VLESS 出站，就在支持的 TCP 入站采集；忽略远端声明 |
| `syn` | 主动采集当前连接 SYN，忽略远端声明 |
| `vless` | 仅接受 trustedUsers 内已认证账户的有效扩展 |
| `off` | 不采集、不采用远端声明；本入站类别为 unknown |

source=vless 的 `onMissing` 默认 `unknown`。字段缺失、无效、未知版本或账户不受信任时保持 unknown，最后使用 freedom fallback。可显式设 `syn` 改用当前连接的 SYN，但它代表上一跳机器，而非原始用户。

上一跳明确发送 `unknown` 时，即使 onMissing=syn 也保留 unknown，不会把上一跳机器误当成用户。每一跳都应显式启用接收策略和出站转发；中途遗漏会丢失类别。新增 auto/forward 出站若通过动态 API 添加，需重启实例才能让原有未启用采集的监听器开始采集；显式 source=syn 的监听器不受此限制。

## Mux 和原版兼容性

用户到第一入口可以使用入站 Mux：逻辑流继承该物理 TCP 的观测类别。**节点间启用 tcpFingerprintForward 的 VLESS 出站不能启用 Mux**，配置时会报错。VLESS Addons 属于整条物理连接，无法为同一 Mux 连接中不同用户的逻辑流分别携带类别。这一版本不改变 Mux 帧格式，也不实现按类别隔离连接池。

扩展使用 VLESS 请求 Addons 的 protobuf bytes 字段 65001，内容为 `XTFP` + 版本字节 `01` + 类别字节（0 unknown、1 windows、2 macos、3 linux），总计六字节。字段号是本 fork 私有实验编号，未来若与上游冲突需要迁移。序列化后的 Addons 长度不得超过一字节长度前缀所能表示的 255。

Addons 解析不依赖 REALITY；普通 VLESS、TLS 和 Vision 都可携带。原版 protobuf 解码器跳过未知字段，正常处理请求，但原版中转重新生成 VLESS 请求时会丢弃类别。原版客户端连接本 fork 也可正常传输；没有类别时按上述缺失策略处理。不要把本 fork 的新增配置直接交给原版并期待其实现功能。

已用固定上游提交 `3519dfecbd65022ba71d9bc73e94063d0cbc8636` 的二进制测试双向互通：普通 VLESS、TLS、Vision over TLS，均通过 256 KiB 负载验证。三节点传播也覆盖这些传输。尚未完成 REALITY 握手端到端测试，不能把线格式兼容性等同于所有版本、所有传输组合均已验证。

## 日志和验证

设置 `log.loglevel` 为 `info`：

```text
TCP fingerprint inbound: detected=windows peer=...
TCP fingerprint VLESS outbound: category=windows forwarding=true
TCP fingerprint VLESS inbound: status=accepted source=vless category=windows user=entry@relay
TCP fingerprint freedom: mode=auto detected=windows selected=windows fallback=false source=vless template=64240_2-1-3-1-1-4_*_8 dialing=tcp:...
```

接收状态包括 accepted、missing、invalid、untrusted。日志表示所选类别和拨号尝试，最终出口是否被外层代理改写仍需在相应链路抓包确认。

```bash
# 无需 root 或 runsc；第二个参数可选，用于与原版双向互通
python3 testing/fingerprint/vless_interop.py dist/xrui /path/to/upstream-xray
# root + 三种自定义 runsc：三层 Xray、入站/最终出口抓包
python3 testing/fingerprint/multi_hop_e2e.py dist/xrui
```
