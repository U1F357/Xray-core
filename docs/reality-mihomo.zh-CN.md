# mihomo 与 REALITY 入站兼容性

`fp-v0.2.0`、`fp-v0.2.1` 使用的上游 REALITY 依赖是
`8cdf7bf9c7f0`。该基线要求 ClientHello 在可选的 X25519 之前携带
X25519MLKEM768 key share；mihomo 默认移除它，会报
`REALITY authentication failed`。关闭 TCP 指纹采集不会解决该问题，
同基线的原版 Xray 也有相同行为。

在 mihomo 的对应 VLESS 节点中设置：

```yaml
client-fingerprint: chrome
reality-opts:
  public-key: "原来的公钥"
  short-id: "原来的 short-id"
  support-x25519mlkem768: true
```

其余 server、port、uuid、servername、flow 保持原有正确配置。
`client-fingerprint` 是 TLS 指纹，与本项目 freedom 的 TCP 指纹选项不同。
不要使用不带该 key share 的旧 TLS 模板；本次 mihomo v1.19.31 测试中，
firefox/safari 即便设置该开关仍不能连接这个服务端基线，chrome 可以。

该配置从 mihomo **v1.19.9（含）**开始支持：
[发布说明](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.9)，
[引入提交](https://github.com/MetaCubeX/mihomo/commit/5cf0f18c29a0bb791fafa01a74a85eb9148af6be)。
本次实际运行验证的客户端为官方 stable v1.19.31，未逐个验证所有旧版本。

这个开关并不要求 REALITY 的 target 网站支持 ML-KEM。测试中的本地 nginx
只允许 TLS 1.3 + X25519，仍可完成 REALITY 认证和 256 KiB HTTPS 传输。
原有目标网站的 TLS/SNI 等适配条件仍需要满足；若原先的目标已正常工作，
通常只需调整 mihomo 客户端配置，无须为此更换 target 或密钥。

## 本地复现

需要 nginx、openssl、curl 和独立的 mihomo 二进制。所有测试流量走回环地址，
nginx 使用独立配置和临时证书，不改变系统 nginx 服务或系统证书信任。

```sh
REALITY_MLKEM=1 REALITY_FINGERPRINTS=chrome REALITY_RUN=compatible \
python3 testing/fingerprint/reality_interop.py /path/to/mihomo current=dist/xrui
```

将 `REALITY_MLKEM=0` 可复现默认配置的认证失败（脚本非零退出为预期）。
可继续传入 `release=/path/to/released-binary stock=/path/to/stock-xray`
作版本对照。名称 `stock` 会跳过自定义入站指纹配置。
测试覆盖普通 VLESS、Vision、入口指纹采集开/关及 HTTPS 正文完整性；
日志和 JSON 结果写入 `testing/fingerprint/artifacts/reality-interop*`。
