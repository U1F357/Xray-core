# xrui 容器镜像

镜像：`ghcr.io/u1f357/xrui:fp-v0.7.0`，同时发布 `latest`。当前仅 Linux amd64。
程序文件和进程名是 `xrui`，镜像默认读取 `/usr/local/etc/xrui/` 下的配置。
JSON 字段和环境变量沿用 Xray，包括 `XRAY_LOCATION_ASSET`。

镜像及普通 Release 压缩包均内置 `geoip.dat`、`geosite.dat`。镜像内数据位于
`/usr/local/share/xray/`，来源为 Loyalsoldier/v2ray-rules-dat；提交号和 SHA256 固定在
`scripts/geodata-source.json`，构建时校验。它们是此发行版的数据快照，不会在启动时自动更新。
可通过只读挂载替换数据文件，或用原有 `XRAY_LOCATION_ASSET` 指定数据目录。
第三方许可证和来源记录随镜像提供。

## 运行

将自己的配置放入当前目录的 `config/`。容器入站需要监听 `0.0.0.0` 才能经端口映射访问。
下面演示本机 SOCKS 1080；实际部署按配置调整端口及认证。

```bash
docker pull ghcr.io/u1f357/xrui:fp-v0.7.0
docker run -d --name xrui --restart unless-stopped \
  --cap-add=NET_ADMIN --device=/dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 \
  --sysctl net.ipv4.conf.default.forwarding=1 \
  -p 127.0.0.1:1080:1080 \
  -v "$PWD/config:/usr/local/etc/xrui:ro" \
  ghcr.io/u1f357/xrui:fp-v0.7.0
```

示例 `config/config.json`：

```json
{
  "log": { "loglevel": "info" },
  "inbounds": [{
    "listen": "0.0.0.0", "port": 1080,
    "protocol": "socks", "settings": { "auth": "noauth" }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": { "tcpFingerprint": "auto", "tcpFingerprintFallback": "linux" }
  }]
}
```

Docker 默认把 `/proc/sys` 挂载为只读。上面的两个 sysctl 在容器创建时预先开启转发，
包括后续动态创建的内部 TUN；程序发现已开启时不重复写入。这些设置只影响独立的容器
网络命名空间，不更改宿主全局转发。不要给这条命令添加 `--network host`。
宿主仍需支持 TUN、nftables/NAT/conntrack。镜像默认为 root，以支持自动指纹网络管理；
仅作普通代理或 VLESS 类别中转时，可不授予 NET_ADMIN/TUN、不设置上述 sysctl，
并按配置文件访问权限选择 `--user 65532:65532`。

```bash
docker logs xrui
docker exec xrui /usr/local/bin/xrui version
docker stop xrui
```

镜像使用 distroless 静态基础镜像，含 CA 证书，不含 shell、ip、nft 等命令；
自动指纹功能也不依赖这些外部命令。启动会自动创建内部网络，正常停止时清理。
容器外若有终止并重建 TCP 的代理，仍可能覆盖最终指纹。

## IPv6 出口

`fp-v0.7.0` 镜像已包含 IPv6 指纹出口。
双栈 Docker 网络及容器 IPv6 转发参数见 [IPv6 使用说明](ipv6-fingerprint.zh-CN.md)。

## 离线导入

Release 附带 `xrui-docker-linux-amd64.tar.gz`，无需访问 GHCR 即可导入：

```bash
sha256sum --ignore-missing -c SHA256SUMS
docker load -i xrui-docker-linux-amd64.tar.gz
```

导入后的标签同样是 `ghcr.io/u1f357/xrui:fp-v0.7.0`。镜像 digest 记录在 Release 的
`IMAGE_DIGEST`，可用于固定部署版本。新建 GHCR 包可能默认私有；若匿名拉取被拒绝，
可使用上述公开 Release 镜像包，或登录具有该包读取权限的 GitHub 账户。

## 构建和验证

```bash
bash scripts/build-fingerprint-release.sh
bash scripts/build-fingerprint-image.sh xrui:local local
sudo python3 testing/fingerprint/docker_smoke.py xrui:local
```

镜像复用发行版已测试的同一份静态二进制。发布 Actions 必须先通过代码测试、抓包测试及
容器测试（包括实际加载 geosite/geoip、自动 gVisor 出口和停止清理），再推送镜像和发布附件。
所有自定义实现与此发布流程完全由 AI（OpenAI Codex）完成；上游项目及数据作者的声明保留。
