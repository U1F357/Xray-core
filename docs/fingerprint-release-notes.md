本 fork 的全部自定义修改、测试、文档和发布流程完全由 AI（OpenAI Codex）实现。上游 Xray-core、gVisor、基础镜像及地理数据由各自作者开发；本项目不是 XTLS 官方发行版。

本次发布：

- 程序文件、进程名、版本显示和帮助改为 xrui；保留配置文件名、JSON 字段、环境变量和内部 API。
- 新增 Linux amd64 容器镜像 `ghcr.io/u1f357/xrui:fp-v0.2.1` 和 `latest`。配置目录为 `/usr/local/etc/xrui/`。
- 镜像与普通压缩包均内置固定版本并经 SHA256 校验的 geoip.dat / geosite.dat，以及来源和许可证。
- Docker 只读 /proc/sys 下，转发已由容器 sysctl 开启时不再重复写入；指纹出口仍需 NET_ADMIN、TUN 和容器转发设置。
- 保留三种 TCP 指纹模板、自动选择、可信 VLESS 多跳类别传递与 INFO 日志。节点间转发仍不支持出站 Mux。

附件：

- `xrui`：静态可执行文件。
- `xrui-linux-amd64.tar.gz`：程序、geodata、配置示例和文档。
- `xrui-docker-linux-amd64.tar.gz`：`docker load -i` 可直接导入的镜像。
- `IMAGE_DIGEST` 与 `SHA256SUMS`：镜像 digest 和下载校验。

Docker 配置及权限详见仓库及压缩包中的 `docs/docker.zh-CN.md`。发行前执行代码测试、race 检查、SYN 抓包及真实容器自动指纹出口测试。
