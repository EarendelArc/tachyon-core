# Tachyon Core Alpha VPS 测试计划

本文把真实 VPS relay 测试整理成可重复执行、可回传结果的清单。Tachyon Core
仍处于 alpha 阶段，不是 stable 或生产完成版本。

## 范围

本计划用于在真实 VPS 上验证 Tachyon Core server relay，并为客户端 alpha 测试收集
可分享的诊断信息。内容包括服务端部署、安全 relay ACL、本地 smoke、VPS 验收，
以及需要脱敏回传的输出。

本计划不用于验证客户端 TUN 接管、系统代理行为或完整生产可用性。

## VPS 前置条件

- Debian 或 Ubuntu VPS，具备 shell 和 `sudo` 权限。
- 在宿主防火墙和云厂商安全组中放行 Tachyon server 监听端口的入站 UDP，例如
  UDP `443` 或另一个明确端口。
- VPS 到目标游戏服务器的出站 UDP 可达。
- 域名和证书只有在你的部署方案需要时才准备。基础 TGP relay 路径使用 UDP 和
  PSK，本身不要求 TLS 证书。
- 私有 `tgp.auth.psk`，由安装脚本生成或由安全密钥生成器生成。把它当作密码处理，
  不要粘贴到 issue、聊天、日志或截图中。
- 一组很小且明确的游戏 UDP 目标，用于 `server.relay.allowed_targets`。

## 选择 `allowed_targets`

`server.relay.allowed_targets` 是 relay allow-list，只应描述这台 VPS 可以转发到的
真实游戏 UDP 目标。

较好的示例：

```text
cidr=198.51.100.0/24,ports=27015-27050
domain=game.example.com,ports=27015
domain=region1.game.example.com,ports=7000,7001,7002
```

选择规则：

- 优先使用该游戏、该区域官方或已确认的最小 CIDR 或域名范围。
- 始终填写明确的 UDP 端口或端口范围。
- 不同游戏或区域尽量分成不同规则，方便定位问题。
- 如果暂时不知道目标，保持 `allowed_targets` 为空，接受安全 deny-all 状态，等确认后再填写。

禁止：

- `0.0.0.0/0` 或 `::/0` 这类通配全网目标。
- 任何可能转发到整个互联网的 open relay 形态。
- 省略 `ports`。
- 把订阅代理节点主机直接复制进 `allowed_targets`，除非它确实是游戏 UDP 目的地。

## VPS 前本地 Smoke

在 `tachyon-core` 仓库运行：

```bash
bash scripts/smoke-tgp-relay.sh
```

这是纯本地 smoke。它只绑定临时 `127.0.0.1` UDP 端口，检查 PSK 握手、缺失/错误
PSK 拒绝、ACL allow/deny、默认 deny-all、通配目标拒绝，以及 echo-like UDP relay
往返。

它不会使用你的 VPS、云安全组、真实客户端、真实游戏服务器、TUN、路由、防火墙、
systemd、Docker 或系统代理设置。通过本地 smoke 只能说明 relay 逻辑基本正常，
不能证明 VPS 可达。

## 裸机部署路径

在 VPS 上运行：

```bash
sudo bash scripts/install-server.sh --port 443 \
  --allow-target 'cidr=198.51.100.0/24,ports=27015-27050'
```

为了让 alpha 测试可复现，建议传入明确 release tag，而不是依赖会变化的 latest：

```bash
sudo bash scripts/install-server.sh --version v0.1.0-alpha.15 --port 443 \
  --allow-target 'domain=game.example.com,ports=27015'
```

安装后：

1. 确认 VPS 防火墙和云安全组允许配置监听端口的入站 UDP。
2. 把服务端配置中生成的 `tgp.auth.psk` 复制到 Prism 的 Tachyon server profile。
3. 不要把 PSK 回传给项目。

## Docker 部署路径

在 VPS 上运行：

```bash
sudo TACHYON_ALLOWED_TARGETS='domain=game.example.com,ports=27015' \
  bash scripts/install-server-docker.sh --version v0.1.0-alpha.15 --port 443
```

Docker 路径会把下载得到的静态 `tachyon-core` 二进制挂载进
`debian:bookworm-slim` 容器，不要求 GHCR 镜像。

安装后同时检查宿主 UDP 暴露和容器状态。云安全组仍必须允许入站 UDP 到发布的服务端口。

## 部署后验收

根据部署类型运行只读验收脚本：

```bash
sudo bash scripts/verify-server.sh
sudo bash scripts/verify-server.sh --mode docker
```

如果是在服务启动前检查复制出来的二进制和配置：

```bash
bash scripts/verify-server.sh --mode config --binary ./tachyon-core --config ./server.json
```

`verify-server.sh` 会验证二进制和配置，按需检查服务或容器状态，汇总
`allowed_targets`，检查 UDP 监听，并在输出日志尾部时隐藏 PSK。它不会修改防火墙规则、
云安全组、Docker、systemd、包过滤器、路由或代理设置。

## 支持包

需要协助排查时，优先生成只读支持包，而不是手工复制多段命令输出：

```bash
sudo bash scripts/collect-server-diagnostics.sh
sudo bash scripts/collect-server-diagnostics.sh --mode docker
```

脚本会在当前目录生成带时间戳的 `tachyon-server-diagnostics-*.tar.gz`。如果聊天或邮件
不方便发送压缩包，可以生成单个文本报告：

```bash
sudo bash scripts/collect-server-diagnostics.sh --format txt
```

支持包包含 OS/kernel、Tachyon Core 版本、配置校验摘要、`allowed_targets` 摘要、
服务或容器状态、UDP 监听状态、脱敏后的 journal 或 Docker 日志尾部，以及脱敏后的
`verify-server.sh` 摘要/输出。它只读收集信息，不会启动、停止、重载或重新配置
systemd、Docker、防火墙、iptables、nftables、路由或代理设置。

脚本会隐藏常见 PSK、token、UUID、private key、password、订阅/代理 URL 形式，
但回传前仍必须人工检查生成文件。

## 本地 Smoke 与 VPS Smoke 的区别

- 本地 smoke：`scripts/smoke-tgp-relay.sh`，只在 loopback 上运行，验证 relay 行为，
  不改宿主网络。
- VPS 验收：`scripts/verify-server.sh`，在已部署服务器上运行，验证安装后的
  二进制、配置和监听状态。
- 真实客户端 smoke：Prism 使用 Tachyon server profile 连接 VPS，验证客户端配置、
  启动、日志、游戏模式或手动规则。
- 真实游戏 smoke：真实游戏发出匹配 profile 和 `allowed_targets` 的 UDP，这是本地
  smoke 无法替代的现场结果。

## 需要回传的输出

请回传：

- VPS OS 和版本，例如 Debian 12 或 Ubuntu 24.04。
- 部署路径：裸机或 Docker。
- 去掉 PSK 后的完整安装命令。
- 完整验收命令。
- 人工检查过敏感信息后的 `tachyon-server-diagnostics-*.tar.gz` 或 `.txt` 支持包。
- 云安全组和宿主防火墙是否允许 `server.listen` 端口的入站 UDP。
- 如有需要可脱敏 `server.listen` 地址，但保留 UDP 端口。
- `allowed_targets` 摘要，保留足够排查问题的 CIDR/domain 和 ports。
- 如果和 Prism 联测，提供 Prism 版本和 Core tag。
- 去掉密钥后的客户端错误文本或截图。

不要回传：

- `tgp.auth.psk`。
- 完整私有订阅 URL、代理 URL、token、UUID、password、private key 或 API key。
- SSH key、账号 ID、带有无关密钥的云控制台截图，或完整公私有基础设施清单。

公开发布前仍应人工检查输出，即使诊断脚本会隐藏常见敏感信息形态。
