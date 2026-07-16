# Tachyon Core

[English](README.md)

Windows 路由以 Wintun 的稳定 LUID/interface index 和精确目标属性作为身份；接口重命名不会改变 ownership。只有同步 IP Helper Create 明确成功（包括成功后观察到 context 取消的 typed committed 结果）才建立 ownership；普通错误后的匹配 readback 不会认领并发对象。Delete 明确成功后立即放弃 ownership，之后重建的同属性路由不会被后续 `Close` 删除。崩溃恢复 journal 位于机器级受保护的 `ProgramData\\Tachyon` 目录，仅允许 SYSTEM/Administrators，且在删除路由前拒绝 reparse、越界路径、不可信 owner/DACL 和损坏内容。

Core 在创建 TUN 和安装路由前只解析一次 Relay，并 pin 获批的 `IP:port` 集合。拨号、重连和迁移复用同一 validator，安装路由后不再依赖系统 DNS。空 `game_routes` 表示“无额外游戏目标路由”，并不表示没有 OS 状态；Windows TUN 地址和 MTU 都显式使用 `store=active`。

## 选择性游戏路由语义

- Windows 客户端只会把 `client.tun.game_routes` 中显式填写的目标 CIDR 事务性地指向 Tachyon TUN；初始化失败、正常停止或安装超时都会按逆序回滚。Core 永远不会退化为全局默认路由。
- Linux 与 macOS 当前会在创建 TUN 之前拒绝非空 `game_routes`，直到对应平台具备同等安全的事务路由实现。
- `game_routes` 是目标 CIDR 路由，不是进程路由。同一 CIDR 上的游戏与非游戏程序都会先进入 TUN；PID 和游戏规则只能在接管后决定 TGP 或 fail-closed，无法把非游戏包重新送回原生路径。因此 Prism 必须使用尽可能窄的游戏服务器 CIDR，界面也不得宣称真正的按进程隔离。
- Core 会在 TUN 和路由变更前一次解析 Relay；任何获批 endpoint 落入游戏 CIDR 都会导致启动失败。后续重连与迁移只使用启动时 pin 的 endpoint 集合，不再重新查询系统 DNS。

Tachyon Core 是 Tachyon 游戏协议的无头传输核心。它的角色类似 `xray-core`：它是一个独立网络核心，使用显式 JSON 配置，但协议目标是低延迟、低丢包的游戏 UDP 流量，而不是通用 TCP 代理。

```bash
# 只验证配置，不启动守护进程
tachyon-core validate --config client.json

# 启动核心守护进程
tachyon-core run --config client.json
tachyon-core run --config server.json

# 检查正在运行的 Core 是否健康
tachyonctl health
tachyonctl health --addr 127.0.0.1:55123
```

## 设计边界

- Prism 负责订阅获取、订阅解析、节点选择、Xray 生命周期、Xray JSON 生成、游戏配置管理、启动器扫描和桌面端总控编排。
- Core 负责 Tachyon 协议传输：数据包接管、基于进程的游戏路由、TGP 客户端传输和 TGP 服务端 Relay 行为。
- Tachyon Core 内部没有 Xray 的运行时或编译期依赖。
- TCP 代理流量属于 Prism/Xray；UDP 游戏流量属于 Tachyon Core/TGP。
- 客户端 TUN 当前只支持 TGP-only：`auto_route=true`、`dns_hijack=true` 或
  `tgp_only=false` 会在配置校验阶段失败，因为 Core 尚无原生 direct/DNS 转发路径。
  OS 集成层必须只为候选游戏 UDP 目标安装选择性路由；Core 仍需要 TUN/Wintun 和
  相应权限来处理这些被选中的数据包。
- 客户端规则当前支持进程名、CIDR 和协议匹配；`domain`、`geoip` 在具备可确定的
  packet-path 实现前会直接校验失败。
- JSON 是 Core 的标准配置格式。早期 YAML 文件仅作为开发兼容格式保留。
- Core JSON 中的相对文件路径会以当前加载的配置文件所在目录为基准解析。

## 架构

```text
客户端模式
  OS 选择性游戏路由 -> TUN 设备 -> PID 追踪器 -> 路由引擎
    UDP 游戏流量 -> TGP 客户端会话
    direct 决策 -> fail-closed（不应被接管）

服务端模式
  UDP 监听器 -> TGP Relay -> 真实游戏服务器
```

## 实现状态

Tachyon Core 还不是 stable 或生产完成版本。协议和管道已经可以用于 alpha 集成。
客户端 TUN 自动路由和 DNS hijack 当前不受支持，并会被配置校验拒绝；Windows TUN
仍需要在真实 Windows 主机上以管理员权限创建适配器进行运行时验证。

| 领域 | 状态 |
| --- | --- |
| 统一 client/server CLI | 完成 |
| JSON 配置加载和生成 | 完成 |
| Core JSON 内嵌 Prism 游戏配置 | 完成 |
| 基于进程的路由配置 | 完成 |
| 本地 HTTP 路由桥兼容层 | 完成 |
| tachyonctl health CLI | 完成 |
| tachyon-core validate 干运行 | 完成 |
| Linux TUN 和 PID 追踪 | 完成 |
| Windows PID 追踪 | 完成 |
| macOS TUN | 完成 |
| Windows TUN | Alpha 动态 Wintun 后端 |
| macOS PID 追踪 | Alpha lsof/ps 后端 |
| TGP X25519 握手和 AEAD | 完成 |
| 多路径 transport adapter | 完成；接口发现和策略尚未接入 |
| 持久 TGP UDP Relay 会话池 | 完成 |
| Client TUN -> routing -> TGP writeback 测试 | 完成 |

## 开发

本仓库使用 `mise` 管理 Go。

```bash
mise install
mise exec -- go test ./...
mise exec -- go build ./...
mise exec -- go run ./cmd/tachyon-core generate-config --mode client > client.json
```

部署 VPS 前，可以先运行本地 TGP relay smoke：

```bash
bash scripts/smoke-tgp-relay.sh
```

它只使用临时 `127.0.0.1` UDP 端口，验证 PSK 握手、缺失/错误 PSK 拒绝、
client/server 配置到 TGP relay 的运行时接线、ACL allow/deny、默认 deny-all、
通配全网目标拒绝，以及 echo-like UDP relay 往返；不会启动 TUN，不会调用 Prism
或 Xray，也不会修改路由、防火墙、systemd、Docker 或系统代理状态。
本地 smoke 不能替代真实 VPS、真实客户端和真实游戏 UDP 验证。

## 服务端部署

```bash
sudo bash scripts/install-server.sh --port 443 \
  --ssh-port 22 \
  --allow-target 'cidr=198.51.100.0/24,ports=27015-27050'

sudo TACHYON_ALLOWED_TARGETS='domain=game.example.com,ports=27015' \
  bash scripts/install-server-docker.sh --port 443
```

两种安装脚本都会从 `EarendelArc/tachyon-core` GitHub Releases 下载匹配的
Linux ZIP 资产。`--version latest` 会选择最新 release 条目，包括 alpha
预览版；如需可复现部署，可传入明确 tag，例如
`--version v0.1.0-alpha.15`。Docker 部署会把下载得到的静态
`tachyon-core` 二进制挂载进 `debian:bookworm-slim` 容器运行，不依赖 GHCR
镜像。

裸机安装脚本可以代管 ufw。脚本会先放行 Tachyon UDP 端口和 SSH TCP 端口，再启用
ufw；如果服务器 SSH 不是 22 端口，请传入 `--ssh-port PORT`，如果你使用云防火墙、
nftables、firewalld 或自定义主机防火墙策略，请传入 `--no-firewall` 并自行放行端口。
生成的 systemd 服务以 `tachyon` 用户运行，只保留 `CAP_NET_BIND_SERVICE`，系统目录只读，
仅日志目录保持可写。

Docker 安装脚本为了降低游戏 UDP 抖动，仍然有意使用 `network_mode: host`，避免 Docker
NAT/userland proxy 额外路径。compose 文件同时启用只读 rootfs、no-new-privileges、丢弃
默认 capabilities、仅恢复 `NET_BIND_SERVICE`、tmpfs 临时目录、健康检查和
`restart: unless-stopped`。Docker 脚本不会修改宿主机防火墙规则。

服务端 Relay 默认采用 fail-closed 安全策略。安装脚本会生成新的
`tgp.auth.psk` 并写入 `server.json`，需要把该 PSK 复制到 Prism 的 Tachyon
服务器配置中。`server.relay.allowed_targets` 是显式 UDP 目标 allow-list；
如果安装时没有提供目标，服务端会以安全 deny-all 模式启动，不会转发游戏 UDP，
需要配置后再测试。脚本和 Core 配置校验都会拒绝 `0.0.0.0/0`、`::/0`
这类全网目标，并要求每条 allow 规则显式填写 `ports` 列表或范围。迁移和多路径
新增源地址默认 fail-closed；只有完成基于会话 ECDH 派生密钥的
request/challenge/response 校验后才会接入，重复响应和数据包不能注册路径。
Challenge 使用无状态、绑定来源地址的 cookie；只有完成新鲜 challenge 才能切换
Relay active 回程路径，旧的已授权路径上的业务数据不能切换回程。
PathRequest 使用严格报文长度并携带认证的 10 秒时间窗。未知 SessionID 在 HMAC
前直接丢弃；已知 session 的新鲜请求在认证前不分配状态、不消耗 token，也不发送
响应。无效 HMAC 只增加无状态 CPU 工作，只有有效 HMAC 才进入每会话 burst 8、
每秒恢复 2 的迁移配额。

生成的客户端默认使用 `client.tun.mtu=1280` 和
`tgp.max_datagram_size=1352`，使最坏外层 IPv6/UDP 包为 1396 字节。认证的 TGP v3
握手协商客户端与 relay 的较小预算并传递时钟对齐信息，v1/v2 peer 会 fail-closed。已知低 PMTU 路径可把
数据报上限降到 1232，并同步降低 TUN MTU。Core 会拒绝不一致的预算，对发送超限
返回明确错误并记录接收超限遥测；TGP 当前尚无协议分片或自动 PMTU 探测。

部署完成后，可以用只读验收脚本收集诊断信息：

```bash
sudo bash scripts/verify-server.sh
sudo bash scripts/verify-server.sh --mode docker
bash scripts/verify-server.sh --mode config --binary ./tachyon-core --config ./server.json
```

如果要做显式公网 TGP E2E，请使用已经写入 `server.relay.allowed_targets` 的受控
UDP echo 目标：

```bash
bash scripts/verify-tgp-e2e.sh --mode public \
  --server vps.example.com:443 \
  --target echo.example.com:27015 \
  --psk-file ./tgp.psk
```

E2E 验证脚本默认仍是本地 loopback smoke；只有提供 `--server`、`--target` 和
PSK 时才会访问公网 UDP。它不会创建 TUN、修改路由、改防火墙规则、管理服务或调用
Prism；它只证明 Core/TGP 客户端到 Relay 再到受控 UDP 目标的闭环，不证明 Prism
集成、TUN 接管或真实游戏流量。

如果需要我们协助排查 VPS Relay，请生成带时间戳的支持包：

```bash
sudo bash scripts/collect-server-diagnostics.sh
sudo bash scripts/collect-server-diagnostics.sh --mode docker
sudo bash scripts/collect-server-diagnostics.sh --format txt
```

支持包包含 OS/kernel、Core 版本、配置校验、`allowed_targets`、服务或容器状态、
UDP 监听状态、脱敏日志尾部，以及脱敏后的 `verify-server.sh` 输出。它只读收集信息，
不会修改防火墙、Docker、systemd、包过滤器、路由或代理状态。回传前请人工检查生成的
`tachyon-server-diagnostics-*.tar.gz` 或 `.txt`。不要公开或粘贴 `tgp.auth.psk`、
完整私有订阅/代理 URL、token、UUID、private key、API key 或 password；只需要说明
PSK 是否存在、是否不是占位值，并提供 `allowed_targets` 摘要即可。

完整的本地 smoke 和 VPS 验收清单请见
[docs/tgp-server-verification.zh-CN.md](docs/tgp-server-verification.zh-CN.md)。

真实 VPS alpha relay 测试计划和脱敏回传清单请见
[docs/alpha-test-plan.md](docs/alpha-test-plan.md) 和
[docs/alpha-test-plan.zh-CN.md](docs/alpha-test-plan.zh-CN.md)。

Prism/Core IPC 设计请见 [docs/ipc-api.md](docs/ipc-api.md) 和 [docs/ipc-api.zh-CN.md](docs/ipc-api.zh-CN.md)。TGP 线缆格式请见 [docs/tgp-spec.md](docs/tgp-spec.md)。Prism 使用的 GitHub Release 资产说明请见 [docs/release.md](docs/release.md)。
