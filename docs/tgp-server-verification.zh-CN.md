# TGP 服务端验证

下面的检查用于 VPS 部署前后。部署前的本地 smoke 不依赖用户真实 VPS，也不会启用
本机 TUN、系统代理、路由、防火墙、systemd 或 Docker 状态变更。

## VPS 部署前

在 `tachyon-core` 目录运行本地 smoke：

```bash
bash scripts/smoke-tgp-relay.sh
```

等价的直接命令：

```bash
mise exec -- go test ./internal/app -run '^TestTGPRelay(SmokeVerification|ConfigDrivenSmoke)$' -count=1 -v
```

可以用下面的命令验证可选公网脚本本身；这些命令不会查询公网 DNS，也不会打开公网
socket：

```bash
bash -n scripts/verify-tgp-e2e.sh
bash scripts/verify-tgp-e2e.sh --self-test
env -u TACHYON_E2E_SERVER -u TACHYON_E2E_TARGET -u TACHYON_E2E_PSK \
  mise exec -- go test ./internal/app \
  -run '^(TestTGPRelayPublicE2EFromEnv|TestPublicE2EConfigFromEnv|TestResolvePublicE2EAddrLiteral)$' \
  -count=1 -v
```

三个必需环境变量未设置时，公网测试会在 DNS 解析和创建 socket 前跳过。本地测试会
覆盖部分 opt-in、PSK 长度、payload 大小、响应匹配器冲突、主机/端口解析以及 30 秒
超时上限。

该 smoke 只绑定临时 `127.0.0.1` UDP 端口，验证：

- 带 PSK 的 TGP 握手可以成功。
- 缺失或错误 PSK 的握手会被拒绝。
- client/server 配置字段可以接线到可工作的 TGP relay 路径。
- allow-list 中的 UDP 目标可以完成 echo-like relay 往返。
- 未授权端口和未知目标不会收到 relay 流量。
- 空 `allowed_targets` 保持 deny-all，通配全网 relay 目标会被拒绝。

它不会启动 TUN packet pipeline、创建 TUN 设备、调用 Prism 或 Xray、连接真实游戏服务器，
也不会修改主机网络配置。
本地 smoke 不能替代真实 VPS、云安全组、运营商 UDP 可达性和真实游戏 UDP 端到端验证。

## VPS 部署后

安装时请显式配置 relay 目标。安装脚本支持重复传入 `--allow-target`：

```bash
sudo bash scripts/install-server.sh --version v0.1.0-alpha.17 --port 443 \
  --allow-target 'cidr=198.51.100.10/32,ports=27015'

sudo bash scripts/install-server-docker.sh --version v0.1.0-alpha.17 --port 443 \
  --allow-target 'domain=echo.example.com,ports=27015'
```

请尽量使用最窄的 UDP 目标和端口列表。公网 E2E 验证优先使用你自己控制的 UDP echo
服务，并把该 echo 目标写入 `server.relay.allowed_targets`。不要把验证脚本默认指向
真实游戏服务器，除非你明确知道该服务器会如何响应任意 UDP 探测包。

在 VPS 上按部署方式运行只读验收脚本：

```bash
sudo bash scripts/verify-server.sh
sudo bash scripts/verify-server.sh --mode docker
```

如果只是检查复制出来的二进制和配置，或想在启动服务前检查：

```bash
bash scripts/verify-server.sh --mode config --binary ./tachyon-core --config ./server.json
```

`verify-server.sh` 会验证二进制和配置，按需检查 systemd 服务或 Docker 容器状态，
汇总 `allowed_targets`，检查 UDP 监听，并在输出日志尾部时隐藏 PSK。脚本不会修改
防火墙规则、云安全组、Docker、systemd 或包过滤规则。

## 公网 TGP E2E

当 `verify-server.sh` 已确认二进制和配置有效、服务或容器在运行、UDP 监听存在，并且
`allowed_targets` 不为空后，可以在能访问 VPS 的客户端机器上运行可选的公网 E2E 验证：

```bash
printf '%s\n' '<仅在本地复制 PSK，不要回传>' > ./tgp.psk
bash scripts/verify-tgp-e2e.sh --mode public \
  --server vps.example.com:443 \
  --target echo.example.com:27015 \
  --psk-file ./tgp.psk
```

`--target` 必须是你控制的 UDP echo 端点，并且已经被 VPS 配置显式允许。如果 echo
响应不是请求 payload 本身，也不是 `echo:<payload>`，可以额外传入：

```bash
--expect 'known-response'
--expect-prefix 'echo:'
```

两个响应匹配器只能选择一个。VPS 和目标的 DNS 解析、TGP 握手、等待响应共用同一个
超时（最大 30 秒）；响应中携带的远端地址和端口也必须与解析后的目标一致。

`verify-tgp-e2e.sh` 不会创建 TUN 设备、修改路由、启用系统代理，也不会修改防火墙、
systemd 或 Docker 状态。它的默认模式仍是本地 loopback smoke；只有显式提供
`--server`、`--target` 和 PSK 时才会访问公网 UDP。

建议按以下层次区分验证结果：

- 本地 loopback smoke：`scripts/smoke-tgp-relay.sh`，证明 Core TGP relay 逻辑和
  配置驱动运行时接线，不改宿主网络。
- VPS 只读验收：`scripts/verify-server.sh`，证明已安装服务器的二进制、配置、监听、
  服务或容器状态，并汇总 `allowed_targets`。
- 公网 TGP E2E：`scripts/verify-tgp-e2e.sh --mode public`，证明客户端可以和 VPS
  完成 TGP 握手，并把一个 UDP echo payload relay 到显式允许的目标。
- 真实游戏测试：Prism/游戏流量使用同一 server profile 和已被 `allowed_targets`
  覆盖的真实游戏目标；这仍然需要用户配合，不能由 echo 验证脚本单独证明。

断网的开发机只能完整证明第一层。VPS 监听、云防火墙、公网 UDP 路径、部署后的
PSK、受控 echo 端点以及真实游戏行为，仍然必须针对真实部署逐项验证。

## 需要提供的输出

需要协助排查时，请提供：

- 实际运行的完整命令。
- 检查过敏感信息后的完整 `verify-server.sh` 输出。
- 去除 PSK 后的 `verify-tgp-e2e.sh` 命令和输出。
- VPS 云安全组是否已放行 `server.listen` 对应的入站 UDP 端口。
- 如果从 Prism 测试，请提供 Prism/Core 版本。
- 去除密钥后的客户端错误文本。

不要提供 `tgp.auth.psk`。验收脚本会隐藏常见 PSK 形式，但公开发布前仍请人工检查
输出。可以按需打码公网 IP、账号 ID、主机名或游戏目标名称；但请保留 UDP 端口、
部署模式、配置验证状态和 `allowed_targets` 结构，方便定位问题。
