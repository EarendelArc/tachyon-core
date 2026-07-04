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
mise exec -- go test ./internal/app -run '^TestTGPRelaySmokeVerification$' -count=1 -v
```

该 smoke 只绑定临时 `127.0.0.1` UDP 端口，验证：

- 带 PSK 的 TGP 握手可以成功。
- 缺失或错误 PSK 的握手会被拒绝。
- allow-list 中的 UDP 目标可以完成 echo-like relay 往返。
- 未授权端口和未知目标不会收到 relay 流量。
- 空 `allowed_targets` 保持 deny-all，通配全网 relay 目标会被拒绝。

它不会启动客户端 pipeline、创建 TUN 设备，也不会修改主机网络配置。
本地 smoke 不能替代真实 VPS、云安全组、运营商 UDP 可达性和真实游戏 UDP 端到端验证。

## VPS 部署后

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

## 需要提供的输出

需要协助排查时，请提供：

- 实际运行的完整命令。
- 检查过敏感信息后的完整 `verify-server.sh` 输出。
- VPS 云安全组是否已放行 `server.listen` 对应的入站 UDP 端口。
- 如果从 Prism 测试，请提供 Prism/Core 版本。
- 去除密钥后的客户端错误文本。

不要提供 `tgp.auth.psk`。验收脚本会隐藏常见 PSK 形式，但公开发布前仍请人工检查
输出。可以按需打码公网 IP、账号 ID、主机名或游戏目标名称；但请保留 UDP 端口、
部署模式、配置验证状态和 `allowed_targets` 结构，方便定位问题。
