# Captured UDP Core 契约

[English](captured-udp-api.md)

## 状态

`internal/capturedudp` 已实现 registry 和 Windows Named Pipe v2 preview transport。
通过认证的 helper 数据报会进入真实 TGP `ClientManager`，TGP 回包经过完整身份校验后以
`Delivery` 帧主动推回 helper。特权 helper、Windows Service、WFP 策略管理器、callout
驱动和数据包注入路径仍未实现，因此不得宣称已经实现按应用接管。

## Named Pipe v2 preview

帧格式为 `TCU1 | version=2 | type | uint32 payload_length | payload`。Core 在读取和分配
body 前检查长度，硬上限为 64 KiB。session token 只由 Core 生成，只通过 pipe 内存传递，
使用一次后清零，不进入命令行、环境变量或日志。

认证后支持 Prepare/Commit/Abort/Disable、OpenFlow、Datagram、CloseFlow、Ping/Pong 和
CloseConnection。helper 的 `Datagram` 经 Registry 验证身份后进入真实 TGP manager，响应
只表示发送状态；TGP 回包必须按 FlowID、generation、nonce 与 endpoints 精确解析，再由
Core 主动发送 `Delivery`。v1 对端和 helper 伪造的 reply 帧均 fail closed。

选择 `named_pipe` capture mode 时不会创建或运行 legacy TUN pipeline，两条捕获路径不能
双投递。非零 idle timeout 只关闭当前连接；清理 controller 和 lease 后，listener 会继续
接受下一客户端。Service SID 同时检查启用的 token groups 与 restricted SIDs；普通用户 SID
只能匹配 `TokenUser`，并且必须显式打开 insecure preview 开关。

真实 Service SID 和低完整性 token 场景需要管理员 Windows CI runner。当前本地单元测试只
验证策略与匹配逻辑，不伪造这些 OS 集成场景已经通过。

## 边界与就绪状态

该契约只接受已经由特权平台组件完成进程归属和授权的 UDP flow。Core 在这条路径上不
查询 PID 或可执行文件路径。

公开 API 只能创建未验证的 transport attachment，它不能认证 controller。每个
attachment 都有仅由其来源 registry 接受的内部随机 256-bit capability。Attach 与
Detach 是排他的。生命周期不可逆（`new -> attached -> detached/closed`）：存在
active attachment/controller 时不能替换，外部实例不能撤销，失败或未验证的尝试不得
改变状态。Detach、controller close 与 registry close 会原子清零 capability 和对端
verified 状态；stale attachment 永远不能再次取得 token。未来同包内 Named Pipe transport 必须先验证 OS
对端，才能创建已验证 attachment。仅当以下条件全部成立时，`Health.Ready` 才为 true：

- transport 已连接；
- transport 的 OS 对端已验证；
- 恰好一个 controller 已连接；
- 一个已 commit 的 policy generation 正在生效。

当前没有任何代码路径声称 OS 对端已经通过验证。

## Controller 契约

已验证 transport 建立后，Core 内部生成一次性的 256-bit 强随机 token。认证会消费
token，并把唯一 controller capability 绑定到该 attachment。Controller 或 transport
断开时，capability、prepared policy、active policy 和 flow lease 全部撤销。已经交给
调用方的 payload 会继续占用全局字节预算，直到调用方执行 `Release()`。

未来所有 transport 都必须在 EOF、broken pipe、受监管 helper 退出或意外崩溃时同步
执行 attachment detach 或 controller close，之后才能重连或报告 Ready。这是未来
transport 的不变量；当前仍未实现 Named Pipe transport。

```text
AttachTransport(verified transport) -> one-use token
Authenticate(attachment capability, token) -> sole controller
PrepareGeneration(generation) -> transaction
CommitGeneration(transaction)
AbortGeneration(transaction)
DisableGeneration(generation)
OpenFlow(flow_id, generation, family, local, original_destination) -> lease nonce
AcceptDatagram(flow_id, generation, lease_nonce, sequence, payload)
ResolveReply(TGP tunnel datagram) -> flow_id, generation, lease_nonce, payload
CloseFlow(generation, flow_id, lease_nonce)
Health()
Stats()
```

Prepare 不会影响 active generation 及其 flow。Commit 原子替换 active generation 并
使旧 lease 失效；Abort 保持 active generation 不变。

## TGP tunnel 身份

Captured UDP 使用 `TGD\x02` tunnel payload，并在已建立 TGP session 的
ChaCha20-Poly1305 AEAD 保护范围内携带：

```text
FlowID[16] | generation[8] | lease_nonce[16] |
local endpoint | original remote endpoint | UDP payload
```

服务端原样返回完整身份，并把它纳入 UDP relay flow key。Core 使用完整身份和两端
endpoint 精确匹配回程，不再只依赖四元组。Flow ID 或四元组复用时会生成新的随机
lease nonce，因此旧 lease 的迟到回复不能投递给新 lease。

`TGD\x01` 只为 legacy TUN preview 保持可解析。Captured-UDP registry 不会生成 v1，
并拒绝没有 lease identity 的 v1 回程。只填写部分 v2 identity 也是非法的。

Captured UDP 当前没有 v1/v2 降级或服务端 capability 协商，要求两端都支持 v2。旧
服务端可能拒绝 `TGD\x02`；客户端必须 fail-closed，绝不能把 captured flow 重试为 v1。
未来如需混合版本支持，必须在打开 flow 前通过已认证握手协商 v2。

## 加密数据报预算

`MaxTGPDatagramSize` 表示完整加密 TGP UDP payload。Registry 会先扣除 TGP codec、
AEAD tag、FEC 长度前缀、v2 身份和 endpoint 编码开销，再预留或复制游戏 payload。

| TGP UDP payload | IPv4 游戏 payload | IPv6 游戏 payload |
| ---: | ---: | ---: |
| 1232 | 1100 | 1076 |
| 1352 | 1220 | 1196 |
| 1452 | 1320 | 1296 |

混合地址族 flow 非法。配置的全局上限与具体 flow 地址族预算都会在分配或入队前检查。

## 资源与生命周期不变量

- Generation 非零且只允许单调 commit。
- Flow lease 有 idle TTL；后台 reaper 和数据热路径都会回收过期 lease。
- Flow 数、单包大小、TTL、估算 flow metadata 和所有未释放 payload 总字节数均有
  不可配置突破的硬上限。
- Accepted datagram 与 reply delivery 对 outstanding object 和估算 metadata 同时具有
  不可配置的全局及单方向硬上限。每个对象至少预留 64 字节 payload 预算，零长 payload
  也不例外，因此持续零长流量仍保持有界。
- 每个 controller 对双向数据共享 packet/s 与 byte/s token bucket，控制调用使用独立
  operations/s bucket。零长数据报也消耗一个 packet 和至少一个 byte；rate 与 burst
  配置不能突破硬上限。
- 大 payload 复制发生在释放 registry 全局锁之后。
- Accepted payload 和 delivery 会占用字节预算，调用方必须调用 `Release()`；泄漏预算
  时以 `ErrBufferBudget` fail-closed，而不是允许内存无限增长。`Release()` 幂等，并且
  只精确归还一次 payload、object 与 metadata reservation。
- 每个 lease 的 helper 数据报序列必须严格递增。
- 跨越信任边界的输入输出 payload 都会复制。

## Windows x64 封闭 Alpha 顺序

1. 在契约外实现带版本和长度前缀的 Named Pipe transport。强制 Pipe ACL，并在创建
   当前尚不可用的 verified attachment 前验证客户端进程 token。
2. 实现仓库内 Windows Service/helper，负责 transport 生命周期、策略事务、watchdog、
   bypass 身份和直连回滚。
3. 使用动态 BFE session 和原子事务实现 WFP 管理层。真实 callout 数据面完成前不得
   宣称支持流量接管。
4. 实现并审计仓库内 WDK callout，覆盖 IPv4、IPv6、connected UDP 和未连接 `sendto`，
   包含注入状态防环和原始目标保存；生产分发需要符合 Microsoft 要求的签名。
5. Prism 开放前，必须通过双进程同目标、旧 lease 迟到包、崩溃回滚、100 次启停、
   1,000 次 generation 替换、负载和资源耗尽测试。

此处没有引入任何内核驱动二进制或第三方流量接管产物。

## 当前 Alpha 限制

Wintun selective route 与 PID 反查仍是 legacy diagnostic path。它们未连接到本 registry，
也不是按应用隔离的 WFP capture。
