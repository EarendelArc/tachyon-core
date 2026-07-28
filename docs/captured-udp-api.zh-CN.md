# Captured UDP Core 契约

[English](captured-udp-api.md)

## 状态

`internal/capturedudp` 已实现并测试进程内 controller、策略事务、flow lease 和资源预算
registry。Windows Named Pipe transport、特权 helper、Windows Service、WFP 策略管理器、
callout 驱动和数据包注入路径均未实现。本文档不能作为 Tachyon 已支持按应用接管的证据。

## 边界与就绪状态

该契约只接受已经由特权平台组件完成进程归属和授权的 UDP flow。Core 在这条路径上不
查询 PID 或可执行文件路径。

公开 API 只能创建未验证的 transport attachment，它不能认证 controller。未来同包内
Named Pipe transport 必须先验证 OS 对端，才能创建已验证 attachment。仅当以下条件
全部成立时，`Health.Ready` 才为 true：

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

```text
AttachTransport(verified transport) -> one-use token
Authenticate(attachment_id, token) -> sole controller
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

## 资源与生命周期不变量

- Generation 非零且只允许单调 commit。
- Flow lease 有 idle TTL；后台 reaper 和数据热路径都会回收过期 lease。
- Flow 数、单包大小、TTL、估算 flow metadata 和所有未释放 payload 总字节数均有
  不可配置突破的硬上限。
- 大 payload 复制发生在释放 registry 全局锁之后。
- Accepted payload 和 delivery 会占用字节预算，调用方必须调用 `Release()`；泄漏预算
  时以 `ErrBufferBudget` fail-closed，而不是允许内存无限增长。
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
