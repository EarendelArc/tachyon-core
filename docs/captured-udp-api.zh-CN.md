# Captured UDP Core 契约

[English](captured-udp-api.md)

## 状态

`internal/capturedudp` 已实现并测试进程内 flow lease registry。Windows Named
Pipe transport、特权 helper、Windows Service、WFP 策略管理器、callout 驱动和数据包
注入路径均未实现。本文档不能作为 Tachyon 已经支持按应用接管的证据。

## 边界

该契约只接受已经由特权平台组件完成进程归属和授权的 UDP flow。Core 在这条路径上
不查询 PID 或可执行文件路径。

认证后的 session 可以执行：

```text
ActivateGeneration(generation)
DisableGeneration(generation)
OpenFlow(flow_id, generation, family, local_endpoint, original_destination)
AcceptDatagram(flow_id, generation, sequence, payload) -> TGP tunnel datagram
ResolveReply(TGP tunnel datagram) -> flow_id, generation, payload
CloseFlow(generation, flow_id)
Health()
Stats()
```

## 安全不变量

- 每次启动的 session token 固定为 256 bit，并使用常量时间比较。未来的 transport
  还必须认证 Windows 对端访问令牌。
- Policy generation 非零且严格递增。重复执行当前 generation 的启用或停用是幂等的。
- 替换或停用 generation 会使现有 flow lease 全部失效。
- Helper 发送的每个数据报必须引用 active generation 和已知 Flow ID。
- 每个 flow 的数据报序列必须严格递增；重放和倒序 helper 消息会被拒绝。
- Active 本地/远端四元组必须唯一，因为当前 TGP tunnel payload 的回程不携带本地
  Flow ID。
- Flow 数量和 payload 大小均有上限；跨越信任边界的输入输出 payload 会复制。
- 关闭 registry 时会清除 token 和全部 lease。

Token 是本地通道的第二重认证，不可替代 Named Pipe ACL、对端进程令牌校验、Service
SID 或已签名二进制策略。

## Windows x64 封闭 Alpha 顺序

1. 在 registry 外实现带版本、长度前缀的 Named Pipe 协议。Pipe 只允许 LocalSystem、
   Tachyon Service SID 和 orchestrator 指定的当前交互用户访问；先验证客户端进程
   token，再接受随机 session token。
2. 实现仓库内 Windows Service/helper，负责 Pipe 连接、策略事务、健康 watchdog、
   bypass 身份和直连回滚。此阶段只是契约测试器，不是 packet capture。
3. 使用动态 BFE session 和原子事务实现 WFP 管理层。该步骤可验证应用、用户和 UDP
   策略选择，但真实 callout 数据面完成前不得宣称支持重定向。
4. 实现并审计仓库内 WDK callout driver，覆盖 IPv4、IPv6、connected UDP 和未连接
   `sendto`，包含注入状态防环和原始目标保存。生产分发需要符合 Microsoft 要求的签名。
5. 功能在 Prism 中开放前，必须通过双进程同目标、崩溃回滚、100 次启停和 1,000 次
   generation 替换测试。

本契约步骤没有引入任何内核驱动二进制或第三方流量接管产物。

## 当前 Alpha 限制

Wintun selective route 与 PID 反查仍是 legacy diagnostic path。它们未连接到本 registry，
也不是按应用隔离的 WFP capture。
