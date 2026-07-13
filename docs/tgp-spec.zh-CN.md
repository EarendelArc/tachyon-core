# Tachyon Game Protocol (TGP) 线缆格式规范

[English](tgp-spec.md)

**版本:** TGP/1.0

**状态:** 草案

**目标读者:** Tachyon Core 实现者

**当前实现状态:** Core 已在 `internal/tgp` 中实现 X25519/HKDF 流量密钥派生、ChaCha20-Poly1305 封包/解包、Reed-Solomon FEC 基础编解码、发送侧系统 FEC parity 生成、低流量 FEC 超时 flush、接收侧实时 FEC 恢复、保守动态 FEC 比例调整、Token Bucket pacing、UDP session 握手、客户端/Relay 会话管道、Relay 基于已认证握手来源地址的 demux、来源路径 challenge-response 认证、接收侧滑动 anti-replay 窗口，以及 `MultipathTransport` 多底层 transport 写入 fan-out/读取合并适配器。显式对端丢包反馈仍属于下一阶段。

---

## 1. 目标

TGP 是面向低延迟游戏 UDP 流量设计的传输协议。它的目标不是大吞吐下载，而是在稳定 pacing 下维持极小队列、快速恢复小包丢失，并在客户端网络路径变化时保持连接连续性。

| 目标 | 机制 |
| --- | --- |
| 低抖动 | Token Bucket pacing，不积累突发包 |
| 0-RTT 丢包恢复 | Reed-Solomon FEC |
| 连接迁移 | 128-bit Session ID |
| DPI/QoS 抗识别 | DTLS-like 外层头 + ChaCha20-Poly1305 |
| 多路径预留 | 多 transport fan-out + 接收侧包号去重 |

---

## 2. 数据包结构

所有整数在线缆上均为 big-endian。

### 2.1 外层头

明文外层头模拟 DTLS 1.0 application-data record：

| 字段 | 大小 | 值 |
| --- | ---: | --- |
| ContentType | 1 byte | `0x17` application data |
| Version | 2 bytes | `0xFE 0xFF` DTLS 1.0 |
| Epoch | 2 bytes | 初始为 `0x0000` |
| SequenceNumber | 6 bytes | DTLS 风格包序号 |
| Length | 2 bytes | 后续加密 TGP payload 长度 |

外层头作为 AEAD additional authenticated data 参与认证，任何篡改都会导致解包失败。

### 2.2 内层头

内层头和游戏 payload 使用 ChaCha20-Poly1305 加密。流量密钥派生方式：

```text
HKDF-SHA256(shared_secret, salt=session_id, info="tachyon-tgp-v1 traffic keys")
```

| 字段 | 大小 | 说明 |
| --- | ---: | --- |
| Magic | 4 bytes | `TGP\x01` |
| Flags | 1 byte | 控制、FEC、迁移、关闭、多路径、加密标记 |
| Reserved | 2 bytes | 当前写 0 |
| SessionID | 16 bytes | 用于连接迁移的稳定会话 ID |
| StreamID | 2 bytes | 逻辑流 ID |
| PacketNumber | 8 bytes | 单调递增包号 |
| FECGroup | 4 bytes | FEC group ID |
| FECIndex | 1 byte | group 内 shard index |
| FECTotal | 1 byte | data + parity shard 总数 |
| FECDataShards | 1 byte | 原始 data shard 数量 |
| Reserved | 1 byte | 当前写 0 |
| PayloadLength | 2 bytes | 游戏 payload 长度 |

### 2.3 Flags

| Bit | 名称 | 含义 |
| --- | --- | --- |
| 0 | `FlagControl` | 控制面数据包 |
| 1 | `FlagFEC` | FEC-only shard，不直接交付给游戏 |
| 2 | `FlagMigrate` | 路径迁移标记 |
| 3 | `FlagClose` | 有序关闭 |
| 4 | `FlagMultipath` | 多路径重复包 |
| 5-6 | Reserved | 当前必须为 0 |
| 7 | `FlagEncrypted` | 内层 payload 已加密 |

---

## 3. 会话生命周期

```text
Client                                      Server
  | ---- HELLO (session id, client key) ----> |
  | <--- HELLO_ACK (same id, server key) ---- |
  | ==== encrypted data packets ============> |
  | <==== encrypted relay packets =========== |
  | ---- CLOSE -----------------------------> |
```

当前握手使用临时 X25519 密钥。双方基于 shared secret 和 SessionID 派生双向流量密钥。

---

## 4. FEC Groups

### 4.1 发送路径

1. 真实 data shard 立即发送，不等待 group 填满。
2. 每个 data shard payload 前加 2 字节原始长度，便于恢复后移除 Reed-Solomon padding。
3. 发送端缓存 data shard，直到收集到 `FECDataShards` 个 payload 或 `GroupTimeout` 到达。
4. group 填满后发送 parity shard。
5. `GroupTimeout` 到达但 group 未填满时，发送端补齐 FEC-only synthetic data shard 和 parity shard。

FEC-only synthetic data shard 带 `FlagFEC`，接收端只用它们恢复数据，不会把空 synthetic datagram 交付给游戏。

### 4.2 接收路径

1. shard 按 `(SessionID, FECGroup)` 缓存。
2. 真实 data shard 去掉长度前缀后立即交付。
3. FEC-only shard 保留但不交付。
4. 如果原始 data shard 缺失且 group 至少收到 `FECDataShards` 个 shard，Core 会重建并只交付缺失的真实 payload。
5. 已完成 group 会保留在有界接收窗口中，用来抑制迟到原包或多路径重复包。

### 4.3 动态 FEC 比例

Core 根据接收侧 FEC 恢复比例调整 parity。当前实现把该估计保守应用到本会话后续出站 group。显式对端丢包反馈属于后续控制面升级。

| 观察到的恢复比例 | ParityShards/DataShards |
| --- | --- |
| 0% 到 3% | 1/4，作为探测和保护下限 |
| 3% 到 10% | 2/4 |
| >10% | 4/4，无 ARQ 的最大保护 |

### 4.4 协议资源上限

接收端会在 Reed-Solomon 分配或保存 payload 前拒绝超限输入。TGP 最多允许
32 个 data shard、16 个 parity shard、48 个总 shard、64 个活跃接收 group、
4096 条紧凑的已完成 group 墓碑，以及每会话 4 MiB 的 shard payload 缓冲。
单 shard 不得超过 TGP 数据报 payload 预算。group 完成后立即释放 shard 内存；
未完成 group 和完成墓碑均在 30 秒后过期。

---

## 5. 连接迁移

Relay 首先把 session 绑定到完成认证握手的 UDP 来源地址。新增迁移或多路径来源必须完成以下交换，数据才能进入 session 队列：

1. 客户端从每条路径发送带 `SessionID`、`ClientNonce` 和认证标签的 `PathRequest`。
2. Relay 使用该 session 的 client-to-server 流量密钥派生路径密钥，验证请求后向观测到的 UDP 来源发送新的 `ServerNonce`。
3. 客户端验证 challenge，并从收到 challenge 的同一本地 transport 返回同时覆盖两个 nonce 的 `PathResponse`。
4. Relay 校验 `ServerNonce` 中无状态、绑定来源地址的 cookie；已消费 cookie 进入短时、每会话有界 replay set，已有来源映射不能被其他 session 抢占。

`ClientNonce` 携带认证时间戳，超过 10 秒时间窗的 `PathRequest` 会被拒绝。新鲜请求不分配全局 pending 状态；固定状态的全局 bucket（burst 64、每秒恢复 32）限制认证前 lookup/HMAC 工作。只有 HMAC 有效的请求才会扣除该 CID 的 session bucket（burst 8、每秒恢复 2）并生成响应，因此随机 tag 不能耗尽合法迁移配额，捕获请求造成的反射与 CPU 开销也有明确上界。重复响应会被已消费 cookie 检查拒绝。未知非控制数据仍然 fail-closed，不会广播给所有活跃 session 尝试解密。

PacketNumber 使用有界滑动 anti-replay 窗口。已授权路径的数据可以交付，但业务数据永远不能改变 active 回程路径；只有完成新鲜 challenge 才能切换。非 active 路径 45 秒后老化，达到 8 条上限时安全替换最久未使用的非 active 条目。

---

## 6. 多路径

接收路径已经基于认证后的 PacketNumber 去重。`MultipathTransport` 可以组合多个 `Transport` 实现：每次写入会尝试发送到所有路径，读取则合并任意路径先到达的数据包。每条本地路径都会完成上述来源认证，并周期刷新注册；NAT 映射变化后会保持 fail-closed，直到重新认证成功。客户端只接受当前握手所配置 Relay endpoint 发来的 `PathChallenge`；从未知来源转发的有效 challenge 不会授权来源，也不会消耗数据 anti-replay 状态。Relay 服务端地址迁移必须重新握手。

剩余集成工作是系统网络接口发现和策略选择，例如在移动端选择 Wi-Fi + 蜂窝链路。当前 adapter 依靠 PacketNumber 去重；显式 `FlagMultipath` 标记仍预留给未来控制面集成。

### 6.1 数据报大小与 PMTU

`tgp.max_datagram_size` 限制完整加密 TGP UDP payload。默认值为 1352，协议最大值为
1452；配合默认 1280 TUN MTU，审计后的最坏外层 IPv6/UDP 包为 1396 字节。最低可配置
值是 1232，对应已知 1280 字节路径的外层 IPv6/UDP 预算。客户端配置必须满足
`client.tun.mtu + 68 <= tgp.max_datagram_size`，发送超限返回明确协议错误，接收超限
fail-closed 并增加 `OversizedDatagrams` 遥测。认证的 `TGH\x02` 握手把上限纳入认证
字段，双方存储客户端与 Relay 的较小值；无法证明预算的 v1 peer 会被拒绝。

TGP 当前不做协议分片或自动 PMTU 探测。运维方必须按已知路径配置较低预算和匹配
的 TUN MTU。1280 字节外层路径无法在不做协议分片时承载最小 1280 字节内层 IPv6
包，因此该组合仍不支持并保持 fail-closed；1232 设置只适用于内层 MTU 也能安全
降低的受控场景，例如仅 IPv4 的路径。

---

## 7. 密码学

| 项目 | 选择 |
| --- | --- |
| 密钥交换 | X25519 |
| KDF | HKDF-SHA256 |
| AEAD | ChaCha20-Poly1305 |
| 外层伪装 | DTLS-like application-data record |

---

## 8. 当前限制

- 尚无显式对端丢包反馈；动态 FEC 目前使用接收侧恢复比例作为本地保守估计。
- Relay 路径迁移/重绑定在观测来源完成 authenticated rebind 交换前保持 fail-closed。
- 多路径接口发现和策略选择尚未接入；底层 transport adapter 与接收侧去重已实现。
- `FlagMultipath` 仍是预留标记；当前 fan-out 不会重写已加密内层头来设置它。
- 尚无协议分片或自动 PMTU 探测；配置的数据报与 TUN 上限必须匹配真实路径。
- TGP 设计上不实现 ARQ 重传，依靠 pacing 和 FEC 避免引入物理 RTT 延迟。
