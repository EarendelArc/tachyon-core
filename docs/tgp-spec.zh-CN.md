# Tachyon Game Protocol (TGP) 线格式规范

[English](tgp-spec.md)

**版本:** TGP/1.0

**状态:** 草案

**目标读者:** Tachyon Core 与服务端实现者

**当前实现状态:** Core 已在 `internal/tgp` 中实现 X25519/HKDF 流量密钥派生、ChaCha20-Poly1305 数据包封包/解包、Reed-Solomon FEC 基础编解码、发送侧 parity 生成、低流量 FEC 超时 flush、保守动态 FEC 比例调整、接收侧实时 FEC 恢复、Token Bucket pacing、UDP session 握手、客户端/Relay 会话管道、基于认证包来源地址变化的自动迁移，以及接收侧滑动窗口去重。显式迁移确认控制包、显式对端丢包反馈，以及真正的多 transport fan-out 仍属于下一阶段。

---

## 1. 目标

TGP 是面向游戏 UDP 流量设计的低抖动传输协议。它的目标不是抢占带宽，而是在稳定速率下保持极小队列，减少 Bufferbloat。

| 目标 | 机制 |
|---|---|
| 低抖动 | Token Bucket Pacing，避免突发 |
| 0-RTT 丢包恢复 | Reed-Solomon FEC |
| 连接迁移 | 128-bit Session ID |
| 抗 QoS 识别 | DTLS-like 外层头 + ChaCha20-Poly1305 |
| 多路径预留 | 多 transport fan-out + 接收端去重 |

---

## 2. 数据包结构

所有整数在线上均为 big-endian。

### 2.1 外层头，明文，13 字节

外层头模拟 DTLS 1.0 record header：

| 字段 | 大小 | 值 |
|---|---:|---|
| ContentType | 1 byte | `0x17`，application_data |
| Version | 2 bytes | `0xFE 0xFF`，DTLS 1.0 |
| Epoch | 2 bytes | 初始为 `0x0000` |
| SequenceNumber | 6 bytes | 48-bit 包序号 |
| Length | 2 bytes | 后续密文长度 |

外层头作为 AEAD additional data 参与认证，篡改会导致解包失败。

### 2.2 内层头，认证加密，43 字节

内层头与游戏 payload 一起用 ChaCha20-Poly1305 加密。当前密钥派生方式：

```text
HKDF-SHA256(shared_secret, salt=session_id, info="tachyon-tgp-v1 traffic keys")
```

| 字段 | 大小 | 说明 |
|---|---:|---|
| Magic | 4 bytes | `TGP\x01` |
| Flags | 1 byte | 控制、FEC、迁移、关闭、多路径、加密标记 |
| Reserved | 2 bytes | 保留，当前写 0 |
| SessionID | 16 bytes | 连接迁移使用的会话 ID |
| StreamID | 2 bytes | 逻辑流 ID |
| PacketNumber | 8 bytes | 单调递增包号 |
| FECGroup | 4 bytes | FEC 组 ID |
| FECIndex | 1 byte | shard index |
| FECTotal | 1 byte | data + parity shard 总数 |
| FECDataShards | 1 byte | 原始 data shard 数量 |
| Reserved | 1 byte | 保留，当前写 0 |
| PayloadLength | 2 bytes | 游戏 payload 长度 |

---

## 3. 已实现组件

- `crypto.go`: 生成 X25519 key pair，并从 shared secret 派生双向流量密钥。
- `codec.go`: 生成 DTLS-like 外层头，使用 ChaCha20-Poly1305 封包/解包。
- `fec.go`: 基于 `github.com/klauspost/reedsolomon` 的 FEC 编解码器和接收侧恢复缓冲。发送端会立即发送带 2 字节原始长度前缀的 data shard，并在满组或 `GroupTimeout` 到达时补发 parity shard；接收端会立即交付真实 data shard，并用 parity shard 恢复缺失的原始 payload。
- `pacer.go`: 深度为 1 的 token bucket pacer，用于平滑发包。
- `handshake.go`: 基于 UDP 的 HELLO/HELLO_ACK 握手与会话密钥协商。
- `session.go`: TGP datagram session，包含自动源地址迁移和滑动去重窗口。
- `client_manager.go` / `relay.go`: 客户端会话管理与服务端 Relay 收包管道。

---

## 4. 下一阶段

- 增加显式迁移确认控制包，区分“已接受新路径”和“已确认切换”。
- 增加显式对端丢包反馈，让发送侧不只依赖接收侧恢复比例的对称性假设。
- 实现真正的多 transport fan-out，并把 `FlagMultipath` 接入发送路径。
- 为迁移、去重、FEC 恢复补充更细粒度的遥测事件。
