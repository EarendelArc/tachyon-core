# ADR-0001：应用感知流量接管

[English](0001-application-aware-capture.md)

- 状态：Proposed
- 日期：2026-07-22
- 范围：Tachyon Core、Tachyon Prism 与特权平台集成层

## 背景

Tachyon 必须只加速用户选中游戏程序的 UDP 流量，同时保证访问相同远端地址的其他进程不被接管。游戏服务器可能使用动态地址、CDN 或 Relay 池以及短生命周期 endpoint，因此目标 CIDR 不能作为主要的应用选择手段。

当前客户端预览方案把显式目标路由安装到 TUN，数据包进入 Core 后再反查所属进程。这条路径无法在不产生路由环路的情况下，把误接管的非游戏包安全送回原生网络。进程查询的成本和不确定性也不适合留在延迟敏感的数据包路径中。因此，现有 selective-route TUN 实现属于 legacy preview，而不是目标应用感知架构。

Core 必须保持为纯 TGP 数据面。Prism 继续作为 Xray Core 与 Tachyon Core 的双核心 GUI 和编排层。操作系统流量接管和特权策略执行需要独立边界。

## 决策驱动因素

1. 即使选中进程和未选中进程使用相同协议、目标和端口，也必须可靠区分。
2. 动态游戏 endpoint 必须在不维护大范围目标 CIDR 的情况下工作。
3. 未选中和无法识别的流量必须停留在原生路径。
4. Core、helper、Xray 和 Relay 流量绝不能重新进入接管路径。
5. 接管启用、替换和移除必须具备事务性；作为消费级游戏加速产品，故障时默认 fail-open 到直连。
6. UI 必须保持非特权运行，平台内核或系统 API 不得实现在 Tauri 视图层中。

## 决策

平台接管层必须在 Tachyon Core 接收流量之前完成进程分类。Core 只接收已经被平台层授权用于游戏加速的 UDP flow。

```text
Prism UI
  -> Prism Rust 编排器
  -> 特权平台接管 helper 或 extension
  -> 经过认证的本地 captured-UDP API
  -> Tachyon Core / TGP
  -> Tachyon Server
```

Wintun 和 utun 可以作为平台数据包 transport，但不是进程分类器。“全局 TUN 后反查 PID”不属于本决策允许的生产实现。

## 所有权边界

| 组件 | 负责 | 禁止负责 |
| --- | --- | --- |
| Prism UI | 程序选择、Steam 交互、设置、权限引导、状态和恢复交互 | 驱动安装逻辑、提权命令、路由修改、数据包处理 |
| Prism Rust backend | 配置编排、进程生命周期、策略事务、helper RPC、就绪检查和状态聚合 | TGP 加密/FEC 或直接实现内核过滤器 |
| 平台 helper 或 extension | 进程身份、OS 接管、原目标保存、旁路、原生回注和回滚 | 订阅、Xray JSON 或 TGP transport |
| Tachyon Core | captured flow 到 TGP session 的映射、加密、FEC、pacing、multipath、Relay transport 和遥测 | PID 查询、启动器扫描、WFP、Network Extension、nftables、Xray 或订阅 |
| Tachyon Server | TGP 认证、恢复、去重、ACL 和 UDP Relay | 客户端应用策略 |
| Xray Core | Prism 所生成 Xray JSON 描述的普通代理流量 | Tachyon 游戏 UDP |

驱动、helper 和 extension 逻辑必须放在可独立测试的平台 target 中，不得嵌入 React 组件或普通 Tauri command handler。

## 跨平台接管契约

特权平台 adapter 向 Prism Rust backend 暴露统一控制契约：

```text
Capabilities() -> 平台能力和限制
PreparePolicy(policy, generation) -> transaction handle
CommitPolicy(transaction) -> active generation
RollbackPolicy(transaction or generation)
AttachProcess(process_identity, policy_id)
DetachProcess(process_identity, policy_id)
DisableCapture(generation)
Health() -> 就绪状态、active generation、残留状态报告
Statistics() -> captured、bypassed、rejected、recovered flow
```

面向 Core 的本地数据面不包含进程概念：

```text
OpenFlow(flow_id, original_destination, address_family, policy_generation)
SendDatagram(flow_id, sequence, payload)
ReceiveDatagram(flow_id, payload)
CloseFlow(flow_id, reason)
Health()
Statistics()
```

Windows 使用 Named Pipe；macOS 和 Linux 使用 Unix Domain Socket。本地通道同时认证对端的 OS 身份和每次启动生成的随机 session token。Core 拒绝未知 generation 和 flow ID。

## Windows 决策

Windows 生产路径使用 Windows Filtering Platform 的应用层 enforcement，以及签名 callout/helper 组合。过滤器在重定向或接收选中 flow 之前，根据原始应用身份、用户身份、UDP 和 IPv4/IPv6 进行匹配。helper 保存原始目标并与 Core 交换数据报。

实现必须覆盖 connected UDP 和未连接的 `sendto` 流量。除非测试证明 ALE connect redirect 覆盖两种形式，否则仅实现 ALE 重定向并不充分，还可能需要 datagram 层分类和 injection。WFP 要求的 redirect record、原应用身份和原始目标必须贯穿 outbound proxy socket。

WFP 策略对象使用动态 WFP session 和原子 WFP transaction。helper session 关闭或崩溃后，动态过滤器由系统移除。Core、helper、Xray、Relay endpoint、loopback 和必要系统流量使用更高优先级 bypass 规则。

Wintun 只作为 legacy preview 和诊断 transport 保留，不得展示为按进程隔离接管。

## macOS 决策

消费版首选路径是使用 Developer ID 签名、基于 `NETransparentProxyProvider` 的 Network Extension system extension。它接收符合条件的出站 UDP flow，把选中的 flow 交给 Core；无法可靠识别或未被选中的 flow 使用 transparent provider 的原生旁路行为继续直连。

MDM Per-App VPN 的 app rule 与受管理应用部署绑定，因此不能作为消费版产品基础。承诺正式实现前，必须通过可行性样机证明未受管理的桌面发行版能够稳定获得所需 UDP flow 的来源进程身份，包括 signing identifier 或 audit token。如果验证失败，macOS 只能保持目标规则 preview，不得宣称支持任意程序按进程接管。

utun 只作为兼容实验的数据包 transport 保留，不是进程策略权威层。

## Linux 决策

Linux 生产路径使用 cgroup v2 作为运行时应用身份。特权 helper 启动选中的游戏进程或把它移动到 Tachyon 专用游戏 cgroup，其子进程继承该 cgroup。nftables socket cgroup 匹配只标记这个 cgroup 的公网 UDP，再由 `ip rule` 和专用路由表把已标记的数据包送入接管接口。

Core、Prism、helper 和 Xray 位于 bypass cgroup。Relay 目标、loopback、本地网络、DNS、DHCP 和其他必要控制流量在标记前排除。nftables、policy rule、路由和接管接口应在平台允许范围内原子创建和替换。

“使用 Tachyon 启动”是可靠的 Linux MVP。附加已运行进程属于 best effort，直到测试证明移动进程和追踪子进程不会错过关键首个 flow。Steam 集成应使用受控 launcher 或 wrapper，而不是宽泛目标路由。

## 应用策略

Prism 持有的策略模型至少包含：

```text
policy_id
generation
platform_identity
protocol = UDP
include_ports / exclude_ports
exclude_loopback / exclude_lan / exclude_dns
relay_endpoints
fail_mode = direct
```

各平台身份定义如下：

- Windows：规范化可执行文件路径、发布者身份、适用时的 Package SID，以及可选文件 hash。游戏更新会替换二进制，因此 hash 不能成为唯一身份。
- macOS：Team ID、signing identifier、designated requirement 和 audit token。路径只作为显示信息或有文档说明的降级匹配，不是主要签名身份。
- Linux：运行时 cgroup ID 是权威身份。可执行文件路径、inode、UID 和 launcher 元数据用于创建或附加进程。

选中应用的默认范围是全部公网 UDP，并应用显式排除项。可选端口和 CIDR 规则用于缩小范围，但不是发现动态游戏服务器的必要条件。TCP 继续走原生路径或单独配置的 Xray 路径。

## 直连路径与环路防护

未选中的应用绝不进入接管数据路径。未知身份和不支持的 flow 保持直连。直连 fallback 由平台接管层实现，不能由 Core 把包写回同一个 TUN。

每个 captured flow 都有与 generation 绑定的 flow lease，其中包含原始目标和平台策略身份。helper 没有该 lease 时不得向 Core 打开 flow。Core 流量通过 OS 身份和 helper 专属 bypass 状态排除；目标排除只是纵深防护，不是唯一环路保护。

Linux 已通过 cgroup membership 完成选择，其他 cgroup 的包不得被标记。helper 或 Core 不健康时移除接管策略，使后续数据报恢复原生路由。正在进行的 NAT 状态可能丢失；fail-open 表示避免黑洞，不代表本地组件故障后会话一定不断开。

## 生命周期、故障与回滚

启动顺序固定为：

```text
校验配置
启动 Core 并等待数据面 ready
启动 helper 或 extension 并验证 bypass
准备平台策略 generation N
原子提交 generation N
报告加速已启用
```

停止顺序固定为：

```text
原子禁用 generation N
等待 flow lease 排空或过期
移除路由、过滤器和临时 OS 状态
停止 Core 和 helper
报告直连网络已恢复
```

策略替换先准备 generation N+1，再从 N 切换。prepare 或 commit 失败时 N 保持启用；首次激活失败时接管保持禁用。Prism 只持久化期望策略，helper journal 只保存检测和移除残留特权状态所需的最小标识。

消费级游戏加速默认 fail-open 到直连。Windows 使用动态 WFP 对象；macOS 按 Network Extension 支持的方式把未处理 flow 返回或切换到原生路径；Linux 使用受监管 helper、强制 stop-post cleanup，以及能够在 helper 崩溃后移除 Tachyon 专用 nftables table、rule 和 route 的独立 watchdog。

## 权限、签名与发行

- 所有平台上的 Prism UI 都以非提升权限运行。
- Windows 使用具有受限控制 ACL 的 service。生产内核组件必须满足 Microsoft 兼容的 release signing；测试签名驱动不能作为生产产物。
- macOS 需要 Developer ID 签名、notarization、Network Extension entitlement、system extension 打包和明确用户授权。App Store 与站外发行能力配置分别验证。
- Linux 只向 helper 授予所需能力，通常为 `CAP_NET_ADMIN`，以及具体实现需要时的 `CAP_BPF`。GUI 永远不以 root 运行。
- 本地控制 API 拒绝除 Prism session 所属交互用户和已安装 service 身份以外的非特权用户。

## 最小交付顺序

1. 规范并测试 captured-UDP API、policy generation、helper health 和事务语义。把 PID 查询移出 Core 的生产数据包路径，同时把 legacy preview 保留在显式模式后。
2. 首先交付 Windows x64 和 ARM64 WFP 接管 MVP。Wintun 目标路由必须清晰标记为 legacy preview。
3. 交付 Linux cgroup 启动模式、nftables 标记、policy routing、bypass 和崩溃清理。通过 race 测试后再增加附加已运行进程。
4. 完成 macOS Network Extension 身份与发行可行性样机。只有 P0 身份和旁路标准得到证明后才规划正式实现。
5. 平台基础通过 P0 后，再增加 Steam 自动化、运行中进程附加、策略迁移、multipath 接口集成和现场遥测。

## P0 验收标准

1. 两个进程并发使用相同目标和端口时，只有选中进程进入 TGP，另一个保持直连。
2. IPv4、IPv6、connected UDP 和 unconnected UDP 全部通过平台测试套件。
3. 选中进程可访问快速变化的公网目标，无需更新 CIDR。
4. 游戏 TCP、系统 DNS、loopback、LAN、Core、Prism、helper、Xray 和 Relay transport 都不进入 TGP。
5. 强制结束 Prism、Core 或 helper 后，系统在一秒内恢复直连，且不残留 WFP filter、nftables 对象、policy rule、route、adapter 或 active policy generation。
6. 连续启停一百次并替换策略一千次后，不存在重复 filter、旧 generation、泄漏 handle 或路由状态。
7. 以每秒 5,000 个 UDP 数据报持续 30 分钟时，主机接管层不丢包，本地附加延迟 P99 不超过 1 ms，并报告全部 drop 和 bypass 决策。
8. Steam 子进程、二进制更新、普通与管理员 session、睡眠恢复、接口变化和 helper 升级都有自动化测试。
9. 安装、升级、回滚和卸载会恢复完全一致的先前 OS 网络状态，包括在每个事务阶段强制结束进程后的恢复。
10. macOS 在经过签名、notarized、未受管理的桌面构建中证明稳定来源身份之前，不能通过按进程里程碑。

## 后果

本设计把 PID 反查和宽泛目标路由移出正常 Core 数据包路径。动态游戏 endpoint 成为按进程选择的自然结果；非游戏流量因为从未被接管而保持安全。

代价是规模较大的平台集成和签名工作。Windows 需要生产质量 WFP 组件，macOS 依赖 Network Extension 能力与发行验证，Linux 需要被谨慎监管的特权网络状态。跨平台一致性由共同契约和验收测试定义，不要求所有操作系统强行使用 TUN。

## 被拒绝的替代方案

### 目标 CIDR 加 TUN

拒绝作为目标架构。它无法区分共享目标的不同进程，需要持续发现 endpoint，也无法把误接管数据包安全送回相同路由。该方案只保留为 legacy preview。

### 全局 TUN 加 Core PID 反查

拒绝。归属判定发生过晚，可能存在歧义，缓存未命中时开销高，并迫使 Core 负责原生转发和环路防护。

### 把平台驱动放入 Tachyon Core

拒绝。这会混合特权 OS 策略和 TGP transport，破坏移动端可移植性，并让 Core release 依赖平台签名。

### 把平台逻辑放入 Prism UI 组件

拒绝。UI reload、renderer 故障和前端更新不能持有特权网络状态。

## 参考资料

- [Microsoft：Application Layer Enforcement](https://learn.microsoft.com/en-us/windows/win32/fwp/application-layer-enforcement--ale-)
- [Microsoft：Using Bind or Connect Redirection](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection)
- [Microsoft：WFP Dynamic Sessions](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0)
- [Apple：NETransparentProxyProvider](https://developer.apple.com/documentation/networkextension/netransparentproxyprovider)
- [Apple：Network Extension Provider Deployment](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)
- [Apple：Network Extensions Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking/networkextension)
- [nftables：socket cgroupv2 expression](https://netfilter.org/projects/nftables/manpage.html)
- [Linux kernel：BPF program types and cgroup hooks](https://docs.kernel.org/bpf/libbpf/program_types.html)
