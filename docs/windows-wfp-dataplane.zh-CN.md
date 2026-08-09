# Windows WFP 数据面状态

## 状态：未就绪 / NO-GO

当前 WFP 源码只是未签名的开发检查点。不得安装、加载、作为可用功能分发，
Prism 也不得启用它。Go 测试或 WDK 编译成功都不能单独证明内核运行安全。

接收方向重注入尚未实现。因此规范 ABI 不声明 `INJECT_RECEIVE`，Go provider
的回程注入固定返回 `ErrCaptureUnavailable`，健康状态绝不会报告 `ready`。
没有激活策略时，所有 classify 路径都保持 `FWP_ACTION_PERMIT`。

## 所有权模型

Packet 按 `Captured`、`Dequeued`、`Completing` 流转，最终只能进入一次
`Completed` 或 `Cancelled`。CAS 选出唯一 completion owner；pending 列表持有
基础引用，dequeue/completion 路径持有明确的局部引用，引用归零后才能释放。

用户态线性化模型并发竞争 dequeue、verdict、timeout、flush 和输出缓冲不足，
验证模型中只有一次终态、一次最终释放以及零剩余引用。它不能替代 Driver
Verifier 或 checked-kernel 虚拟机测试。

## 规范 ABI

`drivers/windows/wfp/include/tachyon_wfp_abi.h` 是唯一数值 ABI 来源。
`go generate ./internal/helper` 生成 `wfp_abi_generated.go`，CI 会拒绝生成后
出现差异。C 头同时定义固定 driver/helper build-id、规范 UTF-8 Helper Service
SID 及其 SHA-256、能力位、结构体与 IOCTL。C 构建通过 `_Static_assert` 校验
packed 布局。

## Helper 事务

未来只有能够如实报告 ready 的 provider 才会进入事务：Helper 并发运行捕获
与认证 Named Pipe，按 Core `PrepareGeneration`、WFP `ActivatePolicy`、Core
`CommitGeneration` 顺序激活。断连、组件失败、激活失败或关闭都会执行 WFP 与
Core disable，取消双方 goroutine 并等待退出。

## 尚缺证据

- 独立 WDK 工作流中的 x64、ARM64 成功编译。
- PREfast 与 InfVerif 全部通过。
- Driver Verifier、checked-kernel、强制取消、卸载及低内存 VM 测试。
- 带校验和、endpoint、compartment 和 anti-loop 验证的真实接收重注入。
- 测试签名、安装、升级、回滚和卸载流程。
- 持续 backpressure 与真实游戏流量性能证据。

以上全部关闭前，发布结论始终是 **NO-GO**。
