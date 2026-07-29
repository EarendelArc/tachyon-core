# Windows Helper 安全边界

## 范围

tachyon-core helper --console 与 tachyon-core helper --service 是同一二进制
的两种启动方式。Helper 是 Captured UDP Named Pipe v2 的客户端，Core 仍是
认证后的协议端点。Helper 已覆盖 Hello/token、Ping/Pong、generation 事务、
flow lease、datagram 以及 delivery 映射；断管道会关闭连接，待处理请求和
缓冲有硬上限，重连使用指数退避，会清零会话 token 与帧缓冲。

默认 CaptureProvider 明确 fail-closed：status=not_ready、能力为空且不会
产生 packet callback。因此 helper 不会伪造流量，也不会声称已具备捕获能力。

## Service 策略

scripts/install-helper-service.ps1 使用 LocalService 安装同一二进制，依赖
RpcSs，设置 restricted Service SID，限制服务管理权限，并设置崩溃自动恢复。
Core 的 Named Pipe ACL 必须只允许目标 restricted helper/service SID；Service
安装不会启用 allow_insecure_user_sid。

~~~powershell
.\scripts\install-helper-service.ps1 -BinaryPath .\tachyon-core.exe
.\scripts\diagnose-helper-service.ps1
.\scripts\test-helper-security.ps1 -RunServiceSIDHarness
.\scripts\test-helper-security.ps1 -RunGoHarness
.\scripts\uninstall-helper-service.ps1
~~~

临时 Service SID harness 需要管理员 PowerShell。它不构建或加载驱动，只从
同一二进制启动测试专用 Core Named Pipe 端点，并验证 Service SID ACL、服务端
路径和哈希身份、token 认证、断线后的健康状态以及必须保持的 NotReady 状态。
即使失败也会停止并删除唯一的临时 SCM 服务。Go harness 覆盖错误 SID ACL
拒绝、低完整性拒绝和启用的 service group 匹配。需要特权测试的 CI 或发布机
必须把管理员 harness 缺失视为门禁失败。

## 威胁模型

Helper 被视为特权边界；在操作系统管道身份和 ACL 验证以前，Core 也被视为
不可信。协议拒绝过期 token、请求 ID 重放、无效 flow identity、过期
generation、超大帧和资源耗尽。Delivery 只能来自认证后的 Core 会话，再进入
Injector 契约；默认 Injector 会拒绝注入。

本版本不包含 WFP callout provider、签名驱动、WFP capture、进程捕获、内核
注入或可用的游戏加速实现。internal/helper 中的 WFP contract 只是版本化接口
契约。只有经过单独审查并签名的 provider 实现该契约后，Health 才允许变为
ready。
