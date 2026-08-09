# Tachyon Windows WFP 驱动

这是独立的 KMDF/WFP 驱动目标，不会链接进 Go 二进制。UI 无权访问设备；
设备 ACL 只允许 LocalSystem 和受限制的 `TachyonHelper` Service SID。

当前源码只是开发检查点。WDK 编译成功不能证明签名、安装、运行安全、延迟或
游戏链路正确。接收重注入尚未实现，因此 provider 会保持 `not_ready`。
任何 VM 测试前都必须阅读 `docs/windows-wfp-dataplane.md` 和
`docs/windows-wfp-dataplane.zh-CN.md`。
