# 更新日志

Tachyon Core 的版本变更记录。该文件与英文 `CHANGELOG.md` 同步维护。

## [未发布]

### v0.1.0-alpha.24 发布准备
- 将预览名称统一为 **WFP Helper / Captured UDP Named Pipe v2 Preview（WFP Helper / 捕获 UDP Named Pipe v2 预览版）**。
- 将确定性 `BUILD_METADATA.json`、去敏 Helper evidence manifest 以及外置 Wintun sidecar 契约纳入发布资产。
- 增加覆盖全部资产的严格 SHA-256 校验，以及发布后 immutable、资产集合和远端 digest 校验。
- 收紧本地发布准备：强制使用已存在且指向目标 commit 的 annotated tag，拒绝未声明资产，
  通过统一 Python 路径校验官方 Wintun DLL hash 与 size，并在官方验证不可用时 fail-closed。
- 移除远端 lightweight tag 兼容路径，并为 immutable release 身份、digest、size 与资产集合
  增加可持久复跑的负向 fixture。
- 明确发布边界：不包含真实 WFP callout、签名驱动、内核注入、进程捕获，也不声称完成真实游戏 E2E。

## [v0.1.0-alpha.23] - 2026-07-29

### 发布边界
- Alpha.23 是 **Captured UDP Named Pipe v2 Preview（捕获 UDP Named Pipe v2 预览版）**。
  本版本包含 Core 侧的认证 Named Pipe v2 契约、租约与注册表控制、TGP 桥接、
  生命周期清理，以及 single-writer 关闭竞态修复。
- 本预览版**不包含** helper、Windows Service、WFP callout、UDP 注入或真正的
  按进程捕获；游戏加速在本版本中不可用，也未经过真实游戏链路验证。

### 兼容性
- alpha.22 的旧 JSON/YAML 配置继续由 Core 加载；新增的
  `client.captured_udp` 在旧配置中默认保持 `disabled`。

### 后续说明
- 其余历史变更以英文 `CHANGELOG.md` 为完整记录；后续发布会继续在此文件补充对应中文条目。
