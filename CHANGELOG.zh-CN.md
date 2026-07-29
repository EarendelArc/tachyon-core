# 更新日志

Tachyon Core 的版本变更记录。该文件与英文 `CHANGELOG.md` 同步维护。

## [未发布]

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
