# Tachyon Core v9.8.7-alpha.6

## 发布标识

- 版本：`v9.8.7-alpha.6`
- 源代码提交：`0123456789abcdef0123456789abcdef01234567`
- 发布通道：alpha 预发布版

## 兼容性

- 支持 Windows、macOS 和 Linux 的 AMD64 或 ARM64 平台。
- 产物用于 Prism 托管下载与集成测试。
- Windows TUN 要求将 `wintun.dll` 放在 `tachyon-core.exe` 同目录；发布包不内置该 DLL。

## 安装

下载与目标操作系统和架构匹配的 ZIP。解压前必须完成校验，再通过 Prism 的托管二进制流程
安装 `tachyon-core` 与 `tachyonctl`。使用仓库内服务端安装脚本时，应固定到本次准确版本。

## 校验

下载所选 ZIP 的同时下载 `SHA256SUMS.txt`，并在安装前完成校验。完整下载全部资产后，
可在提供 GNU coreutils 的系统上运行 `sha256sum --check SHA256SUMS.txt`，校验六个 ZIP
以及 `RELEASE_NOTES.md`、`RELEASE_NOTES.zh-CN.md`。

## Alpha 预览边界

- `v9.8.7-alpha.6` 是 **Captured UDP Named Pipe v2 Preview（捕获 UDP Named Pipe v2 预览版）**，包含 Core 侧认证 Named Pipe v2 契约、租约与注册表控制、TGP 桥接、生命周期清理以及 single-writer 关闭竞态修复。
- 本预览版**不包含** helper、Windows Service、WFP callout、UDP 注入或真正的按进程捕获；游戏加速在本版本中不可用，也未经过真实游戏链路验证。

## Alpha 限制

- Tachyon Core 仍为 alpha 软件，尚不稳定，也不完整。
- Prism 托管的 alpha 流程默认禁用系统代理接管；Tachyon Core 不会修改宿主机代理设置。
- 客户端 TUN 自动路由和 DNS hijack 尚不受支持，并会被配置校验拒绝。
- 真实 VPS、真实客户端和真实游戏 UDP 加速路径仍需现场测试。
- Windows TUN 使用动态 `wintun.dll` 后端，仍需在具备管理员权限的真实主机上验证。
