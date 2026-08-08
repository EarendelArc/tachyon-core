# 发布流程

Tachyon Core 由本仓库的 GitHub Actions 发布。当前发布线仍为 alpha，不能描述为
生产可用：WFP Helper 仍是预览实现，尚未验证真实进程捕获或真实游戏 E2E。

## 发布边界

下一版本按已验证提交准备为 `v0.1.0-alpha.24`，名称为 **WFP Helper / Captured UDP
Named Pipe v2 Preview（WFP Helper / 捕获 UDP Named Pipe v2 预览版）**。发布可以包含
Helper 与 Windows Service 的预览契约，但**不包含真实 WFP callout、不包含签名驱动、
不包含内核注入、不包含进程捕获，也没有真实游戏 E2E**。中英文 release notes 与
changelog 必须保持这些表述一致。

## 确定性资产

workflow 构建六个 ZIP：

- `tachyon-core_<tag>_windows_amd64.zip`
- `tachyon-core_<tag>_windows_arm64.zip`
- `tachyon-core_<tag>_darwin_amd64.zip`
- `tachyon-core_<tag>_darwin_arm64.zip`
- `tachyon-core_<tag>_linux_amd64.zip`
- `tachyon-core_<tag>_linux_arm64.zip`

同时发布 `RELEASE_NOTES.md`、`RELEASE_NOTES.zh-CN.md`、`BUILD_METADATA.json`、
`WINTUN_SIDECAR_CONTRACT.json`、`EVIDENCE_MANIFEST.json`、确定性的
`tachyon-helper-evidence_<tag>.tar.gz` 和 `SHA256SUMS.txt`。校验文件覆盖除自身外
的全部资产，共十二项。

`BUILD_METADATA.json` 记录版本、完整 commit、SOURCE_DATE_EPOCH、构建时间、Go 版本、
所有目标平台/架构，以及每个 ZIP 与其中二进制的 SHA-256。构建使用已验证提交的
commit time 作为 `SOURCE_DATE_EPOCH`，不使用 workflow 实时时钟生成发布元数据。

## Helper evidence

Windows CI job 会上传去敏 Helper evidence。release job 只下载同一成功 workflow run
产生的 evidence，并校验内部 manifest 的 commit、run 身份和文件 hash，拒绝疑似密钥
字段，再打包为确定性压缩包。`EVIDENCE_MANIFEST.json` 记录来源 commit、run 身份、
压缩包 hash 以及 fail-closed 的 `not_ready` 范围。它不能证明 WFP 捕获、进程归属、
内核注入或真实游戏 E2E。

## Wintun sidecar

Wintun 不由 Core 打包。Prism 负责外置 sidecar 供应链，并在启动前校验契约。release
workflow 会获取官方 Wintun 页面和压缩包，核对当前正式版及压缩包/DLL SHA-256，生成
`WINTUN_SIDECAR_CONTRACT.json`。任何版本、hash 或官方来源校验失败都会 fail-closed。
sidecar 缺失或不匹配时，Prism 必须拒绝启动 Core。

固定的 Wintun 0.14.1 DLL 大小为：Windows AMD64 `427552` 字节、Windows ARM64
`222488` 字节。两个 PowerShell 准备路径都调用与 CI 相同的官方生成器和 release validator。
离线 fixture 只允许 policy test 显式启用，不能绕过生产路径的网络验证。

## 发布门禁

远端 tag 门禁只接受 peeled commit 与已验证 checkout 一致的真正 annotated tag object；
即使 lightweight tag 正确指向目标 commit，也仍会被拒绝。

发布前必须满足：tag 已验证、Linux/Windows CI 全绿、六个 ZIP、双语 notes、全部 manifest
和严格 SHA-256 校验均通过。workflow 只创建一个 draft，只上传一次完整资产集，然后
发布该 draft。最后调用 `verify-published-release.sh`，检查：

- release 不是 draft、是 prerelease 且已 immutable；
- release 目标 commit 等于已验证 commit；
- 远端资产名称与本地资产集合完全一致；
- 远端资产大小和 GitHub digest 与本地文件一致。

`v*` tag 保护规则必须保持启用。不得替换已有 release，也不得修改 immutable release。
本地发布准备不创建或推送 tag。

本地构建器只接受已存在的 annotated tag，并要求其最终指向当前 `HEAD` 或显式传入的完整
commit。tag 缺失、lightweight tag 或 commit 不一致都会在构建前失败。

## 本地准备

本地 PowerShell 构建器只用于打包辅助。可发布候选必须携带经过验证的 CI evidence，
不能用本地伪造捕获结果宣称 release eligible。权威候选应通过 GitHub workflow 生成，
随后运行 policy tests 和跨平台构建检查，再由统筹者授权创建 tag。
