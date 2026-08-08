# Release tag gate / 发布标签门禁

Every tag release is built from the commit selected by the verified remote tag. For a manual
`workflow_dispatch`, the selected branch commit and the input tag's peeled commit must be identical.
All test, build, and publish jobs then check out that full commit ID. The publish job repeats the
remote tag check immediately before updating GitHub Release assets and requires both the tag object
ID and peeled commit ID to remain unchanged.

每次标签发布都从已验证远端标签所指向的提交构建。手动触发 `workflow_dispatch` 时，所选分支提交必须与
输入标签最终指向的提交完全相同。测试、构建和发布 job 随后统一检出该完整 commit ID；发布 job 在更新
GitHub Release 资产前还会再次检查远端标签，并要求标签对象 ID 与最终提交 ID 均未发生变化。

Runs for the same tag share one non-cancelling concurrency group. A later run waits, then fails if
any GitHub Release (draft or published) already exists for that tag. Publishing creates a new draft,
uploads the complete asset set once without `--clobber`, and publishes that draft only after upload
succeeds. A failed run deletes its own incomplete draft when it can still prove that object is a
draft; it never edits, replaces, or deletes a published release.

同一标签的运行使用同一个不可取消的 concurrency 组。后续运行会等待，并在该标签已有任意 GitHub Release
（draft 或正式发布）时失败。发布流程新建 draft，不使用 `--clobber`，一次上传完整资产集合，上传成功后才
发布该 draft。失败时仅在仍能证明对象是 draft 的情况下清理本次未完成 draft；绝不编辑、替换或删除正式
release。

Build metadata and ZIP file timestamps come from the verified commit's `SOURCE_DATE_EPOCH`, so a
rebuild of the same commit does not embed the workflow wall clock in binaries or archives.

The local PowerShell builder requires an existing annotated tag. Missing tags, lightweight tags,
and tags that peel to a commit other than the checked-out `HEAD` or explicitly supplied full commit
fail closed before metadata or binaries are produced.

构建元数据和 ZIP 文件时间戳均来自已验证 commit 的 `SOURCE_DATE_EPOCH`，因此同一 commit 重构时不会把
workflow 的实时钟表时间写入二进制或归档。

本地 PowerShell 构建器要求 tag 已存在且必须是 annotated tag。tag 缺失、lightweight tag，或 tag
最终指向的 commit 与当前 `HEAD` 或显式传入的完整 commit 不一致时，都会在生成元数据或二进制前
fail-closed。

## Bilingual metadata contract / 双语元数据契约

`v0.1.0-alpha.20` is a historical exception with an English-only automated body and no release-note
assets; it remains immutable. Alpha.24 preparation is the **WFP Helper / Captured UDP Named Pipe v2
Preview** and explicitly makes no claim of a real WFP callout, signed driver, kernel injection,
process capture, or game E2E. Later releases use `.github/scripts/prepare-release.sh` to generate
`RELEASE_NOTES.md` and `RELEASE_NOTES.zh-CN.md` deterministically from the verified tag and full
commit SHA. The GitHub Release body contains both files in English-then-Chinese order and never uses
GitHub automatic release-note generation.

`v0.1.0-alpha.20` 是历史例外，只有英文自动正文且没有 release notes 资产，并将保持不可变。
Alpha.24 准备版本名称为 **WFP Helper / Captured UDP Named Pipe v2 Preview**，明确不声称
完成真实 WFP callout、签名驱动、内核注入、进程捕获或游戏 E2E。后续 release 使用 `.github/scripts/prepare-release.sh`，根据已验证 tag 和完整 commit SHA
确定性生成 `RELEASE_NOTES.md` 与 `RELEASE_NOTES.zh-CN.md`。GitHub Release 正文按先英文、
后中文的顺序包含两份内容，且不使用 GitHub 自动生成 release notes。

The GitHub Release contains exactly thirteen assets. `SHA256SUMS.txt` covers the six platform ZIPs,
both note files, `BUILD_METADATA.json`, `WINTUN_SIDECAR_CONTRACT.json`, `EVIDENCE_MANIFEST.json`,
and the sanitized Helper evidence archive: twelve entries, excluding the checksum file itself.
Publication verifies every entry before the first GitHub write, uploads the complete asset set exactly
once to a new draft, then publishes only that draft.

GitHub Release 固定包含十三项资产。`SHA256SUMS.txt` 覆盖除自身外的其余十二项；发布流程会在
首次写入 GitHub 前完成校验。

`SHA256SUMS.txt` 覆盖六个平台 ZIP、两份 notes、`BUILD_METADATA.json`、
`WINTUN_SIDECAR_CONTRACT.json`、`EVIDENCE_MANIFEST.json` 和去敏 Helper evidence 压缩包，
共十二项，不包含 checksum 文件自身。发布流程会在首次写入 GitHub 前校验每个条目，
将完整资产集合一次性上传到新 draft，最后仅发布该 draft。

CI's Bash generator and Windows-local `scripts/prepare-release.ps1` both render the shared templates
under `.github/release-notes`. The local `scripts/build-release.ps1` resolves the full current commit,
requires an existing requested tag to peel to that commit, and derives `SOURCE_DATE_EPOCH`, embedded
build time, and archive timestamps from the commit time. It does not require Bash or use wall-clock
metadata.

CI 的 Bash 生成器与 Windows 本地 `scripts/prepare-release.ps1` 都渲染
`.github/release-notes` 下的共享模板。本地 `scripts/build-release.ps1` 解析当前完整 commit，
要求已存在的指定 tag 最终指向该 commit，并从 commit time 派生 `SOURCE_DATE_EPOCH`、嵌入式
构建时间和归档时间戳；它不依赖 Bash，也不使用实时时钟元数据。

Both PowerShell release paths call the same Python Wintun generator with `--verify-official` and the
same release asset validator used by CI. The Wintun 0.14.1 contract pins archive SHA-256 plus DLL
SHA-256 and sizes: Windows AMD64 `427552` bytes and ARM64 `222488` bytes. Network, version, digest,
or size verification failures stop preparation. Offline generation is restricted to the explicit
policy-test fixture gate and is never a production fallback.

两个 PowerShell 发布路径都调用与 CI 相同的 Python Wintun 生成器（`--verify-official`）和发布资产
validator。Wintun 0.14.1 契约同时固定压缩包 SHA-256、DLL SHA-256 与大小：Windows AMD64
为 `427552` 字节，ARM64 为 `222488` 字节。网络、版本、digest 或 size 校验失败都会终止准备；
离线生成仅允许显式 policy-test fixture 使用，不能作为生产回退。

Both implementations must preserve the shared template and fixture policy in
`.github/testdata/release-metadata`. The manifest contract is twelve LF-terminated, BOM-free
GNU-format lines: the two notes, six platform ZIPs, four release metadata/evidence assets.

两种实现必须保持 `.github/testdata/release-metadata` 中的共享模板与 fixture policy。manifest
固定为十二行 LF 结尾、无 BOM 的 GNU 格式，包含两份 notes、六个平台 ZIP 和四份发布
元数据/evidence 资产。

## Verification modes / 验证模式

The current alpha pipeline is prerelease-only. Tag pushes and manual `workflow_dispatch` runs both
force `prerelease=true`; no manual formal-release input is exposed. The publisher rejects any other
value before its first GitHub API operation.

当前 alpha 管线只允许 prerelease。tag push 与手动 `workflow_dispatch` 均强制
`prerelease=true`，不暴露手动正式发布入口；publisher 会在首次调用 GitHub API 前拒绝其他值。

- `signature`: `git verify-tag` successfully validates an annotated signed tag. A present but invalid
  or unverifiable signature fails closed.
- `annotated-tag`: the fetched remote object is a real annotated tag object without a signature, and
  its peeled commit exactly matches the verified checkout. Lightweight tags are always rejected.
- `signature`：`git verify-tag` 已成功验证带签名的 annotated tag。标签存在签名但签名无效或无法验证时，
  流程会直接失败。
- `annotated-tag`：远端对象必须是真正的 annotated tag object；未签名时还必须证明其 peeled commit
  与已验证 checkout 完全一致。lightweight tag 一律拒绝。

## TOCTOU boundary / TOCTOU 边界

The workflow reverifies the remote tag object and peeled commit immediately before release API
operations. Without a GitHub tag ruleset that prevents tag updates and deletion, a privileged actor
can still move the tag after that final fetch and before publication completes. Workflow concurrency
does not protect refs changed outside this workflow. Enforce an immutable tag ruleset (and GitHub
immutable releases where available) to close that repository-side gap.

workflow 会在调用发布 API 前立即复验远端标签对象和最终 commit。若 GitHub 未配置禁止更新、删除标签的
tag ruleset，具备权限的操作者仍可能在最后一次 fetch 之后、发布完成之前移动标签；workflow concurrency
无法约束流程外的 ref 修改。要关闭这一仓库侧窗口，应启用不可变 tag ruleset，并在可用时启用 GitHub
immutable releases。

Run the policy checks locally with:

```bash
bash -n .github/scripts/verify-release-tag.sh
bash -n .github/scripts/prepare-release.sh
bash -n .github/scripts/publish-release.sh
bash -n .github/scripts/test-release-policy.sh
bash -n .github/scripts/verify-published-release.sh
bash .github/scripts/test-release-policy.sh
pwsh -NoProfile -File .github/scripts/test-build-release-policy.ps1
```
