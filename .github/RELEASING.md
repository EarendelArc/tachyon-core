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

构建元数据和 ZIP 文件时间戳均来自已验证 commit 的 `SOURCE_DATE_EPOCH`，因此同一 commit 重构时不会把
workflow 的实时钟表时间写入二进制或归档。

## Bilingual metadata contract / 双语元数据契约

`v0.1.0-alpha.20` is a historical exception with an English-only automated body and no release-note
assets; it remains immutable. Later releases use `.github/scripts/prepare-release.sh` to generate
`RELEASE_NOTES.md` and `RELEASE_NOTES.zh-CN.md` deterministically from the verified tag and full
commit SHA. The GitHub Release body contains both files in English-then-Chinese order and never uses
GitHub automatic release-note generation.

`v0.1.0-alpha.20` 是历史例外，只有英文自动正文且没有 release notes 资产，并将保持不可变。
后续 release 使用 `.github/scripts/prepare-release.sh`，根据已验证 tag 和完整 commit SHA
确定性生成 `RELEASE_NOTES.md` 与 `RELEASE_NOTES.zh-CN.md`。GitHub Release 正文按先英文、
后中文的顺序包含两份内容，且不使用 GitHub 自动生成 release notes。

`SHA256SUMS.txt` covers exactly the six platform ZIPs and both note files. Publication verifies every
entry before the first GitHub write, uploads both notes, the ZIPs, and the manifest exactly once to a
new draft, then publishes only that draft.

`SHA256SUMS.txt` 恰好覆盖六个平台 ZIP 和两份 notes。发布流程会在首次写入 GitHub 前校验
每个条目，将 notes、ZIP 和 manifest 一次性上传到新 draft，最后仅发布该 draft。

## Verification modes / 验证模式

- `signature`: `git verify-tag` successfully validates an annotated signed tag. A present but invalid
  or unverifiable signature fails closed.
- `ref-commit`: compatibility mode for the repository's existing lightweight or unsigned annotated
  tags. Signature authenticity is unavailable; publishing is allowed only after fetching the exact
  remote tag ref and proving that it peels to the expected checkout commit.
- `signature`：`git verify-tag` 已成功验证带签名的 annotated tag。标签存在签名但签名无效或无法验证时，
  流程会直接失败。
- `ref-commit`：兼容仓库现有的轻量标签或未签名 annotated tag。该模式不具备签名真实性保证；只有精确抓取
  远端标签 ref，并证明其最终指向预期 checkout commit 后才允许发布。

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
bash .github/scripts/test-release-policy.sh
```
