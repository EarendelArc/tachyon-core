#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C

die() {
  echo "release preparation failed: $*" >&2
  exit 1
}

if [[ $# -ne 3 ]]; then
  die "usage: $0 <tag> <commit> <release-directory>"
fi

version=$1
commit=${2,,}
release_dir=$3

[[ "${version}" =~ ^v[0-9A-Za-z][0-9A-Za-z._-]*$ ]] || die "invalid release tag"
[[ "${commit}" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] || die "commit must be a full Git object ID"
[[ -d "${release_dir}" ]] || die "release directory does not exist"

platforms=(
  windows_amd64
  windows_arm64
  darwin_amd64
  darwin_arm64
  linux_amd64
  linux_arm64
)

zip_names=()
for platform in "${platforms[@]}"; do
  asset="tachyon-core_${version}_${platform}.zip"
  [[ -f "${release_dir}/${asset}" ]] || die "required release asset is missing: ${asset}"
  zip_names+=("${asset}")
done

shopt -s nullglob
actual_zips=("${release_dir}"/*.zip)
[[ ${#actual_zips[@]} -eq ${#zip_names[@]} ]] || \
  die "release directory must contain exactly the six supported ZIP assets"

cat > "${release_dir}/RELEASE_NOTES.md" <<EOF
# Tachyon Core ${version}

## Release identity

- Version: \`${version}\`
- Source commit: \`${commit}\`
- Channel: alpha prerelease

## Compatibility

- Windows, macOS, and Linux on AMD64 or ARM64.
- Artifacts are intended for Prism-managed downloads and integration testing.
- Windows TUN requires \`wintun.dll\` next to \`tachyon-core.exe\`; the DLL is not bundled.

## Installation

Download the ZIP matching the target OS and architecture. Verify it before extraction, then install
\`tachyon-core\` and \`tachyonctl\` through Prism's managed binary flow. Server deployments should
pin this exact version when using the repository's server installer.

## Verification

Download \`SHA256SUMS.txt\` with the selected ZIP and verify before installation. On systems with
GNU coreutils, \`sha256sum --check SHA256SUMS.txt\` verifies all six ZIP files plus
\`RELEASE_NOTES.md\` and \`RELEASE_NOTES.zh-CN.md\` when the complete asset set is present.

## Alpha limitations

- Tachyon Core is alpha software and is not stable or complete.
- System proxy takeover remains disabled by default in Prism-managed alpha flows; Tachyon Core does not modify host proxy settings.
- Client TUN auto-route and DNS hijack are unsupported and rejected by config validation.
- Real VPS, real client, and real game UDP acceleration paths still need field testing.
- Windows TUN uses a dynamic \`wintun.dll\` backend and still needs elevated-host validation.
EOF

cat > "${release_dir}/RELEASE_NOTES.zh-CN.md" <<EOF
# Tachyon Core ${version}

## 发布标识

- 版本：\`${version}\`
- 源代码提交：\`${commit}\`
- 发布通道：alpha 预发布版

## 兼容性

- 支持 Windows、macOS 和 Linux 的 AMD64 或 ARM64 平台。
- 产物用于 Prism 托管下载与集成测试。
- Windows TUN 要求将 \`wintun.dll\` 放在 \`tachyon-core.exe\` 同目录；发布包不内置该 DLL。

## 安装

下载与目标操作系统和架构匹配的 ZIP。解压前必须完成校验，再通过 Prism 的托管二进制流程
安装 \`tachyon-core\` 与 \`tachyonctl\`。使用仓库内服务端安装脚本时，应固定到本次准确版本。

## 校验

下载所选 ZIP 的同时下载 \`SHA256SUMS.txt\`，并在安装前完成校验。完整下载全部资产后，
可在提供 GNU coreutils 的系统上运行 \`sha256sum --check SHA256SUMS.txt\`，校验六个 ZIP
以及 \`RELEASE_NOTES.md\`、\`RELEASE_NOTES.zh-CN.md\`。

## Alpha 限制

- Tachyon Core 仍为 alpha 软件，尚不稳定，也不完整。
- Prism 托管的 alpha 流程默认禁用系统代理接管；Tachyon Core 不会修改宿主机代理设置。
- 客户端 TUN 自动路由和 DNS hijack 尚不受支持，并会被配置校验拒绝。
- 真实 VPS、真实客户端和真实游戏 UDP 加速路径仍需现场测试。
- Windows TUN 使用动态 \`wintun.dll\` 后端，仍需在具备管理员权限的真实主机上验证。
EOF

checksum_inputs=(RELEASE_NOTES.md RELEASE_NOTES.zh-CN.md "${zip_names[@]}")
(
  cd "${release_dir}"
  sha256sum --text "${checksum_inputs[@]}" > SHA256SUMS.txt
)

echo "prepared deterministic bilingual release metadata for ${version} at ${commit}"
