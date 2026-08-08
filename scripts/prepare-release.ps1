[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [string]$Commit,

    [Parameter(Mandatory = $true)]
    [string]$ReleaseDirectory,

    [string]$TemplateDirectory = "",

    [string]$PythonExecutable = "",

    [switch]$OfflineTestFixture
)

$ErrorActionPreference = "Stop"

if ($Version -notmatch '^v[0-9A-Za-z][0-9A-Za-z._-]*$') {
    throw "release preparation failed: invalid release tag"
}

$Commit = $Commit.ToLowerInvariant()
if ($Commit -notmatch '^[0-9a-f]{40}([0-9a-f]{24})?$') {
    throw "release preparation failed: commit must be a full Git object ID"
}

if (-not (Test-Path -LiteralPath $ReleaseDirectory -PathType Container)) {
    throw "release preparation failed: release directory does not exist"
}
$ReleaseDirectory = (Resolve-Path -LiteralPath $ReleaseDirectory).Path
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if ([string]::IsNullOrWhiteSpace($PythonExecutable)) {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCommand) {
        $pythonCommand = Get-Command python3 -ErrorAction SilentlyContinue
    }
    if (-not $pythonCommand) {
        throw "release preparation failed: python is required for fail-closed release validation"
    }
    $PythonExecutable = $pythonCommand.Source
}
if (-not (Test-Path -LiteralPath $PythonExecutable -PathType Leaf)) {
    throw "release preparation failed: python executable does not exist"
}
if ($OfflineTestFixture -and $env:TACHYON_RELEASE_POLICY_TEST -ne "1") {
    throw "release preparation failed: offline Wintun mode is restricted to explicit release policy tests"
}

if ([string]::IsNullOrWhiteSpace($TemplateDirectory)) {
    $TemplateDirectory = Join-Path $PSScriptRoot "..\.github\release-notes"
}
if (-not (Test-Path -LiteralPath $TemplateDirectory -PathType Container)) {
    throw "release preparation failed: release note template directory does not exist"
}
$TemplateDirectory = (Resolve-Path -LiteralPath $TemplateDirectory).Path

$platforms = @(
    "windows_amd64",
    "windows_arm64",
    "darwin_amd64",
    "darwin_arm64",
    "linux_amd64",
    "linux_arm64"
)

$zipNames = @()
foreach ($platform in $platforms) {
    $asset = "tachyon-core_${Version}_${platform}.zip"
    if (-not (Test-Path -LiteralPath (Join-Path $ReleaseDirectory $asset) -PathType Leaf)) {
        throw "release preparation failed: required release asset is missing: $asset"
    }
    $zipNames += $asset
}

$actualZips = @(Get-ChildItem -LiteralPath $ReleaseDirectory -Filter "*.zip" -File)
if ($actualZips.Count -ne $zipNames.Count) {
    throw "release preparation failed: release directory must contain exactly the six supported ZIP assets"
}

$requiredInputNames = @(
    "BUILD_METADATA.json",
    "EVIDENCE_MANIFEST.json",
    "tachyon-helper-evidence_${Version}.tar.gz"
)
foreach ($name in $requiredInputNames) {
    if (-not (Test-Path -LiteralPath (Join-Path $ReleaseDirectory $name) -PathType Leaf)) {
        throw "release preparation failed: required release metadata asset is missing: $name"
    }
}

$auxiliaryNames = @(
    "BUILD_METADATA.json",
    "WINTUN_SIDECAR_CONTRACT.json",
    "EVIDENCE_MANIFEST.json",
    "tachyon-helper-evidence_${Version}.tar.gz"
)
$declaredNames = @($zipNames + $auxiliaryNames + @("RELEASE_NOTES.md", "RELEASE_NOTES.zh-CN.md", "SHA256SUMS.txt"))
$unexpectedNames = @(Get-ChildItem -LiteralPath $ReleaseDirectory -File | Where-Object { $declaredNames -notcontains $_.Name })
if ($unexpectedNames.Count -ne 0) {
    throw "release preparation failed: release directory contains an unexpected asset: $($unexpectedNames[0].Name)"
}

$wintunArguments = @(
    (Join-Path $repoRoot ".github\scripts\generate-wintun-contract.py"),
    "--output",
    (Join-Path $ReleaseDirectory "WINTUN_SIDECAR_CONTRACT.json")
)
if ($OfflineTestFixture) {
    $wintunArguments += "--offline-test-fixture"
}
else {
    $wintunArguments += "--verify-official"
}
& $PythonExecutable @wintunArguments
if ($LASTEXITCODE -ne 0) {
    throw "release preparation failed: official Wintun verification failed"
}

$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$ascii = [System.Text.ASCIIEncoding]::new()

function Write-RenderedTemplate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TemplatePath,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $content = [System.IO.File]::ReadAllText($TemplatePath)
    $content = $content.Replace("`r`n", "`n").Replace("`r", "`n")
    $content = $content.Replace("{{VERSION}}", $Version).Replace("{{COMMIT}}", $Commit)
    if ($content -match '{{(VERSION|COMMIT)}}') {
        throw "release preparation failed: release note template contains an unresolved placeholder: $([System.IO.Path]::GetFileName($TemplatePath))"
    }
    [System.IO.File]::WriteAllText($OutputPath, $content, $utf8NoBom)
}

Write-RenderedTemplate `
    -TemplatePath (Join-Path $TemplateDirectory "RELEASE_NOTES.md.tmpl") `
    -OutputPath (Join-Path $ReleaseDirectory "RELEASE_NOTES.md")
Write-RenderedTemplate `
    -TemplatePath (Join-Path $TemplateDirectory "RELEASE_NOTES.zh-CN.md.tmpl") `
    -OutputPath (Join-Path $ReleaseDirectory "RELEASE_NOTES.zh-CN.md")

& $PythonExecutable (Join-Path $repoRoot ".github\scripts\validate-release-assets.py") `
    --release-directory $ReleaseDirectory `
    --version $Version `
    --commit $Commit
if ($LASTEXITCODE -ne 0) {
    throw "release preparation failed: release asset validation failed"
}

$checksumNames = @("RELEASE_NOTES.md", "RELEASE_NOTES.zh-CN.md") + $zipNames + $auxiliaryNames
$checksumLines = foreach ($name in $checksumNames) {
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $ReleaseDirectory $name)).Hash.ToLowerInvariant()
    "${hash}  ${name}"
}
[System.IO.File]::WriteAllText(
    (Join-Path $ReleaseDirectory "SHA256SUMS.txt"),
    (($checksumLines -join "`n") + "`n"),
    $ascii
)

$actualNames = @(Get-ChildItem -LiteralPath $ReleaseDirectory -File | ForEach-Object { $_.Name } | Sort-Object)
$expectedNames = @($declaredNames | Sort-Object)
if (($actualNames -join "`n") -ne ($expectedNames -join "`n")) {
    throw "release preparation failed: release directory does not contain the exact declared asset set"
}
foreach ($name in $checksumNames) {
    $expectedHash = (($checksumLines | Where-Object { $_ -like "*  $name" }) -split '  ')[0]
    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $ReleaseDirectory $name)).Hash.ToLowerInvariant()
    if ($expectedHash -ne $actualHash) {
        throw "release preparation failed: checksum verification failed for $name"
    }
}

Write-Host "prepared deterministic bilingual release metadata for $Version at $Commit"
