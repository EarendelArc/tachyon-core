[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [string]$Commit,

    [Parameter(Mandatory = $true)]
    [string]$ReleaseDirectory,

    [string]$TemplateDirectory = ""
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

$checksumNames = @("RELEASE_NOTES.md", "RELEASE_NOTES.zh-CN.md") + $zipNames
$checksumLines = foreach ($name in $checksumNames) {
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $ReleaseDirectory $name)).Hash.ToLowerInvariant()
    "${hash}  ${name}"
}
[System.IO.File]::WriteAllText(
    (Join-Path $ReleaseDirectory "SHA256SUMS.txt"),
    (($checksumLines -join "`n") + "`n"),
    $ascii
)

Write-Host "prepared deterministic bilingual release metadata for $Version at $Commit"
