[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$testdata = Join-Path $repoRoot ".github\testdata\release-metadata"
$fixtureDir = Join-Path $testdata "fixture"
$goldenDir = Join-Path $testdata "golden"
$prepareScript = Join-Path $repoRoot "scripts\prepare-release.ps1"
$buildScript = Join-Path $repoRoot "scripts\build-release.ps1"
$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("tachyon-release-policy-" + [guid]::NewGuid().ToString("N"))

function Fail {
    param([string]$Message)
    throw "Windows release policy test failed: $Message"
}

function Assert-SameFile {
    param(
        [string]$Actual,
        [string]$Expected
    )

    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Actual).Hash
    $expectedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Expected).Hash
    if ($actualHash -ne $expectedHash) {
        Fail "$([System.IO.Path]::GetFileName($Actual)) differs from the shared golden file"
    }
}

try {
    New-Item -ItemType Directory -Path $tempDir | Out-Null
    Copy-Item -Path (Join-Path $fixtureDir "*") -Destination $tempDir
    Set-Content -LiteralPath (Join-Path $tempDir "BUILD_METADATA.json") -Value '{"schema_version":1}' -NoNewline
    Copy-Item -LiteralPath (Join-Path $repoRoot ".github\wintun\WINTUN_SIDECAR_CONTRACT.json") -Destination $tempDir
    Set-Content -LiteralPath (Join-Path $tempDir "EVIDENCE_MANIFEST.json") -Value '{"release_eligible":true}' -NoNewline
    [System.IO.File]::WriteAllBytes((Join-Path $tempDir "tachyon-helper-evidence_v9.8.7-alpha.6.tar.gz"), [byte[]](1, 2, 3))

    & $prepareScript `
        -Version "v9.8.7-alpha.6" `
        -Commit "0123456789abcdef0123456789abcdef01234567" `
        -ReleaseDirectory $tempDir

    foreach ($name in @("RELEASE_NOTES.md", "RELEASE_NOTES.zh-CN.md", "SHA256SUMS.txt")) {
        if (-not (Test-Path -LiteralPath (Join-Path $tempDir $name) -PathType Leaf)) {
            Fail "prepared release is missing $name"
        }
    }

    $manifestPath = Join-Path $tempDir "SHA256SUMS.txt"
    $manifestBytes = [System.IO.File]::ReadAllBytes($manifestPath)
    if ($manifestBytes.Length -ge 3 -and $manifestBytes[0] -eq 0xef -and $manifestBytes[1] -eq 0xbb -and $manifestBytes[2] -eq 0xbf) {
        Fail "checksum manifest must be ASCII without a BOM"
    }
    $manifest = [System.IO.File]::ReadAllText($manifestPath)
    if ($manifest.Contains("`r")) {
        Fail "checksum manifest must use LF line endings"
    }
    $manifestLines = @($manifest.TrimEnd("`n").Split("`n"))
    if ($manifestLines.Count -ne 12) {
        Fail "checksum manifest must contain exactly twelve entries"
    }
    foreach ($line in $manifestLines) {
        if ($line -notmatch '^[0-9a-f]{64}  (RELEASE_NOTES(\.zh-CN)?\.md|tachyon-core_v9\.8\.7-alpha\.6_(windows|darwin|linux)_(amd64|arm64)\.zip|BUILD_METADATA\.json|WINTUN_SIDECAR_CONTRACT\.json|EVIDENCE_MANIFEST\.json|tachyon-helper-evidence_v9\.8\.7-alpha\.6\.tar\.gz)$') {
            Fail "checksum manifest has an invalid GNU-format entry: $line"
        }
    }
    $englishNotes = [System.IO.File]::ReadAllText((Join-Path $tempDir "RELEASE_NOTES.md"))
    $chineseNotes = [System.IO.File]::ReadAllText((Join-Path $tempDir "RELEASE_NOTES.zh-CN.md"))
    foreach ($required in @(
        "WFP Helper / Captured UDP Named Pipe v2 Preview",
        "no real WFP callout",
        "no signed WFP driver",
        "no process capture",
        "no real game end-to-end (E2E) validation"
    )) {
        if (-not $englishNotes.Contains($required)) {
            Fail "English release notes are missing the alpha boundary: $required"
        }
    }
    if (-not $chineseNotes.Contains("WFP Helper / Captured UDP Named Pipe v2 Preview")) {
        Fail "Chinese release notes are missing the WFP Helper preview boundary"
    }

    Set-Content -LiteralPath (Join-Path $tempDir "unexpected.zip") -Value "unexpected"
    $failedAsExpected = $false
    try {
        & $prepareScript `
            -Version "v9.8.7-alpha.6" `
            -Commit "0123456789abcdef0123456789abcdef01234567" `
            -ReleaseDirectory $tempDir
    }
    catch {
        if ($_.Exception.Message -like '*exactly the six supported ZIP assets*') {
            $failedAsExpected = $true
        }
        else {
            throw
        }
    }
    if (-not $failedAsExpected) {
        Fail "unexpected ZIP asset was accepted"
    }

    $buildContent = [System.IO.File]::ReadAllText($buildScript)
    foreach ($required in @(
        'show -s --format=%ct $sourceCommit',
        '[DateTimeOffset]::FromUnixTimeSeconds($sourceDateEpoch)',
        '$env:SOURCE_DATE_EPOCH = $sourceDateEpochText',
        'LastWriteTimeUtc = $commitTime',
        'prepare-release.ps1'
    )) {
        if (-not $buildContent.Contains($required)) {
            Fail "build-release.ps1 is missing deterministic behavior: $required"
        }
    }
    if ($buildContent.Contains('Get-Date')) {
        Fail "build-release.ps1 must not embed wall-clock time"
    }

    $metadata = & $buildScript -Tag "v0.0.0-policy-fixture" -MetadataOnly
    $gitSafeDirectory = "safe.directory=$($repoRoot.Replace('\', '/'))"
    $expectedCommit = (& git -c $gitSafeDirectory -C $repoRoot rev-parse --verify HEAD).Trim().ToLowerInvariant()
    $expectedEpoch = [long]((& git -c $gitSafeDirectory -C $repoRoot show -s --format=%ct $expectedCommit).Trim())
    $expectedBuildTime = [DateTimeOffset]::FromUnixTimeSeconds($expectedEpoch).UtcDateTime.ToString(
        "yyyy-MM-ddTHH:mm:ssZ",
        [System.Globalization.CultureInfo]::InvariantCulture
    )
    if ($metadata.Commit -ne $expectedCommit) {
        Fail "metadata-only mode did not resolve the current full commit"
    }
    if ($metadata.SourceDateEpoch -ne $expectedEpoch -or $env:SOURCE_DATE_EPOCH -ne $expectedEpoch.ToString()) {
        Fail "metadata-only mode did not derive SOURCE_DATE_EPOCH from commit time"
    }
    if ($metadata.BuildTime -ne $expectedBuildTime) {
        Fail "metadata-only mode did not derive BuildTime from commit time"
    }
}
finally {
    if (Test-Path -LiteralPath $tempDir) {
        Remove-Item -LiteralPath $tempDir -Recurse -Force
    }
}

Write-Host "Windows release policy tests passed"
