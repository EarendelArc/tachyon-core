param(
    [Parameter(Mandatory = $true)]
    [string]$Tag,
    [string]$Commit = "",
    [string]$OutputDir = "",
    [switch]$MetadataOnly,
    [string]$EvidenceDirectory = "",
    [string]$EvidenceRunID = "0",
    [string]$EvidenceRunAttempt = "1",
    [string]$RepositoryRoot = "",
    [switch]$OfflineTestFixture
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Join-Path $PSScriptRoot ".."
}
$root = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$gitSafeDirectory = "safe.directory=$($root.Replace('\', '/'))"

if ($Tag -notmatch '^v[0-9A-Za-z][0-9A-Za-z._-]*$') {
    throw "release build failed: invalid release tag"
}

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path (Get-Location) "dist"
}

$releaseDir = Join-Path $OutputDir $Tag
$workDir = Join-Path $releaseDir "work"

$headCommit = ([string](& git -c $gitSafeDirectory -C $root rev-parse --verify HEAD 2>$null)).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $headCommit -notmatch '^[0-9a-f]{40}([0-9a-f]{24})?$') {
    throw "could not resolve the source commit"
}

if ([string]::IsNullOrWhiteSpace($Commit)) {
    $sourceCommit = $headCommit
}
else {
    $Commit = $Commit.ToLowerInvariant()
    if ($Commit -notmatch '^[0-9a-f]{40}([0-9a-f]{24})?$') {
        throw "release build failed: specified commit must be a full Git object ID"
    }
    $sourceCommit = ([string](& git -c $gitSafeDirectory -C $root rev-parse --verify "$Commit^{commit}" 2>$null)).Trim().ToLowerInvariant()
    if ($LASTEXITCODE -ne 0 -or $sourceCommit -ne $Commit) {
        throw "release build failed: specified commit could not be resolved exactly"
    }
    if ($sourceCommit -ne $headCommit) {
        throw "release build failed: specified commit $sourceCommit does not match checked-out HEAD $headCommit"
    }
}

$null = & git -c $gitSafeDirectory -C $root show-ref --verify --quiet "refs/tags/$Tag"
if ($LASTEXITCODE -ne 0) {
    throw "release build failed: tag $Tag does not exist"
}
$tagType = ([string](& git -c $gitSafeDirectory -C $root cat-file -t "refs/tags/$Tag" 2>$null)).Trim()
if ($LASTEXITCODE -ne 0 -or $tagType -ne "tag") {
    throw "release build failed: tag $Tag must be an annotated tag"
}
$tagCommit = ([string](& git -c $gitSafeDirectory -C $root rev-parse --verify "$Tag^{commit}" 2>$null)).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $tagCommit -ne $sourceCommit) {
    throw "release build failed: tag $Tag points to $tagCommit, expected $sourceCommit"
}

if ($OfflineTestFixture -and $env:TACHYON_RELEASE_POLICY_TEST -ne "1") {
    throw "release build failed: offline Wintun mode is restricted to explicit release policy tests"
}

$sourceDateEpochText = (& git -c $gitSafeDirectory -C $root show -s --format=%ct $sourceCommit).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceDateEpochText -notmatch '^[0-9]+$') {
    throw "could not resolve SOURCE_DATE_EPOCH from commit $sourceCommit"
}
$sourceDateEpoch = [long]$sourceDateEpochText
$commitTime = [DateTimeOffset]::FromUnixTimeSeconds($sourceDateEpoch).UtcDateTime
$buildTime = $commitTime.ToString("yyyy-MM-ddTHH:mm:ssZ", [System.Globalization.CultureInfo]::InvariantCulture)
$env:SOURCE_DATE_EPOCH = $sourceDateEpochText

if ($MetadataOnly) {
    [pscustomobject]@{
        Version = $Tag
        Commit = $sourceCommit
        SourceDateEpoch = $sourceDateEpoch
        BuildTime = $buildTime
    }
    return
}

if ([string]::IsNullOrWhiteSpace($EvidenceDirectory) -or -not (Test-Path -LiteralPath $EvidenceDirectory -PathType Container)) {
    throw "release candidate preparation requires a validated CI Helper evidence directory; pass -EvidenceDirectory or use the GitHub Release workflow"
}

$goCommand = (Get-Command go -ErrorAction SilentlyContinue)
if ($goCommand) {
    $goExecutable = $goCommand.Source
}
else {
    $goVersionFromTools = $null
    $toolVersionsPath = Join-Path $root ".tool-versions"
    if (Test-Path -LiteralPath $toolVersionsPath) {
        $goLine = Get-Content -LiteralPath $toolVersionsPath |
            Where-Object { $_ -match '^\s*go\s+(.+?)\s*$' } |
            Select-Object -First 1
        if ($goLine -match '^\s*go\s+(.+?)\s*$') {
            $goVersionFromTools = $Matches[1]
        }
    }

    if ($goVersionFromTools) {
        $candidate = Join-Path $env:USERPROFILE "AppData\Local\mise\installs\go\$goVersionFromTools\bin\go.exe"
        if (Test-Path -LiteralPath $candidate) {
            $goExecutable = $candidate
        }
    }

    if (-not $goExecutable) {
        $miseCommand = Get-Command mise -ErrorAction SilentlyContinue
        if (-not $miseCommand) {
            throw "go is not on PATH and mise is not available"
        }
        $miseGoRoot = (& mise exec -- go env GOROOT).Trim()
        if ([string]::IsNullOrWhiteSpace($miseGoRoot)) {
            throw "mise did not return a Go install path"
        }
        $goExecutable = Join-Path $miseGoRoot "bin\go.exe"
        if (-not (Test-Path -LiteralPath $goExecutable)) {
            $goExecutable = Join-Path $miseGoRoot "bin/go"
        }
    }

    if (-not (Test-Path -LiteralPath $goExecutable)) {
        throw "go executable not found"
    }
}

function Invoke-Go {
    param(
        [string[]]$Arguments
    )

    & $script:goExecutable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "go $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

$goVersion = ((Invoke-Go -Arguments @("version")) -split "\s+")[2]
$ldflags = "-s -w -X main.Version=$Tag -X main.BuildTime=$buildTime -X main.GoVersion=$goVersion"

$pythonCommand = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCommand) {
    $pythonCommand = Get-Command python3 -ErrorAction SilentlyContinue
}
if (-not $pythonCommand) {
    throw "python is required to generate deterministic release archives and manifests"
}
$pythonExecutable = $pythonCommand.Source

$targets = @(
    @{ GOOS = "windows"; GOARCH = "amd64"; AssetOS = "windows"; AssetArch = "amd64"; Ext = ".exe" },
    @{ GOOS = "windows"; GOARCH = "arm64"; AssetOS = "windows"; AssetArch = "arm64"; Ext = ".exe" },
    @{ GOOS = "darwin"; GOARCH = "amd64"; AssetOS = "darwin"; AssetArch = "amd64"; Ext = "" },
    @{ GOOS = "darwin"; GOARCH = "arm64"; AssetOS = "darwin"; AssetArch = "arm64"; Ext = "" },
    @{ GOOS = "linux"; GOARCH = "amd64"; AssetOS = "linux"; AssetArch = "amd64"; Ext = "" },
    @{ GOOS = "linux"; GOARCH = "arm64"; AssetOS = "linux"; AssetArch = "arm64"; Ext = "" }
)

New-Item -ItemType Directory -Force -Path $releaseDir | Out-Null
if (Test-Path -LiteralPath $workDir) {
    Remove-Item -LiteralPath $workDir -Recurse -Force
}

foreach ($target in $targets) {
    $assetName = "tachyon-core_${Tag}_$($target.AssetOS)_$($target.AssetArch).zip"
    $targetDir = Join-Path $workDir "$($target.AssetOS)-$($target.AssetArch)"
    New-Item -ItemType Directory -Force -Path $targetDir | Out-Null

    $env:CGO_ENABLED = "0"
    $env:GOOS = $target.GOOS
    $env:GOARCH = $target.GOARCH

    Invoke-Go -Arguments @("build", "-trimpath", "-ldflags", $ldflags, "-o", (Join-Path $targetDir "tachyon-core$($target.Ext)"), "./cmd/tachyon-core")
    Invoke-Go -Arguments @("build", "-trimpath", "-ldflags", $ldflags, "-o", (Join-Path $targetDir "tachyonctl$($target.Ext)"), "./cmd/tachyonctl")
    Copy-Item -LiteralPath (Join-Path $root "README.md") -Destination $targetDir
    Copy-Item -LiteralPath (Join-Path $root "README.zh-CN.md") -Destination $targetDir

    $assetPath = Join-Path $releaseDir $assetName
    if (Test-Path -LiteralPath $assetPath) {
        Remove-Item -LiteralPath $assetPath -Force
    }
    & $pythonExecutable (Join-Path $root ".github\scripts\deterministic_archive.py") `
        --format zip `
        --source-directory $targetDir `
        --output $assetPath `
        --source-date-epoch $sourceDateEpochText `
        --executable "tachyon-core$($target.Ext)" `
        --executable "tachyonctl$($target.Ext)"
    if ($LASTEXITCODE -ne 0) { throw "deterministic archive generation failed for $assetName" }
    (Get-Item -LiteralPath $assetPath).LastWriteTimeUtc = $commitTime
    Write-Host "built $assetName"
}

Remove-Item -LiteralPath $workDir -Recurse -Force

& $pythonExecutable (Join-Path $root ".github\scripts\generate-build-metadata.py") `
    --version $Tag `
    --commit $sourceCommit `
    --source-date-epoch $sourceDateEpochText `
    --build-time $buildTime `
    --go-version $goVersion `
    --release-directory $releaseDir `
    --output (Join-Path $releaseDir "BUILD_METADATA.json")
if ($LASTEXITCODE -ne 0) { throw "BUILD_METADATA.json generation failed" }

$wintunArguments = @(
    (Join-Path $root ".github\scripts\generate-wintun-contract.py"),
    "--output",
    (Join-Path $releaseDir "WINTUN_SIDECAR_CONTRACT.json")
)
if ($OfflineTestFixture) {
    $wintunArguments += "--offline-test-fixture"
}
else {
    $wintunArguments += "--verify-official"
}
& $pythonExecutable @wintunArguments
if ($LASTEXITCODE -ne 0) { throw "official Wintun contract generation failed" }

& $pythonExecutable (Join-Path $root ".github\scripts\generate-evidence-manifest.py") `
    --directory (Resolve-Path -LiteralPath $EvidenceDirectory).Path `
    --version $Tag `
    --commit $sourceCommit `
    --run-id $EvidenceRunID `
    --run-attempt $EvidenceRunAttempt `
    --source-date-epoch $sourceDateEpochText `
    --output-directory $releaseDir
if ($LASTEXITCODE -ne 0) { throw "Helper evidence manifest generation failed" }

& $pythonExecutable (Join-Path $root ".github\scripts\validate-release-assets.py") `
    --release-directory $releaseDir `
    --version $Tag `
    --commit $sourceCommit
if ($LASTEXITCODE -ne 0) { throw "release asset validation failed" }

& (Join-Path $PSScriptRoot "prepare-release.ps1") `
    -Version $Tag `
    -Commit $sourceCommit `
    -ReleaseDirectory $releaseDir `
    -PythonExecutable $pythonExecutable `
    -OfflineTestFixture:$OfflineTestFixture

foreach ($metadataName in @("RELEASE_NOTES.md", "RELEASE_NOTES.zh-CN.md", "BUILD_METADATA.json", "WINTUN_SIDECAR_CONTRACT.json", "EVIDENCE_MANIFEST.json", "tachyon-helper-evidence_${Tag}.tar.gz", "SHA256SUMS.txt")) {
    (Get-Item -LiteralPath (Join-Path $releaseDir $metadataName)).LastWriteTimeUtc = $commitTime
}

Write-Host "release assets written to $releaseDir (commit $sourceCommit, SOURCE_DATE_EPOCH=$sourceDateEpoch)"
