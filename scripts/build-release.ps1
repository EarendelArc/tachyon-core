param(
    [string]$Tag = "",
    [string]$OutputDir = "",
    [switch]$MetadataOnly
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$gitSafeDirectory = "safe.directory=$($root.Replace('\', '/'))"

if ([string]::IsNullOrWhiteSpace($Tag)) {
    $Tag = (& git -c $gitSafeDirectory -C $root describe --tags --abbrev=0 2>$null)
    if ([string]::IsNullOrWhiteSpace($Tag)) {
        $Tag = "v0.0.0-local"
    }
    else {
        $Tag = $Tag.Trim()
    }
}

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path (Get-Location) "dist"
}

$releaseDir = Join-Path $OutputDir $Tag
$workDir = Join-Path $releaseDir "work"

$sourceCommit = (& git -c $gitSafeDirectory -C $root rev-parse --verify HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $sourceCommit -notmatch '^[0-9a-f]{40}([0-9a-f]{24})?$') {
    throw "could not resolve the source commit"
}

$null = & git -c $gitSafeDirectory -C $root show-ref --verify --quiet "refs/tags/$Tag"
if ($LASTEXITCODE -eq 0) {
    $tagCommit = (& git -c $gitSafeDirectory -C $root rev-parse --verify "$Tag^{commit}")
    $tagCommit = $tagCommit.Trim().ToLowerInvariant()
    if ($tagCommit -ne $sourceCommit) {
        throw "tag $Tag points to $tagCommit, but the working tree is at $sourceCommit"
    }
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

    $archiveInputs = @(Get-ChildItem -LiteralPath $targetDir -File | ForEach-Object { $_.FullName })
    [Array]::Sort($archiveInputs, [StringComparer]::Ordinal)
    foreach ($inputPath in $archiveInputs) {
        (Get-Item -LiteralPath $inputPath).LastWriteTimeUtc = $commitTime
    }

    $assetPath = Join-Path $releaseDir $assetName
    if (Test-Path -LiteralPath $assetPath) {
        Remove-Item -LiteralPath $assetPath -Force
    }
    Compress-Archive -LiteralPath $archiveInputs -DestinationPath $assetPath -CompressionLevel Optimal
    (Get-Item -LiteralPath $assetPath).LastWriteTimeUtc = $commitTime
    Write-Host "built $assetName"
}

Remove-Item -LiteralPath $workDir -Recurse -Force

& (Join-Path $PSScriptRoot "prepare-release.ps1") `
    -Version $Tag `
    -Commit $sourceCommit `
    -ReleaseDirectory $releaseDir

foreach ($metadataName in @("RELEASE_NOTES.md", "RELEASE_NOTES.zh-CN.md", "SHA256SUMS.txt")) {
    (Get-Item -LiteralPath (Join-Path $releaseDir $metadataName)).LastWriteTimeUtc = $commitTime
}

Write-Host "release assets written to $releaseDir (commit $sourceCommit, SOURCE_DATE_EPOCH=$sourceDateEpoch)"
