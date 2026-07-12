param(
    [string]$Tag = "",
    [string]$OutputDir = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Tag)) {
    $Tag = (git describe --tags --abbrev=0 2>$null)
    if ([string]::IsNullOrWhiteSpace($Tag)) {
        $Tag = "v0.0.0-local"
    }
}

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path (Get-Location) "dist"
}

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$releaseDir = Join-Path $OutputDir $Tag
$workDir = Join-Path $releaseDir "work"
$buildTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

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

    $assetPath = Join-Path $releaseDir $assetName
    if (Test-Path -LiteralPath $assetPath) {
        Remove-Item -LiteralPath $assetPath -Force
    }
    Compress-Archive -Path (Join-Path $targetDir "*") -DestinationPath $assetPath -CompressionLevel Optimal
    Write-Host "built $assetName"
}

Remove-Item -LiteralPath $workDir -Recurse -Force

$checksumPath = Join-Path $releaseDir "SHA256SUMS.txt"
Get-ChildItem -LiteralPath $releaseDir -Filter "*.zip" |
    Sort-Object Name |
    ForEach-Object {
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant()
        "$hash  $($_.Name)"
    } |
    Set-Content -LiteralPath $checksumPath -Encoding ascii

Write-Host "release assets written to $releaseDir"
