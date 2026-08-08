[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$goldenDir = Join-Path $repoRoot ".github\testdata\release-metadata\golden"
$prepareScript = Join-Path $repoRoot "scripts\prepare-release.ps1"
$buildScript = Join-Path $repoRoot "scripts\build-release.ps1"
$fixtureScript = Join-Path $repoRoot ".github\scripts\create-release-policy-fixtures.py"
$metadataScript = Join-Path $repoRoot ".github\scripts\generate-build-metadata.py"
$evidenceScript = Join-Path $repoRoot ".github\scripts\generate-evidence-manifest.py"
$pythonPolicyScript = Join-Path $repoRoot ".github\scripts\test-release-assets-policy.py"
$publishedPolicyScript = Join-Path $repoRoot ".github\scripts\test-published-release-policy.py"
$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("tachyon-release-policy-" + [guid]::NewGuid().ToString("N"))
$previousPolicyEnvironment = $env:TACHYON_RELEASE_POLICY_TEST

function Fail {
    param([string]$Message)
    throw "Windows release policy test failed: $Message"
}

function Assert-SameFile {
    param([string]$Actual, [string]$Expected)
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $Actual).Hash -ne
        (Get-FileHash -Algorithm SHA256 -LiteralPath $Expected).Hash) {
        Fail "$([System.IO.Path]::GetFileName($Actual)) differs from the shared golden file"
    }
}

function Expect-Failure {
    param([string]$Name, [string]$MessagePattern, [scriptblock]$Action)
    try {
        & $Action
    }
    catch {
        if ($_.Exception.Message -like $MessagePattern) {
            return
        }
        throw
    }
    Fail "$Name unexpectedly succeeded"
}

function Invoke-Python {
    param([string[]]$Arguments)
    & $script:pythonExecutable @Arguments
    if ($LASTEXITCODE -ne 0) {
        Fail "python command failed: $($Arguments -join ' ')"
    }
}

try {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCommand) { $pythonCommand = Get-Command python3 -ErrorAction SilentlyContinue }
    if (-not $pythonCommand) { Fail "python is required" }
    $pythonExecutable = $pythonCommand.Source
    $env:TACHYON_RELEASE_POLICY_TEST = "1"

    New-Item -ItemType Directory -Path $tempDir | Out-Null
    $releaseDir = Join-Path $tempDir "release"
    $evidenceDir = Join-Path $tempDir "evidence"
    $fixtureVersion = "v9.8.7-alpha.6"
    $fixtureCommit = "0123456789abcdef0123456789abcdef01234567"

    Invoke-Python @(
        $fixtureScript, "--release-dir", $releaseDir, "--evidence-dir", $evidenceDir,
        "--version", $fixtureVersion, "--commit", $fixtureCommit
    )
    Invoke-Python @(
        $metadataScript, "--version", $fixtureVersion, "--commit", $fixtureCommit,
        "--source-date-epoch", "0", "--build-time", "1970-01-01T00:00:00Z",
        "--go-version", "go1.test", "--release-directory", $releaseDir,
        "--output", (Join-Path $releaseDir "BUILD_METADATA.json")
    )
    Invoke-Python @(
        $evidenceScript, "--directory", $evidenceDir, "--version", $fixtureVersion,
        "--commit", $fixtureCommit, "--run-id", "1", "--run-attempt", "1",
        "--source-date-epoch", "0", "--output-directory", $releaseDir
    )

    & $prepareScript -Version $fixtureVersion -Commit $fixtureCommit `
        -ReleaseDirectory $releaseDir -PythonExecutable $pythonExecutable -OfflineTestFixture

    foreach ($name in @("RELEASE_NOTES.md", "RELEASE_NOTES.zh-CN.md", "SHA256SUMS.txt")) {
        Assert-SameFile -Actual (Join-Path $releaseDir $name) -Expected (Join-Path $goldenDir $name)
    }

    $manifestPath = Join-Path $releaseDir "SHA256SUMS.txt"
    $manifestBytes = [System.IO.File]::ReadAllBytes($manifestPath)
    if ($manifestBytes.Length -ge 3 -and $manifestBytes[0] -eq 0xef -and $manifestBytes[1] -eq 0xbb -and $manifestBytes[2] -eq 0xbf) {
        Fail "checksum manifest must be ASCII without a BOM"
    }
    $manifest = [System.IO.File]::ReadAllText($manifestPath)
    if ($manifest.Contains("`r")) { Fail "checksum manifest must use LF line endings" }
    $manifestLines = @($manifest.TrimEnd("`n").Split("`n"))
    if ($manifestLines.Count -ne 12) { Fail "checksum manifest must contain exactly twelve entries" }

    Set-Content -LiteralPath (Join-Path $releaseDir "unexpected.txt") -Value "unexpected"
    Expect-Failure "undeclared release asset" "*unexpected asset: unexpected.txt*" {
        & $prepareScript -Version $fixtureVersion -Commit $fixtureCommit `
            -ReleaseDirectory $releaseDir -PythonExecutable $pythonExecutable -OfflineTestFixture
    }
    Remove-Item -LiteralPath (Join-Path $releaseDir "unexpected.txt") -Force

    Invoke-Python @($pythonPolicyScript)
    Invoke-Python @($publishedPolicyScript)

    $gitRepo = Join-Path $tempDir "tag-policy-repo"
    git init --quiet --initial-branch=main $gitRepo
    git -C $gitRepo config user.name "Release Policy Test"
    git -C $gitRepo config user.email "release-policy@example.invalid"
    git -C $gitRepo config core.autocrlf false
    Set-Content -LiteralPath (Join-Path $gitRepo "payload.txt") -Value "first"
    git -C $gitRepo add payload.txt
    git -C $gitRepo commit --quiet -m "first"
    $firstCommit = (git -C $gitRepo rev-parse HEAD).Trim().ToLowerInvariant()
    git -C $gitRepo tag --annotate v1.0.0-wrong --message "wrong" $firstCommit
    Set-Content -LiteralPath (Join-Path $gitRepo "payload.txt") -Value "second"
    git -C $gitRepo commit --quiet -am "second"
    $expectedCommit = (git -C $gitRepo rev-parse HEAD).Trim().ToLowerInvariant()
    git -C $gitRepo tag --annotate v1.0.0-good --message "good" $expectedCommit
    git -C $gitRepo tag v1.0.0-light $expectedCommit

    Expect-Failure "missing tag" "*tag v1.0.0-missing does not exist*" {
        & $buildScript -Tag v1.0.0-missing -RepositoryRoot $gitRepo -MetadataOnly
    }
    Expect-Failure "lightweight tag" "*tag v1.0.0-light must be an annotated tag*" {
        & $buildScript -Tag v1.0.0-light -RepositoryRoot $gitRepo -MetadataOnly
    }
    Expect-Failure "wrong tag commit" "*tag v1.0.0-wrong points to $firstCommit, expected $expectedCommit*" {
        & $buildScript -Tag v1.0.0-wrong -RepositoryRoot $gitRepo -MetadataOnly
    }
    Expect-Failure "specified commit mismatch" "*does not match checked-out HEAD*" {
        & $buildScript -Tag v1.0.0-good -Commit $firstCommit -RepositoryRoot $gitRepo -MetadataOnly
    }

    $metadata = & $buildScript -Tag v1.0.0-good -Commit $expectedCommit -RepositoryRoot $gitRepo -MetadataOnly
    $expectedEpoch = [long]((git -C $gitRepo show -s --format=%ct $expectedCommit).Trim())
    $expectedBuildTime = [DateTimeOffset]::FromUnixTimeSeconds($expectedEpoch).UtcDateTime.ToString(
        "yyyy-MM-ddTHH:mm:ssZ", [System.Globalization.CultureInfo]::InvariantCulture
    )
    if ($metadata.Commit -ne $expectedCommit -or $metadata.SourceDateEpoch -ne $expectedEpoch -or
        $metadata.BuildTime -ne $expectedBuildTime) {
        Fail "metadata-only mode did not preserve the annotated tag/commit identity"
    }

    $buildContent = [System.IO.File]::ReadAllText($buildScript)
    foreach ($required in @(
        "must be an annotated tag", "generate-wintun-contract.py", "--verify-official",
        "validate-release-assets.py", "prepare-release.ps1"
    )) {
        if (-not $buildContent.Contains($required)) { Fail "build-release.ps1 is missing: $required" }
    }
    $prepareContent = [System.IO.File]::ReadAllText($prepareScript)
    foreach ($required in @("generate-wintun-contract.py", "--verify-official", "validate-release-assets.py", "unexpected asset")) {
        if (-not $prepareContent.Contains($required)) { Fail "prepare-release.ps1 is missing: $required" }
    }
}
finally {
    if ($null -eq $previousPolicyEnvironment) {
        Remove-Item Env:TACHYON_RELEASE_POLICY_TEST -ErrorAction SilentlyContinue
    }
    else {
        $env:TACHYON_RELEASE_POLICY_TEST = $previousPolicyEnvironment
    }
    if (Test-Path -LiteralPath $tempDir) {
        Remove-Item -LiteralPath $tempDir -Recurse -Force
    }
}

Write-Host "Windows release policy tests passed"
