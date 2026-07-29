[CmdletBinding()]
param(
    [string]$BinaryPath = "",
    [switch]$RunServiceSIDHarness,
    [switch]$RunGoHarness
)

$ErrorActionPreference = "Stop"
$scriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptRoot)) {
    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}
if ([string]::IsNullOrWhiteSpace($BinaryPath)) {
    $BinaryPath = Join-Path $scriptRoot "..\tachyon-core.exe"
}

if ($RunGoHarness) {
    # Includes the real Windows ACL denial for a wrong SID and the low
    # integrity rejection policy. No packet source is enabled by these tests.
    & mise exec -- go test ./internal/capturedudp -run "TestWindowsNamedPipe(WrongSIDIsDeniedByACL|RejectsLowIntegrityPolicy|MatchesEnabledServiceGroup)$" -count=1
    if ($LASTEXITCODE -ne 0) { throw "Windows identity harness failed with exit code $LASTEXITCODE" }
}

if ($RunServiceSIDHarness) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "The temporary Service SID harness requires an elevated PowerShell session."
    }
    $scPath = Join-Path $env:WINDIR "System32\sc.exe"
    if (-not (Test-Path -LiteralPath $scPath)) { throw "System32 sc.exe was not found." }
    $resolvedBinary = (Resolve-Path -LiteralPath $BinaryPath).Path
    $name = "TachyonHelperHarness-$([guid]::NewGuid().ToString('N'))"
    if ($name -notmatch '^[A-Za-z0-9_.-]{1,80}$' -or (Get-Service -Name $name -ErrorAction SilentlyContinue)) { throw "temporary service name validation failed" }
    $corePipe = "\\.\pipe\Tachyon\harness-core-$PID"
    $diag = Join-Path $env:TEMP "$name.json"
    $serverSID = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    $coreProcess = $null
    $trustedHash = (Get-FileHash -LiteralPath $resolvedBinary -Algorithm SHA256).Hash.ToLowerInvariant()
    Remove-Item -LiteralPath $diag -Force -ErrorAction SilentlyContinue
    $quotedBinary = [char]34 + $resolvedBinary + [char]34
    $quotedTrustedBinary = [char]34 + $resolvedBinary + [char]34
    $image = "$quotedBinary helper --service --service-name $name --pipe $corePipe --server-sid $serverSID --core-binary $quotedTrustedBinary --core-sha256 $trustedHash --diagnostic-file $diag --diagnostic-test-override"
    try {
        & $scPath create $name binPath= $image start= demand obj= "NT AUTHORITY\LocalService" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "temporary service creation failed" }
        & $scPath sidtype $name restricted | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "temporary service SID setup failed" }
        $serviceSID = ""
        $showSID = (& $scPath showsid $name | Out-String)
        if ($showSID -match 'S-1-5-80-[0-9-]+') { $serviceSID = $Matches[0] }
        if ([string]::IsNullOrWhiteSpace($serviceSID)) { throw "SCM did not expose a restricted Service SID" }
        $coreProcess = Start-Process -FilePath $resolvedBinary -ArgumentList @('helper', '--test-server', '--pipe', $corePipe, '--allow-sid', $serviceSID) -PassThru -WindowStyle Hidden
        Start-Sleep -Milliseconds 300
        & $scPath start $name | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "temporary service start failed" }
        $deadline = (Get-Date).AddSeconds(10)
        while (-not (Test-Path -LiteralPath $diag)) {
            if ((Get-Date) -gt $deadline) { throw "helper diagnostic file was not produced" }
            Start-Sleep -Milliseconds 100
        }
        do {
            $health = Get-Content -LiteralPath $diag -Raw | ConvertFrom-Json
            if ($health.pipe_connected -and $health.authenticated) { break }
            if ((Get-Date) -gt $deadline) { throw "helper did not complete Core pipe authentication" }
            Start-Sleep -Milliseconds 100
        } while ($true)
        if ($health.status -ne "not_ready") { throw "helper unexpectedly reported status '$($health.status)'" }
        if ($health.capture_provider -ne "not_ready") { throw "capture provider was not fail-closed" }
        if (-not $health.pipe_connected -or -not $health.authenticated) { throw "Core pipe was not authenticated" }
        if (-not $health.service_sid_present) { throw "temporary service token did not contain a service SID" }
        if ($health.restricted_sid_count -lt 1) { throw "temporary service token did not contain a restricted SID" }
        Write-Host "Temporary restricted Service SID harness passed; helper health is NotReady as required."
    }
    finally {
        try {
            & $scPath stop $name | Out-Null
            $stopDeadline = (Get-Date).AddSeconds(10)
            do {
                $service = Get-Service -Name $name -ErrorAction SilentlyContinue
                if ($null -eq $service -or $service.Status -eq 'Stopped') { break }
                Start-Sleep -Milliseconds 200
            } while ((Get-Date) -lt $stopDeadline)
            if ($null -ne (Get-Service -Name $name -ErrorAction SilentlyContinue) -and (Get-Service -Name $name).Status -ne 'Stopped') { throw "temporary service '$name' did not stop" }
            & $scPath delete $name | Out-Null
            $deleteDeadline = (Get-Date).AddSeconds(10)
            while (Get-Service -Name $name -ErrorAction SilentlyContinue) {
                if ((Get-Date) -gt $deleteDeadline) { throw "temporary service '$name' still exists after cleanup" }
                Start-Sleep -Milliseconds 200
            }
            if (Test-Path -LiteralPath $diag) {
                $stoppedHealth = Get-Content -LiteralPath $diag -Raw | ConvertFrom-Json
                if ($stoppedHealth.stop_timed_out) { throw "helper shutdown reported a timeout" }
                if ($stoppedHealth.provider_cleanup -ne 'confirmed') { throw "provider cleanup was not confirmed: $($stoppedHealth.provider_cleanup)" }
            }
        }
        finally {
            if ($null -ne $coreProcess) {
                if (-not $coreProcess.HasExited) { Stop-Process -Id $coreProcess.Id -Force -ErrorAction SilentlyContinue }
                $coreProcess.WaitForExit(5000)
            }
            if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
                throw "temporary service '$name' still exists after cleanup"
            }
            Remove-Item -LiteralPath $diag -Force -ErrorAction SilentlyContinue
        }
    }
}

if (-not $RunServiceSIDHarness -and -not $RunGoHarness) {
    Write-Host "No harness selected. Use -RunServiceSIDHarness (administrator) and/or -RunGoHarness."
}
