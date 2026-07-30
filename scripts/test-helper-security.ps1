[CmdletBinding()]
param(
    [string]$BinaryPath = "",
    [switch]$RunServiceSIDHarness,
    [switch]$RunGoHarness,
    [switch]$RunPathSecurityTests
)

$ErrorActionPreference = "Stop"
$scriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptRoot)) {
    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}
if ([string]::IsNullOrWhiteSpace($BinaryPath)) {
    $BinaryPath = Join-Path $scriptRoot "..\tachyon-core.exe"
}

function Get-HarnessRoot {
    param([string]$ProgramDataPath = $env:ProgramData)
    if ([string]::IsNullOrWhiteSpace($ProgramDataPath)) { throw "ProgramData is required for the Service SID harness." }
    return Join-Path $ProgramDataPath "Tachyon\Harness"
}

function Assert-NoReparsePointPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($full)
    $relative = $full.Substring($root.Length).TrimStart('\', '/')
    $current = $root
    foreach ($part in ($relative -split '[\\/]' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
        $current = Join-Path $current $part
        if (-not (Test-Path -LiteralPath $current)) { continue }
        if ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Harness path contains a reparse point: $current"
        }
    }
}

function Assert-HarnessDiagnosticPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$ProgramDataPath = $env:ProgramData
    )
    $root = [IO.Path]::GetFullPath((Get-HarnessRoot $ProgramDataPath)).TrimEnd([char]'\', [char]'/')
    $full = [IO.Path]::GetFullPath($Path)
    $prefix = $root + [IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Diagnostic path escapes the protected harness root."
    }
    $relative = $full.Substring($prefix.Length)
    $parts = $relative -split '[\\/]'
    if ($parts.Count -ne 2 -or $parts[0] -notmatch '^[0-9a-fA-F]{32}$' -or -not [string]::Equals($parts[1], 'helper-health.json', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Diagnostic path must be Harness\\<GUID>\\helper-health.json."
    }
    return $full
}

function Resolve-ServiceSID {
    param(
        [Parameter(Mandatory = $true)][string]$ScPath,
        [Parameter(Mandatory = $true)][string]$ServiceName
    )
    $showSID = (& $ScPath showsid $ServiceName | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "sc.exe showsid failed with exit code $LASTEXITCODE" }
    if ($showSID -notmatch 'S-1-5-80-[0-9-]+') { throw "SCM did not expose a restricted Service SID" }
    return $Matches[0]
}

function New-ProtectedHarnessDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$HarnessID,
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [Parameter(Mandatory = $true)][string]$ServiceSID
    )
    if ($HarnessID -notmatch '^[0-9a-f]{32}$') { throw "Harness GUID validation failed." }
    $serviceAccountSID = [Security.Principal.NTAccount]::new('NT SERVICE', $ServiceName).Translate([Security.Principal.SecurityIdentifier])
    if ($serviceAccountSID.Value -ne $ServiceSID) { throw "NT SERVICE account SID does not match SCM Service SID." }
    $root = Get-HarnessRoot
    $directory = Join-Path $root $HarnessID
    $diagnostic = Assert-HarnessDiagnosticPath (Join-Path $directory 'helper-health.json')
    foreach ($path in @((Split-Path -Parent $root), $root, $directory)) {
        if (-not (Test-Path -LiteralPath $path)) { New-Item -ItemType Directory -LiteralPath $path -Force | Out-Null }
        Assert-NoReparsePointPath $path
    }

    $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $none = [Security.AccessControl.PropagationFlags]::None
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $rules = @(
        [PSCustomObject]@{ SID = [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalSystemSid, $null); Rights = [Security.AccessControl.FileSystemRights]::FullControl },
        [PSCustomObject]@{ SID = [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null); Rights = [Security.AccessControl.FileSystemRights]::FullControl },
        [PSCustomObject]@{ SID = [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalServiceSid, $null); Rights = [Security.AccessControl.FileSystemRights]::Modify },
        [PSCustomObject]@{ SID = $serviceAccountSID; Rights = [Security.AccessControl.FileSystemRights]::Modify }
    )
    foreach ($rule in $rules) {
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($rule.SID, $rule.Rights, $inherit, $none, [Security.AccessControl.AccessControlType]::Allow))
    }
    Set-Acl -LiteralPath $directory -AclObject $security
    Assert-NoReparsePointPath $directory
    $applied = Get-Acl -LiteralPath $directory
    if (-not $applied.AreAccessRulesProtected) { throw "Harness ACL unexpectedly inherits parent permissions." }
    foreach ($expected in $rules) {
        $matched = $false
        foreach ($accessRule in $applied.Access) {
            try { $sid = $accessRule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { continue }
            if ($sid -eq $expected.SID.Value -and $accessRule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and (($accessRule.FileSystemRights -band $expected.Rights) -eq $expected.Rights)) {
                $matched = $true
                break
            }
        }
        if (-not $matched) { throw "Harness ACL is missing required access for SID $($expected.SID.Value)." }
    }
    return [PSCustomObject]@{ Directory = $directory; Diagnostic = $diagnostic }
}

function Invoke-ScDiagnostic {
    param(
        [Parameter(Mandatory = $true)][string]$ScPath,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    $output = & $ScPath @Arguments 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    Write-Host "sc.exe $Label exit code: $exitCode"
    if (-not [string]::IsNullOrWhiteSpace($output)) { Write-Host $output.TrimEnd() }
    return $exitCode
}

function Write-SafeHarnessFailureDiagnostics {
    param(
        [Parameter(Mandatory = $true)][string]$ScPath,
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [string]$DiagnosticPath = ""
    )
    Write-Warning "Helper Service SID harness failed. Emitting non-secret service diagnostics."
    [void](Invoke-ScDiagnostic $ScPath 'query' @('query', $ServiceName))
    [void](Invoke-ScDiagnostic $ScPath 'qc' @('qc', $ServiceName))
    if (-not [string]::IsNullOrWhiteSpace($DiagnosticPath) -and (Test-Path -LiteralPath $DiagnosticPath)) {
        try {
            $health = Get-Content -LiteralPath $DiagnosticPath -Raw | ConvertFrom-Json
            $safe = [ordered]@{
                status = $health.status; capture_provider = $health.capture_provider; pipe_connected = $health.pipe_connected
                authenticated = $health.authenticated; lifecycle = $health.lifecycle; stop_timed_out = $health.stop_timed_out
                provider_cleanup = $health.provider_cleanup; service_sid_present = $health.service_sid_present
                restricted_sid_count = $health.restricted_sid_count
            }
            Write-Host ("safe helper diagnostic: " + ($safe | ConvertTo-Json -Compress))
        }
        catch { Write-Warning "Diagnostic file exists but its safe public fields could not be parsed." }
    }
}

function Wait-HarnessServiceState {
    param([Parameter(Mandatory = $true)][string]$ServiceName, [Parameter(Mandatory = $true)][string]$State, [int]$TimeoutSeconds = 10)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($State -eq 'Deleted' -and $null -eq $service) { return $true }
        if ($State -eq 'Stopped' -and ($null -eq $service -or $service.Status -eq 'Stopped')) { return $true }
        Start-Sleep -Milliseconds 200
    } while ((Get-Date) -lt $deadline)
    return $false
}

function Invoke-HarnessPathSecurityTests {
    $programData = Join-Path ([IO.Path]::GetTempPath()) "tachyon-harness-path-$([guid]::NewGuid().ToString('N'))"
    try {
        $valid = Join-Path $programData "Tachyon\Harness\0123456789abcdef0123456789abcdef\helper-health.json"
        if ((Assert-HarnessDiagnosticPath $valid $programData) -ne [IO.Path]::GetFullPath($valid)) { throw "Valid harness path was not canonicalized." }
        foreach ($invalid in @(
            (Join-Path $programData "Tachyon\Harness\bad\helper-health.json"),
            (Join-Path $programData "Tachyon\Harness\0123456789abcdef0123456789abcdef\other.json"),
            (Join-Path $programData "Tachyon\Harness\0123456789abcdef0123456789abcdef\..\helper-health.json"),
            (Join-Path $programData "outside.json")
        )) {
            $accepted = $true
            try { [void](Assert-HarnessDiagnosticPath $invalid $programData) } catch { $accepted = $false }
            if ($accepted) { throw "Unsafe harness path was accepted: $invalid" }
        }
        Write-Host "Harness path security tests passed."
    }
    finally {
        Remove-Item -LiteralPath $programData -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($RunGoHarness) {
    & mise exec -- go test ./internal/capturedudp -run "TestWindowsNamedPipe(WrongSIDIsDeniedByACL|RejectsLowIntegrityPolicy|MatchesEnabledServiceGroup)$" -count=1
    if ($LASTEXITCODE -ne 0) { throw "Windows identity harness failed with exit code $LASTEXITCODE" }
}

if ($RunPathSecurityTests) { Invoke-HarnessPathSecurityTests }

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
    $harnessID = [guid]::NewGuid().ToString('N')
    $corePipe = "\\.\pipe\Tachyon\harness-core-$harnessID"
    $serverSID = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    $coreProcess = $null
    $harness = $null
    $trustedHash = (Get-FileHash -LiteralPath $resolvedBinary -Algorithm SHA256).Hash.ToLowerInvariant()
    $quotedBinary = [char]34 + $resolvedBinary + [char]34
    $quotedTrustedBinary = [char]34 + $resolvedBinary + [char]34
    $failure = $null
    $cleanupFailures = [System.Collections.Generic.List[string]]::new()
    try {
        & $scPath create $name binPath= "$quotedBinary helper --service --service-name $name --pipe $corePipe --server-sid $serverSID --core-binary $quotedTrustedBinary --core-sha256 $trustedHash" start= demand obj= "NT AUTHORITY\LocalService" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "temporary service creation failed with exit code $LASTEXITCODE" }
        & $scPath sidtype $name restricted | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "temporary service SID setup failed with exit code $LASTEXITCODE" }
        $serviceSID = Resolve-ServiceSID $scPath $name
        $harness = New-ProtectedHarnessDirectory $harnessID $name $serviceSID
        $image = "$quotedBinary helper --service --service-name $name --pipe $corePipe --server-sid $serverSID --core-binary $quotedTrustedBinary --core-sha256 $trustedHash --diagnostic-file $($harness.Diagnostic) --diagnostic-test-override"
        & $scPath config $name binPath= $image | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "temporary service configuration failed with exit code $LASTEXITCODE" }
        $coreProcess = Start-Process -FilePath $resolvedBinary -ArgumentList @('helper', '--test-server', '--pipe', $corePipe, '--allow-sid', $serviceSID) -PassThru -WindowStyle Hidden
        Start-Sleep -Milliseconds 300
        & $scPath start $name | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "temporary service start failed with exit code $LASTEXITCODE" }
        $deadline = (Get-Date).AddSeconds(10)
        while (-not (Test-Path -LiteralPath $harness.Diagnostic)) {
            if ((Get-Date) -gt $deadline) { throw "helper diagnostic file was not produced" }
            Start-Sleep -Milliseconds 100
        }
        do {
            $health = Get-Content -LiteralPath $harness.Diagnostic -Raw | ConvertFrom-Json
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
    catch {
        $failure = $_
        Write-SafeHarnessFailureDiagnostics $scPath $name $(if ($null -eq $harness) { "" } else { $harness.Diagnostic })
    }
    finally {
        try {
            if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
                [void](Invoke-ScDiagnostic $scPath 'stop' @('stop', $name))
                if (-not (Wait-HarnessServiceState $name 'Stopped')) { $cleanupFailures.Add("temporary service '$name' did not stop") }
                else {
                    [void](Invoke-ScDiagnostic $scPath 'delete' @('delete', $name))
                    if (-not (Wait-HarnessServiceState $name 'Deleted')) { $cleanupFailures.Add("temporary service '$name' was not deleted") }
                }
            }
        }
        catch { $cleanupFailures.Add("service cleanup failed: $($_.Exception.Message)") }
        if ($null -ne $coreProcess) {
            try {
                if (-not $coreProcess.HasExited) { Stop-Process -Id $coreProcess.Id -Force -ErrorAction Stop }
                [void]$coreProcess.WaitForExit(5000)
            }
            catch { $cleanupFailures.Add("test Core cleanup failed: $($_.Exception.Message)") }
        }
        if ($null -ne $harness -and (Test-Path -LiteralPath $harness.Directory)) {
            try {
                Assert-NoReparsePointPath $harness.Directory
                Remove-Item -LiteralPath $harness.Directory -Recurse -Force -ErrorAction Stop
                if (Test-Path -LiteralPath $harness.Directory) { $cleanupFailures.Add("harness directory '$($harness.Directory)' still exists") }
            }
            catch { $cleanupFailures.Add("harness directory cleanup failed: $($_.Exception.Message)") }
        }
        if (Get-Service -Name $name -ErrorAction SilentlyContinue) { $cleanupFailures.Add("temporary service '$name' still exists after cleanup") }
    }
    if ($null -ne $failure) { throw "Service SID harness failed: $($failure.Exception.Message)" }
    if ($cleanupFailures.Count -gt 0) {
        Write-SafeHarnessFailureDiagnostics $scPath $name $(if ($null -eq $harness) { "" } else { $harness.Diagnostic })
        throw "Service SID harness cleanup failed: $($cleanupFailures -join '; ')"
    }
}

if (-not $RunServiceSIDHarness -and -not $RunGoHarness -and -not $RunPathSecurityTests) {
    Write-Host "No harness selected. Use -RunServiceSIDHarness (administrator), -RunGoHarness, and/or -RunPathSecurityTests."
}
