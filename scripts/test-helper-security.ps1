[CmdletBinding()]
param(
    [string]$BinaryPath = "",
    [switch]$RunServiceSIDHarness,
    [switch]$RunGoHarness,
    [switch]$RunPathSecurityTests,
    [switch]$RunProvisioningSecurityTests
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

function Resolve-VerifiedHarnessPath {
    param(
        [Parameter(Mandatory = $true)][string]$HarnessID,
        [string]$ProgramDataPath = $env:ProgramData
    )
    if ($HarnessID -notmatch '^[0-9a-f]{32}$') { throw "Harness GUID validation failed." }
    $programDataFull = [IO.Path]::GetFullPath($ProgramDataPath)
    $root = [IO.Path]::GetFullPath((Get-HarnessRoot $programDataFull))
    $directory = [IO.Path]::GetFullPath((Join-Path $root $HarnessID))
    $diagnostic = Assert-HarnessDiagnosticPath (Join-Path $directory 'helper-health.json') $programDataFull
    return [PSCustomObject]@{ Directory = $directory; Diagnostic = $diagnostic; ProgramData = $programDataFull }
}

function New-VerifiedHarnessPath {
    param(
        [Parameter(Mandatory = $true)][string]$HarnessID,
        [string]$ProgramDataPath = $env:ProgramData
    )
    $harness = Resolve-VerifiedHarnessPath $HarnessID $ProgramDataPath
    $root = Split-Path -Parent $harness.Directory
    $directory = $harness.Directory
    foreach ($path in @((Split-Path -Parent $root), $root, $directory)) {
        # Paths are derived from ProgramData plus a validated GUID. Directory's
        # API has no wildcard expansion and is supported by Windows PowerShell 5.1.
        Assert-NoReparsePointPath $path
        try { [void][IO.Directory]::CreateDirectory([IO.Path]::GetFullPath($path)) }
        catch { throw "Create protected harness directory failed: $($_.Exception.Message)" }
        Assert-NoReparsePointPath $path
    }
    return $harness
}

function New-ProtectedHarnessDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$HarnessID,
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [Parameter(Mandatory = $true)][string]$ServiceSID,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$OwnerSID
    )
    $serviceAccountSID = [Security.Principal.NTAccount]::new('NT SERVICE', $ServiceName).Translate([Security.Principal.SecurityIdentifier])
    if ($serviceAccountSID.Value -ne $ServiceSID) { throw "NT SERVICE account SID does not match SCM Service SID." }
    $harness = New-VerifiedHarnessPath $HarnessID
    $directory = $harness.Directory
    Set-PreprovisionedDiagnosticArtifacts $directory $harness.Diagnostic $serviceAccountSID $OwnerSID
    return $harness
}

function Get-DiagnosticLimitedRights {
    param([switch]$File)
    $rights = [Security.AccessControl.FileSystemRights]::ReadPermissions -bor [Security.AccessControl.FileSystemRights]::ReadAttributes
    if ($File) {
        $rights = $rights -bor [Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData
    }
    return [Security.AccessControl.FileSystemRights]$rights
}

function Get-DiagnosticExpectedMask {
    param([switch]$File)
    $localService = [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalServiceSid, $null)
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($localService, (Get-DiagnosticLimitedRights -File:$File), [Security.AccessControl.AccessControlType]::Allow)
    return [uint32]$rule.FileSystemRights
}

function Get-DiagnosticAccessRules {
    param([Parameter(Mandatory = $true)][System.Security.AccessControl.FileSystemSecurity]$ACL)
    # PowerShell 7's Access view can omit SIDs that have no account-name mapping.
    return $ACL.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
}

function Get-DiagnosticSIDAccessSummary {
    param(
        [Parameter(Mandatory = $true)][System.Security.AccessControl.FileSystemSecurity]$ACL,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$SID
    )
    $count = 0
    $mask = [uint32]0
    foreach ($accessRule in (Get-DiagnosticAccessRules $ACL)) {
        if ($accessRule.IdentityReference.Value -ne $SID.Value -or $accessRule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        $count++
        $mask = [uint32]($mask -bor [uint32]$accessRule.FileSystemRights)
    }
    return [PSCustomObject]@{ Count = $count; Mask = $mask }
}

function Get-RawDiagnosticSIDAccessSummary {
    param(
        [Parameter(Mandatory = $true)][string]$SDDL,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$SID
    )
    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($SDDL)
    $count = 0
    $mask = [uint32]0
    foreach ($ace in $descriptor.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.CommonAce] -or
            $ace.AceQualifier -ne [Security.AccessControl.AceQualifier]::AccessAllowed -or
            $ace.SecurityIdentifier.Value -ne $SID.Value) { continue }
        $count++
        $mask = [uint32]($mask -bor [uint32]$ace.AccessMask)
    }
    return [PSCustomObject]@{ Count = $count; Mask = $mask }
}

function New-ExactDiagnosticSecurity {
    param(
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$ServiceSID,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$OwnerSID,
        [switch]$File
    )
    $security = if ($File) { [Security.AccessControl.FileSecurity]::new() } else { [Security.AccessControl.DirectorySecurity]::new() }
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner($OwnerSID)
    $limitedRights = Get-DiagnosticLimitedRights -File:$File
    foreach ($rule in @(
        [Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalSystemSid, $null), [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow),
        [Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null), [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow),
        [Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalServiceSid, $null), $limitedRights, [Security.AccessControl.AccessControlType]::Allow),
        [Security.AccessControl.FileSystemAccessRule]::new($ServiceSID, $limitedRights, [Security.AccessControl.AccessControlType]::Allow)
    )) {
        $security.SetAccessRule($rule)
    }
    return $security
}

function Assert-ExactDiagnosticSecurityObject {
    param(
        [Parameter(Mandatory = $true)][System.Security.AccessControl.FileSystemSecurity]$ACL,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$ServiceSID,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$OwnerSID,
        [switch]$File,
        [switch]$SkipOwnerVerification
    )
    if ((-not $SkipOwnerVerification -and $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $OwnerSID.Value) -or -not $acl.AreAccessRulesProtected) {
        throw "Diagnostic owner or inheritance policy is not exact."
    }
    if (-not $acl.AreAccessRulesCanonical) { throw "Diagnostic ACL is not canonical." }
    $limitedRights = Get-DiagnosticExpectedMask -File:$File
    $expected = @{}
    $expected['S-1-5-18'] = [uint32]0x1F01FF
    $expected['S-1-5-32-544'] = [uint32]0x1F01FF
    $expected['S-1-5-19'] = $limitedRights
    $expected[$ServiceSID.Value] = $limitedRights
    $actual = @{}
    foreach ($accessRule in (Get-DiagnosticAccessRules $acl)) {
        if ($accessRule.IsInherited -or $accessRule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $accessRule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or
            $accessRule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
            throw "Diagnostic ACL contains a non-explicit allow ACE."
        }
        $sid = $accessRule.IdentityReference.Value
        if (-not $expected.ContainsKey($sid)) { throw "Diagnostic ACL grants unexpected SID $sid." }
        $rights = [uint32]$accessRule.FileSystemRights
        $expectedRights = [uint32]$expected[$sid]
        if ($rights -eq 0) { throw "Diagnostic ACL contains an empty ACE for SID $sid." }
        if (($rights -bor $expectedRights) -ne $expectedRights) { throw "Diagnostic ACL broadens SID $sid." }
        $currentRights = if ($actual.ContainsKey($sid)) { [uint32]$actual[$sid] } else { [uint32]0 }
        $actual[$sid] = [uint32]($currentRights -bor $rights)
    }
    foreach ($sid in $expected.Keys) {
        if (-not $actual.ContainsKey($sid) -or [uint32]$actual[$sid] -ne [uint32]$expected[$sid]) {
            $actualRights = if ($actual.ContainsKey($sid)) { [uint32]$actual[$sid] } else { [uint32]0 }
            throw "Diagnostic ACL access mismatch for SID $sid; actual=0x$($actualRights.ToString('X')) expected=0x$(([uint32]$expected[$sid]).ToString('X'))."
        }
    }
}

function Assert-ExactDiagnosticSecurity {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$ServiceSID,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$OwnerSID,
        [switch]$File
    )
    $acl = Get-Acl -LiteralPath $Path
    Assert-ExactDiagnosticSecurityObject $acl $ServiceSID $OwnerSID -File:$File
}

function Assert-DiagnosticSecurityRejected {
    param(
        [Parameter(Mandatory = $true)][System.Security.AccessControl.FileSystemSecurity]$ACL,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$ServiceSID,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$OwnerSID,
        [Parameter(Mandatory = $true)][string]$ExpectedMessage
    )
    $failure = $null
    try { Assert-ExactDiagnosticSecurityObject $ACL $ServiceSID $OwnerSID -File }
    catch { $failure = $_ }
    if ($null -eq $failure) { throw "Invalid diagnostic ACL was accepted; expected '$ExpectedMessage'." }
    if (-not $failure.Exception.Message.Contains($ExpectedMessage)) {
        throw "Invalid diagnostic ACL failed for the wrong reason: '$($failure.Exception.Message)'; expected '$ExpectedMessage'."
    }
}

function Write-DiagnosticAclObjectDiagnostics {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][System.Security.AccessControl.FileSystemSecurity]$ACL
    )
    try {
        $sections = [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access
        Write-Host "$Label ACL owner=$($ACL.GetOwner([Security.Principal.SecurityIdentifier]).Value) protected=$($ACL.AreAccessRulesProtected) canonical=$($ACL.AreAccessRulesCanonical)"
        Write-Host "$Label ACL SDDL=$($ACL.GetSecurityDescriptorSddlForm($sections))"
        foreach ($accessRule in (Get-DiagnosticAccessRules $ACL)) {
            $sid = $accessRule.IdentityReference.Value
            $rights = [uint32]$accessRule.FileSystemRights
            Write-Host "$Label ACE sid=$sid mask=0x$($rights.ToString('X')) type=$($accessRule.AccessControlType) inherited=$($accessRule.IsInherited) inheritance=$($accessRule.InheritanceFlags) propagation=$($accessRule.PropagationFlags)"
        }
    }
    catch { Write-Warning "$Label ACL diagnostics failed: $($_.Exception.Message)" }
}

function Write-DiagnosticAclDiagnostics {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$Path
    )
    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            Write-Host "$Label ACL: path does not exist"
            return
        }
        $acl = Get-Acl -LiteralPath $Path
        Write-DiagnosticAclObjectDiagnostics $Label $acl
    }
    catch { Write-Warning "$Label ACL diagnostics failed: $($_.Exception.Message)" }
}

function Set-PrivateHarnessCleanupAccess {
    param([Parameter(Mandatory = $true)][string]$Directory, [Parameter(Mandatory = $true)][string]$Diagnostic)
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $directorySecurity = [Security.AccessControl.DirectorySecurity]::new()
    $directorySecurity.SetAccessRuleProtection($true, $false)
    $directorySecurity.SetAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity, [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow))
    [IO.DirectoryInfo]::new($Directory).SetAccessControl($directorySecurity)
    if (Test-Path -LiteralPath $Diagnostic) {
        $fileSecurity = [Security.AccessControl.FileSecurity]::new()
        $fileSecurity.SetAccessRuleProtection($true, $false)
        $fileSecurity.SetAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity, [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow))
        [IO.FileInfo]::new($Diagnostic).SetAccessControl($fileSecurity)
    }
}

function Remove-VerifiedHarnessArtifacts {
    param([Parameter(Mandatory = $true)][PSCustomObject]$Harness)
    $harnessID = Split-Path -Leaf $Harness.Directory
    $verified = Resolve-VerifiedHarnessPath $harnessID $Harness.ProgramData
    if (-not [string]::Equals($verified.Directory, [IO.Path]::GetFullPath($Harness.Directory), [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals($verified.Diagnostic, [IO.Path]::GetFullPath($Harness.Diagnostic), [StringComparison]::OrdinalIgnoreCase)) {
        throw "Harness cleanup path does not match the verified absolute path."
    }
    if (Test-Path -LiteralPath $verified.Directory) { Assert-NoReparsePointPath $verified.Directory }
    if (Test-Path -LiteralPath $verified.Directory) {
        try { Remove-Item -LiteralPath $verified.Directory -Recurse -Force -ErrorAction Stop }
        catch {
            Set-PrivateHarnessCleanupAccess $verified.Directory $verified.Diagnostic
            Remove-Item -LiteralPath $verified.Directory -Recurse -Force -ErrorAction Stop
        }
    }
    if (Test-Path -LiteralPath $verified.Diagnostic) { throw "Harness diagnostic '$($verified.Diagnostic)' still exists after cleanup." }
    if (Test-Path -LiteralPath $verified.Directory) { throw "Harness directory '$($verified.Directory)' still exists after cleanup." }
}

function Set-PreprovisionedDiagnosticArtifacts {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string]$Diagnostic,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$ServiceSID,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$OwnerSID,
        [switch]$SkipPostProvisionVerification
    )
    Assert-NoReparsePointPath $Directory
    try { [IO.File]::Open($Diagnostic, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read).Dispose() }
    catch { throw "Create pre-provisioned diagnostic file failed: $($_.Exception.Message)" }
    Assert-NoReparsePointPath $Diagnostic
    $fileSecurity = New-ExactDiagnosticSecurity $ServiceSID $OwnerSID -File
    $directorySecurity = New-ExactDiagnosticSecurity $ServiceSID $OwnerSID
    Assert-ExactDiagnosticSecurityObject $fileSecurity $ServiceSID $OwnerSID -File -SkipOwnerVerification
    Assert-ExactDiagnosticSecurityObject $directorySecurity $ServiceSID $OwnerSID -SkipOwnerVerification
    Set-Acl -LiteralPath $Diagnostic -AclObject $fileSecurity
    Set-Acl -LiteralPath $Directory -AclObject $directorySecurity
    if (-not $SkipPostProvisionVerification) {
        try {
            Assert-ExactDiagnosticSecurity $Directory $ServiceSID $OwnerSID
            Assert-ExactDiagnosticSecurity $Diagnostic $ServiceSID $OwnerSID -File
        }
        catch {
            Write-DiagnosticAclDiagnostics 'directory' $Directory
            Write-DiagnosticAclDiagnostics 'diagnostic' $Diagnostic
            throw
        }
    }
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
        $created = New-VerifiedHarnessPath '0123456789abcdef0123456789abcdef' $programData
        if (-not (Test-Path -LiteralPath $created.Directory) -or $created.Diagnostic -ne $valid) {
            throw "Verified harness directory was not created at the expected canonical path."
        }
        Assert-NoReparsePointPath $created.Directory
        Write-Host "Harness path security tests passed."
    }
    finally {
        if (Test-Path -LiteralPath $programData) {
            Remove-Item -LiteralPath $programData -Recurse -Force -ErrorAction Stop
            if (Test-Path -LiteralPath $programData) { throw "Harness path security test cleanup left a residual directory." }
        }
    }
}

function Invoke-SetupFailureCleanupTest {
    $programData = Join-Path ([IO.Path]::GetTempPath()) "tachyon-harness-setup-failure-$([guid]::NewGuid().ToString('N'))"
    $resolved = Resolve-VerifiedHarnessPath '0123456789abcdef0123456789abcdef' $programData
    $completedHarness = $null
    $injectedFailureObserved = $false
    try {
        try {
            $partial = New-VerifiedHarnessPath '0123456789abcdef0123456789abcdef' $programData
            [IO.File]::WriteAllText($partial.Diagnostic, 'partial setup')
            $serviceSID = [Security.Principal.SecurityIdentifier]::new('S-1-5-80-1-2-3-4-5')
            $ownerSID = [Security.Principal.WindowsIdentity]::GetCurrent().User
            Set-PreprovisionedDiagnosticArtifacts $partial.Directory $partial.Diagnostic $serviceSID $ownerSID -SkipPostProvisionVerification
            throw "injected harness setup failure"
        }
        catch {
            if ($_.Exception.Message -ne 'injected harness setup failure') { throw }
            $injectedFailureObserved = $true
        }
        finally {
            Remove-VerifiedHarnessArtifacts $resolved
        }
        if ($null -ne $completedHarness) { throw "Setup failure test unexpectedly assigned a completed harness." }
        if (-not $injectedFailureObserved) { throw "Setup failure test did not observe the injected failure." }
        if ((Test-Path -LiteralPath $resolved.Directory) -or (Test-Path -LiteralPath $resolved.Diagnostic)) {
            throw "Setup failure cleanup left harness artifacts behind."
        }
        Write-Host "Harness setup failure cleanup test passed."
    }
    finally {
        if (Test-Path -LiteralPath $programData) {
            Remove-Item -LiteralPath $programData -Recurse -Force -ErrorAction Stop
        }
    }
}

function Invoke-ProvisioningSecurityTests {
    $programData = Join-Path ([IO.Path]::GetTempPath()) "tachyon-harness-acl-$([guid]::NewGuid().ToString('N'))"
    $harness = $null
    try {
        $harness = New-VerifiedHarnessPath '0123456789abcdef0123456789abcdef' $programData
        $serviceSID = [Security.Principal.SecurityIdentifier]::new('S-1-5-80-1-2-3-4-5')
        $ownerSID = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $isAdministrator = ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if ((Get-DiagnosticExpectedMask) -ne [uint32]0x120080) { throw "Directory rights did not canonicalize to 0x120080." }
        if ((Get-DiagnosticExpectedMask -File) -ne [uint32]0x120086) { throw "File rights did not canonicalize to 0x120086." }
        Set-PreprovisionedDiagnosticArtifacts $harness.Directory $harness.Diagnostic $serviceSID $ownerSID -SkipPostProvisionVerification:(-not $isAdministrator)
        if ($isAdministrator) {
            Assert-ExactDiagnosticSecurity $harness.Directory $serviceSID $ownerSID
            Assert-ExactDiagnosticSecurity $harness.Diagnostic $serviceSID $ownerSID -File
        }
        $fileACL = New-ExactDiagnosticSecurity $serviceSID $ownerSID -File
        $writeDAC = [Security.AccessControl.FileSystemRights]::ChangePermissions
        foreach ($accessRule in (Get-DiagnosticAccessRules $fileACL)) {
            $sid = $accessRule.IdentityReference.Value
            if (($sid -eq 'S-1-5-19' -or $sid -eq $serviceSID.Value) -and (($accessRule.FileSystemRights -band $writeDAC) -ne 0)) {
                throw "Least-privilege diagnostic ACE grants ChangePermissions."
            }
        }
        $sections = [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access
        $splitACL = [Security.AccessControl.FileSecurity]::new()
        $splitSDDL = "O:$($ownerSID.Value)D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120086;;;LS)(A;;0x120080;;;$($serviceSID.Value))(A;;0x6;;;$($serviceSID.Value))"
        $logicalSplit = Get-RawDiagnosticSIDAccessSummary $splitSDDL $serviceSID
        if ($logicalSplit.Count -ne 2 -or $logicalSplit.Mask -ne [uint32]0x120086) {
            throw "Raw logical split-ACE input is invalid: count=$($logicalSplit.Count) union=0x$($logicalSplit.Mask.ToString('X'))."
        }
        $splitACL.SetSecurityDescriptorSddlForm($splitSDDL, $sections)
        $splitInput = Get-DiagnosticSIDAccessSummary $splitACL $serviceSID
        if (($splitInput.Count -ne 1 -and $splitInput.Count -ne 2) -or $splitInput.Mask -ne [uint32]0x120086) {
            throw "FileSecurity split-ACE canonicalization is not strictly equivalent: count=$($splitInput.Count) union=0x$($splitInput.Mask.ToString('X'))."
        }
        Assert-ExactDiagnosticSecurityObject $splitACL $serviceSID $ownerSID -File
        Write-DiagnosticAclObjectDiagnostics 'split input' $splitACL
        if ($isAdministrator) {
            Set-Acl -LiteralPath $harness.Diagnostic -AclObject $splitACL
            $persistedSplitACL = Get-Acl -LiteralPath $harness.Diagnostic
            $persistedSplit = Get-DiagnosticSIDAccessSummary $persistedSplitACL $serviceSID
            if (($persistedSplit.Count -ne 1 -and $persistedSplit.Count -ne 2) -or $persistedSplit.Mask -ne [uint32]0x120086) {
                Write-DiagnosticAclObjectDiagnostics 'persisted split' $persistedSplitACL
                throw "Persisted split-ACE fixture is not strictly equivalent: count=$($persistedSplit.Count) union=0x$($persistedSplit.Mask.ToString('X'))."
            }
            Assert-ExactDiagnosticSecurityObject $persistedSplitACL $serviceSID $ownerSID -File
            Write-DiagnosticAclObjectDiagnostics 'persisted split' $persistedSplitACL
            Write-Host "Persisted split-ACE fixture passed: logical_count=$($logicalSplit.Count) object_count=$($splitInput.Count) persisted_count=$($persistedSplit.Count) union=0x$($persistedSplit.Mask.ToString('X'))."
        }
        else { Write-Host "Logical split-ACE fixture passed: logical_count=$($logicalSplit.Count) object_count=$($splitInput.Count) union=0x$($splitInput.Mask.ToString('X')); elevated CI covers NTFS persistence." }

        $unexpectedACL = [Security.AccessControl.FileSecurity]::new()
        $unexpectedACL.SetSecurityDescriptorSddlForm("$splitSDDL(A;;0x2;;;BU)", $sections)
        Assert-DiagnosticSecurityRejected $unexpectedACL $serviceSID $ownerSID 'unexpected SID'
        $denyACL = [Security.AccessControl.FileSecurity]::new()
        $denyACL.SetSecurityDescriptorSddlForm("O:$($ownerSID.Value)D:PAI(D;;0x2;;;$($serviceSID.Value))(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120086;;;LS)(A;;0x120086;;;$($serviceSID.Value))", $sections)
        Assert-DiagnosticSecurityRejected $denyACL $serviceSID $ownerSID 'non-explicit allow ACE'
        $inheritedACL = [Security.AccessControl.FileSecurity]::new()
        $inheritedACL.SetSecurityDescriptorSddlForm("$splitSDDL(A;ID;0x1;;;SY)", $sections)
        Assert-DiagnosticSecurityRejected $inheritedACL $serviceSID $ownerSID 'non-explicit allow ACE'
        $writeDACACL = [Security.AccessControl.FileSecurity]::new()
        $writeDACACL.SetSecurityDescriptorSddlForm("O:$($ownerSID.Value)D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120086;;;LS)(A;;0x160086;;;$($serviceSID.Value))", $sections)
        Assert-DiagnosticSecurityRejected $writeDACACL $serviceSID $ownerSID 'broadens SID'
        Write-Host "Strict ACL rejection tests passed: extra SID, deny, inherited, and WRITE_DAC."
        Invoke-SetupFailureCleanupTest
        if (-not $isAdministrator) { Write-Host "Provisioning ACL object policy passed; elevated CI covers persisted ACL verification and LocalService E2E." }
        Write-Host "Harness diagnostic provisioning security tests passed."
    }
    finally {
        if ($null -ne $harness) { Remove-VerifiedHarnessArtifacts $harness }
        if (Test-Path -LiteralPath $programData) {
            Remove-Item -LiteralPath $programData -Recurse -Force -ErrorAction Stop
            if (Test-Path -LiteralPath $programData) { throw "Harness provisioning security test cleanup left a residual directory." }
        }
    }
}

if ($RunGoHarness) {
    & mise exec -- go test ./internal/capturedudp -run "TestWindowsNamedPipe(WrongSIDIsDeniedByACL|RejectsLowIntegrityPolicy|MatchesEnabledServiceGroup)$" -count=1
    if ($LASTEXITCODE -ne 0) { throw "Windows identity harness failed with exit code $LASTEXITCODE" }
}

if ($RunPathSecurityTests) { Invoke-HarnessPathSecurityTests }
if ($RunProvisioningSecurityTests) { Invoke-ProvisioningSecurityTests }

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
    $diagnosticOwnerSID = ([Security.Principal.WindowsIdentity]::GetCurrent()).User
    $coreProcess = $null
    $harness = $null
    $harnessPath = Resolve-VerifiedHarnessPath $harnessID
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
        $harness = New-ProtectedHarnessDirectory $harnessID $name $serviceSID $diagnosticOwnerSID
        if (-not [string]::Equals($harness.Directory, $harnessPath.Directory, [StringComparison]::OrdinalIgnoreCase) -or
            -not [string]::Equals($harness.Diagnostic, $harnessPath.Diagnostic, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Created harness path does not match the pre-resolved cleanup path."
        }
        $image = "$quotedBinary helper --service --service-name $name --service-sid $serviceSID --diagnostic-owner-sid $($diagnosticOwnerSID.Value) --pipe $corePipe --server-sid $serverSID --core-binary $quotedTrustedBinary --core-sha256 $trustedHash --diagnostic-file $($harness.Diagnostic) --diagnostic-test-override"
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
        Write-DiagnosticAclDiagnostics 'directory' $harnessPath.Directory
        Write-DiagnosticAclDiagnostics 'diagnostic' $harnessPath.Diagnostic
        Write-SafeHarnessFailureDiagnostics $scPath $name $harnessPath.Diagnostic
    }
    finally {
        try {
            if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
                [void](Invoke-ScDiagnostic $scPath 'stop' @('stop', $name))
                if (-not (Wait-HarnessServiceState $name 'Stopped')) { $cleanupFailures.Add("temporary service '$name' did not stop") }
                [void](Invoke-ScDiagnostic $scPath 'delete' @('delete', $name))
                if (-not (Wait-HarnessServiceState $name 'Deleted')) { $cleanupFailures.Add("temporary service '$name' was not deleted") }
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
        try { Remove-VerifiedHarnessArtifacts $harnessPath }
        catch { $cleanupFailures.Add("harness artifact cleanup failed: $($_.Exception.Message)") }
        try {
            if (Get-Service -Name $name -ErrorAction SilentlyContinue) { $cleanupFailures.Add("temporary service '$name' still exists after cleanup") }
        }
        catch { $cleanupFailures.Add("temporary service residual check failed: $($_.Exception.Message)") }
        try {
            if (Test-Path -LiteralPath $harnessPath.Diagnostic) { $cleanupFailures.Add("diagnostic '$($harnessPath.Diagnostic)' still exists after cleanup") }
        }
        catch { $cleanupFailures.Add("diagnostic residual check failed: $($_.Exception.Message)") }
        try {
            if (Test-Path -LiteralPath $harnessPath.Directory) { $cleanupFailures.Add("directory '$($harnessPath.Directory)' still exists after cleanup") }
        }
        catch { $cleanupFailures.Add("directory residual check failed: $($_.Exception.Message)") }
    }
    if ($cleanupFailures.Count -gt 0) {
        Write-SafeHarnessFailureDiagnostics $scPath $name $harnessPath.Diagnostic
    }
    if ($null -ne $failure -and $cleanupFailures.Count -gt 0) {
        throw "Service SID harness failed: $($failure.Exception.Message); cleanup failed independently: $($cleanupFailures -join '; ')"
    }
    if ($null -ne $failure) { throw "Service SID harness failed: $($failure.Exception.Message)" }
    if ($cleanupFailures.Count -gt 0) {
        throw "Service SID harness cleanup failed: $($cleanupFailures -join '; ')"
    }
}

if (-not $RunServiceSIDHarness -and -not $RunGoHarness -and -not $RunPathSecurityTests -and -not $RunProvisioningSecurityTests) {
    Write-Host "No harness selected. Use -RunServiceSIDHarness (administrator), -RunGoHarness, -RunPathSecurityTests, and/or -RunProvisioningSecurityTests."
}
