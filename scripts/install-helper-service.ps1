[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$BinaryPath = "",
    [string]$ServiceName = "TachyonHelper",
    [string]$PipeName = "\\.\pipe\Tachyon\captured-udp-v2",
    [string]$ServerSID = "",
    [string]$TrustedServerBinary = "",
    [string]$TrustedServerSHA256 = "",
    [string]$DiagnosticFile = "$env:ProgramData\Tachyon\helper-health.json"
)

$ErrorActionPreference = "Stop"
$scriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptRoot)) {
    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}
if ([string]::IsNullOrWhiteSpace($BinaryPath)) {
    $BinaryPath = Join-Path $scriptRoot "..\tachyon-core.exe"
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This operation requires an elevated PowerShell session."
    }
}

function Assert-NoReparsePointPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($full)
    $current = $root
    foreach ($part in ($full.Substring($root.Length).TrimStart('\', '/') -split '[\\/]' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
        $current = Join-Path $current $part
        if ((Test-Path -LiteralPath $current) -and ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Diagnostic path contains a reparse point: $current"
        }
    }
}

function Resolve-ServiceSID {
    param([Parameter(Mandatory = $true)][string]$ScPath, [Parameter(Mandatory = $true)][string]$Name)
    $output = (& $ScPath showsid $Name | Out-String)
    if ($LASTEXITCODE -ne 0 -or $output -notmatch 'S-1-5-80-[0-9-]+') { throw "sc.exe showsid failed for '$Name' with exit code $LASTEXITCODE" }
    return $Matches[0]
}

function Get-ExactDiagnosticSDDL {
    param(
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$ServiceSID,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$OwnerSID,
        [switch]$File
    )
    $limitedRights = if ($File) { [uint32]0x120086 } else { [uint32]0x120080 }
    return "O:$($OwnerSID.Value)D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x$($limitedRights.ToString('X'));;;LS)(A;;0x$($limitedRights.ToString('X'));;;$($ServiceSID.Value))"
}

function New-ExactDiagnosticSecurity {
    param(
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$ServiceSID,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$OwnerSID,
        [switch]$File
    )
    $security = if ($File) { [Security.AccessControl.FileSecurity]::new() } else { [Security.AccessControl.DirectorySecurity]::new() }
    $sections = [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access
    $security.SetSecurityDescriptorSddlForm((Get-ExactDiagnosticSDDL $ServiceSID $OwnerSID -File:$File), $sections)
    return $security
}

function Assert-PreprovisionedDiagnosticSecurity {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$ServiceSID,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$OwnerSID,
        [switch]$File
    )
    $actual = Get-Acl -LiteralPath $Path
    if ($actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $OwnerSID.Value -or -not $actual.AreAccessRulesProtected) {
        throw "Diagnostic owner or inheritance policy is not exact."
    }
    if (-not $actual.AreAccessRulesCanonical) { throw "Diagnostic ACL is not canonical." }
    $limitedRights = if ($File) { [uint32]0x120086 } else { [uint32]0x120080 }
    $expected = @{}
    $expected['S-1-5-18'] = [uint32]0x1F01FF
    $expected['S-1-5-32-544'] = [uint32]0x1F01FF
    $expected['S-1-5-19'] = $limitedRights
    $expected[$ServiceSID.Value] = $limitedRights
    $seen = @{}
    foreach ($accessRule in $actual.Access) {
        if ($accessRule.IsInherited -or $accessRule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $accessRule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or
            $accessRule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
            throw "Diagnostic ACL contains a non-explicit allow ACE."
        }
        try { $sid = $accessRule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }
        catch { throw "Diagnostic ACL contains an unresolvable SID." }
        if (-not $expected.ContainsKey($sid)) { throw "Diagnostic ACL grants unexpected SID $sid." }
        $rights = [uint32]$accessRule.FileSystemRights
        $expectedRights = [uint32]$expected[$sid]
        if ($rights -eq 0) { throw "Diagnostic ACL contains an empty ACE for SID $sid." }
        if (($rights -bor $expectedRights) -ne $expectedRights) { throw "Diagnostic ACL broadens SID $sid." }
        $currentRights = if ($seen.ContainsKey($sid)) { [uint32]$seen[$sid] } else { [uint32]0 }
        $seen[$sid] = [uint32]($currentRights -bor $rights)
    }
    foreach ($sid in $expected.Keys) {
        if (-not $seen.ContainsKey($sid) -or [uint32]$seen[$sid] -ne [uint32]$expected[$sid]) {
            throw "Diagnostic ACL is missing required access for SID $sid."
        }
    }
}

function Preprovision-DiagnosticArtifacts {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$ServiceSID, [Parameter(Mandatory = $true)][string]$OwnerSID)
    $serviceAccountSID = [Security.Principal.NTAccount]::new('NT SERVICE', $ServiceName).Translate([Security.Principal.SecurityIdentifier])
    if ($serviceAccountSID.Value -ne $ServiceSID) { throw "Service SID does not match NT SERVICE\\$ServiceName." }
    $directory = Split-Path -Parent $Path
    Assert-NoReparsePointPath $directory
    [void][IO.Directory]::CreateDirectory($directory)
    Assert-NoReparsePointPath $directory
    try { [IO.File]::Open($Path, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read).Dispose() }
    catch { throw "Create diagnostic file failed: $($_.Exception.Message)" }
    Assert-NoReparsePointPath $Path
    $owner = [Security.Principal.SecurityIdentifier]::new($OwnerSID)
    Set-Acl -LiteralPath $Path -AclObject (New-ExactDiagnosticSecurity $serviceAccountSID $owner -File)
    Set-Acl -LiteralPath $directory -AclObject (New-ExactDiagnosticSecurity $serviceAccountSID $owner)
    Assert-PreprovisionedDiagnosticSecurity $directory $serviceAccountSID $owner
    Assert-PreprovisionedDiagnosticSecurity $Path $serviceAccountSID $owner -File
}

Assert-Administrator
$scPath = Join-Path $env:WINDIR "System32\sc.exe"
if (-not (Test-Path -LiteralPath $scPath)) { throw "System32 sc.exe was not found." }
if ($ServiceName -notmatch '^[A-Za-z0-9_.-]{1,80}$') { throw "Invalid ServiceName." }
if ($PipeName -notmatch '^\\\\\.\\pipe\\Tachyon\\[A-Za-z0-9_.-]{1,96}$') { throw "Invalid Tachyon Named Pipe name." }
if ($ServerSID -notmatch '^S-1-[0-9]+(-[0-9]+)+$') { throw "ServerSID is required and must be a canonical SID string." }
$resolvedBinary = (Resolve-Path -LiteralPath $BinaryPath).Path
if ([IO.Path]::GetExtension($resolvedBinary) -ne '.exe') { throw "BinaryPath must point to an .exe release binary." }
if ((Get-Item -LiteralPath $resolvedBinary).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "BinaryPath cannot be a reparse point." }
if ([string]::IsNullOrWhiteSpace($TrustedServerBinary)) { throw "TrustedServerBinary is required; do not trust the current helper image implicitly." }
$resolvedTrustedServer = (Resolve-Path -LiteralPath $TrustedServerBinary).Path
if ([IO.Path]::GetExtension($resolvedTrustedServer) -ne '.exe') { throw "TrustedServerBinary must point to an .exe release binary." }
if ((Get-Item -LiteralPath $resolvedTrustedServer).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "TrustedServerBinary cannot be a reparse point." }
if ($TrustedServerSHA256 -notmatch '^[0-9a-fA-F]{64}$') { throw "TrustedServerSHA256 must be an externally pinned 64-hex SHA-256." }
$expectedDiagnostic = Join-Path $env:ProgramData "Tachyon\helper-health.json"
$diagnosticFull = [IO.Path]::GetFullPath($DiagnosticFile)
$expectedDiagnosticFull = [IO.Path]::GetFullPath($expectedDiagnostic)
if (-not [string]::Equals($diagnosticFull, $expectedDiagnosticFull, [StringComparison]::OrdinalIgnoreCase)) { throw "DiagnosticFile must use ProgramData\Tachyon\helper-health.json." }
$quotedBinary = [char]34 + $resolvedBinary + [char]34
$bootstrapArgs = "$quotedBinary helper --service --service-name $ServiceName --pipe $PipeName --server-sid $ServerSID --core-binary `"$resolvedTrustedServer`" --core-sha256 $TrustedServerSHA256"

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    throw "Service '$ServiceName' already exists; uninstall it explicitly before reinstalling."
}

if ($PSCmdlet.ShouldProcess($ServiceName, "Create restricted Tachyon helper service")) {
    $created = $false
    try {
        & $scPath create $ServiceName binPath= $bootstrapArgs start= auto obj= "NT AUTHORITY\LocalService" DisplayName= "Tachyon Privileged Helper" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed with exit code $LASTEXITCODE" }
        $created = $true
        & $scPath sidtype $ServiceName restricted | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "sc.exe sidtype restricted failed with exit code $LASTEXITCODE" }
        $serviceSID = Resolve-ServiceSID $scPath $ServiceName
        $diagnosticOwnerSID = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
        Preprovision-DiagnosticArtifacts $diagnosticFull $serviceSID $diagnosticOwnerSID
        $serviceArgs = "$quotedBinary helper --service --service-name $ServiceName --service-sid $serviceSID --diagnostic-owner-sid $diagnosticOwnerSID --pipe $PipeName --server-sid $ServerSID --core-binary `"$resolvedTrustedServer`" --core-sha256 $TrustedServerSHA256 --diagnostic-file $DiagnosticFile"
        & $scPath config $ServiceName binPath= $serviceArgs | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "sc.exe config binPath failed with exit code $LASTEXITCODE" }
        & $scPath config $ServiceName depend= RpcSs | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "sc.exe config depend failed with exit code $LASTEXITCODE" }
        & $scPath failure $ServiceName reset= 86400 actions= "restart/5000/restart/30000/0" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "sc.exe failure failed with exit code $LASTEXITCODE" }

        # Only SYSTEM, Built-in Administrators, and the service controller may
        # administer the service. The Named Pipe ACL is configured by Core.
        $sddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;SU)"
        & $scPath sdset $ServiceName $sddl | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "sc.exe sdset failed with exit code $LASTEXITCODE" }
        Write-Host "Installed $ServiceName with restricted Service SID and LocalService account."
        Write-Host "Provider state is intentionally NotReady until a verified WFP callout provider is installed."
    }
    catch {
        if ($created) {
            & $scPath stop $ServiceName | Out-Null
            $stopDeadline = (Get-Date).AddSeconds(10)
            do {
                $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                if ($null -eq $service -or $service.Status -eq 'Stopped') { break }
                Start-Sleep -Milliseconds 200
            } while ((Get-Date) -lt $stopDeadline)
            if ($null -ne (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) -and (Get-Service -Name $ServiceName).Status -ne 'Stopped') { throw "Install failed and rollback could not stop '$ServiceName'. Original error: $($_.Exception.Message)" }
            & $scPath delete $ServiceName | Out-Null
            $deleteDeadline = (Get-Date).AddSeconds(10)
            while (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
                if ((Get-Date) -gt $deleteDeadline) { throw "Install failed and rollback could not delete '$ServiceName'. Original error: $($_.Exception.Message)" }
                Start-Sleep -Milliseconds 200
            }
        }
        throw
    }
}
