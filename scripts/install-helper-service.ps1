[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$BinaryPath = "",
    [string]$ServiceName = "TachyonHelper",
    [string]$PipeName = "\\.\pipe\Tachyon\captured-udp-v2",
    [string]$ServerSID = "",
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

Assert-Administrator
$scPath = Join-Path $env:WINDIR "System32\sc.exe"
if (-not (Test-Path -LiteralPath $scPath)) { throw "System32 sc.exe was not found." }
if ($ServiceName -notmatch '^[A-Za-z0-9_.-]{1,80}$') { throw "Invalid ServiceName." }
if ($PipeName -notmatch '^\\\\\.\\pipe\\Tachyon\\[A-Za-z0-9_.-]{1,96}$') { throw "Invalid Tachyon Named Pipe name." }
if ($ServerSID -notmatch '^S-1-[0-9]+(-[0-9]+)+$') { throw "ServerSID is required and must be a canonical SID string." }
$resolvedBinary = (Resolve-Path -LiteralPath $BinaryPath).Path
if ([IO.Path]::GetExtension($resolvedBinary) -ne '.exe') { throw "BinaryPath must point to an .exe release binary." }
if ((Get-Item -LiteralPath $resolvedBinary).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "BinaryPath cannot be a reparse point." }
$expectedDiagnostic = Join-Path $env:ProgramData "Tachyon\helper-health.json"
$diagnosticFull = [IO.Path]::GetFullPath($DiagnosticFile)
$expectedDiagnosticFull = [IO.Path]::GetFullPath($expectedDiagnostic)
if (-not [string]::Equals($diagnosticFull, $expectedDiagnosticFull, [StringComparison]::OrdinalIgnoreCase)) { throw "DiagnosticFile must use ProgramData\Tachyon\helper-health.json." }
$quotedBinary = [char]34 + $resolvedBinary + [char]34
$serviceArgs = "$quotedBinary helper --service --service-name $ServiceName --pipe $PipeName --server-sid $ServerSID --diagnostic-file $DiagnosticFile"

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    throw "Service '$ServiceName' already exists; uninstall it explicitly before reinstalling."
}

if ($PSCmdlet.ShouldProcess($ServiceName, "Create restricted Tachyon helper service")) {
    & $scPath create $ServiceName binPath= $serviceArgs start= auto obj= "NT AUTHORITY\LocalService" DisplayName= "Tachyon Privileged Helper" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed with exit code $LASTEXITCODE" }
    & $scPath sidtype $ServiceName restricted | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe sidtype restricted failed with exit code $LASTEXITCODE" }
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
