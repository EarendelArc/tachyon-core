[CmdletBinding(SupportsShouldProcess)]
param([string]$ServiceName = "TachyonHelper")

$ErrorActionPreference = "Stop"
$scPath = Join-Path $env:WINDIR "System32\sc.exe"
if (-not (Test-Path -LiteralPath $scPath)) { throw "System32 sc.exe was not found." }
if ($ServiceName -notmatch '^[A-Za-z0-9_.-]{1,80}$') { throw "Invalid ServiceName." }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This operation requires an elevated PowerShell session."
}
if ($PSCmdlet.ShouldProcess($ServiceName, "Stop and remove Tachyon helper service")) {
    & $scPath stop $ServiceName | Out-Null
    $deadline = (Get-Date).AddSeconds(10)
    do {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($null -eq $service -or $service.Status -eq 'Stopped') { break }
        Start-Sleep -Milliseconds 200
    } while ((Get-Date) -lt $deadline)
    & $scPath delete $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe delete failed with exit code $LASTEXITCODE" }
    $deadline = (Get-Date).AddSeconds(10)
    while (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        if ((Get-Date) -gt $deadline) { throw "service '$ServiceName' was not deleted" }
        Start-Sleep -Milliseconds 200
    }
}
