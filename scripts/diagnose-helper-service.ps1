[CmdletBinding()]
param([string]$ServiceName = "TachyonHelper")

$ErrorActionPreference = "Stop"
$scPath = Join-Path $env:WINDIR "System32\sc.exe"
if (-not (Test-Path -LiteralPath $scPath)) { throw "System32 sc.exe was not found." }
if ($ServiceName -notmatch '^[A-Za-z0-9_.-]{1,80}$') { throw "Invalid ServiceName." }
Write-Host "=== service configuration ==="
& $scPath qc $ServiceName
Write-Host "=== service SID type ==="
& $scPath qsidtype $ServiceName
Write-Host "=== service state ==="
& $scPath query $ServiceName
Write-Host "=== safety assertions ==="
$query = (& $scPath qc $ServiceName | Out-String)
if ($query -notmatch "helper --service") { throw "Service image path does not contain helper --service." }
if ($query -match "allow_insecure") { throw "Service image path enables insecure identity mode." }
Write-Host "The service entry point is present; WFP capture readiness must still be checked in helper-health.json."
