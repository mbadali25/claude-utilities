# scripts/start-server.ps1 - start the claude-swap server and keep its stdout and stderr in a log file.
#
# A server that exits at startup (bad --listen, a wrong CLAUDESWAP_KEY, a port in use) writes its reason
# to stderr. Started detached with no redirect, that reason is lost. This script redirects both streams
# to <LogDir>\server.out.log and server.err.log and, after a short wait, reports whether the process
# is still alive and shows the tail of server.err.log.
#
# CLAUDESWAP_KEY and CLAUDESWAP_ADMIN_PASSWORD (or a set-password hash in the data dir) must already be
# in the environment of this shell. They are inherited by the child and never printed or logged here.
#
#   .\scripts\start-server.ps1 -Listen 192.0.2.10:8443 -DataDir D:\claude-swap\data
param(
    [Parameter(Mandatory)][string]$Listen,
    [string]$DataDir,
    [string]$ServerExe = (Join-Path $PSScriptRoot '..\server.exe'),
    [string]$LogDir = (Join-Path $env:LOCALAPPDATA 'claude-swap-server'),
    [int]$WaitSeconds = 3
)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ServerExe)) { throw "server binary not found: $ServerExe (build it: go build -o server.exe ./cmd/server)" }
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$out = Join-Path $LogDir 'server.out.log'
$err = Join-Path $LogDir 'server.err.log'

$argList = @('--listen', $Listen)
if ($DataDir) { $argList += @('--data-dir', $DataDir) }

$p = Start-Process -FilePath $ServerExe -ArgumentList $argList -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput $out -RedirectStandardError $err
Start-Sleep -Seconds $WaitSeconds
$p.Refresh()

if ($p.HasExited) {
    Write-Output "server exited with code $($p.ExitCode) within $WaitSeconds s. stderr ($err):"
    if (Test-Path -LiteralPath $err) { Get-Content -LiteralPath $err -Tail 20 }
    exit 1
}
Write-Output "server running, pid $($p.Id). Logs: $out and $err"
