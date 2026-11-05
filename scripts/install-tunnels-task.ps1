<#
.SYNOPSIS
  Registers (or removes) the 'claude-swap-tunnels' logon task that supervises the
  reverse SSH tunnels to the Linux hosts.

.DESCRIPTION
  The task runs scripts\claude-swap-tunnels.ps1 as the current user at logon,
  hidden, with no time limit and a restart-on-failure policy. No password is
  stored: LogonType Interactive means the task only runs while the user is
  logged on, which is exactly the lifetime the tunnels need.

  Nothing here knows a host address, a username or a password. The supervisor
  reads the host list at runtime from the config file outside the repository.

  Install copies claude-swap-tunnels.ps1 next to the config file and points the
  task at that copy, so the task does not depend on a git worktree that may be
  pruned. Re-run the installer after you change the script.

.PARAMETER Uninstall
  Unregister the task, stop only the processes it started (matched on the
  tunnel script name and on the dedicated key file name), delete the config
  file and the installed copy of the supervisor. The log is kept; it holds no
  secrets.

.PARAMETER DryRun
  Print every action and change nothing.

.EXAMPLE
  powershell -NoProfile -File scripts\install-tunnels-task.ps1 -DryRun

.EXAMPLE
  powershell -NoProfile -File scripts\install-tunnels-task.ps1 -Uninstall

.NOTES
  THIS TASK IS THE INTERIM SUPERVISOR. The server supervises the same tunnels
  itself when it is started with --tunnels, and that is where the work goes now:
  the key lives encrypted in the keyring instead of on disk at
  ~\.ssh\id_ed25519_claudeswap, and the Tunnels tab shows each host's state.

  Do not run both. Two supervisors dial the same -R 127.0.0.1:8443 and the
  second forward is refused, so the app sits in forward_refused and this task
  wins silently. Unregister this task BEFORE starting the server with
  --tunnels; the move is written out in docs/runbooks/linux-agent-install.md,
  "Moving to the app-managed supervisor".

  Re-install this task only to roll back. Nothing here is removed by the move,
  so -Uninstall then a later plain run restores the old arrangement, with one
  caveat: -Uninstall deletes tunnels.json, which the app's import reads. Import
  the host list into the app first, or keep a copy.

  Re-run the installer after editing claude-swap-tunnels.ps1: the task runs the
  copy beside the config, not the file in this repository.
#>
[CmdletBinding()]
param(
    [string] $TaskName = 'claude-swap-tunnels',
    [string] $ScriptPath = '',
    [string] $ConfigPath = (Join-Path $env:USERPROFILE '.claude-swap\tunnels.json'),
    [string] $KeyPath = (Join-Path $env:USERPROFILE '.ssh\id_ed25519_claudeswap'),
    [switch] $Uninstall,
    [switch] $DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# $PSScriptRoot is not populated in a param default on Windows PowerShell 5.1.
if ([string]::IsNullOrWhiteSpace($ScriptPath)) {
    $here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $PSCommandPath }
    $ScriptPath = Join-Path $here 'claude-swap-tunnels.ps1'
}

$keyLeaf = Split-Path -Leaf $KeyPath
$scriptLeaf = Split-Path -Leaf $ScriptPath
# The task runs a copy of the supervisor kept beside the config, so it does not
# depend on a git worktree or a checkout path that may move or be pruned.
$runtimeDir = Split-Path -Parent $ConfigPath
$runtimeScript = Join-Path $runtimeDir $scriptLeaf

function Write-Action {
    param([string] $Message)
    if ($DryRun) { Write-Host "DRY-RUN: $Message" } else { Write-Host $Message }
}

# Processes this task owns: the supervisor, and the ssh clients it launched with
# the dedicated key. Nothing else on the machine matches both names.
function Get-OwnedProcess {
    $all = @()
    foreach ($p in (Get-CimInstance Win32_Process -Filter "Name='ssh.exe'" -ErrorAction SilentlyContinue)) {
        if ($p.CommandLine -and $p.CommandLine -like "*$keyLeaf*") {
            $all += [pscustomobject]@{ Id = $p.ProcessId; Kind = 'tunnel' }
        }
    }
    foreach ($p in (Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -in 'powershell.exe', 'pwsh.exe' })) {
        if ($p.CommandLine -and $p.CommandLine -like "*$scriptLeaf*") {
            $all += [pscustomobject]@{ Id = $p.ProcessId; Kind = 'supervisor' }
        }
    }
    $all
}

# ------------------------------------------------------------- uninstall -----

if ($Uninstall) {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        Write-Action "unregister scheduled task '$TaskName'"
        if (-not $DryRun) {
            try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch { }
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        }
    } else {
        Write-Action "scheduled task '$TaskName' is not registered: nothing to unregister"
    }

    $owned = @(Get-OwnedProcess)
    if ($owned.Count -eq 0) {
        Write-Action 'no supervisor or tunnel process to stop'
    }
    foreach ($o in $owned) {
        if ($o.Id -eq $PID) { continue }
        Write-Action "stop $($o.Kind) process pid=$($o.Id)"
        if (-not $DryRun) { Stop-Process -Id $o.Id -Force -ErrorAction SilentlyContinue }
    }

    if (Test-Path -LiteralPath $ConfigPath) {
        Write-Action "delete config $ConfigPath"
        if (-not $DryRun) { Remove-Item -LiteralPath $ConfigPath -Force }
    } else {
        Write-Action "config $ConfigPath is already absent"
    }

    if ((Test-Path -LiteralPath $runtimeScript) -and $runtimeScript -ne $ScriptPath) {
        Write-Action "delete installed supervisor copy $runtimeScript"
        if (-not $DryRun) { Remove-Item -LiteralPath $runtimeScript -Force }
    }

    Write-Action 'the log and the private key are left in place; delete them by hand if you want them gone'
    return
}

# --------------------------------------------------------------- install -----

if (-not (Test-Path -LiteralPath $ScriptPath)) { throw "tunnel script not found: $ScriptPath" }
if (-not (Test-Path -LiteralPath $KeyPath)) { throw "private key not found: $KeyPath" }
if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "config not found: $ConfigPath (create it outside the repo first)" }

$runner = (Get-Command 'powershell.exe').Source
$arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}"' -f $runtimeScript
$userId = '{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME

Write-Action "task      : $TaskName"
Write-Action "copy      : $ScriptPath -> $runtimeScript"
Write-Action "action    : $runner $arguments"
Write-Action "trigger   : at logon of $userId"
Write-Action 'principal : LogonType Interactive, RunLevel Limited, no stored password'
Write-Action 'settings  : hidden, no execution time limit, restart on failure every 1 min (up to 999)'

if ($DryRun) {
    Write-Action 'would register the task and leave it stopped; start it with Start-ScheduledTask'
    return
}

if ($runtimeScript -ne $ScriptPath) {
    Copy-Item -LiteralPath $ScriptPath -Destination $runtimeScript -Force
    & icacls.exe $runtimeScript /inheritance:r /grant:r "$($env:USERNAME):(F)" | Out-Null
}

$action = New-ScheduledTaskAction -Execute $runner -Argument $arguments
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $userId
$principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet `
    -Hidden `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null

$task = Get-ScheduledTask -TaskName $TaskName
Write-Host "registered '$TaskName', state $($task.State)"
Write-Host "start it now with: Start-ScheduledTask -TaskName $TaskName"
