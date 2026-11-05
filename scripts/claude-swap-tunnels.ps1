<#
.SYNOPSIS
  Keeps a reverse SSH tunnel up to every Linux host that runs the claude-swap agent.

.DESCRIPTION
  The claude-swap server listens on 127.0.0.1 only, so each Linux host reaches it
  through `ssh -R 127.0.0.1:<port>:127.0.0.1:<port>` dialled from this machine.
  This script is the supervisor: it starts one hidden ssh.exe per host and
  restarts any that exits, after a short backoff, for as long as it runs.

  Host addresses and usernames live OUTSIDE the repository, in the config file
  named by -ConfigPath (default ~\.claude-swap\tunnels.json). This script holds
  no address, no username and no password: authentication is public key only.

  Config format - a JSON array, one object per host:
      [ { "name": "example", "host": "example.internal", "user": "someone" } ]
  "name" is a label used in the log. "host" and "user" are never logged.

.PARAMETER ConfigPath
  JSON host list. Default: $env:USERPROFILE\.claude-swap\tunnels.json

.PARAMETER KeyPath
  Private key used for every tunnel. Default:
  $env:USERPROFILE\.ssh\id_ed25519_claudeswap

.PARAMETER LogPath
  Append-only log, one line per start and per exit. Rotated at -LogMaxBytes.

.PARAMETER Port
  Port forwarded on both ends. Must match the host's permitlisten option.

.PARAMETER RestartDelaySeconds
  Backoff before a dead tunnel is restarted.

.PARAMETER DryRun
  Print the actions and the ssh argument list, start nothing, write no log.

.EXAMPLE
  powershell -NoProfile -File scripts\claude-swap-tunnels.ps1 -DryRun
#>
[CmdletBinding()]
param(
    [string] $ConfigPath = (Join-Path $env:USERPROFILE '.claude-swap\tunnels.json'),
    [string] $KeyPath = (Join-Path $env:USERPROFILE '.ssh\id_ed25519_claudeswap'),
    [string] $LogPath = (Join-Path $env:USERPROFILE '.claude-swap\tunnels.log'),
    [ValidateRange(1, 65535)][int] $Port = 8443,
    [ValidateRange(1, 3600)][int] $RestartDelaySeconds = 15,
    [ValidateRange(1024, 1073741824)][int] $LogMaxBytes = 1048576,
    [switch] $DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- logging ----

function Write-TunnelLog {
    param([string] $Message)

    $line = '{0} {1}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'), $Message
    if ($DryRun) { Write-Host "DRY-RUN: log: $line"; return }

    $dir = Split-Path -Parent $LogPath
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    # Explicit retention: one rotation, so the log cannot grow without bound.
    try {
        $existing = Get-Item -LiteralPath $LogPath -ErrorAction Stop
        if ($existing.Length -ge $LogMaxBytes) {
            Move-Item -LiteralPath $LogPath -Destination "$LogPath.1" -Force
        }
    } catch [System.Management.Automation.ItemNotFoundException] {
        # first write
    }
    Add-Content -LiteralPath $LogPath -Value $line -Encoding utf8
}

# Never let a host address, a username or an IP literal reach the log.
function Protect-Text {
    param([string] $Text, [string] $HostAddress, [string] $User)

    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $out = $Text
    if ($HostAddress) { $out = $out.Replace($HostAddress, '<host>') }
    if ($User) { $out = $out.Replace($User, '<user>') }
    # Loopback is part of the forward spec and carries no information; mask the rest.
    $out = $out -replace '\b(?!127\.0\.0\.1\b)(?:\d{1,3}\.){3}\d{1,3}\b', '<ip>'
    ($out -replace '\s+', ' ').Trim()
}

# ----------------------------------------------------------------- config ----

function Get-TunnelConfig {
    param([string] $Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "config not found: $Path (see the 'Durable tunnels' runbook section)"
    }
    $parsed = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    $entries = @($parsed)
    if ($entries.Count -eq 0) { throw "config has no host entries: $Path" }

    $result = @()
    foreach ($e in $entries) {
        foreach ($field in 'name', 'host', 'user') {
            if (-not $e.PSObject.Properties[$field] -or [string]::IsNullOrWhiteSpace($e.$field)) {
                throw "config entry is missing '$field': $Path"
            }
        }
        $result += [pscustomobject]@{ Name = $e.name; HostAddress = $e.host; User = $e.user }
    }
    $result
}

# ------------------------------------------------------------------- ssh -----

function Get-SshArgumentList {
    param([pscustomobject] $Entry)

    # `-F NUL` ignores the user's ssh_config and the system-wide one, so no
    # DynamicForward, LocalForward, ProxyCommand or ControlMaster can leak in.
    # The -R below is the only forward this process may ever carry.
    @(
        '-F', 'NUL'
        '-i', $KeyPath
        '-N'
        '-o', 'ForwardAgent=no'
        '-o', 'ForwardX11=no'
        '-o', 'PermitLocalCommand=no'
        '-o', 'IdentitiesOnly=yes'
        '-o', 'BatchMode=yes'
        '-o', 'PubkeyAuthentication=yes'
        '-o', 'PreferredAuthentications=publickey'
        '-o', 'ExitOnForwardFailure=yes'
        '-o', 'ServerAliveInterval=30'
        '-o', 'ServerAliveCountMax=3'
        '-o', 'StrictHostKeyChecking=yes'
        '-R', ('127.0.0.1:{0}:127.0.0.1:{0}' -f $Port)
        ('{0}@{1}' -f $Entry.User, $Entry.HostAddress)
    )
}

# ProcessStartInfo.ArgumentList is .NET Core only and the logon task runs
# Windows PowerShell 5.1, so build the command line by hand. No argument here
# ever contains a double quote; refuse one rather than mis-quote it.
function ConvertTo-CommandLine {
    param([string[]] $ArgumentList)

    $parts = foreach ($a in $ArgumentList) {
        if ($a.Contains('"')) { throw "argument contains a double quote: $a" }
        if ($a -match '\s') { '"' + ($a -replace '(\\+)$', '$1$1') + '"' } else { $a }
    }
    $parts -join ' '
}

function Start-Tunnel {
    param([pscustomobject] $Entry, [string] $SshPath)

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $SshPath
    $psi.Arguments = ConvertTo-CommandLine -ArgumentList (Get-SshArgumentList -Entry $Entry)
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    # A passphrase-less key must never fall back to a prompt of any kind.
    $psi.EnvironmentVariables['SSH_ASKPASS_REQUIRE'] = 'never'
    $psi.EnvironmentVariables.Remove('SSH_ASKPASS') | Out-Null

    $proc = [System.Diagnostics.Process]::Start($psi)
    $proc.StandardInput.Close()
    [pscustomobject]@{
        Process = $proc
        Stderr  = $proc.StandardError.ReadToEndAsync()
        Stdout  = $proc.StandardOutput.ReadToEndAsync()
    }
}

# ------------------------------------------------------------------ main -----

$ssh = Get-Command 'ssh.exe' -ErrorAction SilentlyContinue
if (-not $ssh) { throw 'ssh.exe not found on PATH (install the Windows OpenSSH client)' }
if (-not (Test-Path -LiteralPath $KeyPath)) { throw "private key not found: $KeyPath" }

$entries = Get-TunnelConfig -Path $ConfigPath

if ($DryRun) {
    Write-Host "DRY-RUN: ssh.exe        = $($ssh.Source)"
    Write-Host "DRY-RUN: config         = $ConfigPath ($($entries.Count) host(s))"
    Write-Host "DRY-RUN: key            = $KeyPath"
    Write-Host "DRY-RUN: log            = $LogPath (rotate at $LogMaxBytes bytes)"
    Write-Host "DRY-RUN: forward        = -R 127.0.0.1:$Port`:127.0.0.1:$Port"
    Write-Host "DRY-RUN: restart delay  = $RestartDelaySeconds s, unconditional, per host"
    foreach ($e in $entries) {
        $redacted = Protect-Text `
            -Text (ConvertTo-CommandLine -ArgumentList (Get-SshArgumentList -Entry $e)) `
            -HostAddress $e.HostAddress -User $e.User
        Write-Host "DRY-RUN: would start hidden ssh for name=$($e.Name): $redacted"
    }
    Write-Host 'DRY-RUN: would then supervise forever, restarting any tunnel that exits'
    return
}

Write-TunnelLog ("supervisor start hosts={0} port={1} pid={2}" -f $entries.Count, $Port, $PID)

$state = @{}
foreach ($e in $entries) {
    $state[$e.Name] = [pscustomobject]@{ Entry = $e; Run = $null; NextStart = (Get-Date) }
}

try {
    while ($true) {
        foreach ($name in @($state.Keys)) {
            $slot = $state[$name]

            if ($slot.Run -and $slot.Run.Process.HasExited) {
                $code = $slot.Run.Process.ExitCode
                $err = Protect-Text -Text $slot.Run.Stderr.Result `
                    -HostAddress $slot.Entry.HostAddress -User $slot.Entry.User
                if ($err.Length -gt 200) { $err = $err.Substring(0, 200) }
                Write-TunnelLog ("tunnel exit name={0} pid={1} code={2} reason='{3}'" -f `
                        $name, $slot.Run.Process.Id, $code, $err)
                $slot.Run.Process.Dispose()
                $slot.Run = $null
                $slot.NextStart = (Get-Date).AddSeconds($RestartDelaySeconds)
            }

            if (-not $slot.Run -and (Get-Date) -ge $slot.NextStart) {
                try {
                    $slot.Run = Start-Tunnel -Entry $slot.Entry -SshPath $ssh.Source
                    Write-TunnelLog ("tunnel start name={0} pid={1} port={2}" -f `
                            $name, $slot.Run.Process.Id, $Port)
                } catch {
                    $why = Protect-Text -Text $_.Exception.Message `
                        -HostAddress $slot.Entry.HostAddress -User $slot.Entry.User
                    Write-TunnelLog ("tunnel start-failed name={0} reason='{1}'" -f $name, $why)
                    $slot.NextStart = (Get-Date).AddSeconds($RestartDelaySeconds)
                }
            }
        }
        Start-Sleep -Seconds 2
    }
} finally {
    foreach ($name in @($state.Keys)) {
        $slot = $state[$name]
        if ($slot.Run -and -not $slot.Run.Process.HasExited) {
            try { $slot.Run.Process.Kill() } catch { }
            Write-TunnelLog ("tunnel stopped name={0} pid={1} reason='supervisor exit'" -f `
                    $name, $slot.Run.Process.Id)
        }
    }
    Write-TunnelLog ("supervisor stop pid={0}" -f $PID)
}
