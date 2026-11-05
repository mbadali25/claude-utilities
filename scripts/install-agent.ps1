<#
.SYNOPSIS
  Install and enrol the claude-swap agent on a Windows host.

.DESCRIPTION
  The Windows counterpart of scripts/install-agent.sh, with the same contract:
  no parameters, every input from the environment, because an enrolment code on
  a command line is readable from another process's command line.

    required  CLAUDESWAP_SERVER        https://host:port of the server
              CLAUDESWAP_PIN           server certificate sha256 (64 hex chars)
    binary    CLAUDESWAP_AGENT_BIN     path to an agent.exe to copy, OR
              CLAUDESWAP_AGENT_URL     URL to download, which then requires
              CLAUDESWAP_AGENT_SHA256  its expected sha256 (64 hex chars)
    optional  CLAUDESWAP_ENROL_CODE    one-time code; without it the enrolment
                                       waits for an admin to approve this host
              CLAUDESWAP_DRY_RUN=1     print every action, change nothing

  CLAUDESWAP_STATE_DIR is deliberately NOT honoured here. `agent install`
  registers a logon task, and schtasks passes no environment, so the task can
  only ever use the default state dir; installing against any other directory
  would leave the agent unable to find its config. CLAUDE_CONFIG_DIR is never
  set either, so the agent reads the default profile's ~/.claude.json.

  Re-running is safe: the binary is replaced, enrolment is skipped once
  agent.json exists (a one-time code is spent), and the task is re-registered.
#>
#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$BinName = 'claude-swap-agent.exe'
$TaskName = 'ClaudeSwapAgent'
$DryRun = $env:CLAUDESWAP_DRY_RUN -eq '1'

function Step { param([string]$Message) Write-Host "==> $Message" }
# Die writes to stderr directly and exits 1. Write-Error would throw under
# $ErrorActionPreference='Stop', so the `exit 1` would never run and the process
# would report success on a refused install.
function Die { param([string]$Message) [Console]::Error.WriteLine("install-agent: $Message"); exit 1 }
function Test-Hex64 { param([string]$Value) $Value -match '^[0-9a-fA-F]{64}$' }

# ---------------------------------------------------------------- inputs

if (-not $env:CLAUDESWAP_SERVER) { Die 'CLAUDESWAP_SERVER is not set (https://host:port)' }
if ($env:CLAUDESWAP_SERVER -notlike 'https://*') { Die 'CLAUDESWAP_SERVER must be an https:// URL' }
if (-not $env:CLAUDESWAP_PIN) { Die 'CLAUDESWAP_PIN is not set (the server prints it at startup)' }
if (-not (Test-Hex64 $env:CLAUDESWAP_PIN)) { Die 'CLAUDESWAP_PIN must be 64 hex characters' }
if (-not $env:CLAUDESWAP_AGENT_BIN -and -not $env:CLAUDESWAP_AGENT_URL) {
  Die 'set CLAUDESWAP_AGENT_BIN (a local agent.exe) or CLAUDESWAP_AGENT_URL + CLAUDESWAP_AGENT_SHA256'
}
if ($env:CLAUDESWAP_AGENT_URL -and -not $env:CLAUDESWAP_AGENT_BIN) {
  if (-not $env:CLAUDESWAP_AGENT_SHA256) { Die 'CLAUDESWAP_AGENT_URL needs CLAUDESWAP_AGENT_SHA256' }
  if (-not (Test-Hex64 $env:CLAUDESWAP_AGENT_SHA256)) { Die 'CLAUDESWAP_AGENT_SHA256 must be 64 hex characters' }
}
if ($env:CLAUDESWAP_STATE_DIR) {
  Die "CLAUDESWAP_STATE_DIR is set. The logon task cannot be given an environment, so it would use $env:APPDATA\claude-swap-agent instead. Unset it and run this again."
}

# Must match internal/install.TaskStateDir: os.UserConfigDir() + DefaultStateDirName.
$StateDir = Join-Path $env:APPDATA 'claude-swap-agent'
$BinDir = Join-Path $env:LOCALAPPDATA 'claude-swap-agent'
$BinPath = Join-Path $BinDir $BinName

if ($DryRun) { Step 'dry run: nothing below is executed' }
Step "server $env:CLAUDESWAP_SERVER, pin $($env:CLAUDESWAP_PIN.Substring(0,8))..., state dir $StateDir"

# ---------------------------------------------------------------- binary

$work = $null
try {
  if ($env:CLAUDESWAP_AGENT_BIN) {
    if (-not (Test-Path -LiteralPath $env:CLAUDESWAP_AGENT_BIN -PathType Leaf)) {
      Die "CLAUDESWAP_AGENT_BIN $env:CLAUDESWAP_AGENT_BIN is not a file"
    }
    $source = $env:CLAUDESWAP_AGENT_BIN
    Step "using local binary $source"
  } elseif ($DryRun) {
    Step "downloading $env:CLAUDESWAP_AGENT_URL"
    Write-Host "DRY-RUN: download $env:CLAUDESWAP_AGENT_URL and verify sha256 $env:CLAUDESWAP_AGENT_SHA256"
    $source = $null
  } else {
    Step "downloading $env:CLAUDESWAP_AGENT_URL"
    # Its own empty directory: a download is untrusted until the digest matches.
    $work = Join-Path ([System.IO.Path]::GetTempPath()) ('claude-swap-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    $source = Join-Path $work $BinName
    Invoke-WebRequest -Uri $env:CLAUDESWAP_AGENT_URL -OutFile $source -UseBasicParsing
    $got = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
    $want = $env:CLAUDESWAP_AGENT_SHA256.ToLowerInvariant()
    if ($got -ne $want) { Die "sha256 mismatch: got $got, expected $want" }
    Step 'sha256 verified'
  }

  if ($DryRun) {
    Write-Host "DRY-RUN: install binary to $BinPath"
  } else {
    New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
    # A running exe cannot be overwritten, but it can be renamed out of the way.
    if (Test-Path -LiteralPath $BinPath) {
      $aside = "$BinPath.old"
      Remove-Item -LiteralPath $aside -Force -ErrorAction SilentlyContinue
      Rename-Item -LiteralPath $BinPath -NewName ($BinName + '.old') -Force
    }
    Copy-Item -LiteralPath $source -Destination $BinPath -Force
    Remove-Item -LiteralPath "$BinPath.old" -Force -ErrorAction SilentlyContinue
    Step "installed $BinPath"
  }
} finally {
  if ($work -and (Test-Path -LiteralPath $work)) { Remove-Item -Recurse -Force -LiteralPath $work }
}

# ---------------------------------------------------------------- enrol

if (Test-Path -LiteralPath (Join-Path $StateDir 'agent.json')) {
  Step "already enrolled ($StateDir\agent.json exists): skipping enrol"
} elseif ($DryRun) {
  Write-Host "DRY-RUN: $BinPath enrol --server $env:CLAUDESWAP_SERVER --pin <pin> (code from CLAUDESWAP_ENROL_CODE)"
} else {
  if ($env:CLAUDESWAP_ENROL_CODE) {
    Step 'enrolling with a one-time code'
  } else {
    Step 'enrolling: an admin must approve this host in the web UI (up to 10 minutes)'
  }
  # The code reaches the child through the environment. It is never an argument
  # and never printed. Exit 2 means the server denied this host.
  & $BinPath enrol --server $env:CLAUDESWAP_SERVER --pin $env:CLAUDESWAP_PIN
  if ($LASTEXITCODE -ne 0) { Die "enrol exited $LASTEXITCODE (2 = denied: the code may be spent)" }
}
$env:CLAUDESWAP_ENROL_CODE = $null

# ---------------------------------------------------------------- task

# `agent install` is what creates the state dir 0700-equivalent (icacls), and
# registers the logon task. It prints how to start the task now.
Step 'registering the logon task'
if ($DryRun) {
  Write-Host "DRY-RUN: $BinPath install"
} else {
  & $BinPath install
  if ($LASTEXITCODE -ne 0) { Die "install exited $LASTEXITCODE" }
}

Write-Host @"

done.

  start now:  schtasks /Run /TN $TaskName
  state dir:  $StateDir
  if it will not start, read: $StateDir\agent-run.log
"@
