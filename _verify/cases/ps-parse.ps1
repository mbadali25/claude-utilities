# _verify/cases/ps-parse.ps1 - parse-only syntax check of the PowerShell scripts given as arguments.
# Exit 0 = every file parses, 1 = a parse error (printed as file:line:col message), 2 = file missing.
# Nothing is executed: Parser.ParseFile builds the AST and reports errors.
# readonly: yes
param([Parameter(Mandatory, ValueFromRemainingArguments)][string[]]$Path)
$ErrorActionPreference = 'Stop'
$rc = 0
foreach ($p in $Path) {
    if (-not (Test-Path -LiteralPath $p)) { Write-Output "FAIL missing: $p"; $rc = 2; continue }
    $full = (Resolve-Path -LiteralPath $p).ProviderPath
    $tokens = $null; $errs = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($full, [ref]$tokens, [ref]$errs)
    foreach ($e in $errs) {
        Write-Output ("FAIL parse {0}:{1}:{2} {3}" -f $p, $e.Extent.StartLineNumber, $e.Extent.StartColumnNumber, $e.Message)
        if ($rc -eq 0) { $rc = 1 }
    }
}
exit $rc
