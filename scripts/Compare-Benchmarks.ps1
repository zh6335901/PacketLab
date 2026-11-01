param(
    [Parameter(Mandatory)][string] $Project,
    [Parameter(Mandatory)][string] $Base,
    [string] $Candidate = 'HEAD'
)

$ErrorActionPreference = 'Stop'
$python = Get-Command python3 -ErrorAction SilentlyContinue
if ($env:OS -eq 'Windows_NT' -or !$python) { $python = Get-Command python }
& $python.Source "$PSScriptRoot/compare_benchmarks.py" $Project $Base $Candidate
exit $LASTEXITCODE
