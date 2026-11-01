param(
    [Parameter(Mandatory)][string] $Project,
    [Parameter(Mandatory)][string] $Base,
    [string] $Candidate = 'HEAD'
)

$ErrorActionPreference = 'Stop'
dotnet fsi "$PSScriptRoot/Compare-Benchmarks.fsx" $Project $Base $Candidate
exit $LASTEXITCODE
