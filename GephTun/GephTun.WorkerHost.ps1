#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ResultFile,
    [Parameter(Mandatory=$true)][string]$CaptureFile,
    [Parameter(Mandatory=$true)][ValidateSet('Check','Connect','Disconnect','Status')][string]$Action,
    [ValidateRange(0,65535)][int]$Port = 0,
    [ValidateRange(0,2147483647)][int]$OwnerProcessId = 0,
    [ValidatePattern('^[a-f0-9]{32}$')][string]$OperationToken
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:WorkerPath = Join-Path $PSScriptRoot 'GephTun.Worker.ps1'
$script:OutputPathsValidated = $false
$script:ProgramData = [Environment]::GetEnvironmentVariable('ProgramData')

function Get-ValidatedWorkerOutputPath {
    param([Parameter(Mandatory=$true)][string]$Path, [Parameter(Mandatory=$true)][string]$ExpectedDirectory, [Parameter(Mandatory=$true)][string]$LeafPattern)
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'A worker output path cannot be empty.' }
    if ($Path.IndexOf([char]0) -ge 0 -or $Path.IndexOf('"') -ge 0) { throw 'A worker output path contains an unsupported character.' }
    $target = [IO.Path]::GetFullPath($Path)
    $parent = [IO.Path]::GetDirectoryName($target)
    if (-not $parent -or -not [IO.Directory]::Exists($parent)) { throw ('Worker output directory is unavailable: ' + $parent) }
    $canonicalParent = [IO.Path]::GetFullPath($ExpectedDirectory)
    if (-not [string]::Equals($parent, $canonicalParent, [StringComparison]::OrdinalIgnoreCase)) { throw 'Worker output directory is outside the protected GephTun state tree.' }
    $parentAttributes = [IO.File]::GetAttributes($parent)
    if (($parentAttributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Worker output directory is redirected.' }
    if ([IO.Path]::GetFileName($target) -notmatch $LeafPattern) { throw 'Worker output filename is invalid.' }
    if ([IO.Directory]::Exists($target)) { throw 'Worker output path is a directory.' }
    if ([IO.File]::Exists($target)) {
        $targetAttributes = [IO.File]::GetAttributes($target)
        if (($targetAttributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Worker output file is redirected.' }
    }
    return $target
}

function Write-WorkerFailure {
    param([string]$Message)
    if ([IO.File]::Exists($ResultFile)) { return }
    try {
        $failure = @{ Success = $false; Message = ('Worker failed: ' + $Message); Details = @{ WorkerLog = $CaptureFile } }
        $temporary = $ResultFile + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
        try {
            [IO.File]::WriteAllText($temporary, ($failure | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
            [IO.File]::Move($temporary, $ResultFile)
        }
        finally { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) } }
    }
    catch {
        # Keep the original process failure visible if the fallback result
        # cannot be published (for example, a protected or removed directory).
        Write-Error ('Could not write worker failure result: ' + $_.Exception.Message) -ErrorAction Continue
    }
}

try {
    if ([string]::IsNullOrWhiteSpace($script:ProgramData)) { throw 'Windows ProgramData is unavailable.' }
    $stateDirectory = Join-Path $script:ProgramData 'GephTun'
    $ResultFile = Get-ValidatedWorkerOutputPath $ResultFile (Join-Path $stateDirectory 'results') '^[a-f0-9]{32}\.json$'
    $CaptureFile = Get-ValidatedWorkerOutputPath $CaptureFile (Join-Path $stateDirectory 'logs') '^ui-worker-[a-f0-9]{32}\.log$'
    $script:OutputPathsValidated = $true
    if (-not [IO.File]::Exists($script:WorkerPath)) { throw ('Worker script is missing: ' + $script:WorkerPath) }
    $workerArguments = @{
        Action = $Action
        Port = $Port
        OwnerProcessId = $OwnerProcessId
        ResultFile = $ResultFile
    }
    if ($OperationToken) { $workerArguments.OperationToken = $OperationToken }
    & $script:WorkerPath @workerArguments *> $CaptureFile
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
catch {
    if ($script:OutputPathsValidated) { Write-WorkerFailure $_.Exception.Message }
    exit 1
}
