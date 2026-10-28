#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][int[]]$ProcessIds,
    [Parameter(Mandatory=$true)][string]$OutputCsv,
    [ValidateRange(1,7200)][int]$DurationSeconds = 900,
    [ValidateRange(1,60)][int]$SampleSeconds = 5
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Package.Common.ps1')
$root = Get-GephPackageFullPath (Split-Path -Parent $PSScriptRoot)
$output = Get-GephPackageFullPath $OutputCsv
Assert-GephPackageOutput $output $root

# Read-only sampling: explicit PIDs are bound to their initial start times.
# This script never starts/stops a process or changes networking. Exited PIDs
# are not replaced with newly started processes that happen to reuse a number.
$identities = @{}
foreach ($processId in @($ProcessIds | Select-Object -Unique)) {
    if ($processId -lt 1) { throw 'Every process ID must be positive.' }
    $process = $null
    try {
        $process = [Diagnostics.Process]::GetProcessById($processId)
        $identities[$processId] = @{
            Name = $process.ProcessName; StartUtc = $process.StartTime.ToUniversalTime()
            PreviousCpu = $null; PreviousElapsed = $null; Terminal = ''
        }
    } finally { if ($null -ne $process) { $process.Dispose() } }
}
[void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($output))
Assert-GephPackageOutput $output $root
$stream = $null; $writer = $null
$timer = [Diagnostics.Stopwatch]::StartNew()
$invariant = [Globalization.CultureInfo]::InvariantCulture
$logicalProcessors = [Environment]::ProcessorCount
$rows = 0
try {
    $stream = [IO.File]::Open($output,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    $writer = New-Object IO.StreamWriter($stream, (New-Object Text.UTF8Encoding($false)))
    $writer.WriteLine('TimestampUtc,ElapsedSeconds,ProcessId,ProcessName,StartTimeUtc,State,CpuSeconds,MachineCpuPercent,WorkingSetBytes,PrivateBytes,Handles,Threads,Error')
    do {
        foreach ($processId in @($identities.Keys | Sort-Object)) {
            $identity = $identities[$processId]
            $process = $null; $state = $identity.Terminal; $errorText = ''
            $cpu = ''; $cpuPercent = ''; $working = ''; $private = ''; $handles = ''; $threads = ''
            $elapsed = $timer.Elapsed.TotalSeconds
            if (-not $state) {
                try {
                    $process = [Diagnostics.Process]::GetProcessById($processId)
                    if ($process.StartTime.ToUniversalTime().Ticks -ne $identity.StartUtc.Ticks) {
                        $state = 'PID_REUSED'; $identity.Terminal = $state
                    } else {
                        $process.Refresh()
                        $cpuValue = $process.TotalProcessorTime.TotalSeconds
                        $cpu = $cpuValue.ToString('F6',$invariant)
                        $working = $process.WorkingSet64; $private = $process.PrivateMemorySize64
                        $handles = $process.HandleCount; $threads = $process.Threads.Count
                        if ($null -ne $identity.PreviousCpu -and $elapsed -gt $identity.PreviousElapsed) {
                            $cpuPercent = (100.0 * ($cpuValue - $identity.PreviousCpu) / ($elapsed - $identity.PreviousElapsed) / $logicalProcessors).ToString('F4',$invariant)
                        }
                        $identity.PreviousCpu = $cpuValue; $identity.PreviousElapsed = $elapsed
                        $state = 'RUNNING'
                    }
                } catch [ArgumentException] {
                    $state = 'EXITED'; $identity.Terminal = $state
                } catch {
                    # Access/measurement failures are visible gaps, never zero usage.
                    $state = 'ERROR'; $errorText = $_.Exception.Message
                } finally { if ($null -ne $process) { $process.Dispose() } }
            }
            $values = @([DateTime]::UtcNow.ToString('o'),$elapsed.ToString('F3',$invariant),$processId,$identity.Name,$identity.StartUtc.ToString('o'),$state,$cpu,$cpuPercent,$working,$private,$handles,$threads,$errorText)
            $line = @($values | ForEach-Object { '"' + ([string]$_).Replace('"','""') + '"' }) -join ','
            $writer.WriteLine($line); $rows++
        }
        # Flush each sample so an interrupted run retains its observations.
        $writer.Flush()
        $remaining = $DurationSeconds - $timer.Elapsed.TotalSeconds
        if ($remaining -le 0) { break }
        [Threading.Thread]::Sleep([int](1000 * [Math]::Min($SampleSeconds,$remaining)))
    } while ($true)
} finally {
    $timer.Stop()
    if ($null -ne $writer) { $writer.Dispose() }
    elseif ($null -ne $stream) { $stream.Dispose() }
}
Write-Output ('Saved {0} observations to {1}. CPU percentage is normalized to {2} logical processors. Measurements are observations, not a production PASS.' -f $rows,$output,$logicalProcessors)
