# Shared helpers for read-only engineering diagnostics; never imports the controller.
Set-StrictMode -Version 2.0
$script:DiagnosticPackageRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $script:DiagnosticPackageRoot 'tests/Package.Common.ps1')

function Write-DiagnosticResult($Report,[string]$ResultJson) {
    if($ResultJson){
        $output=Get-GephPackageFullPath $ResultJson
        Assert-GephPackageOutput $output $script:DiagnosticPackageRoot
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($output))
        Assert-GephPackageOutput $output $script:DiagnosticPackageRoot
        Write-GephPackageNewJson $output $Report
    }
    return $Report
}

function Get-DiagnosticFileState([string]$Path) {
    try {
        $attributes=[IO.File]::GetAttributes($Path)
        if(($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Redirected diagnostic input.'}
        return [pscustomobject]@{Path=$Path;State='PRESENT';Error=''}
    }catch{
        $cause=$_.Exception.GetBaseException()
        $state='UNKNOWN'
        if($cause -is [IO.FileNotFoundException] -or $cause -is [IO.DirectoryNotFoundException]){$state='ABSENT'}
        return [pscustomobject]@{Path=$Path;State=$state;Error=$cause.Message}
    }
}

function Get-DiagnosticProcess([int]$ProcessId) {
    $process=$null
    $record=[ordered]@{ProcessId=$ProcessId;State='UNKNOWN';Name=$null;StartUtc=$null;WorkingSetBytes=$null;PrivateBytes=$null;Handles=$null;Threads=$null;CpuSeconds=$null;Error=''}
    try{
        $process=[Diagnostics.Process]::GetProcessById($ProcessId)
        $record.Name=$process.ProcessName
        $record.StartUtc=$process.StartTime.ToUniversalTime().ToString('o')
        $record.WorkingSetBytes=$process.WorkingSet64
        $record.PrivateBytes=$process.PrivateMemorySize64
        $record.Handles=$process.HandleCount
        $record.Threads=$process.Threads.Count
        $record.CpuSeconds=$process.TotalProcessorTime.TotalSeconds
        $record.State='READ'
    }catch{
        if($_.Exception.GetBaseException() -is [ArgumentException]){$record.State='EXITED'}
        $record.Error=$_.Exception.Message
    }finally{if($null -ne $process){$process.Dispose()}}
    return [pscustomobject]$record
}
