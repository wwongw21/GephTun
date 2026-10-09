#Requires -Version 5.1
[CmdletBinding()]
param([string]$PackageDirectory,[string]$ResultJson)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
if(-not $PackageDirectory){$PackageDirectory=Split-Path -Parent $PSScriptRoot}
$toolRoot=Join-Path $PackageDirectory 'tools/diagnostics'
. (Join-Path $PackageDirectory 'tests/Package.Common.ps1')
$sources=@(foreach($path in @('tools/diagnostics/Diagnostics.Common.ps1','tools/diagnostics/Get-GephTunDiagnostics.ps1','tools/diagnostics/Compare-GephTunFiles.ps1','tools/diagnostics/Measure-CimWorkload.ps1','tools/diagnostics/Get-GephTunCleanupState.ps1','tests/Diagnostics.Tests.ps1','tests/Measure-WindowsResources.ps1','tests/Package.Common.ps1')){
    [pscustomobject]@{Path=$path;Sha256=(Get-FileHash -LiteralPath (Join-Path $PackageDirectory $path) -Algorithm SHA256).Hash.ToLowerInvariant()}
})
$root=Join-Path ([IO.Path]::GetTempPath()) ('GephTun-diagnostic-tests-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)
$cases=[Collections.Generic.List[object]]::new()
function Assert-Diagnostic($Value,[string]$Message){if(-not $Value){throw $Message}}
function Test-Diagnostic([string]$Name,[scriptblock]$Body){
    try{& $Body;$cases.Add([pscustomobject]@{Result='PASS';Test=$Name;Detail=''})}
    catch{$cases.Add([pscustomobject]@{Result='FAIL';Test=$Name;Detail=$_.Exception.Message})}
}
try{
    Test-Diagnostic 'Exited diagnostic PIDs remain exited with unavailable measurements' {
        $r=& (Join-Path $toolRoot 'Get-GephTunDiagnostics.ps1') -Sections Processes -ProcessIds 2147483647
        Assert-Diagnostic ($r.Data.Processes[0].State -eq 'EXITED' -and $null -eq $r.Data.Processes[0].PrivateBytes) 'Missing PID became zero memory or a replacement process.'
    }
    Test-Diagnostic 'Invalid diagnostic PIDs produce an explicit partial result' {
        $r=& (Join-Path $toolRoot 'Get-GephTunDiagnostics.ps1') -Sections Processes -ProcessIds 0
        Assert-Diagnostic ($r.Result -eq 'PARTIAL' -and $r.Checks[0].Result -eq 'UNKNOWN') 'Invalid PID was silently ignored.'
    }
    Test-Diagnostic 'Confirmed missing state is different from unreadable state' {
        $r=& (Join-Path $toolRoot 'Get-GephTunDiagnostics.ps1') -Sections State -StateDirectory $root
        Assert-Diagnostic ($r.Result -eq 'COMPLETE' -and @($r.Data.State|Where-Object{$_.State -eq 'ABSENT'}).Count -eq 2) 'Missing state was misreported.'
    }
    Test-Diagnostic 'Malformed state remains unknown rather than clean' {
        $state=Join-Path $root 'malformed';[void][IO.Directory]::CreateDirectory($state)
        [IO.File]::WriteAllText((Join-Path $state 'session.json'),'broken-json{{{')
        $r=& (Join-Path $toolRoot 'Get-GephTunDiagnostics.ps1') -Sections State -StateDirectory $state
        Assert-Diagnostic ($r.Result -eq 'PARTIAL' -and $r.Data.State[0].State -eq 'UNKNOWN') 'Malformed state became absence.'
    }
    foreach($encodingName in @('UTF8','Unicode')){
        Test-Diagnostic ("Bounded log tails preserve readable "+$encodingName+" text") {
            $state=Join-Path $root $encodingName;[void][IO.Directory]::CreateDirectory((Join-Path $state 'logs'))
            $encoding=[Text.Encoding]::UTF8
            if($encodingName -eq 'Unicode'){$encoding=[Text.Encoding]::Unicode}
            [IO.File]::WriteAllText((Join-Path $state 'logs/GephTun.log'),(('older text '*1000)+'latest log marker'),$encoding)
            $r=& (Join-Path $toolRoot 'Get-GephTunDiagnostics.ps1') -Sections Log -StateDirectory $state -LogTailBytes 256
            Assert-Diagnostic ($r.Result -eq 'COMPLETE' -and $r.Data.Log.Tail.EndsWith('latest log marker') -and $r.Data.Log.Tail.Length -le 256) 'Log tail was unbounded or decoded incorrectly.'
        }
    }
    Test-Diagnostic 'Missing comparison inputs are unknown rather than matching' {
        $r=& (Join-Path $toolRoot 'Compare-GephTunFiles.ps1') -PackageDirectory $root -ReferenceDirectories $root -Files @('missing.txt')
        Assert-Diagnostic ($r.Rows[0].State -eq 'UNKNOWN' -and $null -eq $r.Rows[0].PackageSha256) 'Missing files matched.'
    }
    Test-Diagnostic 'File comparisons report real differences' {
        $left=Join-Path $root 'left';$right=Join-Path $root 'right'
        [void][IO.Directory]::CreateDirectory($left);[void][IO.Directory]::CreateDirectory($right)
        [IO.File]::WriteAllText((Join-Path $left 'sample.txt'),'left')
        [IO.File]::WriteAllText((Join-Path $right 'sample.txt'),'right')
        $r=& (Join-Path $toolRoot 'Compare-GephTunFiles.ps1') -PackageDirectory $left -ReferenceDirectories $right -Files @('sample.txt')
        Assert-Diagnostic ($r.Rows[0].State -eq 'DIFFERENT') 'Different contents matched.'
    }
    Test-Diagnostic 'Unsafe comparison paths are rejected before access' {
        $failed=$false
        try{& (Join-Path $toolRoot 'Compare-GephTunFiles.ps1') -PackageDirectory $root -ReferenceDirectories $root -Files @('../outside.txt')|Out-Null}catch{$failed=$true}
        Assert-Diagnostic $failed 'Comparison accepted a traversal path.'
    }
    Test-Diagnostic 'Diagnostic outputs cannot overwrite the project or an existing output' {
        $inside=Join-Path $PackageDirectory 'forbidden-diagnostic.json'
        $outside=Join-Path $root 'existing-output.json';[IO.File]::WriteAllText($outside,'preserve me')
        foreach($path in @($inside,$outside)){
            $failed=$false
            try{& (Join-Path $toolRoot 'Get-GephTunDiagnostics.ps1') -Sections Processes -ProcessIds $PID -ResultJson $path|Out-Null}catch{$failed=$true}
            Assert-Diagnostic $failed 'A protected diagnostic output was overwritten.'
        }
        Assert-Diagnostic ([IO.File]::ReadAllText($outside) -eq 'preserve me' -and -not [IO.File]::Exists($inside)) 'Output rejection changed files.'
    }
    Test-Diagnostic 'An event permission failure stays unknown' {
        function Get-WinEvent{[CmdletBinding()]param($FilterHashtable,$MaxEvents)throw [UnauthorizedAccessException]::new('Fixture event access denied')}
        $r=& (Join-Path $toolRoot 'Get-GephTunDiagnostics.ps1') -Sections Events
        Assert-Diagnostic ($r.Result -eq 'PARTIAL' -and $r.Checks[0].Result -eq 'UNKNOWN') 'Denied events became an empty successful query.'
    }
    Test-Diagnostic 'Confirmed no matching events is an explicit empty result' {
        function Get-WinEvent{[CmdletBinding()]param($FilterHashtable,$MaxEvents)Write-Error 'Fixture no events' -ErrorId NoMatchingEventsFound -ErrorAction Stop}
        $r=& (Join-Path $toolRoot 'Get-GephTunDiagnostics.ps1') -Sections Events
        Assert-Diagnostic ($r.Result -eq 'COMPLETE' -and $r.Checks[0].Result -eq 'EMPTY') 'Confirmed empty event results were not distinguished.'
    }
    Test-Diagnostic 'CIM workload records denied providers and process-local GC without network mutation' {
        function Get-CimInstance{[CmdletBinding()]param($ClassName,$Filter)return @()}
        function Get-NetUDPEndpoint{[CmdletBinding()]param()return @()}
        function Get-NetTCPConnection{[CmdletBinding()]param()return @()}
        function Get-NetRoute{[CmdletBinding()]param($PolicyStore)throw [UnauthorizedAccessException]::new('Fixture route access denied')}
        function Get-NetAdapter{[CmdletBinding()]param()return @()}
        function Find-NetRoute{[CmdletBinding()]param($RemoteIPAddress)return @()}
        function Get-DnsClientNrptRule{[CmdletBinding()]param()return @()}
        function Get-DnsClientNrptPolicy{[CmdletBinding()]param([switch]$Effective)return @()}
        $r=& (Join-Path $toolRoot 'Measure-CimWorkload.ps1') -DurationSeconds 1 -SampleMilliseconds 10000 -ForceGcEvery 1
        Assert-Diagnostic ($r.Samples[0].ForcedCollections -ge 1 -and @($r.Samples[0].Queries|Where-Object{$_.Name -eq 'Routes' -and $_.Result -eq 'UNKNOWN'}).Count -eq 1) 'Provider failure was hidden.'
    }
    foreach($mode in @('UnreadableCommand','EncodedCommand','ActiveEngine','TaskDenied','SavedJournal')){
        Test-Diagnostic ("Cleanup gate refuses uncertain or active dependencies: "+$mode) {
            $state=Join-Path $root $mode;[void][IO.Directory]::CreateDirectory($state)
            if($mode -eq 'SavedJournal'){[IO.File]::WriteAllText((Join-Path $state 'session.json'),'preserve journal')}
            function Get-CimInstance{
                [CmdletBinding()]param($ClassName,$Filter)
                if($mode -eq 'UnreadableCommand'){[pscustomobject]@{ProcessId=2147483646;Name='powershell.exe';CommandLine=$null}}
                elseif($mode -eq 'EncodedCommand'){[pscustomobject]@{ProcessId=2147483646;Name='powershell.exe';CommandLine='powershell.exe -EncodedCommand Zml4dHVyZQ=='}}
                elseif($mode -eq 'ActiveEngine'){[pscustomobject]@{ProcessId=2147483646;Name='tun2socks-windows-amd64.exe';CommandLine='fixture'}}
            }
            function Get-ScheduledTask{
                [CmdletBinding()]param()
                if($mode -eq 'TaskDenied'){throw [UnauthorizedAccessException]::new('Fixture scheduler denied')}
                return @()
            }
            $r=& (Join-Path $toolRoot 'Get-GephTunCleanupState.ps1') -StateDirectory $state
            Assert-Diagnostic (-not $r.SafeToRemoveOldFolders) 'Cleanup accepted unreadable or active state.'
            if($mode -eq 'SavedJournal'){Assert-Diagnostic ([IO.File]::ReadAllText((Join-Path $state 'session.json')) -eq 'preserve journal') 'Cleanup gate changed the journal.'}
        }
    }
    Test-Diagnostic 'Resource sampling binds an explicitly selected PID and writes outside the project' {
        $csv=Join-Path $root 'resources.csv'
        & (Join-Path $PackageDirectory 'tests/Measure-WindowsResources.ps1') -ProcessIds $PID -DurationSeconds 1 -SampleSeconds 1 -OutputCsv $csv|Out-Null
        $rows=@(Import-Csv -LiteralPath $csv)
        Assert-Diagnostic ($rows.Count -gt 0 -and @($rows|Where-Object{$_.State -ne 'RUNNING' -or [int]$_.ProcessId -ne $PID}).Count -eq 0) 'Resource sampling lost its selected process identity.'
    }
    Test-Diagnostic 'Diagnostic sources stay byte-identical during tests' {
        foreach($source in $sources){Assert-Diagnostic ((Get-FileHash -LiteralPath (Join-Path $PackageDirectory $source.Path)).Hash -eq $source.Sha256) ('Source changed: '+$source.Path)}
    }
}finally{
    $resolved=[IO.Path]::GetFullPath($root)
    $temporary=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar
    if(-not $resolved.StartsWith($temporary,[StringComparison]::OrdinalIgnoreCase)){throw 'Diagnostic test cleanup escaped its temporary workspace.'}
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
$failed=@($cases|Where-Object{$_.Result -eq 'FAIL'})
$report=[ordered]@{CapturedUtc=[DateTime]::UtcNow.ToString('o');Total=$cases.Count;Passed=$cases.Count-$failed.Count;Failed=$failed.Count;Skipped=0;Sources=$sources;Tests=$cases.ToArray();Scope='Isolated diagnostic behavior, bounded temporary files, and sampling this test process; no networking changes or live qualification.'}
if($ResultJson){$output=Get-GephPackageFullPath $ResultJson;Assert-GephPackageOutput $output $PackageDirectory;Write-GephPackageNewJson $output $report}
foreach($failure in $failed){Write-Output ('FAIL: '+$failure.Test+': '+$failure.Detail)}
Write-Output ('{0} diagnostic tests; {1} passed; {2} failed.' -f $report.Total,$report.Passed,$report.Failed)
if($failed.Count){exit 1}
