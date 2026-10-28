#Requires -Version 5.1
# Read-only cleanup gate. Never starts recovery or changes Windows networking.
[CmdletBinding()]
param([string]$StateDirectory,[string]$ResultJson)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Diagnostics.Common.ps1')
if(-not $StateDirectory){$StateDirectory=Join-Path $env:ProgramData 'GephTun'}
$checks=[Collections.Generic.List[object]]::new()
try{
    $rows=@(Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe' OR Name='tun2socks-windows-amd64.exe'" -ErrorAction Stop|Where-Object{$_.ProcessId -ne $PID})
    $unknown=@($rows|Where-Object{$_.Name -ne 'tun2socks-windows-amd64.exe' -and
        ([string]::IsNullOrWhiteSpace($_.CommandLine) -or $_.CommandLine -match '(?i)\s-(?:EncodedCommand|enc|ec|e)\s')})
    $active=@($rows|Where-Object{
        $_.Name -eq 'tun2socks-windows-amd64.exe' -or
        ($_.CommandLine -notmatch '(?i)\s-Command\b' -and $_.CommandLine -match '(?i)\s-File\s.*GephTun')
    })
    $result='PASS'
    if($unknown.Count){$result='UNKNOWN'}
    if($active.Count){$result='BLOCKED'}
    $checks.Add([pscustomobject]@{Name='Product processes';Result=$result;Detail=('Active='+$active.Count+'; unreadable PowerShell commands='+$unknown.Count);Processes=@($active|Select-Object ProcessId,Name,CommandLine)})
}catch{$checks.Add([pscustomobject]@{Name='Product processes';Result='UNKNOWN';Detail=$_.Exception.Message})}
foreach($leaf in @('session.json','GephTun-BootReconcile.ps1')){
    $state=Get-DiagnosticFileState (Join-Path $StateDirectory $leaf)
    $checks.Add([pscustomobject]@{Name=$leaf;Result=$(if($state.State -eq 'ABSENT'){'PASS'}elseif($state.State -eq 'PRESENT'){'BLOCKED'}else{'UNKNOWN'});Detail=$state.Error})
}
try{
    $tasks=@(Get-ScheduledTask -ErrorAction Stop|Where-Object{$_.TaskName -eq 'GephTunBootReconcile'})
    $checks.Add([pscustomobject]@{Name='Boot recovery task';Result=$(if($tasks.Count){'BLOCKED'}else{'PASS'});Detail=('Task count='+$tasks.Count)})
}catch{$checks.Add([pscustomobject]@{Name='Boot recovery task';Result='UNKNOWN';Detail=$_.Exception.Message})}
$lease=$null;$acquired=$false
try{
    try{$lease=[Threading.Mutex]::OpenExisting('Global\GephTun-Session-v1')}
    catch{
        if($_.Exception.GetBaseException() -isnot [Threading.WaitHandleCannotBeOpenedException]){throw}
    }
    if($null -ne $lease){
        try{$acquired=$lease.WaitOne(0)}
        catch{if($_.Exception.GetBaseException() -is [Threading.AbandonedMutexException]){$acquired=$true}else{throw}}
    }
    $checks.Add([pscustomobject]@{Name='Session mutex';Result=$(if($null -eq $lease -or $acquired){'PASS'}else{'BLOCKED'});Detail=$(if($null -eq $lease){'Confirmed absent'}elseif($acquired){'Confirmed unowned'}else{'Owned by another process'})})
}catch{$checks.Add([pscustomobject]@{Name='Session mutex';Result='UNKNOWN';Detail=$_.Exception.Message})}
finally{if($null -ne $lease){if($acquired){$lease.ReleaseMutex()};$lease.Dispose()}}
$status=Get-DiagnosticFileState (Join-Path $StateDirectory 'status.json')
$report=[ordered]@{
    Kind='GephTunCleanupPreflight';CapturedUtc=[DateTime]::UtcNow.ToString('o')
    SafeToRemoveOldFolders=(@($checks|Where-Object{$_.Result -ne 'PASS'}).Count -eq 0)
    Checks=$checks.ToArray()
    HistoricalStatusObservation=$status
    Scope='Folder-dependency gate only. A status file is not an armed recovery dependency; its access errors remain visible. Windows routing, DNS and firewall normalcy are not certified.'
}
Write-DiagnosticResult $report $ResultJson
