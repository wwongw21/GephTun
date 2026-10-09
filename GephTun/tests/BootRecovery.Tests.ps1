#Requires -Version 5.1
# Isolated doubles for the actual standalone boot script. No Windows policy is changed.
[CmdletBinding()]
param([string]$BootScriptPath, [switch]$PassThru, [string]$ResultJson)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if (-not $BootScriptPath) { $BootScriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'GephTun-BootReconcile.ps1' }
$originalHash = (Get-FileHash -LiteralPath $BootScriptPath -Algorithm SHA256).Hash
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('GephTun-boot-tests-' + [guid]::NewGuid().ToString('N'))
$results = [Collections.Generic.List[object]]::new()
$previousFixture = Get-Variable -Name GephTunBootFixture -Scope Global -ErrorAction SilentlyContinue

function Assert-Boot($Value, [string]$Message) { if (-not $Value) { throw $Message } }

function Invoke-BootFixture([string]$Mode, [scriptblock]$Check) {
    $fixtureRoot = Join-Path $testRoot ([guid]::NewGuid().ToString('N'))
    $stateRoot = Join-Path $fixtureRoot 'GephTun'
    [void][IO.Directory]::CreateDirectory($stateRoot)
    $copy = Join-Path $stateRoot 'GephTun-BootReconcile.ps1'
    [IO.File]::Copy($BootScriptPath, $copy)
    $start = [DateTime]::UtcNow.AddMinutes(-5)
    $global:GephTunBootFixture = [pscustomobject]@{
        Mode=$Mode; Nrpt=[Collections.Generic.List[object]]::new(); Firewall=[Collections.Generic.List[object]]::new()
        RemovedNrpt=[Collections.Generic.List[string]]::new(); RemovedFirewall=[Collections.Generic.List[string]]::new()
        NrptReads=0; FirewallReads=0; Unregisters=0; TaskExists=$true; ForeignTaskExists=$true; Released=0; Disposed=0; Waits=0
        Start=$start; StateRoot=$stateRoot; Copy=$copy; Runs=0; OwnershipReadFailures=0
    }
    $fixture = $global:GephTunBootFixture
    $fixture.Nrpt.Add([pscustomobject]@{Name='owned-dns';Comment=('GephTun:'+('a'*32))})
    $fixture.Nrpt.Add([pscustomobject]@{Name='foreign-dns';Comment='OtherVPN:keep'})
    $fixture.Firewall.Add([pscustomobject]@{Name=('GephTun-IPv6-Contain-'+('a'*32))})
    $fixture.Firewall.Add([pscustomobject]@{Name='OtherVPN-keep'})
    if ($Mode -in @('Empty','TaskAbsent','TaskQueryDenied','TaskStillPresent','TaskRemovalDenied')) {
        $fixture.Nrpt.RemoveAt(0); $fixture.Firewall.RemoveAt(0)
    }
    if ($Mode -eq 'TaskAbsent') { $fixture.TaskExists=$false }
    $journal = @{Schema=2;Token=('a'*32);Worker=@{Id=4242;StartUtc=$start.ToString('o');Path='fixture-powershell.exe'}}
    if ($Mode -eq 'LegacyProfiles') { $journal.Containment=@{Profiles=@(@{Name='Public';WasEnabled=$false})} }
    if ($Mode -eq 'MissingIdentity') { $journal.Worker.Remove('StartUtc') }
    if ($Mode -eq 'Live') {
        $journal.Token=('b'*32)
        $fixture.Nrpt.Add([pscustomobject]@{Name='live-dns';Comment=('GephTun:'+('b'*32))})
        $fixture.Firewall.Add([pscustomobject]@{Name=('GephTun-IPv6-Contain-'+('b'*32))})
    }
    if ($Mode -in @('LegacyProfiles','Live','Dead','PidReused','WrongProcess','ProcessDenied','MissingIdentity','JournalDenied','Malformed')) {
        $text = $journal | ConvertTo-Json -Depth 6
        if ($Mode -eq 'Malformed') { $text='broken-json{{{' }
        [IO.File]::WriteAllText((Join-Path $stateRoot 'session.json'), $text)
    }

    # Every operating-system command called by the production boot script is
    # replaced here. The only real files are the fixture's temporary files.
    function New-Object {
        [CmdletBinding()]param([string]$TypeName,[object[]]$ArgumentList)
        Assert-Boot ($TypeName -eq 'Threading.Mutex') 'Unexpected constructor crossed the boot fixture boundary.'
        Assert-Boot ($ArgumentList[1] -eq 'Global\GephTun-Session-v1') 'Boot must share the controller session mutex.'
        $lease=[pscustomobject]@{}
        $lease|Add-Member ScriptMethod WaitOne {
            param($Timeout)
            $global:GephTunBootFixture.Waits++
            if($global:GephTunBootFixture.Mode -eq 'MutexDenied'){throw [UnauthorizedAccessException]::new('Fixture mutex denied')}
            if($global:GephTunBootFixture.Mode -eq 'Abandoned'){throw [Threading.AbandonedMutexException]::new()}
            return $global:GephTunBootFixture.Mode -ne 'Busy'
        }
        $lease|Add-Member ScriptMethod ReleaseMutex {$global:GephTunBootFixture.Released++}
        $lease|Add-Member ScriptMethod Dispose {$global:GephTunBootFixture.Disposed++}
        return $lease
    }
    function Start-Sleep { [CmdletBinding()]param($Seconds) }
    function Get-Process {
        [CmdletBinding()]param($Id)
        $f=$global:GephTunBootFixture
        if($f.Mode -in @('Dead','LegacyProfiles')){throw [ArgumentException]::new('Fixture process is gone')}
        if($f.Mode -eq 'ProcessDenied'){throw [UnauthorizedAccessException]::new('Fixture process metadata denied')}
        $actual=$f.Start
        if($f.Mode -eq 'PidReused'){$actual=$actual.AddTicks(1)}
        return [pscustomobject]@{ProcessName=$(if($f.Mode -eq 'WrongProcess'){'explorer'}else{'powershell'});StartTime=$actual.ToLocalTime();Path='fixture-powershell.exe'}
    }
    function Get-Content {
        [CmdletBinding()]param($LiteralPath,[switch]$Raw,$Encoding)
        if($global:GephTunBootFixture.Mode -eq 'JournalDenied'){throw [UnauthorizedAccessException]::new('Fixture journal denied')}
        return Microsoft.PowerShell.Management\Get-Content -LiteralPath $LiteralPath -Raw -Encoding UTF8 -ErrorAction Stop
    }
    function Get-DnsClientNrptRule {
        [CmdletBinding()]param()
        $f=$global:GephTunBootFixture;$f.NrptReads++
        if($f.Mode -eq 'NrptUnreadable' -or ($f.Mode -eq 'VerifyUnreadable' -and $f.NrptReads -ge 2)){
            throw [UnauthorizedAccessException]::new('Fixture DNS provider denied')
        }
        if($f.Mode -eq 'Transient' -and $f.NrptReads -le 2){throw [IO.IOException]::new('Fixture DNS provider not ready')}
        return $f.Nrpt.ToArray()
    }
    function Get-NetFirewallRule {
        [CmdletBinding()]param($PolicyStore)
        Assert-Boot ($PolicyStore -eq 'PersistentStore') 'Boot must enumerate the persistent firewall store.'
        $f=$global:GephTunBootFixture;$f.FirewallReads++
        if($f.Mode -eq 'FirewallUnreadable'){throw [UnauthorizedAccessException]::new('Fixture firewall provider denied')}
        return $f.Firewall.ToArray()
    }
    function Remove-DnsClientNrptRule {
        [CmdletBinding()]param($Name,[switch]$Force)
        $f=$global:GephTunBootFixture
        Assert-Boot ($f.NrptReads -gt 0 -and $f.FirewallReads -gt 0) 'Both providers must be read before removal.'
        if($f.Mode -eq 'NrptDenied'){throw [UnauthorizedAccessException]::new('Fixture DNS removal denied')}
        $f.RemovedNrpt.Add($Name)
        if($f.Mode -ne 'Remaining') { foreach($rule in @($f.Nrpt.ToArray()|Where-Object{$_.Name -eq $Name})){[void]$f.Nrpt.Remove($rule)} }
    }
    function Remove-NetFirewallRule {
        [CmdletBinding()]param($Name)
        $f=$global:GephTunBootFixture
        if($f.Mode -eq 'FirewallDenied'){throw [UnauthorizedAccessException]::new('Fixture firewall removal denied')}
        $f.RemovedFirewall.Add($Name)
        foreach($rule in @($f.Firewall.ToArray()|Where-Object{$_.Name -eq $Name})){[void]$f.Firewall.Remove($rule)}
    }
    function Unregister-ScheduledTask {
        [CmdletBinding()]param($TaskName,$TaskPath,[switch]$Confirm)
        Assert-Boot ($TaskPath -eq '\') 'Task removal must use the exact root task namespace.'
        $f=$global:GephTunBootFixture;$f.Unregisters++
        if($f.Mode -eq 'TaskRemovalDenied'){throw [UnauthorizedAccessException]::new('Fixture task removal denied')}
        if($f.Mode -eq 'TaskAbsent'){Write-Error 'Fixture task absent' -Category ObjectNotFound -ErrorAction Stop}
        if($f.Mode -ne 'TaskStillPresent'){$f.TaskExists=$false}
    }
    function Get-ScheduledTask {
        [CmdletBinding()]param($TaskName,$TaskPath)
        Assert-Boot ($TaskPath -eq '\') 'Task verification must use the exact root task namespace.'
        $f=$global:GephTunBootFixture
        if($f.Mode -eq 'TaskQueryDenied'){throw [UnauthorizedAccessException]::new('Fixture task absence query denied')}
        if($f.TaskExists){return [pscustomobject]@{TaskName=$TaskName}}
        return @()
    }
    function Run-Boot {
        $f=$global:GephTunBootFixture;$f.Runs++
        & $f.Copy
    }
    $previousProgramData=$env:ProgramData
    try {
        $env:ProgramData=$fixtureRoot
        Run-Boot
        & $Check $fixture
        Assert-Boot (@($fixture.Nrpt|Where-Object{$_.Name -eq 'foreign-dns'}).Count -eq 1) 'A foreign DNS rule was changed.'
        Assert-Boot (@($fixture.Firewall|Where-Object{$_.Name -eq 'OtherVPN-keep'}).Count -eq 1) 'A foreign firewall rule was changed.'
        Assert-Boot $fixture.ForeignTaskExists 'A same-named foreign task was changed.'
        Assert-Boot ($fixture.Disposed -eq $fixture.Runs) 'Every mutex lease must be disposed.'
        if($fixture.Mode -in @('Busy','MutexDenied')){
            Assert-Boot ($fixture.Released -eq 0) 'An unowned mutex must not be released.'
        }else{Assert-Boot ($fixture.Released -eq $fixture.Runs) 'Every owned mutex must be released.'}
    } finally { $env:ProgramData=$previousProgramData }
}

function Test-BootCase([string]$Name,[string]$Mode,[scriptblock]$Check) {
    try {
        Invoke-BootFixture $Mode $Check
        $results.Add([pscustomobject]@{Result='PASS';Test=$Name;Detail=''})
    }catch{$results.Add([pscustomobject]@{Result='FAIL';Test=$Name;Detail=$_.Exception.Message})}
}

try {
    foreach($mode in @('NoJournal','Dead','PidReused','WrongProcess','Transient','Abandoned','SameNameForeignTask')){
        Test-BootCase ("Boot confirmed stale recovery succeeds: "+$mode) $mode {
            param($f)
            Assert-Boot (-not $f.TaskExists) 'Successful recovery must remove the task.'
            Assert-Boot (-not [IO.File]::Exists($f.Copy)) 'Confirmed task absence must remove only the state copy.'
            Assert-Boot ($f.RemovedNrpt.Count -eq 1 -and $f.RemovedFirewall.Count -eq 1) 'Owned stale rules were not removed.'
        }
    }
    foreach($mode in @('Empty','TaskAbsent')){
        Test-BootCase ("Boot already-clean recovery is idempotent: "+$mode) $mode {
            param($f)
            Assert-Boot (-not $f.TaskExists -and -not [IO.File]::Exists($f.Copy)) 'Already-clean recovery did not complete.'
            Assert-Boot ($f.RemovedNrpt.Count -eq 0 -and $f.RemovedFirewall.Count -eq 0) 'Already-clean recovery removed foreign policy.'
        }
    }
    foreach($mode in @('NrptUnreadable','FirewallUnreadable','ProcessDenied','MissingIdentity','JournalDenied','Malformed','Busy','MutexDenied')){
        Test-BootCase ("Boot uncertain state preserves all recovery: "+$mode) $mode {
            param($f)
            Assert-Boot ($f.TaskExists -and [IO.File]::Exists($f.Copy)) 'Uncertain state lost its task or script.'
            Assert-Boot ($f.RemovedNrpt.Count -eq 0 -and $f.RemovedFirewall.Count -eq 0 -and $f.Unregisters -eq 0) 'Uncertain state performed cleanup.'
        }
    }
    foreach($mode in @('NrptDenied','FirewallDenied','Remaining','VerifyUnreadable')){
        Test-BootCase ("Boot incomplete cleanup preserves recovery: "+$mode) $mode {
            param($f)
            Assert-Boot ($f.TaskExists -and [IO.File]::Exists($f.Copy) -and $f.Unregisters -eq 0) 'Incomplete cleanup lost recovery.'
        }
    }
    foreach($mode in @('TaskRemovalDenied','TaskStillPresent')){
        Test-BootCase ("Boot task removal failure preserves its script: "+$mode) $mode {
            param($f)
            Assert-Boot ($f.TaskExists -and [IO.File]::Exists($f.Copy)) 'Task removal failure deleted its script.'
        }
    }
    Test-BootCase 'Boot legacy global profile changes retain a path to explicit recovery' 'LegacyProfiles' {
        param($f)
        Assert-Boot ($f.TaskExists -and [IO.File]::Exists($f.Copy) -and $f.Unregisters -eq 0) 'A legacy profile journal lost its recovery path.'
        Assert-Boot ($f.RemovedNrpt.Count -eq 1 -and $f.RemovedFirewall.Count -eq 1) 'Stale policy cleanup was not attempted.'
    }
    Test-BootCase 'Boot unreadable task-absence confirmation preserves its script' 'TaskQueryDenied' {
        param($f)
        Assert-Boot ([IO.File]::Exists($f.Copy)) 'Unconfirmed task absence deleted the state copy.'
    }
    Test-BootCase 'Boot keeps live-session policy and recovery while removing stale foreign-session policy' 'Live' {
        param($f)
        Assert-Boot ($f.TaskExists -and [IO.File]::Exists($f.Copy) -and $f.Unregisters -eq 0) 'A live session lost its guard.'
        Assert-Boot ($f.RemovedNrpt.Count -eq 1 -and $f.RemovedFirewall.Count -eq 1) 'Stale-session cleanup was skipped.'
        Assert-Boot (@($f.Nrpt|Where-Object{$_.Name -eq 'live-dns'}).Count -eq 1) 'Live-session policy was removed.'
    }
    Test-BootCase 'Boot failed cleanup can be retried successfully using the retained script' 'NrptDenied' {
        param($f)
        Assert-Boot ($f.TaskExists -and [IO.File]::Exists($f.Copy)) 'The first failed run lost recovery.'
        $f.Mode='NoJournal'
        Run-Boot
        Assert-Boot (-not $f.TaskExists -and -not [IO.File]::Exists($f.Copy)) 'A repeated recovery could not complete.'
    }
    Assert-Boot ((Get-FileHash -LiteralPath $BootScriptPath -Algorithm SHA256).Hash -eq $originalHash) 'The installed boot script was modified.'
} finally {
    if($previousFixture){Set-Variable -Scope Global -Name GephTunBootFixture -Value $previousFixture.Value}
    else{Remove-Variable -Scope Global -Name GephTunBootFixture -ErrorAction SilentlyContinue}
    $resolved=[IO.Path]::GetFullPath($testRoot)
    $temporary=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar
    if(-not $resolved.StartsWith($temporary,[StringComparison]::OrdinalIgnoreCase)){throw 'Test cleanup escaped its temporary workspace.'}
    if([IO.Directory]::Exists($resolved)){Remove-Item -LiteralPath $resolved -Recurse -Force}
}
if($ResultJson){
    . (Join-Path $PSScriptRoot 'Package.Common.ps1')
    $output=Get-GephPackageFullPath $ResultJson
    Assert-GephPackageOutput $output (Get-GephPackageFullPath (Split-Path -Parent $PSScriptRoot))
    $failedCount=@($results|Where-Object Result -eq 'FAIL').Count
    Write-GephPackageNewJson $output ([ordered]@{CapturedUtc=[DateTime]::UtcNow.ToString('o');Version='1.5.0';Scope='Actual boot script with isolated filesystem and Windows command doubles; no real boot.';Total=$results.Count;Passed=$results.Count-$failedCount;Failed=$failedCount;Skipped=0;Tests=$results.ToArray()})
}
if($PassThru){$results.ToArray()}
else{
    $results|Format-Table Result,Test,Detail -AutoSize -Wrap
    $failed=@($results|Where-Object{$_.Result -eq 'FAIL'}).Count
    Write-Output ('{0} boot recovery tests; {1} passed; {2} failed.' -f $results.Count,($results.Count-$failed),$failed)
    if($failed){exit 1}
}
