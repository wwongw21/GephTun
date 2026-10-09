#Requires -Version 5.1
# Execute the actual resilience functions against module-scope doubles.
# No network command, elevated storage initialization, process launch or policy mutation runs.
[CmdletBinding()]
param([string]$PackageDirectory, [string]$ResultJson)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if (-not $PackageDirectory) { $PackageDirectory = Split-Path -Parent $PSScriptRoot }
$modulePath = Join-Path $PackageDirectory 'GephTun.Core.psm1'
$results = New-Object 'Collections.Generic.List[object]'
$module = $null

function Assert-True($Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function New-Fixture {
    if ($null -ne $script:module) { Remove-Module $script:module -Force }
    $script:module = Import-Module $modulePath -Force -PassThru -DisableNameChecking
    & $script:module {
        $script:Fixture = [pscustomobject]@{
            Stop = $null; Cancel = $null; RecoveryCalls=0; RecoverAfter=0; OwnerAlive = $true; Order = (New-Object 'Collections.Generic.List[string]')
            RestoreFails = $false; Residue = $false; CancelAfterRestore = $false; CancelDuringWait = $false
            LeaseOpens=0;LeaseCloses=0;HardStartFailure = $false; TransientStarts = 0; Starts = 0; Snapshots = 0; SnapshotFailures = 0
            ProxyPath = 'C:\Geph\geph.exe'; Fingerprints = @('network-a','network-a','network-a'); FingerprintIndex = 0
        }
        $script:ConnectionIntent = [pscustomobject]@{
            Schema = 1; Token = ('a' * 32); Worker = [pscustomobject]@{Id=123;StartUtc='2026-10-09T00:00:00Z';Path='powershell.exe'}
            Owner = $null; Port = 9909; OperationToken = ''; ProxyPath = 'C:\Geph\geph.exe'
        }
        $script:Session = [pscustomobject]@{Token=('b'*32)}
        function script:Get-GephTunRoot { return ([IO.Path]::GetTempPath()) }
        function script:Read-GephTunJson([string]$Path) {
            switch ([IO.Path]::GetFileName($Path)) {
                'disconnect-intent.json' { return $script:Fixture.Stop }
                'connection-intent.json' { return $script:ConnectionIntent }
                default { return $null }
            }
        }
        function script:Write-GephTunJson($Path,$Value) { $script:Fixture.Order.Add('write:'+[IO.Path]::GetFileName($Path)) }
        function script:Write-GephTunLog([string]$Message) { }
        function script:Test-GephTunProcessIdentity($Identity) { return $script:Fixture.OwnerAlive }
        function script:Set-GephTunStatus([string]$Status,[string]$Message) { $script:Fixture.Order.Add('status:'+$Status) }
        function script:Set-GephTunReconnectStatus([string]$Message) { $script:Fixture.Order.Add('waiting') }
        function script:Restore-GephTunSession {
            $script:Fixture.RecoveryCalls++;$script:Fixture.Order.Add('restore')
            if ($script:Fixture.RestoreFails -and ($script:Fixture.RecoverAfter -eq 0 -or $script:Fixture.RecoveryCalls -lt $script:Fixture.RecoverAfter)) { throw 'Injected cleanup failure' }
            $script:Session = $null
            if ($script:Fixture.CancelAfterRestore) { $script:Fixture.Stop = [pscustomobject]@{Token=('a'*32)} }
        }
        function script:Test-Path { [CmdletBinding()]param($LiteralPath) return $script:Fixture.Residue }
        function script:Wait-GephTunReconnectDelay([int]$Milliseconds) {
            $script:Fixture.Order.Add('delay')
            if ($script:Fixture.CancelDuringWait) { $script:Fixture.Stop = [pscustomobject]@{Token=('a'*32)} }
            Assert-GephTunIntentContinuing
        }
        function script:Wait-GephTunRecoveryDelay($Milliseconds) {$script:Fixture.Order.Add('recovery-delay:'+ $Milliseconds)}
        function script:Start-Sleep { [CmdletBinding()]param($Milliseconds,$Seconds) }
        function script:Get-GephTunDefaultRoutes { return [pscustomobject]@{InterfaceIndex=7;InterfaceGuid='wifi';Gateway='192.0.2.1'} }
        function script:Get-GephTunNetworkFingerprint($Network) {
            $i = [Math]::Min($script:Fixture.FingerprintIndex, $script:Fixture.Fingerprints.Count-1)
            $script:Fixture.FingerprintIndex++
            return $script:Fixture.Fingerprints[$i]
        }
        function script:Open-GephTunProtectionLease { $script:Fixture.LeaseOpens++;$script:ProtectionLease=[pscustomobject]@{Fixture=$true} }
        function script:Close-GephTunProtectionLease { if($null -ne $script:ProtectionLease){$script:Fixture.LeaseCloses++};$script:ProtectionLease=$null }
        function script:Get-GephTunProxy([int]$Port) { return [pscustomobject]@{Port=$Port;Process=[pscustomobject]@{Path=$script:Fixture.ProxyPath}} }
        function script:Start-GephTunSession([int]$Port,[int]$OwnerProcessId,[string]$OperationToken) {
            $script:Fixture.Starts++; $script:Fixture.Order.Add('start')
            if ($script:Fixture.HardStartFailure) { throw 'Injected firewall policy mismatch' }
            if ($script:Fixture.TransientStarts -gt 0) {
                $script:Fixture.TransientStarts--
                Throw-GephTunTransient 'DNS_UNAVAILABLE' 'Injected DNS outage'
            }
            $script:Session = [pscustomobject]@{Token=('c'*32)}
            return [pscustomobject]@{Success=$true}
        }
        function script:Get-GephTunPeerRouteSnapshot($Identity) {
            $script:Fixture.Snapshots++
            if ($script:Fixture.Snapshots -le $script:Fixture.SnapshotFailures) { Throw-GephTunTransient 'PEER_SNAPSHOT' 'Transient snapshot' }
            return [pscustomobject]@{Prefix='192.0.2.20/32';InterfaceIndex=7;NextHop='192.0.2.1'}
        }
        # Any accidental mutation outside the named doubles fails the test closed.
        function script:New-NetRoute { throw 'Unexpected network mutation' }
        function script:Remove-NetRoute { throw 'Unexpected network mutation' }
        function script:Set-NetFirewallProfile { throw 'Unexpected firewall mutation' }
        function script:Start-Process { throw 'Unexpected process launch' }
    }
}
function Test-Case([string]$Name,[scriptblock]$Body) {
    New-Fixture
    try { & $Body; $results.Add([pscustomobject]@{Name=$Name;Result='PASS';Detail=''}) }
    catch { $results.Add([pscustomobject]@{Name=$Name;Result='FAIL';Detail=$_.Exception.Message}) }
}
try {
    Test-Case 'Typed failures retain their code through exception wrapping' {
        $value = & $module { try { Throw-GephTunTransient 'PEER_MISSING' 'test' } catch { Get-GephTunFailureCode $_ } }
        Assert-True ($value -ceq 'PEER_MISSING') 'Failure provenance was lost.'
    }
    Test-Case 'Unknown and security failures are not in the reconnect allow-list' {
        $value = & $module { (Get-GephTunFailureCode ([InvalidOperationException]::new('firewall failed'))) -eq '' -and
            -not (Test-GephTunRetryableFailure 'FIREWALL_CHANGED') -and -not (Test-GephTunRetryableFailure '') }
        Assert-True $value 'A hard failure was classified as retryable.'
    }
    Test-Case 'Only six documented transient classes may reconnect' {
        $value = & $module {
            foreach ($code in @('NETWORK_UNAVAILABLE','NETWORK_CHANGED','PEER_SNAPSHOT','PEER_MISSING','PROXY_UNAVAILABLE','DNS_UNAVAILABLE')) {
                if (-not (Test-GephTunRetryableFailure $code)) { return $false }
            }
            return $true
        }
        Assert-True $value 'A documented transient classification is missing.'
    }
    Test-Case 'A matching stop request is latched while no session exists' {
        $value = & $module {
            $script:Session = $null
            $script:Fixture.Stop = [pscustomobject]@{Token=('a'*32)}
            (Test-GephTunIntentStopRequested) -and (Test-GephTunIntentStopRequested)
        }
        Assert-True $value 'A between-session cancellation was missed or consumed.'
    }
    Test-Case 'A foreign stop token cannot cancel the controller' {
        $value = & $module { $script:Fixture.Stop=[pscustomobject]@{Token=('f'*32)}; Test-GephTunIntentStopRequested }
        Assert-True (-not $value) 'A foreign stop request was honored.'
    }
    Test-Case 'A closed owner cancels retries' {
        $value = & $module { $script:ConnectionIntent.Owner=[pscustomobject]@{Id=888}; $script:Fixture.OwnerAlive=$false; Test-GephTunIntentStopRequested }
        Assert-True $value 'Owner exit did not cancel retries.'
    }
    Test-Case 'Expired reconnect budget prevents another setup checkpoint' {
        $value = & $module {
            $script:ReconnectBudget=[pscustomobject]@{Elapsed=[pscustomobject]@{TotalSeconds=181}}
            try { Assert-GephTunIntentContinuing; return $false } catch { return $_.Exception.Message -match '180-second' }
        }
        Assert-True $value 'The reconnect time budget was not enforced.'
    }
    Test-Case 'The old session is recovered before a fresh connection is attempted' {
        $value = & $module {
            $ok=Invoke-GephTunReconnect 'network changed'
            $ok -and $script:Fixture.Starts -eq 1 -and $script:Fixture.Order[0] -eq 'restore' -and $null -ne $script:Session
        }
        Assert-True $value 'Reconnect did not require clean rollback first.'
    }
    Test-Case 'Cleanup failure cannot start a replacement session' {
        $value = & $module {
            $script:Fixture.RestoreFails=$true
            try { Invoke-GephTunReconnect 'network changed' | Out-Null; return $false }
            catch { return $script:Fixture.Starts -eq 0 -and $_.Exception.Message -match 'cleanup failure' }
        }
        Assert-True $value 'Reconnect ignored a cleanup failure.'
    }
    Test-Case 'Residual session journal prevents reconnect' {
        $value = & $module {
            $script:Fixture.Residue=$true
            try { Invoke-GephTunReconnect 'network changed' | Out-Null; return $false }
            catch { return $script:Fixture.Starts -eq 0 -and $_.Exception.Message -match 'not fully recovered' }
        }
        Assert-True $value 'Reconnect crossed an incomplete recovery boundary.'
    }
    Test-Case 'Disconnect during cleanup prevents a new session' {
        $value = & $module { $script:Fixture.CancelAfterRestore=$true; $ok=Invoke-GephTunReconnect 'network changed'; (-not $ok) -and $script:Fixture.Starts -eq 0 }
        Assert-True $value 'Cancellation after cleanup was missed.'
    }
    Test-Case 'Disconnect during the stabilization wait prevents a new session' {
        $value = & $module { $script:Fixture.CancelDuringWait=$true; $ok=Invoke-GephTunReconnect 'network changed'; (-not $ok) -and $script:Fixture.Starts -eq 0 }
        Assert-True $value 'Cancellation during the wait was missed.'
    }
    Test-Case 'An already requested disconnect never starts recovery-driven reconnect' {
        $value = & $module { $script:Fixture.Stop=[pscustomobject]@{Token=('a'*32)}; $ok=Invoke-GephTunReconnect 'network changed'; (-not $ok) -and $script:Fixture.Order.Count -eq 0 }
        Assert-True $value 'Reconnect began after cancellation.'
    }
    Test-Case 'Geph executable path changes require manual review' {
        $value = & $module {
            $script:Fixture.ProxyPath='C:\Other\geph.exe'
            try { Invoke-GephTunReconnect 'network changed' | Out-Null; return $false }
            catch { return $script:Fixture.Starts -eq 0 -and $_.Exception.Message -match 'installation changed' }
        }
        Assert-True $value 'A different Geph installation was adopted automatically.'
    }
    Test-Case 'The network is rechecked after the blocking proxy probe' {
        $value = & $module {
            $script:Fixture.Fingerprints=@('a','a','b','b','b','b')
            $ok=Invoke-GephTunReconnect 'network changed'
            $ok -and $script:Fixture.FingerprintIndex -ge 6 -and $script:Fixture.Starts -eq 1 -and $script:Fixture.LeaseOpens -eq 2 -and $script:Fixture.LeaseCloses -eq 1
        }
        Assert-True $value 'A stale pre-probe network snapshot was accepted.'
    }
    Test-Case 'Transient failed starts are bounded and can recover' {
        $value = & $module { $script:Fixture.TransientStarts=2; $ok=Invoke-GephTunReconnect 'dns'; $ok -and $script:Fixture.Starts -eq 3 }
        Assert-True $value 'Transient retry sequence was incorrect.'
    }
    Test-Case 'A fourth start is never attempted in one recovery cycle' {
        $value = & $module {
            $script:Fixture.TransientStarts=5
            try { Invoke-GephTunReconnect 'dns' | Out-Null; return $false }
            catch { return $script:Fixture.Starts -eq 3 -and $_.Exception.Message -match 'retry budget' }
        }
        Assert-True $value 'The per-cycle attempt budget was exceeded.'
    }
    Test-Case 'A hard preflight failure is not retried' {
        $value = & $module {
            $script:Fixture.HardStartFailure=$true
            try { Invoke-GephTunReconnect 'dns' | Out-Null; return $false }
            catch { return $script:Fixture.Starts -eq 1 -and $_.Exception.Message -match 'firewall' }
        }
        Assert-True $value 'A hard policy failure was retried.'
    }
    Test-Case 'Rapid reconnect loops trip the circuit breaker' {
        $value = & $module {
            1..3 | ForEach-Object { $script:ReconnectHistory.Add([DateTime]::UtcNow) }
            try { Invoke-GephTunReconnect 'flapping' | Out-Null; return $false }
            catch { return $script:Fixture.Starts -eq 0 -and $_.Exception.Message -match 'three recovery cycles' }
        }
        Assert-True $value 'The reconnect circuit breaker was bypassed.'
    }
    Test-Case 'Old reconnect episodes age out of the circuit breaker' {
        $value = & $module { 1..3 | ForEach-Object { $script:ReconnectHistory.Add([DateTime]::UtcNow.AddMinutes(-11)) }; Invoke-GephTunReconnect 'new outage' }
        Assert-True $value 'Historical outages incorrectly disabled reconnect forever.'
    }
    Test-Case 'Peer observation retries take fresh snapshots' {
        $value = & $module { $script:Fixture.SnapshotFailures=2; $rows=@(Get-GephTunPeerRoutes $null); $script:Fixture.Snapshots -eq 3 -and $rows.Count -eq 1 }
        Assert-True $value 'Fresh snapshot retry did not recover.'
    }
    Test-Case 'Peer observation retries stop after three reads' {
        $value = & $module {
            $script:Fixture.SnapshotFailures=10
            try { Get-GephTunPeerRoutes $null | Out-Null; return $false }
            catch { return $script:Fixture.Snapshots -eq 3 -and (Get-GephTunFailureCode $_) -eq 'PEER_SNAPSHOT' }
        }
        Assert-True $value 'Peer snapshot retries were unbounded or lost provenance.'
    }
    Test-Case 'A changed physical gateway is typed for clean-session recovery' {
        $value = & $module {
            $script:Session=[pscustomobject]@{OriginalNetwork=[pscustomobject]@{InterfaceIndex=7;InterfaceGuid='wifi';Gateway='192.0.2.254'}}
            try { Test-GephTunPhysicalNetwork; return $false }
            catch { return (Get-GephTunFailureCode $_) -eq 'NETWORK_CHANGED' }
        }
        Assert-True $value 'Physical-network transition was not identified.'
    }
    Test-Case 'Disabled firewall baseline is rejected without changing profiles' {
        $value = & $module {
            function script:Test-GephTunFirewallProfiles { }
            function script:Get-NetFirewallProfile { [CmdletBinding()]param($PolicyStore)
                foreach($name in @('Domain','Private','Public')) { [pscustomobject]@{Name=$name;Enabled='False'} }
            }
            try { Test-GephTunFirewallBaseline; return $false }
            catch { return $_.Exception.Message -match 'no longer changes global firewall' }
        }
        Assert-True $value 'A disabled baseline was accepted or changed.'
    }
    Test-Case 'Enabled firewall baseline is accepted without mutations' {
        $value = & $module {
            function script:Test-GephTunFirewallProfiles { }
            function script:Get-NetFirewallProfile { [CmdletBinding()]param($PolicyStore)
                foreach($name in @('Domain','Private','Public')) { [pscustomobject]@{Name=$name;Enabled='True'} }
            }
            Test-GephTunFirewallBaseline; return $true
        }
        Assert-True $value 'An enabled baseline was rejected.'
    }
    Test-Case 'Repeated real recovery loop failures stop at three attempts with journal and protection intact' {
        $ok=& $module {
            $script:Fixture.RestoreFails=$true;$script:ProtectionLease=[pscustomobject]@{Fixture=$true}
            try{Wait-GephTunRecovery;$false}catch{
                $script:Fixture.RecoveryCalls -eq 3 -and $null -ne $script:Session -and $null -eq $script:ProtectionLease -and
                $script:Fixture.LeaseCloses -eq 1 -and $_.Exception.Message -like '*Injected cleanup failure*' -and $_.Exception.Message -like '*persistent protection was not disabled*'
            }
        }
        Assert-True $ok 'Recovery was unbounded, lost its journal, or silently unlocked.'
    }
    Test-Case 'Recovery backoff increases and a later successful cleanup ends retries' {
        $ok=& $module {$script:Fixture.RestoreFails=$true;$script:Fixture.RecoverAfter=3;Wait-GephTunRecovery;$script:Fixture.RecoveryCalls -eq 3 -and $null -eq $script:Session -and ($script:Fixture.Order -join ',') -match 'recovery-delay:1000.*recovery-delay:2000'}
        Assert-True $ok 'Backoff or successful recovery was incorrect.'
    }
    Test-Case 'Cancellation stops repeated cleanup but preserves incomplete recovery state' {
        $ok=& $module {$script:Fixture.RestoreFails=$true;$script:Fixture.Stop=[pscustomobject]@{Token=('a'*32)};try{Wait-GephTunRecovery;$false}catch{$script:Fixture.RecoveryCalls -eq 1 -and $null -ne $script:Session}}
        Assert-True $ok 'Cancellation erased the journal or kept retrying.'
    }
    Test-Case 'Operator can retry cleanup after the original worker exhausts recovery' {
        $ok=& $module {
            $script:Fixture.RestoreFails=$true;try{Wait-GephTunRecovery}catch{}
            if($null -eq $script:Session){return $false}
            $script:Fixture.RestoreFails=$false;Wait-GephTunRecovery
            $script:Fixture.RecoveryCalls -eq 4 -and $null -eq $script:Session
        }
        Assert-True $ok 'An exhausted loop prevented a later explicit retry.'
    }
    Test-Case 'Permission close failure remains an actionable recovery blocker' {
        $ok=& $module {
            $script:Fixture.RestoreFails=$true
            function script:Close-GephTunProtectionLease {throw 'Injected lease close failure'}
            try{Wait-GephTunRecovery;$false}catch{$_.Exception.Message -like '*Injected cleanup failure*Injected lease close failure*' -and $null -ne $script:Session}
        }
        Assert-True $ok 'Permission uncertainty was suppressed or journal discarded.'
    }

    foreach($mode in @('CancellationRead','Backoff')) {
        Test-Case ('Recovery control exception closes permissions and preserves state: '+$mode) {
            $ok=& $module {param($Mode)
                $script:Fixture.RestoreFails=$true;Open-GephTunProtectionLease
                if($Mode -eq 'CancellationRead'){function script:Test-GephTunRecoveryCancelled {throw 'Injected cancellation read failure'}}
                else{function script:Wait-GephTunRecoveryDelay($Milliseconds) {throw 'Injected backoff failure'}}
                try{Wait-GephTunRecovery;$false}catch{$_.Exception.Message -match 'Recovery control failed' -and $script:Fixture.LeaseCloses -eq 1 -and $null -ne $script:Session}
            } $mode
            Assert-True $ok 'A recovery control exception retained access or discarded the journal.'
        }
    }
    Test-Case 'Explicit operator recovery reacquires the mutex after retry exhaustion' {
        $ok=& $module {
            $script:Fixture.RestoreFails=$true;try{Wait-GephTunRecovery}catch{}
            $script:Fixture.RestoreFails=$false;$script:ConnectionIntent=$null
            function script:Get-GephTunLock {$script:Fixture.Order.Add('lock');[pscustomobject]@{Fixture=$true}}
            function script:Release-GephTunLock($Mutex) {$script:Fixture.Order.Add('unlock')}
            Request-GephTunDisconnect
            $script:Fixture.RecoveryCalls -eq 4 -and $null -eq $script:Session -and $script:Fixture.Order.Contains('unlock')
        }
        Assert-True $ok 'Explicit Disconnect / Recover could not complete a later attempt.'
    }
    Test-Case 'Uncertain controller ownership blocks explicit takeover before cleanup' {
        $ok=& $module {
            function script:Get-GephTunProcessIdentityState($Identity) {'UNKNOWN'}
            try{Request-GephTunDisconnect;$false}catch{$script:Fixture.RecoveryCalls -eq 0 -and $null -ne $script:Session}
        }
        Assert-True $ok 'Unknown controller identity authorized recovery.'
    }
}
finally { if ($null -ne $module) { Remove-Module $module -Force } }
$failed=@($results | Where-Object Result -eq 'FAIL').Count
$report=[ordered]@{CapturedUtc=[DateTime]::UtcNow.ToString('o');Version='1.5.0';Scope='Actual PowerShell controller functions with isolated module-scope doubles; no live Windows/network acceptance.';PowerShellVersion=$PSVersionTable.PSVersion.ToString();Total=$results.Count;Passed=$results.Count-$failed;Failed=$failed;Skipped=0;Tests=$results.ToArray()}
if($ResultJson){
    . (Join-Path $PSScriptRoot 'Package.Common.ps1')
    $output=Get-GephPackageFullPath $ResultJson
    Assert-GephPackageOutput $output (Get-GephPackageFullPath $PackageDirectory)
    Write-GephPackageNewJson $output $report
}
$results | Format-Table -AutoSize -Wrap
if($failed){exit 1}
