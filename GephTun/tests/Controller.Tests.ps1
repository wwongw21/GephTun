#Requires -Version 5.1
# Current 1.5.0 supervisor tests. All OS, storage, transport and clock operations
# are module-scope doubles. This does not initialize protected storage or networking.
[CmdletBinding()]
param([string]$PackageDirectory,[string]$ResultJson)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
if(-not $PackageDirectory){$PackageDirectory=Split-Path -Parent $PSScriptRoot}
$results=New-Object 'Collections.Generic.List[object]'
$module=$null
function Assert-True($Value,[string]$Message){if(-not $Value){throw $Message}}
function New-Fixture {
    if($null -ne $script:module){Remove-Module $script:module -Force}
    $script:module=Import-Module (Join-Path $PackageDirectory 'GephTun.Core.psm1') -Force -PassThru -DisableNameChecking
    & $script:module {
        $script:Fixture=[pscustomobject]@{
            Loop=0;MaxLoops=2;Step=25;PeerCodes=@('','');DnsFailures=0;DnsCalls=0
            HardCheck='';StopAt=0;OwnerAlive=$true;TunnelAlive=$true;PhysicalCode=''
            Checks=(New-Object 'Collections.Generic.List[string]');Statuses=(New-Object 'Collections.Generic.List[string]')
            Clock=[pscustomobject]@{Elapsed=[pscustomobject]@{TotalSeconds=0}}
            Status=[pscustomobject]@{Status='Connected';WorkerPid=$PID;WorkerStartUtc='worker';UpdatedUtc='old'}
        }
        $script:ConnectionIntent=[pscustomobject]@{Worker=[pscustomobject]@{StartUtc='worker'}}
        $script:Session=[pscustomobject]@{Token=('b'*32);Owner=$null;Tunnel=[pscustomobject]@{Kind='tunnel'};ProxyProcess=[pscustomobject]@{Kind='proxy'};Worker=[pscustomobject]@{StartUtc='worker'}}
        $script:Relay=[pscustomobject]@{Healthy=$true;LastError='fixture upstream error';RejectedRequests=0;ActiveRequests=0;HighWaterRequests=0;UpstreamFailures=0;LastErrorUtc=''}
        function script:Get-GephTunRoot { [IO.Path]::GetTempPath() }
        function script:Test-Path { [CmdletBinding()]param($LiteralPath) return $false }
        function script:Start-Sleep { [CmdletBinding()]param($Milliseconds)
            $script:Fixture.Loop++
            $script:Fixture.Clock.Elapsed.TotalSeconds=($script:Fixture.Loop-1)*$script:Fixture.Step
            if($script:Fixture.Loop -gt $script:Fixture.MaxLoops){throw 'fixture-stop'}
        }
        function script:Get-GephTunHealthClock { return ([DateTime]'2026-10-09T00:00:00Z').AddSeconds($script:Fixture.Loop*$script:Fixture.Step) }
        function script:New-GephTunOutageClock { return $script:Fixture.Clock }
        function script:Wait-GephTunProbeRetry { }
        function script:Test-GephTunIntentStopRequested { return $script:Fixture.StopAt -gt 0 -and $script:Fixture.Loop -ge $script:Fixture.StopAt }
        function script:Assert-GephTunIntentContinuing { if(Test-GephTunIntentStopRequested){Throw-GephTunTransient 'CANCELLED' 'cancelled'} }
        function script:Test-GephTunProcessIdentity($Identity){
            if($Identity.Kind -eq 'owner'){return $script:Fixture.OwnerAlive}
            if($Identity.Kind -eq 'tunnel'){return $script:Fixture.TunnelAlive}
            return $true
        }
        function script:Test-GephTunPhysicalNetwork {
            $script:Fixture.Checks.Add('physical')
            if($script:Fixture.PhysicalCode){Throw-GephTunTransient $script:Fixture.PhysicalCode 'physical network changed'}
        }
        function script:Update-GephTunBypasses {
            $index=[Math]::Min($script:Fixture.Loop-1,$script:Fixture.PeerCodes.Count-1)
            $code=$script:Fixture.PeerCodes[$index]
            if($code){Throw-GephTunTransient $code 'peer unavailable'}
        }
        function script:Assert-GephTunProtection { $script:Fixture.Checks.Add('wfp');if($script:Fixture.HardCheck -eq 'wfp'){throw 'hard WFP failure'} }
        function script:Sync-GephTunContainment { $script:Fixture.Checks.Add('sync') }
        function script:Test-GephTunContainment { $script:Fixture.Checks.Add('firewall');if($script:Fixture.HardCheck -eq 'firewall'){throw 'hard firewall failure'} }
        function script:Test-GephTunInstalledRoutes { $script:Fixture.Checks.Add('routes');if($script:Fixture.HardCheck -eq 'routes'){throw 'hard route failure'} }
        function script:Test-GephTunDnsPolicy { $script:Fixture.Checks.Add('dns-policy');if($script:Fixture.HardCheck -eq 'dns-policy'){throw 'hard DNS policy failure'} }
        function script:Resolve-DnsName { [CmdletBinding()]param($Name,$Type,$Server,[switch]$DnsOnly,[switch]$NoHostsFile)
            $script:Fixture.DnsCalls++
            if($script:Fixture.DnsCalls -le $script:Fixture.DnsFailures){throw 'DNS fixture failure'}
        }
        function script:Read-GephTunJson($Path){return $script:Fixture.Status}
        function script:Write-GephTunJson($Path,$Value){$script:Fixture.Status=$Value}
        function script:Write-GephTunLog($Message){ }
        function script:Set-GephTunStatus($Status,$Message){$script:Fixture.Status.Status=$Status;$script:Fixture.Statuses.Add($Status)}
        # A regression must not accidentally reach actual Windows mutation commands.
        function script:Remove-Item { throw 'Unexpected mutation in monitoring fixture' }
        function script:New-NetRoute { throw 'Unexpected route mutation' }
        function script:Remove-NetRoute { throw 'Unexpected route mutation' }
        function script:Set-NetFirewallProfile { throw 'Unexpected profile mutation' }
        function script:Start-Process { throw 'Unexpected process launch' }
    }
}
function Run-Monitor {
    return & $script:module {
        try { Watch-GephTunCurrentSession; return [pscustomobject]@{Code='';Error='';Returned=$true} }
        catch { return [pscustomobject]@{Code=(Get-GephTunFailureCode $_);Error=$_.Exception.Message;Returned=$false} }
    }
}
function Test-Case($Name,[scriptblock]$Body){
    New-Fixture
    try { & $Body;$results.Add([pscustomobject]@{Name=$Name;Result='PASS';Detail=''}) }
    catch {$results.Add([pscustomobject]@{Name=$Name;Result='FAIL';Detail=$_.Exception.Message})}
}
try {
    Test-Case 'Healthy monitoring refreshes the verified heartbeat' {
        $run=Run-Monitor
        Assert-True ($run.Error -eq 'fixture-stop') 'Healthy monitoring terminated unexpectedly.'
        Assert-True (& $module {$script:Fixture.Status.UpdatedUtc -ne 'old'}) 'Heartbeat did not advance.'
    }
    Test-Case 'A missing peer recovers without tearing down a verified session' {
        & $module {$script:Fixture.PeerCodes=@('PEER_MISSING','')}
        $run=Run-Monitor
        Assert-True ($run.Error -eq 'fixture-stop') 'A brief peer gap was fatal.'
        Assert-True (& $module {($script:Fixture.Statuses -join ',') -eq 'Reconnecting,Connected'}) 'Recovered state was not published.'
    }
    Test-Case 'An unreadable peer snapshot gets the same bounded grace' {
        & $module {$script:Fixture.PeerCodes=@('PEER_SNAPSHOT','')}
        $run=Run-Monitor
        Assert-True ($run.Error -eq 'fixture-stop') 'A brief unreadable snapshot was fatal.'
        Assert-True (& $module {$script:Fixture.Status.Status -eq 'Connected'}) 'Recovery was not verified.'
    }
    Test-Case 'A prolonged peer gap leaves monitoring with the typed failure' {
        & $module {$script:Fixture.PeerCodes=@('PEER_MISSING');$script:Fixture.MaxLoops=3}
        $run=Run-Monitor
        Assert-True ($run.Code -eq 'PEER_MISSING') 'The grace period never expired or lost provenance.'
    }
    foreach($check in @('firewall','routes','dns-policy','wfp')){
        Test-Case ('A '+$check+' failure is never waived during a peer gap') {
            & $module {param($Check)$script:Fixture.PeerCodes=@('PEER_MISSING');$script:Fixture.HardCheck=$Check} $check
            $run=Run-Monitor
            Assert-True ($run.Code -eq '' -and $run.Error -like 'hard *') 'A security failure was ignored or retried.'
            Assert-True (& $module {$script:Fixture.Statuses.Count -eq 0}) 'Grace was published without valid protections.'
        }
    }
    Test-Case 'All invariant checks still execute during the grace period' {
        & $module {$script:Fixture.PeerCodes=@('PEER_MISSING');$script:Fixture.MaxLoops=1}
        $null=Run-Monitor
        Assert-True (& $module {foreach($name in @('physical','sync','firewall','routes','dns-policy','wfp')){if(-not $script:Fixture.Checks.Contains($name)){return $false}};return $true}) 'A required check was bypassed.'
    }
    Test-Case 'A transient DNS failure is retried within the heartbeat' {
        & $module {$script:Fixture.DnsFailures=1;$script:Fixture.MaxLoops=1}
        $run=Run-Monitor
        Assert-True ($run.Error -eq 'fixture-stop') 'One DNS failure killed the session.'
        Assert-True (& $module {$script:Fixture.DnsCalls -eq 2}) 'DNS retry count was incorrect.'
    }
    Test-Case 'Three DNS failures enter grace and a later successful check recovers' {
        & $module {$script:Fixture.DnsFailures=3}
        $run=Run-Monitor
        Assert-True ($run.Error -eq 'fixture-stop') 'Grace did not recover.'
        Assert-True (& $module {($script:Fixture.Statuses -join ',') -eq 'Reconnecting,Connected'}) 'DNS recovery states are incorrect.'
    }
    Test-Case 'Sustained DNS failure expires the grace period' {
        & $module {$script:Fixture.DnsFailures=99;$script:Fixture.MaxLoops=3}
        $run=Run-Monitor
        Assert-True ($run.Code -eq 'DNS_UNAVAILABLE') 'DNS grace was unbounded.'
    }
    Test-Case 'Disconnect during grace ends monitoring without another probe' {
        & $module {$script:Fixture.PeerCodes=@('PEER_MISSING');$script:Fixture.StopAt=2}
        $run=Run-Monitor
        Assert-True $run.Returned 'Cancellation did not exit normally.'
        Assert-True (& $module {$script:Fixture.DnsCalls -eq 0}) 'A probe ran after cancellation.'
    }
    Test-Case 'A physical transition returns a typed clean-reconnect reason' {
        & $module {$script:Fixture.PhysicalCode='NETWORK_CHANGED'}
        $run=Run-Monitor
        Assert-True ($run.Code -eq 'NETWORK_CHANGED') 'Network transition was not classified.'
    }
    Test-Case 'Tunnel engine death is a hard failure' {
        & $module {$script:Fixture.TunnelAlive=$false}
        $run=Run-Monitor
        Assert-True ($run.Code -eq '' -and $run.Error -eq 'The tunnel engine stopped.') 'Engine death was silently retried.'
    }
    Test-Case 'An unhealthy DNS relay is a hard failure' {
        & $module {$script:Relay.Healthy=$false}
        $run=Run-Monitor
        Assert-True ($run.Code -eq '' -and $run.Error -eq 'The DNS forwarder stopped.') 'Relay death was ignored.'
    }
    Test-Case 'Owner exit ends the session rather than auto-reconnecting' {
        & $module {$script:Session.Owner=[pscustomobject]@{Kind='owner'};$script:Fixture.OwnerAlive=$false}
        $run=Run-Monitor
        Assert-True $run.Returned 'Owner exit did not stop monitoring.'
    }
    Test-Case 'Direct module callers without a connection intent do not silently opt into retries' {
        & $module {$script:ConnectionIntent=$null;$script:Fixture.PeerCodes=@('PEER_MISSING')}
        $run=Run-Monitor
        Assert-True ($run.Code -eq 'PEER_MISSING') 'An unowned controller acquired reconnect behavior.'
    }
} finally {if($null -ne $module){Remove-Module $module -Force}}
$failed=@($results | Where-Object Result -eq 'FAIL').Count
$report=[ordered]@{CapturedUtc=[DateTime]::UtcNow.ToString('o');Version='1.5.0';Scope='Actual session supervisor with deterministic clocks and complete OS/transport doubles; not Windows acceptance.';PowerShellVersion=$PSVersionTable.PSVersion.ToString();Total=$results.Count;Passed=$results.Count-$failed;Failed=$failed;Skipped=0;Tests=$results.ToArray()}
if($ResultJson){. (Join-Path $PSScriptRoot 'Package.Common.ps1');$output=Get-GephPackageFullPath $ResultJson;Assert-GephPackageOutput $output (Get-GephPackageFullPath $PackageDirectory);Write-GephPackageNewJson $output $report}
$results | Format-Table -AutoSize -Wrap
if($failed){exit 1}
