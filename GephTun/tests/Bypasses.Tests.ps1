#Requires -Version 5.1
# Actual wrapper registry functions with isolated Windows/storage doubles. No OS network changes.
[CmdletBinding()]
param([string]$PackageDirectory,[string]$ResultJson)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
if(-not $PackageDirectory){$PackageDirectory=Split-Path -Parent $PSScriptRoot}
. (Join-Path $PSScriptRoot 'Package.Common.ps1')
$results=New-Object 'Collections.Generic.List[object]';$module=$null
function Assert-True($Value,[string]$Message){if(-not $Value){throw $Message}}
function New-Fixture {
    if($null -ne $script:module){Remove-Module $script:module -Force}
    $script:module=Import-Module (Join-Path $PackageDirectory 'GephTun.Core.psm1') -Force -PassThru -DisableNameChecking
    & $script:module {
        $script:ActualAddRoute=${function:Add-GephTunOwnedRoute};$script:ActualRemoveRoute=${function:Remove-GephTunOwnedRoute}
        $script:F=[pscustomobject]@{Now=0.0;Live=@();Peers=@();Adds=0;Removes=0;Messages=(New-Object 'Collections.Generic.List[string]');Cache=$null;Saved=$null;ReadFail=$false;Guid='wifi';Up=$true;Hardware=$true;InterfaceMetrics=@{7=10;8=1};Selection=$null;SelectionFail=$false;AddFail=$false;RemoveFail=$false}
        $script:Session=[pscustomobject]@{ProxyProcess=[pscustomobject]@{Path='C:\Geph\geph.exe'};Routes=@();OriginalNetwork=[pscustomobject]@{InterfaceIndex=7};OriginalRoutes=@([pscustomobject]@{InterfaceIndex=7;InterfaceGuid='wifi';DestinationPrefix='0.0.0.0/0';NextHop='192.0.2.1';Cost=1})}
        function script:Get-GephTunRoot {[IO.Path]::GetTempPath()}
        function script:Get-GephTunBypassNow {$script:F.Now}
        function script:Get-GephTunProtectionConfiguration {[pscustomobject]@{TrustedImages=@([pscustomobject]@{Path='C:\Geph\geph.exe';Sha256=('a'*64)})}}
        function script:Read-GephTunJson($Path){$script:F.Cache}
        function script:Write-GephTunJson($Path,$Object){$script:F.Saved=$Object}
        function script:Write-GephTunLog($Message){$script:F.Messages.Add($Message)}
        function script:Save-GephTunSession {}
        function script:Assert-GephTunConnectContinuing {}
        function script:Get-NetAdapter { [CmdletBinding()]param($InterfaceIndex,[switch]$IncludeHidden)
            [pscustomobject]@{InterfaceIndex=7;InterfaceGuid=$script:F.Guid;Status=$(if($script:F.Up){'Up'}else{'Down'});HardwareInterface=$script:F.Hardware}
        }
        function script:Get-NetRoute { [CmdletBinding()]param($PolicyStore)
            if($script:F.ReadFail){throw 'Injected route read failure'}
            $script:F.Live
        }
        function script:Find-NetRoute { [CmdletBinding()]param($RemoteIPAddress)
            if($script:F.SelectionFail){throw 'Injected selected route query failure'}
            if($null -ne $script:F.Selection){return $script:F.Selection}
            @($script:F.Live|Where-Object DestinationPrefix -eq ($RemoteIPAddress+'/32')|Sort-Object @{Expression={ [int]$_.RouteMetric+[int]$script:F.InterfaceMetrics[[int]$_.InterfaceIndex] }}|Select-Object -First 1)
        }
        function script:Get-GephTunPeerRoutes($Identity){$script:F.Peers}
        function script:Add-GephTunOwnedRoute($Prefix,$Index,$Gateway,$Kind){
            if($script:F.AddFail){throw 'Injected owned route add failure'}
            if(@($script:F.Live|Where-Object {$_.DestinationPrefix -eq $Prefix -and $_.InterfaceIndex -eq $Index -and $_.NextHop -eq $Gateway}).Count -eq 0){
                $route=[pscustomobject]@{DestinationPrefix=$Prefix;InterfaceIndex=$Index;NextHop=$Gateway;Kind=$Kind;InterfaceGuid='wifi';RouteMetric=3}
                $script:F.Live+= $route;$script:Session.Routes+= $route;$script:F.Adds++
            }
        }
        function script:Remove-GephTunOwnedRoute($Route){
            if($script:F.RemoveFail){throw 'Injected owned route removal failure'}
            $script:F.Removes++
            $script:F.Live=@($script:F.Live|Where-Object {-not ($_.DestinationPrefix -eq $Route.DestinationPrefix -and $_.InterfaceIndex -eq $Route.InterfaceIndex -and $_.NextHop -eq $Route.NextHop -and $_.RouteMetric -eq $Route.RouteMetric)})
        }
        function script:New-NetRoute {throw 'Unexpected real network mutation'}
        function script:Remove-NetRoute {throw 'Unexpected real network mutation'}
        function script:Set-NetFirewallProfile {throw 'Unexpected real firewall mutation'}
        function script:Initialize-GephTunWfpTypes {throw 'Unexpected native WFP path'}
        Initialize-GephTunBypassRegistry
        $script:BypassAdapters=@{};$script:BypassRoutesSnapshot=$null
    }
}
function Peer([string]$Address='192.0.2.20',[bool]$Captured=$false){[pscustomobject]@{Prefix=($Address+'/32');InterfaceIndex=7;NextHop='192.0.2.1';Recovered=$Captured}}
function Test-Case($Name,[scriptblock]$Body){
    New-Fixture
    try{& $Body;$results.Add([pscustomobject]@{Name=$Name;Result='PASS';Detail=''})}catch{$results.Add([pscustomobject]@{Name=$Name;Result='FAIL';Detail=$_.Exception.Message})}
}
try {
Test-Case 'Repeated snapshots reuse one verified bypass without adding routes or log floods' {
    $peer=Peer
    & $module {param($Peer) $script:F.Peers=@($Peer);1..20|ForEach-Object {Invoke-GephTunBypassRefresh}} $peer
    Assert-True (& $module {$script:F.Adds -eq 1 -and $script:BypassRegistry.Count -eq 1 -and $script:F.Messages.Count -eq 0}) 'Duplicate work or messages.'
}
Test-Case 'New endpoints produce one periodic summary instead of per-IP normal warnings' {
    & $module {param($A,$B)$script:F.Peers=@($A,$B);$script:F.Now=31;Invoke-GephTunBypassRefresh} (Peer) (Peer '192.0.2.21')
    Assert-True (& $module {$script:F.Adds -eq 2 -and $script:F.Messages.Count -eq 1 -and $script:F.Messages[0] -like 'Geph bypass update:*'}) 'Summary was missing or duplicated.'
}
Test-Case 'Persistent captured socket is escalated but warning is rate-limited' {
    & $module {param($Peer)$script:F.Peers=@($Peer);Invoke-GephTunBypassRefresh;$script:F.Now=16;Invoke-GephTunBypassRefresh;$script:F.Now=17;Invoke-GephTunBypassRefresh} (Peer '192.0.2.20' $true)
    Assert-True (& $module {@($script:F.Messages|Where-Object {$_ -like 'BypassNeedsAttention:*'}).Count -eq 1}) 'Captured socket escalation incorrect.'
}
Test-Case 'Unused owned routes are retired after the quiet period' {
    & $module {param($A,$B)$script:F.Peers=@($A);Invoke-GephTunBypassRefresh;$script:F.Now=301;$script:F.Peers=@($B);Invoke-GephTunBypassRefresh} (Peer) (Peer '192.0.2.21')
    Assert-True (& $module {$script:F.Removes -eq 1 -and $script:BypassRegistry.Count -eq 1 -and @($script:Session.Routes).Count -eq 1}) 'Old owned route was not retired.'
}
Test-Case 'An empty peer snapshot cannot prune owned routes' {
    $rejected=& $module {param($Peer)$script:F.Peers=@($Peer);Invoke-GephTunBypassRefresh;$script:F.Now=400;$script:F.Peers=@();try{Invoke-GephTunBypassRefresh;$false}catch{$true}} (Peer)
    Assert-True $rejected 'Empty peer snapshot accepted.'
    Assert-True (& $module {$script:F.Removes -eq 0}) 'An unreadable network deleted routes.'
}
Test-Case 'Borrowed routes are never removed by retirement' {
    & $module {param($A,$B)
        $script:F.Live=@([pscustomobject]@{DestinationPrefix=$A.Prefix;InterfaceIndex=7;NextHop='192.0.2.1';RouteMetric=9})
        $script:F.Peers=@($A);Invoke-GephTunBypassRefresh;$script:F.Now=301;$script:F.Peers=@($B);Invoke-GephTunBypassRefresh
    } (Peer) (Peer '192.0.2.21')
    Assert-True (& $module {$script:F.Removes -eq 0 -and @($script:F.Live|Where-Object DestinationPrefix -eq '192.0.2.20/32').Count -eq 1}) 'Borrowed route was deleted.'
}
Test-Case 'Changed owned route metric is rejected, not overwritten' {
    $rejected=& $module {param($Peer)$script:F.Peers=@($Peer);Invoke-GephTunBypassRefresh
        $script:F.Live=@([pscustomobject]@{DestinationPrefix=$Peer.Prefix;InterfaceIndex=7;NextHop='192.0.2.1';RouteMetric=44})
        try{Invoke-GephTunBypassRefresh;$false}catch{$true}
    } (Peer)
    Assert-True $rejected 'An altered owned route was accepted.'
}
Test-Case 'Adapter identity changes are rejected before adding a route' {
    $rejected=& $module {param($Peer)$script:F.Peers=@($Peer);$script:F.Guid='replacement';try{Invoke-GephTunBypassRefresh;$false}catch{$true}} (Peer)
    Assert-True $rejected 'A replacement interface was accepted.'
    Assert-True (& $module {$script:F.Adds -eq 0}) 'Mutation happened before adapter validation.'
}
Test-Case 'Remembered endpoint is preinstalled on the fresh session gateway' {
    & $module {
        $script:F.Cache=[pscustomobject]@{Schema=1;Identity=('c:\geph\geph.exe|'+('a'*64));Entries=@([pscustomobject]@{Address='192.0.2.88';LastSeenUtc=[DateTime]::UtcNow.AddMinutes(-5).ToString('o')})}
        Initialize-GephTunBypassRegistry;Install-GephTunRememberedBypasses
    }
    Assert-True (& $module {$script:F.Adds -eq 1 -and $script:F.Live[0].NextHop -eq '192.0.2.1'}) 'Current gateway was not used.'
}
Test-Case 'Wrong image identity cannot seed the endpoint cache' {
    & $module {$script:F.Cache=[pscustomobject]@{Schema=1;Identity='wrong';Entries=@([pscustomobject]@{Address='192.0.2.88';LastSeenUtc=[DateTime]::UtcNow.ToString('o')})};Initialize-GephTunBypassRegistry;Install-GephTunRememberedBypasses}
    Assert-True (& $module {$script:F.Adds -eq 0}) 'Wrong Geph image seeded routes.'
}
Test-Case 'Old and future endpoint records are ignored' {
    & $module {$script:F.Cache=[pscustomobject]@{Schema=1;Identity=('c:\geph\geph.exe|'+('a'*64));Entries=@(
        [pscustomobject]@{Address='192.0.2.88';LastSeenUtc=[DateTime]::UtcNow.AddHours(-25).ToString('o')},
        [pscustomobject]@{Address='192.0.2.89';LastSeenUtc=[DateTime]::UtcNow.AddHours(1).ToString('o')})};Initialize-GephTunBypassRegistry;Install-GephTunRememberedBypasses}
    Assert-True (& $module {$script:F.Adds -eq 0}) 'Expired or future cache seeded routes.'
}
Test-Case 'Unsafe cache address classes are excluded' {
    Assert-True (& $module {foreach($ip in @('127.0.0.1','0.0.0.0','224.0.0.1','169.254.1.1','198.18.0.1','::','::1','fe80::1','ff02::1','::ffff:192.0.2.1')){if(Test-GephTunCacheAddress $ip){return $false}};return $true}) 'Unsafe cached address accepted.'
}
Test-Case 'Cache serialization drops old overflow entries rather than growing unbounded' {
    & $module {1..600|ForEach-Object {$address='10.0.'+[int][Math]::Floor($_/250)+'.'+($_%250+1);$script:BypassCache[$address]=[pscustomobject]@{Address=$address;LastSeenUtc=[DateTime]::UtcNow.ToString('o')}};Save-GephTunBypassCache -Force}
    Assert-True (& $module {$script:BypassCache.Count -eq 512 -and @($script:F.Saved.Entries).Count -eq 512}) 'Cache exceeded its cap.'
}
foreach($mode in @('Competitor','WrongGateway','Ambiguous','Missing','QueryFailure')) {
Test-Case ('Actual selected route is required: '+$mode) {
    $rejected=& $module {param($Peer,$Mode)
        $script:F.Peers=@($Peer)
        $bad=[pscustomobject]@{DestinationPrefix=$Peer.Prefix;InterfaceIndex=8;NextHop='192.0.2.2';RouteMetric=1}
        if($Mode -eq 'Competitor'){$script:F.Live=@($bad)}
        if($Mode -eq 'WrongGateway'){$bad.InterfaceIndex=7;$script:F.Selection=@($bad)}
        if($Mode -eq 'Ambiguous'){$script:F.Selection=@($bad,$bad)}
        if($Mode -eq 'Missing'){$script:F.Selection=@()}
        if($Mode -eq 'QueryFailure'){$script:F.SelectionFail=$true}
        try{Invoke-GephTunBypassRefresh;$false}catch{$true}
    } (Peer) $mode
    Assert-True $rejected 'Ineffective/unknown route selection was accepted.'
    Assert-True (& $module {$script:F.Removes -eq 0}) 'Foreign route was removed to obtain a passing selection.'
}}
Test-Case 'Borrowed route metric changes that select another path are refused' {
    $rejected=& $module {param($Peer)
        $script:F.Live=@([pscustomobject]@{DestinationPrefix=$Peer.Prefix;InterfaceIndex=7;NextHop=$Peer.NextHop;RouteMetric=2})
        $script:F.Peers=@($Peer);Invoke-GephTunBypassRefresh
        $script:F.Live[0].RouteMetric=50
        $script:F.Live+=[pscustomobject]@{DestinationPrefix=$Peer.Prefix;InterfaceIndex=8;NextHop='192.0.2.2';RouteMetric=1}
        try{Invoke-GephTunBypassRefresh;$false}catch{$true}
    } (Peer)
    Assert-True $rejected 'Changed effective borrowed route was accepted.'
    Assert-True (& $module {$script:F.Adds -eq 0 -and $script:F.Removes -eq 0}) 'Borrowed/foreign route was mutated.'
}
Test-Case 'Failed retirement preserves route journal and registry for another attempt' {
    $rejected=& $module {param($A,$B)
        $script:F.Peers=@($A);Invoke-GephTunBypassRefresh;$script:F.Now=301;$script:F.Peers=@($B);$script:F.RemoveFail=$true
        try{Invoke-GephTunBypassRefresh;$false}catch{$true}
    } (Peer) (Peer '192.0.2.21')
    Assert-True $rejected 'Removal failure was suppressed.'
    Assert-True (& $module {$script:BypassRegistry.Count -eq 2 -and @($script:Session.Routes).Count -eq 2}) 'Failed removal lost ownership records.'
}
foreach($mode in @('Down','NotHardware','RouteQuery','AddFailure')) {
Test-Case ('Exceptional bypass conditions fail without foreign deletion: '+$mode) {
    $failed=& $module {param($Peer,$Mode)
        $script:F.Peers=@($Peer)
        if($Mode -eq 'Down'){$script:F.Up=$false}
        if($Mode -eq 'NotHardware'){$script:F.Hardware=$false}
        if($Mode -eq 'RouteQuery'){$script:F.ReadFail=$true}
        if($Mode -eq 'AddFailure'){$script:F.AddFail=$true}
        try{Invoke-GephTunBypassRefresh;$false}catch{$true}
    } (Peer) $mode
    Assert-True $failed 'Unsafe/failed bypass operation was accepted.'
    Assert-True (& $module {$script:F.Removes -eq 0}) 'Failure deleted a foreign route.'
}}
Test-Case 'Combined interface and route metrics determine the selected path' {
    $rejected=& $module {param($Peer)
        # Its route metric is higher, but its total metric is lower than ours.
        $script:F.Live=@([pscustomobject]@{DestinationPrefix=$Peer.Prefix;InterfaceIndex=8;NextHop='192.0.2.2';RouteMetric=5})
        $script:F.Peers=@($Peer);try{Invoke-GephTunBypassRefresh;$false}catch{$true}
    } (Peer)
    Assert-True $rejected 'Route-only metric comparison missed the actual competitor.'
    Assert-True (& $module {$script:F.Removes -eq 0}) 'Competing route was deleted.'
}
Test-Case 'A higher total metric competitor permits the intended physical route' {
    & $module {param($Peer)
        $script:F.InterfaceMetrics[8]=100
        $script:F.Live=@([pscustomobject]@{DestinationPrefix=$Peer.Prefix;InterfaceIndex=8;NextHop='192.0.2.2';RouteMetric=1})
        $script:F.Peers=@($Peer);Invoke-GephTunBypassRefresh
    } (Peer)
    Assert-True (& $module {$script:BypassRegistry.Count -eq 1 -and $script:F.Removes -eq 0 -and $script:F.Live.Count -eq 2}) 'Harmless competing route was changed or rejected.'
}
Test-Case 'Gateway changes are rejected before installing a stale bypass' {
    $rejected=& $module {param($Peer)$Peer.NextHop='192.0.2.99';try{Confirm-GephTunBypass $Peer;$false}catch{$true}} (Peer)
    Assert-True $rejected 'A stale session gateway was accepted.'
    Assert-True (& $module {$script:F.Adds -eq 0}) 'Stale gateway mutated routing.'
}
foreach($mode in @('AdapterChanged','MetricChanged','RemovalUnconfirmed','RemovalSuccess','AlreadyAbsent')) {
Test-Case ('Actual route cleanup retains ownership on uncertainty: '+$mode) {
    $ok=& $module {param($Mode)
        $entry=[pscustomobject]@{DestinationPrefix='192.0.2.20/32';InterfaceIndex=7;InterfaceGuid='wifi';NextHop='192.0.2.1';RouteMetric=3;Kind='Bypass'}
        $script:F.Live=@($entry)
        $foreign=[pscustomobject]@{DestinationPrefix='192.0.2.20/32';InterfaceIndex=8;NextHop='192.0.2.2';RouteMetric=1}
        if($Mode -eq 'AdapterChanged'){$script:F.Guid='other'}
        if($Mode -eq 'MetricChanged'){$script:F.Live=@([pscustomobject]@{DestinationPrefix=$entry.DestinationPrefix;InterfaceIndex=7;NextHop=$entry.NextHop;RouteMetric=90})}
        if($Mode -eq 'AlreadyAbsent'){$script:F.Live=@()}
        $script:F.Live+=@($foreign);$script:F.RemoveFail=$Mode -eq 'RemovalUnconfirmed'
        function script:Remove-NetRoute {
            [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject,[switch]$Confirm)
            process {$script:F.Removes++;if(-not $script:F.RemoveFail){$script:F.Live=@($script:F.Live|Where-Object {-not ($_.DestinationPrefix -eq $InputObject.DestinationPrefix -and $_.InterfaceIndex -eq $InputObject.InterfaceIndex -and $_.NextHop -eq $InputObject.NextHop -and $_.RouteMetric -eq $InputObject.RouteMetric)})}}
        }
        $success=$false;try{& $script:ActualRemoveRoute $entry;$success=$true}catch{}
        $expected=$Mode -in @('RemovalSuccess','AlreadyAbsent')
        $success -eq $expected -and @($script:F.Live|Where-Object InterfaceIndex -eq 8).Count -eq 1 -and
            ($Mode -notin @('AdapterChanged','MetricChanged') -or $script:F.Removes -eq 0)
    } $mode
    Assert-True $ok 'Actual cleanup deleted foreign state or ignored uncertain ownership/removal.'
}}
foreach($mode in @('Borrowed','Added','AddFailure')) {
Test-Case ('Actual route creation journals only newly owned resources: '+$mode) {
    $ok=& $module {param($Mode)
        if($Mode -eq 'Borrowed'){$script:F.Live=@([pscustomobject]@{DestinationPrefix='192.0.2.20/32';InterfaceIndex=7;NextHop='192.0.2.1';RouteMetric=99})}
        $script:F.AddFail=$Mode -eq 'AddFailure'
        function script:New-NetRoute {[CmdletBinding()]param($DestinationPrefix,$InterfaceIndex,$NextHop,$RouteMetric,$PolicyStore)
            $script:F.Adds++;if($script:F.AddFail){throw 'Injected native route add failure'}
            $script:F.Live+=@([pscustomobject]@{DestinationPrefix=$DestinationPrefix;InterfaceIndex=$InterfaceIndex;NextHop=$NextHop;RouteMetric=$RouteMetric})
        }
        $failed=$false;try{& $script:ActualAddRoute '192.0.2.20/32' 7 '192.0.2.1' 'Bypass'}catch{$failed=$true}
        if($Mode -eq 'Borrowed'){return (-not $failed -and $script:F.Adds -eq 0 -and $script:Session.Routes.Count -eq 0)}
        $script:Session.Routes.Count -eq 1 -and $script:Session.Routes[0].Planned -eq ($Mode -eq 'AddFailure') -and $failed -eq ($Mode -eq 'AddFailure')
    } $mode
    Assert-True $ok 'Borrowed ownership or write-before-add recovery record was incorrect.'
}}
} finally {if($null -ne $module){Remove-Module $module -Force}}
$failed=@($results|Where-Object Result -eq 'FAIL').Count
$report=[ordered]@{Version='1.5.0';CapturedUtc=[DateTime]::UtcNow.ToString('o');Scope='Actual bypass registry/cache functions with isolated OS/storage doubles. No live networking.';Total=$results.Count;Passed=$results.Count-$failed;Failed=$failed;Skipped=0;Tests=$results.ToArray()}
if($ResultJson){$output=Get-GephPackageFullPath $ResultJson;Assert-GephPackageOutput $output (Get-GephPackageFullPath $PackageDirectory);Write-GephPackageNewJson $output $report}
$results|Format-Table -AutoSize -Wrap
if($failed){exit 1}
