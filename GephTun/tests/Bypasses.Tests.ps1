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
        $script:F=[pscustomobject]@{Now=0.0;Live=@();Peers=@();Adds=0;Removes=0;Messages=(New-Object 'Collections.Generic.List[string]');Cache=$null;Saved=$null;ReadFail=$false;Guid='wifi';Up=$true;Hardware=$true}
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
            [pscustomobject]@{InterfaceGuid=$script:F.Guid;Status=$(if($script:F.Up){'Up'}else{'Down'});HardwareInterface=$script:F.Hardware}
        }
        function script:Get-NetRoute { [CmdletBinding()]param($PolicyStore)
            if($script:F.ReadFail){throw 'Injected route read failure'}
            $script:F.Live
        }
        function script:Get-GephTunPeerRoutes($Identity){$script:F.Peers}
        function script:Add-GephTunOwnedRoute($Prefix,$Index,$Gateway,$Kind){
            if(@($script:F.Live|Where-Object {$_.DestinationPrefix -eq $Prefix}).Count -eq 0){
                $route=[pscustomobject]@{DestinationPrefix=$Prefix;InterfaceIndex=$Index;NextHop=$Gateway;Kind=$Kind;InterfaceGuid='wifi';RouteMetric=7}
                $script:F.Live+= $route;$script:Session.Routes+= $route;$script:F.Adds++
            }
        }
        function script:Remove-GephTunOwnedRoute($Route){
            $script:F.Removes++
            $script:F.Live=@($script:F.Live|Where-Object {$_.DestinationPrefix -ne $Route.DestinationPrefix})
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
} finally {if($null -ne $module){Remove-Module $module -Force}}
$failed=@($results|Where-Object Result -eq 'FAIL').Count
$report=[ordered]@{Version='1.5.0';CapturedUtc=[DateTime]::UtcNow.ToString('o');Scope='Actual bypass registry/cache functions with isolated OS/storage doubles. No live networking.';Total=$results.Count;Passed=$results.Count-$failed;Failed=$failed;Skipped=0;Tests=$results.ToArray()}
if($ResultJson){$output=Get-GephPackageFullPath $ResultJson;Assert-GephPackageOutput $output (Get-GephPackageFullPath $PackageDirectory);Write-GephPackageNewJson $output $report}
$results|Format-Table -AutoSize -Wrap
if($failed){exit 1}
