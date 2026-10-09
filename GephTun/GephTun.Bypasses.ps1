# Bounded, identity-aware bypass registry. No Geph engine patch is claimed.
# Known endpoints are preloaded BEFORE tunnel diversion; genuinely new endpoints
# still use the validated observation/retry path because Geph has no supplied pre-dial hook.
$script:BypassRoutesSnapshot = $null
$script:BypassAdapters = @{}
$script:BypassRegistry = @{}
$script:BypassCache = @{}
$script:BypassClock = $null
$script:BypassLogAt = 0.0
$script:BypassCacheAt = 0.0
$script:BypassCounters = @{ Added=0; Retired=0; Captured=0; Preloaded=0 }

function Get-GephTunBypassNow {
    if ($null -eq $script:BypassClock) { $script:BypassClock=[Diagnostics.Stopwatch]::StartNew() }
    return [double]$script:BypassClock.Elapsed.TotalSeconds
}

function Get-GephTunBypassKey($Peer) { return ('{0}|{1}|{2}' -f $Peer.Prefix,$Peer.InterfaceIndex,$Peer.NextHop) }

function Test-GephTunCacheAddress([string]$Text) {
    $address=$null
    if (-not [Net.IPAddress]::TryParse($Text,[ref]$address) -or [Net.IPAddress]::IsLoopback($address)) { return $false }
    if ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
        $b=$address.GetAddressBytes()
        return ($b[0] -gt 0 -and $b[0] -lt 224 -and $b[0] -ne 127 -and
            -not ($b[0] -eq 169 -and $b[1] -eq 254) -and -not ($b[0] -eq 198 -and $b[1] -in @(18,19)))
    }
    return ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6 -and -not $address.IsIPv6LinkLocal -and
        -not $address.IsIPv6Multicast -and -not $address.IsIPv4MappedToIPv6 -and $address.ToString() -ne '::')
}

function Get-GephTunBypassCacheIdentity {
    $path=[string]$script:Session.ProxyProcess.Path
    $config=Get-GephTunProtectionConfiguration
    $image=@($config.TrustedImages | Where-Object { [string]::Equals($_.Path,$path,[StringComparison]::OrdinalIgnoreCase) })
    if ($image.Count -ne 1) { throw 'The bypass cache requires an explicitly approved Geph identity.' }
    return ($path.ToLowerInvariant()+'|'+$image[0].Sha256.ToLowerInvariant())
}

function Save-GephTunBypassCache([switch]$Force) {
    $now=Get-GephTunBypassNow
    if (-not $Force -and $now-$script:BypassCacheAt -lt 60) { return }
    $records=@($script:BypassCache.Values | Sort-Object LastSeenUtc -Descending | Select-Object -First 512)
    $script:BypassCache=@{}
    foreach ($record in $records) { $script:BypassCache[$record.Address]=$record }
    Write-GephTunJson (Join-Path (Get-GephTunRoot) 'upstream-cache.json') ([ordered]@{
        Schema=1; Identity=(Get-GephTunBypassCacheIdentity); Entries=$records
    })
    $script:BypassCacheAt=$now
}

function Initialize-GephTunBypassRegistry {
    $script:BypassRegistry=@{}; $script:BypassCache=@{}; $script:BypassClock=[Diagnostics.Stopwatch]::StartNew()
    $script:BypassLogAt=0.0; $script:BypassCacheAt=0.0
    $script:BypassCounters=@{Added=0;Borrowed=0;Retired=0;Captured=0;Preloaded=0}
    # Cache corruption is not permission to add routes. Skip the optimization.
    try {
        $cache=Read-GephTunJson (Join-Path (Get-GephTunRoot) 'upstream-cache.json')
        if ($null -eq $cache) { return }
        if ($cache.Schema -ne 1 -or $cache.Identity -cne (Get-GephTunBypassCacheIdentity) -or @($cache.Entries).Count -gt 512) { return }
        foreach ($entry in @($cache.Entries)) {
            if (-not (Test-GephTunCacheAddress ([string]$entry.Address))) { continue }
            $time=[DateTimeOffset]::Parse([string]$entry.LastSeenUtc)
            $age=([DateTimeOffset]::UtcNow-$time).TotalHours
            if ($age -lt 0 -or $age -gt 24) { continue }
            $ip=[Net.IPAddress]::Parse($entry.Address).ToString()
            $script:BypassCache[$ip]=[pscustomobject]@{Address=$ip;LastSeenUtc=$time.UtcDateTime.ToString('o')}
        }
    } catch { $script:BypassCache=@{}; Write-GephTunLog ('Bypass cache ignored; live observations will be used: '+$_.Exception.Message) }
}

function Confirm-GephTunBypass($Peer, [switch]$Preloaded) {
    $key=Get-GephTunBypassKey $Peer
    $now=Get-GephTunBypassNow
    $new=-not $script:BypassRegistry.ContainsKey($key)
    if ($new -and $script:BypassRegistry.Count -ge 512) { throw 'The live Geph bypass registry reached its safety limit. Reconnect rather than accumulating unbounded routes.' }
    $prefixEntries=@($script:Session.Routes | Where-Object { $_.Kind -eq 'Bypass' -and $_.DestinationPrefix -eq $Peer.Prefix })
    if (@($prefixEntries | Where-Object { $_.InterfaceIndex -ne $Peer.InterfaceIndex -or $_.NextHop -ne $Peer.NextHop }).Count -gt 0) {
        Throw-GephTunTransient 'NETWORK_CHANGED' 'A Geph endpoint needs a different physical route; starting a fresh session is safer than mutating the old routing snapshot.'
    }
    $adapterKey=[int]$Peer.InterfaceIndex
    if (-not $script:BypassAdapters.ContainsKey($adapterKey)) {
        $script:BypassAdapters[$adapterKey]=Get-NetAdapter -InterfaceIndex $Peer.InterfaceIndex -IncludeHidden -ErrorAction Stop
    }
    $adapter=$script:BypassAdapters[$adapterKey]
    if (-not $adapter.HardwareInterface -or $adapter.Status -ne 'Up') { Throw-GephTunTransient 'NETWORK_UNAVAILABLE' 'The Geph bypass physical adapter is unavailable.' }
    $expected=@($script:Session.OriginalRoutes | Where-Object { $_.InterfaceIndex -eq $Peer.InterfaceIndex -and $_.InterfaceGuid -eq $adapter.InterfaceGuid.ToString() })
    if ($expected.Count -eq 0) { Throw-GephTunTransient 'NETWORK_CHANGED' 'The Geph bypass adapter no longer matches this session.' }
    $baseline=@($script:Session.OriginalRoutes | Where-Object {
        $_.InterfaceIndex -eq $Peer.InterfaceIndex -and $_.InterfaceGuid -eq $adapter.InterfaceGuid.ToString() -and
        (Test-GephTunPrefix $Peer.Prefix.Split('/')[0] $_.DestinationPrefix)
    } | Sort-Object @{Expression={ [int]$_.DestinationPrefix.Split('/')[1] };Descending=$true},Cost)
    if ($baseline.Count -eq 0 -or $baseline[0].NextHop -ne $Peer.NextHop) { Throw-GephTunTransient 'NETWORK_CHANGED' 'The bypass gateway no longer matches the saved physical route.' }
    if ($new) {
        Add-GephTunOwnedRoute $Peer.Prefix $Peer.InterfaceIndex $Peer.NextHop 'Bypass'
        if ($Preloaded) { $script:BypassCounters.Preloaded++ }
    }
    if ($new) { $script:BypassRoutesSnapshot=$null }
    if ($null -eq $script:BypassRoutesSnapshot) { $script:BypassRoutesSnapshot=@(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop) }
    $actual=@($script:BypassRoutesSnapshot | Where-Object {
        $_.DestinationPrefix -eq $Peer.Prefix -and $_.InterfaceIndex -eq $Peer.InterfaceIndex -and $_.NextHop -eq $Peer.NextHop
    })
    if ($actual.Count -ne 1) { throw ('The Geph bypass route is missing or ambiguous: '+$Peer.Prefix) }
    # Find-NetRoute returns the chosen route and source-address record. A
    # matching host route alone is insufficient when another interface wins.
    try { $selection=@(Find-NetRoute -RemoteIPAddress $Peer.Prefix.Split('/')[0] -ErrorAction Stop) }
    catch { Throw-GephTunTransient 'PEER_SNAPSHOT' ('Selected bypass route could not be queried: '+$_.Exception.Message) }
    $selected=@($selection | Where-Object { $_.PSObject.Properties['DestinationPrefix'] })
    if ($selected.Count -ne 1) { throw 'Selected bypass route is missing or ambiguous; no foreign route was modified.' }
    if ($selected[0].DestinationPrefix -ne $Peer.Prefix -or [int]$selected[0].InterfaceIndex -ne [int]$Peer.InterfaceIndex -or $selected[0].NextHop -ne $Peer.NextHop) {
        Throw-GephTunTransient 'NETWORK_CHANGED' 'Windows selected a competing Geph bypass route; recover before repairing this session.'
    }
    $sources=@($selection | Where-Object { $_.PSObject.Properties['IPAddress'] })
    if ($sources.Count -gt 1 -or ($sources.Count -eq 1 -and [int]$sources[0].InterfaceIndex -ne [int]$Peer.InterfaceIndex)) { throw 'Selected bypass source interface is inconsistent.' }
    $owned=@($script:Session.Routes | Where-Object { $_.Kind -eq 'Bypass' -and $_.DestinationPrefix -eq $Peer.Prefix })
    if ($owned.Count -gt 0 -and ([int]$actual[0].RouteMetric -ne [int]$owned[0].RouteMetric -or $owned[0].InterfaceGuid -ne $adapter.InterfaceGuid.ToString())) {
        throw ('An owned Geph bypass was changed: '+$Peer.Prefix)
    }
    if ($new) {
        if ($owned.Count -eq 1) { $script:BypassCounters.Added++ } else { $script:BypassCounters.Borrowed++ }
        $script:BypassRegistry[$key]=[pscustomobject]@{Prefix=$Peer.Prefix;InterfaceIndex=[int]$Peer.InterfaceIndex;NextHop=$Peer.NextHop;LastSeen=$now;CapturedAt=-1.0;LastWarning=-60.0;Owned=($owned.Count -eq 1)}
    }
    $record=$script:BypassRegistry[$key]
    if (-not $Preloaded) {
        $record.LastSeen=$now
        $ip=$Peer.Prefix.Split('/')[0]
        if (Test-GephTunCacheAddress $ip) { $script:BypassCache[$ip]=[pscustomobject]@{Address=$ip;LastSeenUtc=[DateTime]::UtcNow.ToString('o')} }
        if ($Peer.PSObject.Properties['Recovered'] -and $Peer.Recovered) {
            if ($record.CapturedAt -lt 0) { $record.CapturedAt=$now; $script:BypassCounters.Captured++ }
            elseif ($now-$record.CapturedAt -ge 15 -and $now-$record.LastWarning -ge 60) {
                $record.LastWarning=$now
                Write-GephTunLog ('BypassNeedsAttention: endpoint='+$Peer.Prefix+' remains on a captured socket despite a verified route. Geph must recreate that socket; the wrapper cannot rebind it.')
            }
        } else { $record.CapturedAt=-1.0 }
    }
}

function Install-GephTunRememberedBypasses {
    $script:BypassRoutesSnapshot=$null; $script:BypassAdapters=@{}
    # Only validated IPs from the same approved executable, at most 24 hours old.
    # Recompute the physical route from THIS session; never persist/reuse a gateway.
    $remembered=@($script:BypassCache.Values | Sort-Object LastSeenUtc -Descending | Select-Object -First 128)
    foreach ($entry in $remembered) {
        Assert-GephTunConnectContinuing
        $routes=@($script:Session.OriginalRoutes | Where-Object {
            $_.InterfaceIndex -eq $script:Session.OriginalNetwork.InterfaceIndex -and (Test-GephTunPrefix $entry.Address $_.DestinationPrefix)
        } | Sort-Object @{Expression={ [int]$_.DestinationPrefix.Split('/')[1] };Descending=$true},Cost)
        if ($routes.Count -eq 0) { continue }
        $ip=[Net.IPAddress]::Parse($entry.Address); $bits=128
        if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) { $bits=32 }
        Confirm-GephTunBypass ([pscustomobject]@{Prefix=$ip.ToString()+'/'+$bits;InterfaceIndex=$routes[0].InterfaceIndex;NextHop=$routes[0].NextHop}) -Preloaded
    }
}

function Invoke-GephTunBypassRefresh {
    $script:BypassRoutesSnapshot=$null; $script:BypassAdapters=@{}
    $peers=@(Get-GephTunPeerRoutes $script:Session.ProxyProcess)
    if ($peers.Count -eq 0) { Throw-GephTunTransient 'PEER_MISSING' 'Geph has no observable physical TCP server connection. Waiting within the reconnect budget.' }
    foreach ($peer in $peers) { Confirm-GephTunBypass $peer }
    $now=Get-GephTunBypassNow
    # Do not prune if a peer snapshot failed or was empty. All Geph non-loopback
    # UDP sockets are rejected by Get-GephTunPeerRouteSnapshot, so untracked UDP
    # is not silently used as a reason to delete a live transport route.
    foreach ($key in @($script:BypassRegistry.Keys)) {
        $record=$script:BypassRegistry[$key]
        if ($now-$record.LastSeen -lt 300) { continue }
        $owned=@($script:Session.Routes | Where-Object { $_.Kind -eq 'Bypass' -and $_.DestinationPrefix -eq $record.Prefix -and $_.InterfaceIndex -eq $record.InterfaceIndex -and $_.NextHop -eq $record.NextHop })
        if ($owned.Count -eq 1) {
            Remove-GephTunOwnedRoute $owned[0]
            $script:Session.Routes=@($script:Session.Routes | Where-Object { -not ($_.Kind -eq 'Bypass' -and $_.DestinationPrefix -eq $record.Prefix -and $_.InterfaceIndex -eq $record.InterfaceIndex -and $_.NextHop -eq $record.NextHop) })
            Save-GephTunSession
            $script:BypassCounters.Retired++
        }
        $script:BypassRegistry.Remove($key) # Never delete a borrowed route.
    }
    $allPeers=@($script:BypassRegistry.Values | ForEach-Object { [pscustomobject]@{Prefix=$_.Prefix;InterfaceIndex=$_.InterfaceIndex;NextHop=$_.NextHop} })
    if ($script:Session.PSObject.Properties['PeerBypasses']) { $script:Session.PeerBypasses=$allPeers }
    else { $script:Session | Add-Member -NotePropertyName PeerBypasses -NotePropertyValue $allPeers }
    Save-GephTunBypassCache
    if ($now-$script:BypassLogAt -ge 30 -and ($script:BypassCounters.Added+$script:BypassCounters.Borrowed+$script:BypassCounters.Retired+$script:BypassCounters.Captured) -gt 0) {
        Write-GephTunLog ('Geph bypass update: added={0}; preloaded={1}; retired={2}; captured endpoints={3}; tracked={4}; borrowed={5}. Destination routes do not grant other applications direct WFP permission.' -f $script:BypassCounters.Added,$script:BypassCounters.Preloaded,$script:BypassCounters.Retired,$script:BypassCounters.Captured,$script:BypassRegistry.Count,$script:BypassCounters.Borrowed)
        $script:BypassCounters=@{Added=0;Borrowed=0;Retired=0;Captured=0;Preloaded=0};$script:BypassLogAt=$now
    }
}
