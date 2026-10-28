#Requires -Version 5.1
# GephTun 1.5.0. Dot-sourced only by the controller module.
# An intent lives for one Connect worker; it never authorizes unattended boot startup.
$script:ConnectionIntent = $null
$script:ReconnectBudget = $null
$script:ReconnectHistory = New-Object 'Collections.Generic.List[DateTime]'
$script:LastReconnectStatus = ''

function Throw-GephTunTransient([string]$Code, [string]$Message) {
    $exception = [InvalidOperationException]::new($Message)
    $exception.Data['GephTun.FailureCode'] = $Code
    throw $exception
}

function Get-GephTunFailureCode($Failure) {
    if ($Failure -is [Management.Automation.ErrorRecord]) { $Failure = $Failure.Exception }
    while ($null -ne $Failure -and $Failure -is [Exception]) {
        if ($Failure.Data.Contains('GephTun.FailureCode')) { return [string]$Failure.Data['GephTun.FailureCode'] }
        $Failure = $Failure.InnerException
    }
    return '' # Unknown errors, security checks and cleanup failures are NOT retried.
}

function Test-GephTunRetryableFailure([string]$Code) {
    return $Code -in @('NETWORK_UNAVAILABLE','NETWORK_CHANGED','PEER_SNAPSHOT','PEER_MISSING','PROXY_UNAVAILABLE','DNS_UNAVAILABLE')
}

function Get-GephTunConnectionIntent {
    $intent = Read-GephTunJson (Join-Path (Get-GephTunRoot) 'connection-intent.json')
    if ($null -eq $intent) { return $null }
    if (-not $intent.PSObject.Properties['Schema'] -or $intent.Schema -ne 1 -or
        -not $intent.PSObject.Properties['Token'] -or [string]$intent.Token -cnotmatch '\A[a-f0-9]{32}\z' -or
        -not $intent.PSObject.Properties['Worker'] -or $null -eq $intent.Worker -or
        -not $intent.Worker.PSObject.Properties['Id'] -or -not $intent.Worker.PSObject.Properties['StartUtc'] -or
        -not $intent.Worker.PSObject.Properties['Path']) {
        throw 'The connection-intent record is invalid. Recovery must be verified before another connection.'
    }
    return $intent
}

function Initialize-GephTunConnectionIntent([int]$Port = 0, [int]$OwnerProcessId = 0, [string]$OperationToken = '') {
    # Caller owns Global\GephTun-Session-v1 before entering this function.
    $previous = Get-GephTunConnectionIntent
    if ($null -ne $previous -and (Test-GephTunProcessIdentity $previous.Worker)) {
        throw 'A verified connection controller already owns this intent.'
    }
    if ($OperationToken -and $OperationToken -cnotmatch '\A[a-f0-9]{32}\z') { throw 'Invalid connection operation token.' }
    $owner = $null
    if ($OwnerProcessId -gt 0) { $owner = Get-GephTunProcessIdentity $OwnerProcessId }
    $token = [guid]::NewGuid().ToString('N')
    $script:ConnectionIntent = [pscustomobject]@{
        Schema = 1; Token = $token; Worker = (Get-GephTunProcessIdentity $PID); Owner = $owner
        Port = $Port; OperationToken = $OperationToken; ProxyPath = ''
        CreatedUtc = [DateTime]::UtcNow.ToString('o')
    }
    Write-GephTunJson (Join-Path (Get-GephTunRoot) 'connection-intent.json') $script:ConnectionIntent
    $script:ReconnectHistory.Clear()
}

function Test-GephTunIntentStopRequested {
    if ($null -eq $script:ConnectionIntent) { return $false }
    $intent = $script:ConnectionIntent
    if ($null -ne $intent.Owner -and -not (Test-GephTunProcessIdentity $intent.Owner)) { return $true }
    # This request is level-triggered and is not consumed between sessions.
    # A Disconnect arriving after old-session cleanup cannot miss the new token.
    $request = Read-GephTunJson (Join-Path (Get-GephTunRoot) 'disconnect-intent.json')
    if ($null -ne $request -and $request.PSObject.Properties['Token'] -and $request.Token -ceq $intent.Token) { return $true }
    if ($intent.OperationToken) {
        $cancelPath = Join-Path (Join-Path (Get-GephTunRoot) 'results') ($intent.OperationToken + '.cancel.json')
        $cancel = Read-GephTunJson $cancelPath
        if ($null -ne $cancel -and $cancel.PSObject.Properties['Token'] -and $cancel.Token -ceq $intent.OperationToken) { return $true }
    }
    return $false
}

function Assert-GephTunIntentContinuing {
    if (Test-GephTunIntentStopRequested) {
        $exception = [OperationCanceledException]::new('Connection cancelled. Saved network changes will be restored.')
        $exception.Data['GephTun.FailureCode'] = 'CANCELLED'
        throw $exception
    }
    if ($null -ne $script:ReconnectBudget -and $script:ReconnectBudget.Elapsed.TotalSeconds -ge 180) {
        throw 'Automatic reconnect exhausted its 180-second budget. Connect Geph, then choose Connect again.'
    }
}

function Clear-GephTunConnectionIntent {
    # Only remove our own (or a confirmed-dead worker's) protected record.
    $current = Get-GephTunConnectionIntent
    if ($null -eq $current) { $script:ConnectionIntent = $null; return }
    if ($null -ne $script:ConnectionIntent) {
        if ($current.Token -cne $script:ConnectionIntent.Token) { throw 'Connection-intent ownership changed; it was not removed.' }
    }
    elseif (Test-GephTunProcessIdentity $current.Worker) { throw 'A live controller still owns the connection intent.' }
    $stop = Read-GephTunJson (Join-Path (Get-GephTunRoot) 'disconnect-intent.json')
    if ($null -ne $stop -and $stop.PSObject.Properties['Token'] -and $stop.Token -ceq $current.Token) {
        $path = Join-Path (Get-GephTunRoot) 'disconnect-intent.json'
        Assert-GephTunPlainPath $path
        [IO.File]::Delete($path)
    }
    $path = Join-Path (Get-GephTunRoot) 'connection-intent.json'
    Assert-GephTunPlainPath $path
    [IO.File]::Delete($path)
    $script:ConnectionIntent = $null
}

function Set-GephTunReconnectStatus([string]$Message) {
    if ($script:LastReconnectStatus -cne $Message) {
        Set-GephTunStatus 'Reconnecting' $Message
        $script:LastReconnectStatus = $Message
    }
    else {
        # This timestamp is a controller-progress heartbeat, NOT tunnel-health evidence.
        $status = Read-GephTunJson (Join-Path (Get-GephTunRoot) 'status.json')
        if ($null -ne $status -and $status.Status -eq 'Reconnecting' -and $status.WorkerPid -eq $PID -and
            $status.WorkerStartUtc -eq $script:ConnectionIntent.Worker.StartUtc) {
            $status.UpdatedUtc = [DateTime]::UtcNow.ToString('o')
            Write-GephTunJson (Join-Path (Get-GephTunRoot) 'status.json') $status
        }
    }
}

function Wait-GephTunReconnectDelay([int]$Milliseconds) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while ($timer.ElapsedMilliseconds -lt $Milliseconds) {
        Assert-GephTunIntentContinuing
        Start-Sleep -Milliseconds ([Math]::Min(250, [Math]::Max(1, $Milliseconds - [int]$timer.ElapsedMilliseconds)))
    }
}

function Get-GephTunNetworkFingerprint($Network) {
    try {
        $addresses = @(Get-NetIPAddress -InterfaceIndex $Network.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.IPAddress -and $_.IPAddress -notlike '169.254.*' } |
            ForEach-Object { [string]$_.IPAddress } | Sort-Object -Unique)
    }
    catch { Throw-GephTunTransient 'NETWORK_UNAVAILABLE' ('The physical IPv4 address is not yet readable: ' + $_.Exception.Message) }
    if ($addresses.Count -eq 0) { Throw-GephTunTransient 'NETWORK_UNAVAILABLE' 'The physical network is waiting for an IPv4 address.' }
    return ('{0}|{1}|{2}|{3}' -f $Network.InterfaceIndex, $Network.InterfaceGuid, $Network.Gateway, ($addresses -join ','))
}

function Invoke-GephTunReconnect([string]$Reason) {
    if ($null -eq $script:ConnectionIntent) { throw 'Automatic reconnect requires a live, owned connection intent.' }
    if (Test-GephTunIntentStopRequested) { return $false }
    $now = [DateTime]::UtcNow
    for ($i = $script:ReconnectHistory.Count - 1; $i -ge 0; $i--) {
        if (($now - $script:ReconnectHistory[$i]).TotalSeconds -gt 600) { $script:ReconnectHistory.RemoveAt($i) }
    }
    if ($script:ReconnectHistory.Count -ge 3) {
        throw 'Automatic reconnect stopped after three recovery cycles within ten minutes. Check the network and Geph, then reconnect manually.'
    }
    $script:ReconnectHistory.Add($now)
    Write-GephTunLog ('Automatic reconnect: ' + $Reason)
    # Never refresh the saved routing snapshot while any old-session effect remains.
    Restore-GephTunSession
    if ($null -ne $script:Session -or (Test-Path -LiteralPath (Join-Path (Get-GephTunRoot) 'session.json'))) {
        throw 'The old session is not fully recovered; automatic reconnect was refused.'
    }
    if (Test-GephTunIntentStopRequested) { return $false }
    $script:ReconnectBudget = [Diagnostics.Stopwatch]::StartNew()
    $script:LastReconnectStatus = ''
    $fingerprint = ''
    $attempts = 0
    try {
        while ($script:ReconnectBudget.Elapsed.TotalSeconds -lt 180 -and $attempts -lt 3) {
            Assert-GephTunIntentContinuing
            Set-GephTunReconnectStatus 'Waiting for a stable physical network and Geph. The previous session is removed; WFP protection remains enabled. Disconnect cancels retries.'
            try {
                $network = Get-GephTunDefaultRoutes
                $next = Get-GephTunNetworkFingerprint $network
                if ($next -cne $fingerprint) {
                    Close-GephTunProtectionLease
                    $fingerprint = $next
                    Wait-GephTunReconnectDelay 3000
                    continue
                }
                # Verify the original Geph installation, not simply any similarly named process.
                if ($null -eq $script:ProtectionLease) { Open-GephTunProtectionLease }
                $proxy = Get-GephTunProxy ([int]$script:ConnectionIntent.Port)
                if ($script:ConnectionIntent.ProxyPath -and -not [string]::Equals(
                    [string]$proxy.Process.Path, [string]$script:ConnectionIntent.ProxyPath, [StringComparison]::OrdinalIgnoreCase)) {
                    throw 'The Geph installation changed during reconnect. Choose Connect manually after verifying the new installation.'
                }
                Assert-GephTunIntentContinuing
                # Geph's own lookup may have blocked while Wi-Fi changed again.
                $afterProbe = Get-GephTunNetworkFingerprint (Get-GephTunDefaultRoutes)
                if ($afterProbe -cne $fingerprint) { Close-GephTunProtectionLease; $fingerprint = ''; Wait-GephTunReconnectDelay 3000; continue }
                $attempts++
                Set-GephTunReconnectStatus ('Revalidating a fresh session (attempt {0}/3). WFP continues blocking direct application traffic until the tunnel is verified.' -f $attempts)
                $ownerId = 0
                if ($null -ne $script:ConnectionIntent.Owner) { $ownerId = [int]$script:ConnectionIntent.Owner.Id }
                # Start performs ALL ordinary preflight, identity, hash/signature,
                # route, NRPT and firewall checks against a fresh clean baseline.
                Start-GephTunSession -Port ([int]$script:ConnectionIntent.Port) -OwnerProcessId $ownerId `
                    -OperationToken ([string]$script:ConnectionIntent.OperationToken) | Out-Null
                $script:LastReconnectStatus = ''
                Write-GephTunLog 'Automatic reconnect verified a new session. Existing application TCP connections may still need to reconnect.'
                return $true
            }
            catch {
                $code = Get-GephTunFailureCode $_
                if ($code -eq 'CANCELLED') { return $false }
                if (-not (Test-GephTunRetryableFailure $code)) { throw }
                if ($null -ne $script:Session -or (Test-Path -LiteralPath (Join-Path (Get-GephTunRoot) 'session.json'))) { throw }
                Write-GephTunLog ('Reconnect waiting [' + $code + ']: ' + $_.Exception.Message)
                Close-GephTunProtectionLease
                $fingerprint = ''
                Wait-GephTunReconnectDelay 5000
            }
        }
        throw 'Automatic reconnect could not verify a connection within its retry budget. Connect Geph, then choose Connect again.'
    }
    catch {
        if ((Get-GephTunFailureCode $_) -eq 'CANCELLED') { return $false }
        throw
    }
    finally {
        $script:ReconnectBudget = $null
        if ($null -eq $script:Session) { Close-GephTunProtectionLease }
    }
}

function Get-GephTunPeerRoutes($ProxyIdentity) {
    # Repeat the ENTIRE observation rather than reusing a socket that disappeared.
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try { return @(Get-GephTunPeerRouteSnapshot $ProxyIdentity) }
        catch {
            if ((Get-GephTunFailureCode $_) -ne 'PEER_SNAPSHOT' -or $attempt -eq 3) { throw }
            Assert-GephTunIntentContinuing
            Start-Sleep -Milliseconds 200
        }
    }
}

function Write-GephTunPeerDiagnostic($Peer, [string]$Detail) {
    try {
        $observation = [ordered]@{
            Event = 'PeerValidation'; LocalAddress = [string]$Peer.LocalAddress
            RemoteAddress = [string]$Peer.RemoteAddress; OwningProcess = [int]$Peer.OwningProcess
            State = [string]$Peer.State; Detail = $Detail
        }
        Write-GephTunLog ($observation | ConvertTo-Json -Depth 4 -Compress)
    } catch { }
}

function Test-GephTunFirewallBaseline {
    Test-GephTunFirewallProfiles
    $profiles = @(Get-NetFirewallProfile -PolicyStore PersistentStore -ErrorAction Stop)
    $names = @($profiles | ForEach-Object { [string]$_.Name } | Sort-Object -Unique)
    if ($profiles.Count -ne 3 -or ($names -join ',') -ne 'Domain,Private,Public') {
        throw 'The local Windows Firewall baseline could not be verified.'
    }
    foreach ($profile in $profiles) {
        if ([string]$profile.Enabled -notin @('True','NotConfigured')) {
            throw 'A local Windows Firewall profile is disabled or unknown. Enable the required profiles yourself before connecting; GephTun no longer changes global firewall profile settings.'
        }
    }
}

function Watch-GephTunSession {
    while ($null -ne $script:Session) {
        try { Watch-GephTunCurrentSession; return }
        catch {
            $code = Get-GephTunFailureCode $_
            if ($code -eq 'CANCELLED' -or (Test-GephTunIntentStopRequested)) { return }
            if ($null -eq $script:ConnectionIntent -or -not (Test-GephTunRetryableFailure $code)) { throw }
            if (-not (Invoke-GephTunReconnect ('[' + $code + '] ' + $_.Exception.Message))) { return }
        }
    }
}

# Small timing seams keep the real supervisor testable without real waits.
function Get-GephTunHealthClock { return [DateTime]::UtcNow }
function New-GephTunOutageClock { return [Diagnostics.Stopwatch]::StartNew() }
function Wait-GephTunProbeRetry {
    for ($slice = 0; $slice -lt 4; $slice++) {
        Assert-GephTunIntentContinuing
        [Threading.Thread]::Sleep(250)
    }
}
