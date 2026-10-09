# GephTun 1.5.0. Dot-sourced by Core. No automatic recovery service.
$script:ProtectionLease = $null
$script:ProtectionObserved = 'Unknown'
$script:ProtectionCheckedUtc = $null

function Initialize-GephTunWfpTypes {
    if (-not ('GephTun.Security.WfpController' -as [type])) {
        Add-Type -Path (Join-Path $script:PackageRoot 'GephTun.Wfp.cs') -ErrorAction Stop
    }
    [GephTun.Security.WfpController]::AssertLayout()
}

function Get-GephTunProtectionStatus {
    try {
        Initialize-GephTunWfpTypes
        $result = [GephTun.Security.WfpController]::Inspect()
        $script:ProtectionObserved = [string]$result.State
        $script:ProtectionCheckedUtc = [DateTime]::UtcNow.ToString('o')
        return $result
    }
    catch {
        $script:ProtectionObserved = 'Unknown'
        $script:ProtectionCheckedUtc = [DateTime]::UtcNow.ToString('o')
        return [pscustomobject]@{ State='Unknown'; Detail=$_.Exception.Message; PersistentFilters=0; TemporaryFilters=0 }
    }
}

function Get-GephTunTransportCandidates {
    # Discovery only, NOT approval. The GUI shows these exact paths for consent.
    $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.LocalAddress -in @('127.0.0.1','0.0.0.0') })
    $processes = @(Get-CimInstance Win32_Process -Filter "Name LIKE 'geph%'" -ErrorAction Stop | Where-Object {
        $_.ExecutablePath -and ([IO.Path]::GetFileNameWithoutExtension($_.ExecutablePath) -match '^geph(?:[-_0-9a-z.]*)$')
    })
    $owners = @($processes | Where-Object { [int]$_.ProcessId -in @($listeners | ForEach-Object { [int]$_.OwningProcess }) })
    $directories = @($owners | ForEach-Object { [IO.Path]::GetDirectoryName($_.ExecutablePath) } | Sort-Object -Unique)
    if ($directories.Count -ne 1) { throw 'Start one Geph installation in local-proxy mode first. Its exact executables must be reviewed before enabling protection.' }
    $paths = @($processes | Where-Object { [IO.Path]::GetDirectoryName($_.ExecutablePath) -eq $directories[0] } | ForEach-Object { [string]$_.ExecutablePath } | Sort-Object -Unique)
    if ($paths.Count -lt 1 -or $paths.Count -gt 8) { throw 'A bounded Geph executable list could not be identified.' }
    return $paths
}

function Get-GephTunProtectionConfiguration {
    $config = Read-GephTunJson (Join-Path (Get-GephTunRoot) 'protection.json')
    if ($null -eq $config -or $config.Schema -ne 1 -or @($config.TrustedImages).Count -lt 1 -or @($config.TrustedImages).Count -gt 8) {
        throw 'Configure the WFP kill switch first using Protection-GephTun.cmd or the tray Enable protection command.'
    }
    foreach ($image in @($config.TrustedImages)) {
        if ($image.Path -isnot [string] -or -not [IO.Path]::IsPathRooted($image.Path) -or $image.Sha256 -cnotmatch '^[a-fA-F0-9]{64}$' -or
            [IO.Path]::GetFileNameWithoutExtension($image.Path) -notmatch '^geph(?:[-_0-9a-z.]*)$') { throw 'Invalid approved Geph executable record.' }
    }
    return $config
}

function Enable-GephTunProtection([string[]]$GephExecutable, [switch]$AllowBlocking) {
    if (-not $AllowBlocking) { throw 'Enabling persistent blocking requires explicit confirmation.' }
    $mutex = Get-GephTunLock
    try {
        if (Test-Path -LiteralPath (Join-Path (Get-GephTunRoot) 'session.json')) { throw 'Finish Disconnect / Recover before changing protection.' }
        $images = @()
        foreach ($path in @($GephExecutable | Sort-Object -Unique)) {
            $full = [IO.Path]::GetFullPath($path)
            Assert-GephTunPlainPath $full
            if ([IO.Path]::GetFileNameWithoutExtension($full) -notmatch '^geph(?:[-_0-9a-z.]*)$' -or [IO.Path]::GetExtension($full) -ne '.exe') {
                throw 'Only explicitly reviewed Geph executables may receive transport permissions.'
            }
            if (-not [IO.File]::Exists($full)) { throw ('Geph executable is missing: ' + $full) }
            $images += [pscustomobject]@{ Path=$full; Sha256=(Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant() }
        }
        if ($images.Count -lt 1 -or $images.Count -gt 8) { throw 'Review between one and eight exact Geph executables.' }
        Initialize-GephTunWfpTypes
        # Save durable intent before installing filters. A failed install never claims protection.
        $config = [ordered]@{ Schema=1; Requested='Enabled'; TrustedImages=$images; ApprovedUtc=[DateTime]::UtcNow.ToString('o'); Version='1.5.0' }
        Write-GephTunJson (Join-Path (Get-GephTunRoot) 'protection.json') $config
        [GephTun.Security.WfpController]::Enable()
        $status = Get-GephTunProtectionStatus
        if ($status.State -ne 'Enabled') { throw ('WFP policy could not be verified: ' + $status.Detail) }
        Write-GephTunLog 'WFP protection enabled. Disconnect, tray Exit, controller failure and reboot do NOT unlock it. Use Disable protection explicitly for direct internet.'
        Set-GephTunStatus 'Disconnected' 'Disconnected; WFP protection is enabled. Choose Connect for a protected session, or explicitly Disable protection for direct internet.'
        return $status
    } finally { Release-GephTunLock $mutex }
}

function Disable-GephTunProtection([switch]$AllowDirectInternet) {
    if (-not $AllowDirectInternet) { throw 'Explicit confirmation to allow direct internet is required.' }
    # Normal unlock requires completed recovery. No force-kill or blanket firewall reset.
    Request-GephTunDisconnect
    $mutex = Get-GephTunLock
    try {
        if (Test-Path -LiteralPath (Join-Path (Get-GephTunRoot) 'session.json')) { throw 'Recovery is incomplete; protection was retained.' }
        Initialize-GephTunWfpTypes
        [GephTun.Security.WfpController]::Disable($true)
        $configPath = Join-Path (Get-GephTunRoot) 'protection.json'
        $config = Read-GephTunJson $configPath
        if ($null -ne $config) { $config.Requested='Disabled'; Write-GephTunJson $configPath $config }
        $status = Get-GephTunProtectionStatus
        if ($status.State -ne 'Disabled') { throw 'The explicit unlock could not be verified.' }
        Write-GephTunLog 'WFP protection explicitly disabled by the user. Ordinary direct internet is permitted by GephTun.'
        Set-GephTunStatus 'Disconnected' 'Disconnected; protection explicitly disabled. Ordinary direct internet is allowed.'
        return $status
    } finally { Release-GephTunLock $mutex }
}

function Open-GephTunProtectionLease {
    if ($null -ne $script:ProtectionLease) { throw 'A WFP permission lease is already active.' }
    $config = Get-GephTunProtectionConfiguration
    if ($config.Requested -ne 'Enabled') { throw 'Enable protection before connecting. This version refuses an unprotected tunnel session.' }
    $status = Get-GephTunProtectionStatus
    if ($status.State -ne 'Enabled') { throw ('The persistent WFP policy is not verified: ' + $status.Detail) }
    $images = @($config.TrustedImages | ForEach-Object {
        Assert-GephTunPlainPath $_.Path
        $item = New-Object GephTun.Security.TrustedImage
        $item.Path=[string]$_.Path; $item.Sha256=[string]$_.Sha256; $item
    })
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { $_.HardwareInterface -and $_.Status -eq 'Up' })
    if ($adapters.Count -eq 0) { Throw-GephTunTransient 'NETWORK_UNAVAILABLE' 'No active physical adapter is available for Geph bootstrap.' }
    [ulong[]]$luids = @($adapters | ForEach-Object { [GephTun.Security.WfpController]::InterfaceLuid($_.InterfaceGuid.ToString()) })
    $script:ProtectionLease = [GephTun.Security.WfpController]::OpenLease([GephTun.Security.TrustedImage[]]$images, $luids)
    $script:ProtectionObserved='Enabled'
    Write-GephTunLog 'Temporary exact-image Geph TCP permissions opened on verified physical interfaces. The persistent blocker remains installed.'
}

function Close-GephTunProtectionLease {
    if ($null -ne $script:ProtectionLease) {
        $script:ProtectionLease.Dispose()
        $script:ProtectionLease=$null
    }
}

function Remove-GephTunTunnelPermission {
    if ($null -ne $script:ProtectionLease) {
        try { $script:ProtectionLease.RevokeTunnel() }
        catch {
            $failure=$_.Exception.Message
            # Losing all temporary permissions is safer than retaining an obsolete tunnel permit.
            Close-GephTunProtectionLease
            throw ('Tunnel permission could not be revoked individually; the temporary session was closed. '+$failure)
        }
    }
}

function Add-GephTunTunnelPermission {
    if ($null -eq $script:ProtectionLease) { throw 'No live WFP permission lease owns the session.' }
    $adapter=Get-NetAdapter -InterfaceIndex $script:Session.TunnelInterfaceIndex -IncludeHidden -ErrorAction Stop
    if ($adapter.InterfaceGuid.ToString() -ne $script:Session.TunnelInterfaceGuid) { throw 'The tunnel adapter identity changed before WFP authorization.' }
    $luid=[GephTun.Security.WfpController]::InterfaceLuid($adapter.InterfaceGuid.ToString())
    $script:ProtectionLease.AuthorizeTunnel($luid)
}

function Assert-GephTunProtection {
    if ($null -eq $script:ProtectionLease) { throw 'WFP permission ownership is missing; the session must stop.' }
    try { $script:ProtectionLease.Verify(); $script:ProtectionObserved='Enabled'; $script:ProtectionCheckedUtc=[DateTime]::UtcNow.ToString('o') }
    catch {
        $script:ProtectionObserved='Unknown'
        Close-GephTunProtectionLease
        throw ('WFP protection could not be verified. Temporary permissions were closed; manual attention is required. ' + $_.Exception.Message)
    }
}

function Assert-GephTunApprovedProxy($Identity) {
    $config=Get-GephTunProtectionConfiguration
    if (@($config.TrustedImages | Where-Object { [string]::Equals($_.Path,$Identity.Path,[StringComparison]::OrdinalIgnoreCase) }).Count -ne 1) {
        throw 'This Geph proxy executable was not explicitly approved for WFP bootstrap. Review protection configuration before connecting.'
    }
}
