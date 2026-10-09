#Requires -Version 5.1
# Standalone boot recovery. This copy can run as SYSTEM without the app folder.
# Unknown ownership, unreadable providers, or failed cleanup keep recovery armed.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$root = Join-Path ([Environment]::GetEnvironmentVariable('ProgramData')) 'GephTun'
$logDir = Join-Path $root 'logs'
$logPath = Join-Path $logDir 'boot-reconcile.log'

function Write-BootLog([string]$Message) {
    try {
        [void][IO.Directory]::CreateDirectory($logDir)
        Add-Content -LiteralPath $logPath -Value ('{0}  {1}' -f [DateTime]::UtcNow.ToString('o'), $Message) -ErrorAction Stop
    } catch { }
}

function New-BootSessionMutex {
    # Connect holds this same mutex for its whole session, including recovery.
    return (New-Object Threading.Mutex($false, 'Global\GephTun-Session-v1'))
}

function ConvertTo-GephTunProcessStartUtc($Value) {
    if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime }
    if ($Value -is [DateTime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) { throw 'Process timestamp has no verified timezone.' }
        return $Value.ToUniversalTime()
    }
    if ($Value -isnot [string] -or $Value -cnotmatch '\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})\z') {
        throw 'Process timestamp must be an exact ISO timestamp with a timezone.'
    }
    return [DateTimeOffset]::Parse($Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None).UtcDateTime
}

function Get-GephTunBootTaskExecutable {
    if ([string]::IsNullOrWhiteSpace($env:SystemRoot)) { throw 'Windows system directory is unknown.' }
    return (Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe')
}

function Assert-GephTunBootTaskOwned($Task, [string]$StateScript) {
    if ($null -eq $Task -or $Task.TaskName -cne 'GephTunBootReconcile' -or $Task.TaskPath -cne '\' -or
        @($Task.Actions).Count -ne 1) { throw 'Recovery task ownership is unknown; task and script retained.' }
    $action=@($Task.Actions)[0]
    $expected=Get-GephTunBootTaskExecutable
    $arguments='-NoProfile -ExecutionPolicy Bypass -File "' + $StateScript + '"'
    if (-not [string]::Equals([string]$action.Execute,$expected,[StringComparison]::OrdinalIgnoreCase) -or
        [string]$action.Arguments -cne $arguments -or
        -not [string]::IsNullOrEmpty([string]$action.WorkingDirectory) -or
        [string]$Task.Principal.UserId -notin @('SYSTEM','S-1-5-18','NT AUTHORITY\SYSTEM') -or
        [string]$Task.Principal.LogonType -ne 'ServiceAccount' -or
        [string]$Task.Principal.RunLevel -ne 'Highest') {
        throw 'Recovery task action or principal is foreign or unreadable; task and script retained.'
    }
}

function Get-BootWorkerState($Worker) {
    if ($null -eq $Worker -or -not $Worker.PSObject.Properties['Id'] -or
        -not $Worker.PSObject.Properties['StartUtc'] -or
        -not $Worker.PSObject.Properties['Path']) { return 'UNKNOWN' }
    $process = $null
    try {
        if ([int]$Worker.Id -lt 1 -or [string]::IsNullOrWhiteSpace([string]$Worker.StartUtc) -or
            [string]::IsNullOrWhiteSpace([string]$Worker.Path)) { return 'UNKNOWN' }
        $expected = ConvertTo-GephTunProcessStartUtc $Worker.StartUtc
        try { $process = Get-Process -Id ([int]$Worker.Id) -ErrorAction Stop }
        catch {
            $cause = $_.Exception.GetBaseException()
            if ($cause -is [ArgumentException] -or $_.CategoryInfo.Category -eq 'ObjectNotFound') { return 'DEAD' }
            return 'UNKNOWN'
        }
        if ($null -eq $process) { return 'UNKNOWN' }
        if ([string]::IsNullOrWhiteSpace([string]$process.Path) -or $null -eq $process.StartTime) { return 'UNKNOWN' }
        if ([string]$process.ProcessName -notin @('powershell','pwsh') -or
            (ConvertTo-GephTunProcessStartUtc $process.StartTime).Ticks -ne $expected.Ticks -or
            -not [string]::Equals([string]$process.Path, [string]$Worker.Path, [StringComparison]::OrdinalIgnoreCase)) {
            return 'DEAD'
        }
        return 'ALIVE'
    } catch { return 'UNKNOWN' }
    finally { if ($process -is [IDisposable]) { $process.Dispose() } }
}

function Get-BootSession {
    $path = Join-Path $root 'session.json'
    # File.Exists hides access failures as absence. Only a confirmed missing
    # file may mean that there is no journal; other errors propagate.
    try {
        $attributes = [IO.File]::GetAttributes($path)
        if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'The recovery journal is redirected.' }
    } catch {
        $cause = $_.Exception.GetBaseException()
        if ($cause -is [IO.FileNotFoundException] -or $cause -is [IO.DirectoryNotFoundException]) { return $null }
        throw
    }
    $session = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($null -eq $session -or -not $session.PSObject.Properties['Schema'] -or $session.Schema -notin @(1,2) -or -not $session.PSObject.Properties['Token'] -or
        [string]$session.Token -cnotmatch '\A[a-f0-9]{32}\z' -or -not $session.PSObject.Properties['Worker']) {
        throw 'The recovery journal does not establish session ownership.'
    }
    return $session
}

function Get-BootNrptRules {
    for ($attempt = 1; $attempt -le 6; $attempt++) {
        try { return @(Get-DnsClientNrptRule -ErrorAction Stop) }
        catch {
            if ($attempt -eq 6) { throw }
            Start-Sleep -Seconds 5
        }
    }
}

function Get-BootFirewallRules {
    for ($attempt = 1; $attempt -le 6; $attempt++) {
        # Enumerate the store, then filter ownership. A wildcard lookup that
        # throws "not found" must not hide an unavailable firewall provider.
        try { return @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop) }
        catch {
            if ($attempt -eq 6) { throw }
            Start-Sleep -Seconds 5
        }
    }
}

function Get-BootOwnedNrpt($Rules, $LiveTokens) {
    foreach ($rule in @($Rules)) {
        $comment = [string]$rule.Comment
        if ($comment -cmatch '\AGephTun:([a-f0-9]{32})\z' -and -not $LiveTokens.ContainsKey($Matches[1])) { $rule }
    }
}

function Get-BootOwnedFirewall($Rules, $LiveTokens) {
    foreach ($rule in @($Rules)) {
        $name = [string]$rule.Name
        if ($name -cmatch '\AGephTun-IPv6-Contain-([a-f0-9]{32})\z' -and -not $LiveTokens.ContainsKey($Matches[1])) { $rule }
    }
}

$mutex = $null
$taken = $false
try {
    $mutex = New-BootSessionMutex
    try { $taken = $mutex.WaitOne(0) }
    catch {
        # PowerShell can wrap native method failures; inspect the actual cause.
        if ($_.Exception.GetBaseException() -is [Threading.AbandonedMutexException]) { $taken = $true }
        else { throw }
    }
    if (-not $taken) {
        Write-BootLog 'A session owns the recovery mutex; keeping the task and script armed.'
        return
    }
    $liveTokens = @{}
    $session = Get-BootSession
    if ($null -ne $session) {
        $workerState = Get-BootWorkerState $session.Worker
        if ($workerState -eq 'UNKNOWN') { throw 'Worker identity is unreadable or incomplete; keeping recovery armed.' }
        if ($workerState -eq 'ALIVE') { $liveTokens[[string]$session.Token] = $true }
    }
    # Both providers must be readable before the first removal is attempted.
    $nrpt = @(Get-BootOwnedNrpt @(Get-BootNrptRules) $liveTokens)
    $firewall = @(Get-BootOwnedFirewall @(Get-BootFirewallRules) $liveTokens)
    $failed = $false
    foreach ($rule in $nrpt) {
        try {
            Remove-DnsClientNrptRule -Name $rule.Name -Force -ErrorAction Stop
            Write-BootLog ('Removed stale DNS policy ' + $rule.Name)
        } catch { $failed = $true; Write-BootLog ('DNS policy removal failed: ' + $_.Exception.Message) }
    }
    foreach ($rule in $firewall) {
        try {
            Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
            Write-BootLog ('Removed stale IPv6 containment ' + $rule.Name)
        } catch { $failed = $true; Write-BootLog ('Containment removal failed: ' + $_.Exception.Message) }
    }
    $remainingNrpt = @(Get-BootOwnedNrpt @(Get-BootNrptRules) $liveTokens)
    $remainingFirewall = @(Get-BootOwnedFirewall @(Get-BootFirewallRules) $liveTokens)
    if ($failed -or $remainingNrpt.Count -ne 0 -or $remainingFirewall.Count -ne 0) {
        throw 'Owned cleanup is not confirmed complete; keeping the task and script armed.'
    }
    if ($liveTokens.Count -ne 0) {
        Write-BootLog 'Stale cleanup verified; a live session keeps its recovery task and script.'
        return
    }
    if ($null -ne $session -and $session.PSObject.Properties['Containment'] -and
        $null -ne $session.Containment -and $session.Containment.PSObject.Properties['Profiles'] -and
        @($session.Containment.Profiles).Count -gt 0) {
        throw 'A legacy session changed global firewall profiles. Open GephTun and choose Disconnect / Recover; boot cleanup will not guess whether an administrator changed those profiles.'
    }
    $ownedTasks=@()
    try { $ownedTasks=@(Get-ScheduledTask -TaskName 'GephTunBootReconcile' -TaskPath '\' -ErrorAction Stop) }
    catch { if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { throw } }
    if ($ownedTasks.Count -gt 1) { throw 'Recovery task identity is ambiguous.' }
    foreach ($task in $ownedTasks) { Assert-GephTunBootTaskOwned $task (Join-Path $root 'GephTun-BootReconcile.ps1') }
    try { if ($ownedTasks.Count -eq 1) { Unregister-ScheduledTask -TaskName 'GephTunBootReconcile' -TaskPath '\' -Confirm:$false -ErrorAction Stop } }
    catch { if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { throw } }
    $tasks = @()
    try { $tasks = @(Get-ScheduledTask -TaskName 'GephTunBootReconcile' -TaskPath '\' -ErrorAction Stop) }
    catch { if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { throw } }
    if ($tasks.Count -ne 0) { throw 'The startup recovery task is still present; keeping its script.' }
    # Never delete the installed script. Only the protected state-tree copy
    # self-deletes, after both owned policy and task absence are verified.
    if ([IO.Path]::GetDirectoryName($PSCommandPath) -ieq $root) { [IO.File]::Delete($PSCommandPath) }
    Write-BootLog 'Owned policy and task absence verified; boot reconciliation completed.'
} catch {
    Write-BootLog ('Recovery could not be confirmed; retained recovery files where possible: ' + $_.Exception.Message)
} finally {
    if ($null -ne $mutex) {
        try { if ($taken) { $mutex.ReleaseMutex() } } catch { Write-BootLog ('Mutex release failed: ' + $_.Exception.Message) }
        try { $mutex.Dispose() } catch { Write-BootLog ('Mutex disposal failed: ' + $_.Exception.Message) }
    }
}
