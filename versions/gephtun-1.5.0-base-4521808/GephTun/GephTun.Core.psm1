# GephTun 1.5.0 - Windows PowerShell 5.1
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:PackageRoot = $PSScriptRoot
$script:Session = $null
$script:Relay = $null
$script:ConnectContext = $null
$script:ContainmentSecurityBaseline = $null
. (Join-Path $PSScriptRoot 'GephTun.Resilience.ps1')
. (Join-Path $PSScriptRoot 'GephTun.Protection.ps1')
. (Join-Path $PSScriptRoot 'GephTun.Bypasses.ps1')

function Assert-GephTunConnectContinuing {
    Assert-GephTunIntentContinuing
    # Cooperative cancellation never terminates the controller in the middle of a
    # journaled mutation. The next checkpoint enters the ordinary recovery path.
    if ($null -eq $script:ConnectContext) { return }
    if ([DateTime]::UtcNow -ge $script:ConnectContext.DeadlineUtc) {
        throw 'Connection setup exceeded 120 seconds. Saved network changes will be restored.'
    }
    if ($null -ne $script:ConnectContext.Owner -and -not (Test-GephTunProcessIdentity $script:ConnectContext.Owner)) {
        throw 'The interface closed during connection setup. Saved network changes will be restored.'
    }
    if ($script:ConnectContext.CancelPath -and (Test-Path -LiteralPath $script:ConnectContext.CancelPath)) {
        $cancel = Read-GephTunJson $script:ConnectContext.CancelPath
        if ($null -ne $cancel -and $cancel.PSObject.Properties['Token'] -and $cancel.Token -eq $script:ConnectContext.Token) {
            throw 'Connection cancelled. Saved network changes will be restored.'
        }
    }
    if ($null -ne $script:Session) {
        $request = Join-Path (Get-GephTunRoot) 'disconnect.json'
        if (Test-Path -LiteralPath $request) {
            $stop = Read-GephTunJson $request
            if ($null -ne $stop -and $stop.PSObject.Properties['Token'] -and $stop.Token -eq $script:Session.Token) {
                throw 'Connection cancelled. Saved network changes will be restored.'
            }
        }
    }
}

function Assert-GephTunWindows {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess -or
        $env:PROCESSOR_ARCHITECTURE -ne 'AMD64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') {
        throw 'GephTun requires 64-bit Windows and 64-bit Windows PowerShell.'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'Open Launch-GephTun.cmd and approve the Windows administrator prompt.'
        }
    } finally {
        # This check runs at every worker start. Release the native token handle
        # immediately instead of waiting for finalization on long-lived sessions.
        if ($identity -is [IDisposable]) { $identity.Dispose() }
    }
}

function Get-GephTunRoot { Join-Path $env:ProgramData 'GephTun' }

function Get-GephTunFileAttributes([string]$Path) {
    # Query the filesystem directly. During native atomic replacement the
    # PowerShell provider can expose a disappearing/stale FileSystemInfo object.
    [IO.File]::GetAttributes($Path)
}

function Get-GephTunIoFailureKind([Exception]$Exception) {
    # PowerShell wraps exceptions from .NET method calls. Inspect the cause for
    # classification, but rethrow the original error record at the call site.
    $cause = $Exception.GetBaseException()
    if ($cause -is [IO.FileNotFoundException] -or $cause -is [IO.DirectoryNotFoundException]) { return 'Missing' }
    if ($cause -is [IO.IOException] -and ($cause.HResult -band 65535) -in @(32, 33)) { return 'SharingViolation' }
    return 'Other'
}

function Assert-GephTunPlainPath([string]$Path, [ValidateRange(1, 6)][int]$Attempts = 6) {
    for ($attempt = 0; $attempt -lt $Attempts; $attempt++) {
        try {
            $attributes = Get-GephTunFileAttributes $Path
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                # A later plain/missing observation cannot make an observed
                # redirection trustworthy. Never retry away this refusal.
                throw "Refusing a redirected file or directory: $Path"
            }
            return
        } catch {
            $kind = Get-GephTunIoFailureKind $_.Exception
            if ($kind -eq 'Missing') { return }
            if ($kind -ne 'SharingViolation' -or $attempt -eq ($Attempts - 1)) { throw }
            [Threading.Thread]::Sleep(60)
        }
    }
}

function Initialize-GephTunStorage {
    Assert-GephTunWindows
    $root = Get-GephTunRoot
    Assert-GephTunPlainPath $env:ProgramData
    Assert-GephTunPlainPath $root
    $admins = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner($admins)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($admins, $system)) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    if (Test-Path -LiteralPath $root) {
        # Validate the tree observed by this branch before normalization can
        # erase evidence of earlier untrusted writes, including a root that
        # appeared concurrently during setup.
        Assert-GephTunStorageTreePermissions $root
        $owner = (Get-Acl -LiteralPath $root).GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin @($admins.Value, $system.Value)) {
            throw 'The GephTun settings folder has an unexpected owner. An administrator must review its ownership and permissions, preserving the session journal and recovery state.'
        }
        Set-Acl -LiteralPath $root -AclObject $acl
    } else {
        $dir = New-Object IO.DirectoryInfo($root)
        $dir.Create($acl)
    }
    # Create(ACL) is a no-op if a concurrent creator supplied the directory.
    # Verify its entire resulting tree before changing existing child paths.
    Assert-GephTunStorageTreePermissions $root
    foreach ($name in @('logs', 'results', 'ui-requests')) {
        $path = Join-Path $root $name
        Assert-GephTunPlainPath $path
        if (-not (Test-Path -LiteralPath $path)) { [IO.Directory]::CreateDirectory($path) | Out-Null }
        Set-Acl -LiteralPath $path -AclObject $acl
    }
    $logsPath = Join-Path $root 'logs'
    $logsAcl = Get-Acl -LiteralPath $logsPath
    $readerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $logsAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($readerSid, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    Set-Acl -LiteralPath $logsPath -AclObject $logsAcl
    # Resetting directory inheritance cannot remove an explicit write grant on
    # a pre-existing state file. Refuse unsafe contents before reading status,
    # journals, cancellation requests, or operation results from this tree.
    Assert-GephTunStorageTreePermissions $root
    if (-not (Test-Path -LiteralPath (Join-Path $root 'status.json'))) {
        Write-GephTunJson (Join-Path $root 'status.json') (Get-GephTunStatus)
    }
}

function Assert-GephTunRequestPathPermissions([string]$Path) {
    Assert-GephTunPlainPath $Path
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $trustedOwners = @('S-1-5-32-544', 'S-1-5-18')
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trustedOwners) {
        throw "The GephTun state path has an untrusted owner. An administrator must review its ownership and permissions, preserving any session journal and recovery state: $Path"
    }
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    # A null DACL grants everyone access and yields no ACEs. An empty DACL is
    # also unusable for this channel; both require review rather than trust.
    if ($rules.Count -eq 0) { throw "The GephTun state path has an unverifiable DACL. An administrator must review its permissions, preserving any session journal and recovery state: $Path" }
    $writeRights = [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $rules) {
        if ([string]$rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $trustedOwners -and
            (($rule.FileSystemRights -band $writeRights) -ne 0)) {
            throw "The GephTun state path allows writes without administrator permissions. An administrator must review its permissions, preserving any session journal and recovery state: $Path"
        }
    }
}

function Assert-GephTunStorageTreePermissions([string]$Path) {
    $pending = New-Object 'Collections.Generic.Stack[string]'
    $pending.Push($Path)
    while ($pending.Count -gt 0) {
        $current = $pending.Pop()
        try {
            Assert-GephTunRequestPathPermissions $current
            $attributes = Get-GephTunFileAttributes $current
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Refusing a redirected file or directory: $current" }
            if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) {
                foreach ($child in [IO.Directory]::GetFileSystemEntries($current)) { $pending.Push($child) }
            }
        } catch {
            # Atomic status/result writes remove their temporary child files.
            # A disappearing descendant of a validated parent is harmless;
            # unreadable files, redirected paths and a missing root still fail.
            $missing = $_.Exception -is [Management.Automation.ItemNotFoundException] -or
                (Get-GephTunIoFailureKind $_.Exception) -eq 'Missing'
            if ($current -ne $Path -and $missing) {
                # Test-Path can turn a provider failure into false. Only another
                # typed filesystem absence can justify skipping this descendant.
                try { Get-GephTunFileAttributes $current | Out-Null }
                catch {
                    if ((Get-GephTunIoFailureKind $_.Exception) -eq 'Missing') { continue }
                    throw
                }
                # RACE FIX 1.3.7 (native 2026-09-17 finding): the confirm read
                # succeeding proves the earlier miss was replacement churn, not
                # a stable absence, so this scan round skips the entry instead
                # of rethrowing the stale transient failure. The parent was
                # already validated; per-request permission checks still gate
                # every specific write, and the next scan re-validates the node.
                continue
            }
            throw
        }
    }
}

function Initialize-GephTunRequestDirectory([ValidateRange(0, 2147483647)][int]$SessionId) {
    Assert-GephTunWindows
    $root = Get-GephTunRoot
    $parent = Join-Path $root 'ui-requests'
    Assert-GephTunRequestPathPermissions $root
    Assert-GephTunRequestPathPermissions $parent
    $path = Join-Path $parent ([string]$SessionId)
    if (-not (Test-Path -LiteralPath $path -ErrorAction Stop)) {
        # Create with the validated parent's owner and DACL from the first
        # instant; applying ACLs after Directory.CreateDirectory leaves a gap.
        $acl = Get-Acl -LiteralPath $parent -ErrorAction Stop
        $acl.SetAccessRuleProtection($true, $true)
        $directory = New-Object IO.DirectoryInfo($path)
        $directory.Create($acl)
    }
    # Existing explicit child/file ACEs survive a parent's ACL reset. Check
    # them before consuming requests, without legitimizing untrusted contents
    # through a broad permissions rewrite. Never traverse a redirected child.
    Assert-GephTunStorageTreePermissions $path
    if (-not (Get-Item -LiteralPath $path -Force -ErrorAction Stop).PSIsContainer) { throw 'The launcher request path is not a directory.' }
    return $path
}

function Write-GephTunJson([string]$Path, $Value) {
    Assert-GephTunPlainPath $Path
    Assert-GephTunPlainPath (Split-Path -Parent $Path)
    $temporary = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    $operationError = $null
    try {
        $json = ConvertTo-Json -InputObject $Value -Depth 14
        [IO.File]::WriteAllText($temporary, $json, (New-Object Text.UTF8Encoding($false)))
        # RACE FIX 1.3.7 (F-1 family, writer side): native acceptance on
        # 2026-09-17 recorded the provider plus real-time file filtering
        # holding a destination across ~50 consecutive replacement attempts
        # ("Unable to remove the file to be replaced."). A single publish
        # attempt can therefore fail transiently, so the atomic publish is
        # retried within the same bounded budget the readers use. A sustained
        # failure rethrows the original error record — the update is never
        # silently lost, and classification by exception identity is preserved.
        $lastError = $null
        $published = $false
        for ($attempt = 0; $attempt -lt 6 -and -not $published; $attempt++) {
            if ($attempt -gt 0) { [Threading.Thread]::Sleep(60) }
            try {
                if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temporary, $Path, [System.Management.Automation.Language.NullString]::Value) }
                else { [IO.File]::Move($temporary, $Path) }
                $published = $true
            } catch [IO.IOException] { $lastError = $_ }
        }
        if (-not $published) { throw $lastError }
    } catch {
        # Keep the publish failure available to the caller. Cleanup below must
        # never turn a meaningful replace/move error into a provider error.
        $operationError = $_
        throw
    } finally {
        try {
            # Use the .NET filesystem directly: a PowerShell provider query can
            # observe the same transient replacement gap as the writer itself.
            # File.Delete treats an already-published/missing temp path as a
            # no-op, while still surfacing permission and other I/O failures.
            [IO.File]::Delete($temporary)
        } catch {
            # A cleanup failure is actionable when the write otherwise succeeded,
            # but it must not mask the original publish failure or its identity.
            if ($null -eq $operationError) { throw }
        }
    }
}

function Open-GephTunJsonSnapshot([string]$Path) {
    # Pin one snapshot without blocking atomic replacement by the writer.
    $share = [IO.FileShare]::Read -bor [IO.FileShare]::Write -bor [IO.FileShare]::Delete
    [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, $share)
}

function Read-GephTunJson([string]$Path) {
    $lastSharingError = $null
    for ($attempt = 0; $attempt -lt 6; $attempt++) {
        $stream = $null; $reader = $null
        try {
            # Each attempt repeats the redirection check. Test-Path followed by
            # provider Get-Item can misclassify an atomic replacement on Windows;
            # opening directly gives typed absence/denial instead.
            Assert-GephTunPlainPath $Path -Attempts 1
            $stream = Open-GephTunJsonSnapshot $Path
            $reader = New-Object IO.StreamReader($stream, [Text.Encoding]::UTF8, $true)
            $json = $reader.ReadToEnd()
        } catch {
            $kind = Get-GephTunIoFailureKind $_.Exception
            if ($kind -notin @('Missing', 'SharingViolation')) { throw }
            if ($kind -eq 'SharingViolation') { $lastSharingError = $_ }
            if ($attempt -eq 5) {
                # Only an entirely missing sequence means no document. An
                # unresolved sharing failure must not become a clean-state claim.
                if ($null -ne $lastSharingError) { throw $lastSharingError }
                return $null
            }
            [Threading.Thread]::Sleep(60)
            continue
        } finally {
            if ($null -ne $reader) { $reader.Dispose() }
            elseif ($null -ne $stream) { $stream.Dispose() }
        }
        # Existing blank/null/scalar/array files are corrupt state, not absence.
        # All controller documents have an object root; preserve invalid journals
        # for review before any recovery mutation or success publication.
        if ([string]::IsNullOrWhiteSpace($json) -or -not $json.TrimStart().StartsWith('{')) {
            throw "The JSON file must contain one object; the existing file was preserved: $Path"
        }
        # 1.3.8 (D-004): Windows PowerShell 5.1 ConvertFrom-Json rejects inputs
        # over ~2 MB. A journal that grew past that limit must fail with this
        # explicit, reviewable error instead of a raw parser failure, and the
        # oversized file is preserved untouched.
        if ($json.Length -gt 2000000) {
            throw "The JSON document exceeds the 2 MB Windows PowerShell 5.1 limit and was preserved for administrative review: $Path"
        }
        # PowerShell 7.5+ otherwise coerces ISO strings to DateTime, changing
        # process-identity comparisons after a journal round trip. Windows
        # PowerShell 5.1 preserves these strings and has no DateKind parameter.
        if ($PSVersionTable.PSVersion -ge [version]'7.5') { $value = ConvertFrom-Json -InputObject $json -DateKind String }
        else { $value = ConvertFrom-Json -InputObject $json }
        if ($null -eq $value -or $value -isnot [pscustomobject]) {
            throw "The JSON file must contain one object; the existing file was preserved: $Path"
        }
        return $value
    }
}

function Write-GephTunLog([string]$Message) {
    $path = Join-Path (Get-GephTunRoot) 'logs\GephTun.log'
    Assert-GephTunPlainPath $path
    if ((Test-Path -LiteralPath $path) -and (Get-Item -LiteralPath $path).Length -gt 2097152) {
        $old = $path + '.previous'
        Assert-GephTunPlainPath $old
        Move-Item -LiteralPath $path -Destination $old -Force
    }
    [IO.File]::AppendAllText($path, ('{0}  {1}{2}' -f [DateTime]::UtcNow.ToString('o'), $Message, [Environment]::NewLine))
}

function Save-GephTunSession {
    if ($null -ne $script:Session) {
        Write-GephTunJson (Join-Path (Get-GephTunRoot) 'session.json') $script:Session
    }
}

function Set-GephTunStatus([string]$Status, [string]$Message) {
    if ($Status -eq 'Disconnected' -and $script:ProtectionObserved -eq 'Enabled') { $Message += ' WFP protection remains enabled; direct application internet stays blocked.' }
    $s = $script:Session
    $worker = Get-GephTunProcessIdentity $PID
    $value = [ordered]@{
        ProtectionState = $script:ProtectionObserved; ProtectionCheckedUtc = $script:ProtectionCheckedUtc
        Status = $Status; Message = $Message; UpdatedUtc = [DateTime]::UtcNow.ToString('o')
        ProxyPort = 0; StartedUtc = $null; WorkerPid = $PID
        WorkerStartUtc = $worker.StartUtc
        LogPath = (Join-Path (Get-GephTunRoot) 'logs\GephTun.log')
    }
    if ($null -ne $s) { $value.ProxyPort = $s.ProxyPort; $value.StartedUtc = $s.StartedUtc }
    elseif ($null -ne $script:ConnectionIntent) { $value.ProxyPort = $script:ConnectionIntent.Port }
    Write-GephTunJson (Join-Path (Get-GephTunRoot) 'status.json') $value
    try { Write-GephTunLog "$Status - $Message" } catch { }
}

function Get-GephTunProcessIdentity([int]$ProcessId) {
    $p = Get-Process -Id $ProcessId -ErrorAction Stop
    try {
        [pscustomobject]@{ Id = $p.Id; StartUtc = $p.StartTime.ToUniversalTime().ToString('o'); Path = $p.Path }
    } finally {
        # Monitoring reads several identities each second. Release their native
        # handles immediately, including when an identity property cannot be read.
        if ($p -is [IDisposable]) { $p.Dispose() }
    }
}

function Test-GephTunProcessIdentity($Identity) {
    if ($null -eq $Identity) { return $false }
    # Process metadata can be briefly unreadable while Windows is closing or
    # reopening the process handle. Do not turn one typed sharing/access blip
    # into RecoveryRequired, but keep the check fail-closed after a small,
    # bounded retry budget. Missing processes and unclassified failures remain
    # immediate negatives; a later success still has to match all identity
    # fields exactly.
    for ($attempt = 0; $attempt -lt 3; $attempt++) {
        try {
            $p = Get-GephTunProcessIdentity ([int]$Identity.Id)
            return ($p.StartUtc -eq $Identity.StartUtc -and $p.Path -eq $Identity.Path)
        } catch {
            $cause = $_.Exception.GetBaseException()
            $transient = $cause -is [UnauthorizedAccessException] -or
                ($cause -is [IO.IOException] -and ($cause.HResult -band 65535) -in @(32, 33)) -or
                ($cause -is [ComponentModel.Win32Exception] -and $cause.NativeErrorCode -in @(5, 32, 33))
            if (-not $transient -or $attempt -eq 2) { return $false }
            [Threading.Thread]::Sleep(60)
        }
    }
    return $false
}

function Get-GephTunSessionStatus {
    $state = Read-GephTunJson (Join-Path (Get-GephTunRoot) 'status.json')
    $session = Read-GephTunJson (Join-Path (Get-GephTunRoot) 'session.json')
    $intent = Get-GephTunConnectionIntent
    if ($null -eq $session -and $null -ne $intent) {
        if (-not (Test-GephTunProcessIdentity $intent.Worker)) {
            return [pscustomobject]@{ Status = 'RecoveryRequired'; Message = 'A previous reconnect controller stopped. Choose Disconnect / Recover before reconnecting.'; ProxyPort = 0; WorkerPid = 0; WorkerStartUtc = ''; LogPath = (Join-Path (Get-GephTunRoot) 'logs\GephTun.log') }
        }
        return [pscustomobject]@{ Status = 'Reconnecting'; Message = 'The connection controller is active. WFP protection remains enabled between sessions. Disconnect cancels retries without unlocking.'; ProxyPort = $intent.Port; WorkerPid = $intent.Worker.Id; WorkerStartUtc = $intent.Worker.StartUtc; LogPath = (Join-Path (Get-GephTunRoot) 'logs\GephTun.log') }
    }
    if ($null -ne $session -and -not (Test-GephTunProcessIdentity $session.Worker)) {
        return [pscustomobject]@{ Status = 'RecoveryRequired'; Message = 'A previous session ended unexpectedly. Choose Disconnect / Recover.'; ProxyPort = $session.ProxyPort; WorkerPid = 0; WorkerStartUtc = ''; LogPath = (Join-Path (Get-GephTunRoot) 'logs\GephTun.log') }
    }
    if ($null -ne $session -and ($null -eq $state -or
        -not $state.PSObject.Properties['WorkerPid'] -or -not $state.PSObject.Properties['WorkerStartUtc'] -or
        $state.WorkerPid -ne $session.Worker.Id -or $state.WorkerStartUtc -ne $session.Worker.StartUtc -or
        $state.Status -notin @('Connecting', 'Reconnecting', 'Connected', 'Disconnecting', 'RecoveryRequired'))) {
        return [pscustomobject]@{ Status = 'RecoveryRequired'; Message = 'A saved session still requires Disconnect / Recover. Its status could not be confirmed.'; ProxyPort = $session.ProxyPort; WorkerPid = $session.Worker.Id; WorkerStartUtc = $session.Worker.StartUtc; LogPath = (Join-Path (Get-GephTunRoot) 'logs\GephTun.log') }
    }
    if ($null -ne $state) { return $state }
    [pscustomobject]@{ Status = 'Disconnected'; Message = 'Connect Geph in local-proxy mode, then choose Check.'; ProxyPort = 0; WorkerPid = 0; WorkerStartUtc = ''; LogPath = (Join-Path (Get-GephTunRoot) 'logs\GephTun.log') }
}

function Get-GephTunStatus {
    $state=Get-GephTunSessionStatus
    $protection=Get-GephTunProtectionStatus
    $state | Add-Member -NotePropertyName ProtectionState -NotePropertyValue ([string]$protection.State) -Force
    $state | Add-Member -NotePropertyName ProtectionCheckedUtc -NotePropertyValue $script:ProtectionCheckedUtc -Force
    $state | Add-Member -NotePropertyName ProtectionDetail -NotePropertyValue ([string]$protection.Detail) -Force
    return $state
}

function Initialize-GephTunNetworkTypes {
    if (-not ('GephTun.ProxyProbe' -as [type])) {
        Add-Type -Path (Join-Path $script:PackageRoot 'GephTun.Network.cs')
    }
}

function Test-GephTunBinaries {
    $manifest = Read-GephTunJson (Join-Path $script:PackageRoot 'DEPENDENCIES.json')
    if ($null -eq $manifest) { throw 'DEPENDENCIES.json is missing. Extract the complete package again.' }
    $files = @($manifest.Binaries | ForEach-Object { $_.File } | Sort-Object -Unique)
    if ($files.Count -ne 2 -or $files[0] -ne 'tun2socks-windows-amd64.exe' -or $files[1] -ne 'wintun.dll') {
        throw 'The dependency manifest must contain exactly one tunnel executable and one Wintun DLL.'
    }
    foreach ($entry in $manifest.Binaries) {
        if ($entry.File -notin @('tun2socks-windows-amd64.exe', 'wintun.dll')) { throw 'Unexpected dependency manifest entry.' }
        $path = Join-Path (Join-Path $script:PackageRoot 'bin') $entry.File
        Assert-GephTunPlainPath $path
        if (-not (Test-Path -LiteralPath $path)) { throw "Missing $($entry.File). Extract the complete package again." }
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $entry.Sha256) { throw "The checksum for $($entry.File) does not match this release. Extract the complete package again." }
        $stream = [IO.File]::OpenRead($path)
        $reader = New-Object IO.BinaryReader($stream)
        try {
            if ($reader.ReadUInt16() -ne 0x5a4d) { throw 'Invalid Windows binary.' }
            $stream.Position = 0x3c
            $offset = $reader.ReadUInt32()
            $stream.Position = $offset
            if ($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne 0x8664) {
                throw "$($entry.File) is not an AMD64 Windows binary."
            }
        } finally { $reader.Dispose(); $stream.Dispose() }
    }
    if (@($manifest.Binaries).Count -ne 2) { throw 'The dependency manifest is incomplete.' }
    $signature = Get-AuthenticodeSignature -LiteralPath (Join-Path $script:PackageRoot 'bin\wintun.dll')
    if ($signature.Status -ne 'Valid') { throw "Windows could not validate the Wintun driver signature ($($signature.Status)). Check the clock, Windows trust updates, and logs." }
}

function Get-GephTunProxy([int]$Port = 0) {
    Initialize-GephTunNetworkTypes
    $ports = @(9909, 9809, 1080, 10808, 10809)
    if ($Port -gt 0) { $ports = @($Port) }
    $failures = New-Object Collections.Generic.List[string]
    # The helper always connects to 127.0.0.1. An IPv6-only listener with the
    # same port does not establish ownership of that IPv4 endpoint.
    $available = @(Get-NetTCPConnection -ErrorAction Stop | Where-Object {
        $_.State -eq 'Listen' -and $_.LocalAddress -in @('127.0.0.1', '0.0.0.0')
    })
    foreach ($candidate in $ports) {
        Assert-GephTunConnectContinuing
        $listeners = @($available | Where-Object { $_.LocalPort -eq $candidate })
        foreach ($listener in $listeners) {
            Assert-GephTunConnectContinuing
            try {
                $identity = Get-GephTunProcessIdentity ([int]$listener.OwningProcess)
                $name = [IO.Path]::GetFileNameWithoutExtension($identity.Path)
                if ($null -ne $script:ProtectionLease) { Assert-GephTunApprovedProxy $identity }
                if ($name -notmatch '^geph(?:[-_0-9a-z.]*)$') { throw "Port $candidate belongs to $name, not an identifiable Geph process." }
                $details = [GephTun.ProxyProbe]::Test([int]$candidate)
                Assert-GephTunConnectContinuing
                if (-not (Test-GephTunProcessIdentity $identity)) { throw 'The Geph proxy process restarted during its connection check.' }
                return [pscustomobject]@{ Port = [int]$candidate; Process = $identity; Details = $details }
            } catch { $failures.Add($_.Exception.Message) }
        }
    }
    Assert-GephTunConnectContinuing
    $message = 'No working Geph SOCKS5 proxy was found. Select local-proxy mode in Geph, connect, and try again.'
    if ($failures.Count) { $message += ' ' + ($failures -join ' | ') }
    Throw-GephTunTransient 'PROXY_UNAVAILABLE' $message
}

function Get-GephTunDefaultRoutes {
    # These are observations, not permission to mutate a newly discovered route.
    # Missing CIM objects during a real Wi-Fi transition are transient too.
    try {
        $routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -PolicyStore ActiveStore -ErrorAction Stop |
            Where-Object { $_.NextHop -ne '0.0.0.0' -and $_.State -eq 'Alive' })
        $ranked = foreach ($route in $routes) {
            $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -IncludeHidden -ErrorAction Stop
            if ($null -ne $adapter -and $adapter.Status -eq 'Up' -and $adapter.HardwareInterface) {
                $ipif = Get-NetIPInterface -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop
                [pscustomobject]@{ InterfaceIndex = [int]$route.InterfaceIndex; InterfaceGuid = $adapter.InterfaceGuid.ToString(); Alias = $adapter.Name; Gateway = $route.NextHop; Cost = [int]$route.RouteMetric + [int]$ipif.InterfaceMetric }
            }
        }
        $sorted = @($ranked | Sort-Object Cost)
    }
    catch { Throw-GephTunTransient 'NETWORK_UNAVAILABLE' ('The physical gateway could not be observed: ' + $_.Exception.Message) }
    if ($sorted.Count -eq 0) { Throw-GephTunTransient 'NETWORK_UNAVAILABLE' 'No active physical IPv4 gateway was found. Waiting for Wi-Fi or Ethernet.' }
    return $sorted[0]
}

function Get-GephTunLock {
    $mutex = New-Object Threading.Mutex($false, 'Global\GephTun-Session-v1')
    $taken = $false
    try { $taken = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $taken = $true }
    if (-not $taken) { $mutex.Dispose(); throw 'Another GephTun session is already running. Use Disconnect first.' }
    return $mutex
}

function Release-GephTunLock($Mutex) {
    if ($null -ne $Mutex) { $Mutex.ReleaseMutex(); $Mutex.Dispose() }
}

function Test-GephTunPreflight([int]$Port = 0) {
    Assert-GephTunConnectContinuing
    Test-GephTunBinaries
    foreach ($command in @('Get-NetAdapter', 'Get-NetRoute', 'New-NetRoute', 'Remove-NetRoute', 'Find-NetRoute',
        'Get-NetIPAddress', 'New-NetIPAddress', 'Get-NetIPInterface', 'Set-NetIPInterface',
        'Get-NetTCPConnection', 'Get-NetUDPEndpoint', 'Get-DnsClientNrptRule', 'Get-DnsClientNrptPolicy',
        'Add-DnsClientNrptRule', 'Remove-DnsClientNrptRule', 'Set-DnsClientServerAddress',
        'Set-DnsClient', 'Clear-DnsClientCache', 'Resolve-DnsName',
        'Get-NetFirewallRule', 'New-NetFirewallRule', 'Set-NetFirewallRule', 'Remove-NetFirewallRule',
        'Get-NetFirewallAddressFilter', 'Get-NetFirewallApplicationFilter', 'Get-NetFirewallServiceFilter',
        'Get-NetFirewallPortFilter', 'Get-NetFirewallInterfaceFilter', 'Get-NetFirewallInterfaceTypeFilter',
        'Get-NetFirewallSecurityFilter',
        'Get-NetFirewallProfile', 'Set-NetFirewallProfile',
        'Disable-NetAdapterBinding',
        'Register-ScheduledTask', 'Unregister-ScheduledTask', 'Get-ScheduledTask',
        'New-ScheduledTaskAction', 'New-ScheduledTaskTrigger', 'New-ScheduledTaskPrincipal', 'New-ScheduledTaskSettingsSet')) {
        if (-not (Get-Command $command -ErrorAction SilentlyContinue)) { throw "Required Windows networking command is unavailable: $command" }
    }
    if (Test-Path -LiteralPath (Join-Path (Get-GephTunRoot) 'session.json')) {
        throw 'A session or unfinished recovery already exists. Use Disconnect / Recover first.'
    }
    # 1.3.8 (D-008 v3): after rapid disconnect/reconnect cycles the NRPT
    # policy store can still hold a tombstoned registry key, and ANY provider
    # access - rule reads, EFFECTIVE-policy reads, rule creation - can fail
    # with ERROR_KEY_DELETED ("marked for deletion"). Tolerate a bounded
    # settle window on every read so a draining delete from a previous
    # session cannot fail this connect.
    $rules = $null
    for ($nrptSettle = 1; $nrptSettle -le 10; $nrptSettle++) {
        try { $rules = @(Get-DnsClientNrptRule -ErrorAction Stop); break }
        catch {
            if ($nrptSettle -lt 10 -and $_.Exception.Message -match 'marked for deletion') { [Threading.Thread]::Sleep(2000); continue }
            throw
        }
    }
    for ($policySettle = 1; $policySettle -le 10; $policySettle++) {
        try { $effective = @(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop); break }
        catch {
            if ($policySettle -lt 10 -and $_.Exception.Message -match 'marked for deletion') { [Threading.Thread]::Sleep(2000); continue }
            throw
        }
    }
    if ($rules.Count -gt 0) {
        throw 'Existing DNS routing policy was found. Disconnect the other VPN or ask your network administrator before using GephTun.'
    }
    if ($effective.Count -gt 0) {
        throw 'A network-managed DNS policy is active. GephTun will not replace it.'
    }
    if (@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object { $_.Name -like 'GephTun-IPv6-Contain-*' }).Count -gt 0) {
        throw 'A leftover GephTun IPv6 containment rule exists. Run Disconnect / Recover from the previous GephTun session, or remove the rule manually, before connecting.'
    }
    # 1.3.8 (D-009): the startup recovery task is session-scoped residue. A
    # task without its session means an earlier teardown never completed.
    if (@(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -eq 'GephTunBootReconcile' }).Count -gt 0) {
        throw 'A leftover GephTun startup recovery task exists. Run Disconnect / Recover from the previous GephTun session before connecting.'
    }
    Test-GephTunFirewallBaseline
    $activeRoutes = @(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop)
    foreach ($prefix in @('0.0.0.0/1', '128.0.0.0/1', '::/1', '8000::/1')) {
        if (@($activeRoutes | Where-Object { $_.DestinationPrefix -eq $prefix }).Count -gt 0) {
            throw 'Another tunnel already has routes installed. Disconnect that tunnel before using GephTun.'
        }
    }
    $gateway = Get-GephTunDefaultRoutes
    # 1.3.1 no longer assigns an IPv6 address to the tunnel, so only the IPv4
    # tunnel address can collide with another adapter.
    if (@(Get-NetIPAddress -ErrorAction Stop | Where-Object { $_.IPAddress -eq '198.18.0.1' }).Count -gt 0) {
        throw 'Another adapter already uses a GephTun address. Disconnect the other tunnel before continuing.'
    }
    $proxy = Get-GephTunProxy $Port
    Assert-GephTunConnectContinuing
    try { $dnsCheck = [GephTun.ProxyProbe]::TestDns([int]$proxy.Port) }
    catch { Throw-GephTunTransient 'DNS_UNAVAILABLE' ('Geph DNS preflight failed: ' + $_.Exception.Message) }
    $peers = @(Get-GephTunPeerRoutes $proxy.Process)
    Assert-GephTunConnectContinuing
    if ($peers.Count -eq 0) { Throw-GephTunTransient 'PEER_MISSING' 'Geph has no observable physical TCP server connection. Wait for Geph to finish connecting.' }
    [pscustomobject]@{ Proxy = $proxy; Network = $gateway; Message = "Geph SOCKS5 and encrypted internet connectivity verified on port $($proxy.Port)." }
}

function Add-GephTunOwnedRoute([string]$Prefix, [int]$InterfaceIndex, [string]$NextHop, [string]$Kind) {
    # Enumerating the store distinguishes an absent route from a provider error.
    $existing = @(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop |
        Where-Object { $_.DestinationPrefix -eq $Prefix -and $_.InterfaceIndex -eq $InterfaceIndex -and $_.NextHop -eq $NextHop })
    if ($existing.Count -gt 0) {
        if ($Kind -eq 'Bypass') { return }
        throw "An unexpected route already exists for $Prefix."
    }
    $adapter = Get-NetAdapter -InterfaceIndex $InterfaceIndex -ErrorAction Stop
    $entry = [pscustomobject]@{
        DestinationPrefix = $Prefix; InterfaceIndex = $InterfaceIndex
        InterfaceGuid = $adapter.InterfaceGuid.ToString(); NextHop = $NextHop
        RouteMetric = 3; Kind = $Kind; Planned = $true
    }
    $script:Session.Routes = @($script:Session.Routes) + @($entry)
    Save-GephTunSession
    New-NetRoute -DestinationPrefix $Prefix -InterfaceIndex $InterfaceIndex -NextHop $NextHop -RouteMetric 3 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
    $entry.Planned = $false
    Save-GephTunSession
}

function Remove-GephTunOwnedRoute($Entry) {
    # A saved index is insufficient: Windows may reuse it for a different adapter.
    $adapter = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { $_.InterfaceIndex -eq [int]$Entry.InterfaceIndex }) | Select-Object -First 1
    if ($null -eq $adapter -or $adapter.InterfaceGuid.ToString() -ne $Entry.InterfaceGuid) { return }
    $matching = @(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop |
        Where-Object { $_.DestinationPrefix -eq $Entry.DestinationPrefix -and $_.InterfaceIndex -eq [int]$Entry.InterfaceIndex -and $_.NextHop -eq $Entry.NextHop })
    if (@($matching | Where-Object { [int]$_.RouteMetric -ne [int]$Entry.RouteMetric }).Count -gt 0) {
        throw 'A saved route metric was changed by another program. Its recovery record and forwarding services are retained.'
    }
    $routes = @($matching | Where-Object { [int]$_.RouteMetric -eq [int]$Entry.RouteMetric })
    foreach ($route in $routes) { $route | Remove-NetRoute -Confirm:$false -ErrorAction Stop }
}

function Remove-GephTunDnsPolicy($Session) {
    $rules = @(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object { $_.Comment -eq $Session.DnsTag })
    foreach ($rule in $rules) {
        if (@($rule.Namespace).Count -ne 1 -or $rule.Namespace[0] -ne '.' -or
            (@($rule.NameServers) -join ',') -ne '127.0.0.1') {
            throw 'The saved GephTun DNS rule was changed by another program. Review it before recovery.'
        }
        Remove-DnsClientNrptRule -Name $rule.Name -Force -ErrorAction Stop
    }
}

function Get-GephTunIpv6AddressBytes([string]$Address) {
    $parsed = [Net.IPAddress]::Parse($Address)
    if ($parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetworkV6) {
        throw "Not an IPv6 address: $Address"
    }
    , $parsed.GetAddressBytes()
}

function ConvertTo-GephTunIpv6Text([byte[]]$Bytes) {
    ([Net.IPAddress]::new($Bytes)).ToString()
}

function Compare-GephTunIpv6Bytes([byte[]]$Left, [byte[]]$Right) {
    for ($i = 0; $i -lt 16; $i++) {
        if ([int]$Left[$i] -lt [int]$Right[$i]) { return -1 }
        if ([int]$Left[$i] -gt [int]$Right[$i]) { return 1 }
    }
    return 0
}

function Step-GephTunIpv6Bytes([byte[]]$Bytes, [bool]$Up) {
    $copy = [byte[]]::new(16)
    [Array]::Copy($Bytes, $copy, 16)
    if ($Up) {
        for ($i = 15; $i -ge 0; $i--) {
            if ($copy[$i] -lt 255) { $copy[$i] = [byte]($copy[$i] + 1); break }
            $copy[$i] = 0
        }
    } else {
        for ($i = 15; $i -ge 0; $i--) {
            if ($copy[$i] -gt 0) { $copy[$i] = [byte]($copy[$i] - 1); break }
            $copy[$i] = 255
        }
    }
    , $copy
}

function Get-GephTunIpv6ContainmentRanges([string[]]$Exclusions) {
    # Block all nonlocal IPv6 unicast, including NAT64 and ULA/site-local space.
    # Only loopback, link-local and multicast remain outside these two blocks.
    # A fixed 2000::/3 rule misses valid internet paths such as 64:ff9b::/96.
    $blocks = @(
        [pscustomobject]@{ Start = (Get-GephTunIpv6AddressBytes '::2'); End = (Get-GephTunIpv6AddressBytes 'fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff') },
        [pscustomobject]@{ Start = (Get-GephTunIpv6AddressBytes 'fec0::'); End = (Get-GephTunIpv6AddressBytes 'feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff') }
    )
    $items = New-Object 'Collections.Generic.List[object]'
    foreach ($exclusion in @($Exclusions)) {
        if ([string]::IsNullOrWhiteSpace($exclusion)) { continue }
        $parts = ([string]$exclusion).Split('/')
        if ($parts.Count -ne 2 -or $parts[1] -ne '128' -or $parts[0].Contains('%')) {
            throw "Only unscoped single IPv6 addresses can be excluded from containment: $exclusion"
        }
        $bytes = Get-GephTunIpv6AddressBytes $parts[0]
        $inside = $false
        foreach ($block in $blocks) {
            if ((Compare-GephTunIpv6Bytes $bytes $block.Start) -ge 0 -and (Compare-GephTunIpv6Bytes $bytes $block.End) -le 0) { $inside = $true; break }
        }
        if (-not $inside) { throw "The containment exclusion is not nonlocal IPv6 unicast: $exclusion" }
        $duplicate = $false
        foreach ($existing in $items) {
            if ((Compare-GephTunIpv6Bytes $existing $bytes) -eq 0) { $duplicate = $true; break }
        }
        if (-not $duplicate) { $items.Add($bytes) }
    }
    # Do not pipe byte arrays: PowerShell 5.1 would flatten their elements.
    for ($i = 1; $i -lt $items.Count; $i++) {
        $key = $items[$i]; $j = $i - 1
        while ($j -ge 0 -and (Compare-GephTunIpv6Bytes $items[$j] $key) -gt 0) { $items[$j + 1] = $items[$j]; $j-- }
        $items[$j + 1] = $key
    }
    $ranges = New-Object Collections.Generic.List[string]
    foreach ($block in $blocks) {
        $cursor = [byte[]]$block.Start.Clone(); $exhausted = $false
        foreach ($current in $items) {
            if ((Compare-GephTunIpv6Bytes $current $block.Start) -lt 0 -or (Compare-GephTunIpv6Bytes $current $block.End) -gt 0) { continue }
            if ((Compare-GephTunIpv6Bytes $current $cursor) -gt 0) {
                $below = Step-GephTunIpv6Bytes $current $false
                $ranges.Add((ConvertTo-GephTunIpv6Text $cursor) + '-' + (ConvertTo-GephTunIpv6Text $below))
            }
            if ((Compare-GephTunIpv6Bytes $current $block.End) -ge 0) { $exhausted = $true; break }
            $cursor = Step-GephTunIpv6Bytes $current $true
        }
        if (-not $exhausted) { $ranges.Add((ConvertTo-GephTunIpv6Text $cursor) + '-' + (ConvertTo-GephTunIpv6Text $block.End)) }
    }
    $ranges.ToArray()
}

function Get-GephTunContainmentExclusions($Session) {
    # Current verified peers include pre-existing routes we must never claim or
    # remove. Historical owned routes alone would omit these borrowed IPv6 paths
    # and keep obsolete relay destinations exempt for the rest of the session.
    $prefixes = @()
    if ($Session.PSObject.Properties['PeerBypasses']) { $prefixes = @($Session.PeerBypasses | ForEach-Object { $_.Prefix }) }
    else { $prefixes = @($Session.Routes | Where-Object { $_.Kind -eq 'Bypass' } | ForEach-Object { $_.DestinationPrefix }) }
    $exclusions = New-Object 'Collections.Generic.List[string]'
    foreach ($prefix in $prefixes) {
        if ($prefix -notlike '*:*') { continue }
        $parts = ([string]$prefix).Split('/')
        if ($parts.Count -ne 2 -or $parts[1] -ne '128') { throw 'Invalid Geph IPv6 relay containment exclusion.' }
        $address = [Net.IPAddress]::Parse($parts[0])
        if ($address.IsIPv6LinkLocal) { continue }
        if ($address.ScopeId -ne 0 -or $address.IsIPv6Multicast -or [Net.IPAddress]::IsLoopback($address) -or $address.Equals([Net.IPAddress]::IPv6Any)) {
            throw 'Invalid Geph IPv6 relay containment exclusion.'
        }
        $exclusions.Add($address.ToString() + '/128')
    }
    @($exclusions.ToArray() | Sort-Object -Unique)
}

function Get-GephTunContainmentRule([string]$RuleName, [string]$PolicyStore = 'PersistentStore') {
    # Exact-name CDXML queries report absence as an error. Enumerating the store
    # distinguishes actual absence from provider/access failures in recovery.
    @(Get-NetFirewallRule -PolicyStore $PolicyStore -ErrorAction Stop | Where-Object { $_.Name -eq $RuleName })
}

function Test-GephTunFirewallProfiles([switch]$AllowDisabled) {
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    $names = @($profiles | ForEach-Object { [string]$_.Name } | Sort-Object -Unique)
    if ($profiles.Count -ne 3 -or ($names -join ',') -ne 'Domain,Private,Public') {
        throw 'Windows Firewall profiles could not be enumerated. GephTun cannot contain IPv6 egress without them.'
    }
    foreach ($profile in $profiles) {
        # GpoBoolean is an enum, not a .NET bool. Compare its named value.
        if ([string]$profile.Enabled -notin @('True', 'False') -or (-not $AllowDisabled -and [string]$profile.Enabled -ne 'True')) {
            throw 'An effective Windows Firewall profile is disabled or unknown. IPv6 containment cannot be verified.'
        }
        if ([string]$profile.AllowLocalFirewallRules -eq 'False') {
            throw 'Network policy prevents local firewall rules. GephTun cannot verify IPv6 containment on this computer.'
        }
        if (@($profile.DisabledInterfaceAliases | Where-Object { $_ -and $_ -ne 'NotConfigured' }).Count -gt 0) {
            throw 'Windows Firewall excludes one or more network adapters. GephTun cannot verify IPv6 containment on this computer.'
        }
    }
}

function Install-GephTunContainment {
    $script:ContainmentSecurityBaseline = $null
    Test-GephTunFirewallBaseline
    $ruleName = 'GephTun-IPv6-Contain-' + $script:Session.Token
    if (@(Get-GephTunContainmentRule $ruleName).Count -gt 0) {
        throw 'A GephTun IPv6 containment rule already exists for this session token.'
    }
    $record = [pscustomobject]@{
        RuleName = $ruleName
        DisplayName = 'GephTun IPv6 containment ' + $script:Session.Token
        Planned = $true; Profiles = @()
        Exclusions = @(Get-GephTunContainmentExclusions $script:Session)
    }
    if ($script:Session.PSObject.Properties['Containment']) { $script:Session.Containment = $record }
    else { $script:Session | Add-Member -NotePropertyName Containment -NotePropertyValue $record }
    Save-GephTunSession
    # 1.4.0 never enables/disables global firewall profiles. This avoids
    # unowned persistent changes across reboot or administrative policy updates.
    Test-GephTunFirewallProfiles
    $created = @(New-NetFirewallRule -Name $ruleName -DisplayName $record.DisplayName `
        -Description ('GephTun session ' + $script:Session.Token + ' blocks native IPv6 internet egress while connected. GephTun removes this rule on disconnect or recovery.') `
        -Direction Outbound -Action Block -Enabled True -Profile Any -PolicyStore PersistentStore -RemoteAddress (Get-GephTunIpv6ContainmentRanges $record.Exclusions) `
        -Authentication NotRequired -Encryption NotRequired -OverrideBlockRules $false -ErrorAction Stop)
    if ($created.Count -ne 1 -or $created[0].Name -cne $ruleName -or $created[0].DisplayName -cne $record.DisplayName) {
        throw 'The newly created IPv6 containment rule could not be verified.'
    }
    # LocalUser/RemoteUser/RemoteMachine are intentionally not restricted at
    # creation. Capture this provider's representation through the returned
    # new rule, rather than guessing whether its unscoped lists are null/Any.
    # The baseline is worker memory only: recovery never needs it, and a later
    # persistent/effective policy read must not silently redefine it.
    $security = Get-GephTunFirewallSecurityValues $created[0]
    if ($security.Authentication -cne 'NotRequired' -or $security.Encryption -cne 'NotRequired' -or $security.OverrideBlockRules -cne 'False') {
        throw 'The newly created IPv6 containment security settings were not applied.'
    }
    $script:ContainmentSecurityBaseline = [pscustomobject]@{ Token = $script:Session.Token; RuleName = $ruleName; Values = $security }
    $record.Planned = $false
    Save-GephTunSession
    Test-GephTunContainment
}

function Sync-GephTunContainment {
    if ($null -eq $script:Session) { return }
    if (-not $script:Session.PSObject.Properties['Containment'] -or $null -eq $script:Session.Containment) { return }
    $record = $script:Session.Containment
    if ($record.Planned) { return }
    $current = @(Get-GephTunContainmentExclusions $script:Session)
    $saved = @($record.Exclusions)
    $changed = $current.Count -ne $saved.Count
    if (-not $changed -and $current.Count -gt 0) {
        $changed = $null -ne (Compare-Object -ReferenceObject $current -DifferenceObject $saved -SyncWindow 0)
    }
    if (-not $changed) { return }
    if (@(Get-GephTunContainmentRule $record.RuleName).Count -ne 1) {
        throw 'The IPv6 containment rule is missing. Disconnecting to restore the saved network settings.'
    }
    Set-NetFirewallRule -Name $record.RuleName -PolicyStore PersistentStore -RemoteAddress (Get-GephTunIpv6ContainmentRanges $current) -ErrorAction Stop
    $record.Exclusions = $current
    Save-GephTunSession
}

function Test-GephTunContainment {
    if (-not $script:Session.PSObject.Properties['Containment'] -or $null -eq $script:Session.Containment) {
        throw 'The IPv6 containment record is missing. Disconnecting to restore the saved network settings.'
    }
    $record = $script:Session.Containment
    $rules = @(Get-GephTunContainmentRule $record.RuleName 'ActiveStore')
    if ($rules.Count -ne 1) { throw 'The IPv6 containment rule is missing. Disconnecting to restore the saved network settings.' }
    if ($rules[0].DisplayName -ne $record.DisplayName -or [string]$rules[0].Direction -ne 'Outbound' -or [string]$rules[0].Action -ne 'Block' -or
        [string]$rules[0].Enabled -ne 'True' -or [string]$rules[0].Profile -ne 'Any') {
        throw 'The IPv6 containment rule was changed by another program. Disconnecting to restore the saved network settings.'
    }
    $expected = @(Get-GephTunIpv6ContainmentRanges @(Get-GephTunContainmentExclusions $script:Session))
    $filters = @($rules[0] | Get-NetFirewallAddressFilter -ErrorAction Stop)
    if ($filters.Count -ne 1) { throw 'The IPv6 containment rule filter cannot be read. Disconnecting to restore the saved network settings.' }
    $expected = @($expected | ForEach-Object { ConvertTo-GephTunFirewallRange $_ } | Sort-Object)
    $actual = @($filters[0].RemoteAddress | ForEach-Object { ConvertTo-GephTunFirewallRange $_ } | Sort-Object)
    if ((@($filters[0].LocalAddress) -join ',') -ne 'Any' -or $actual.Count -ne $expected.Count -or
        $null -ne (Compare-Object -ReferenceObject $expected -DifferenceObject $actual)) {
        throw 'The IPv6 containment rule no longer matches the Geph server paths. Disconnecting to restore the saved network settings.'
    }
    $checks = @(
        [pscustomobject]@{ Items = @($rules[0] | Get-NetFirewallApplicationFilter -ErrorAction Stop); Fields = @('Program', 'Package') },
        [pscustomobject]@{ Items = @($rules[0] | Get-NetFirewallServiceFilter -ErrorAction Stop); Fields = @('Service') },
        [pscustomobject]@{ Items = @($rules[0] | Get-NetFirewallPortFilter -ErrorAction Stop); Fields = @('Protocol', 'LocalPort', 'RemotePort') },
        [pscustomobject]@{ Items = @($rules[0] | Get-NetFirewallInterfaceFilter -ErrorAction Stop); Fields = @('InterfaceAlias') },
        [pscustomobject]@{ Items = @($rules[0] | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop); Fields = @('InterfaceType') }
    )
    foreach ($check in $checks) {
        if ($check.Items.Count -ne 1) { throw 'An IPv6 containment filter cannot be read.' }
        foreach ($field in $check.Fields) {
            $value = @($check.Items[0].$field) -join ','
            # The NetSecurity provider reports an unrestricted AppContainer Package
            # as an empty value (verified on Windows 11 PowerShell 5.1), while every
            # other unrestricted field reports the literal 'Any'. A real package
            # restriction is a non-empty SID string and still fails this check.
            if ($value -ne 'Any' -and -not ($field -ceq 'Package' -and [string]::IsNullOrEmpty($value))) { throw 'An IPv6 containment filter was restricted by another program. Disconnecting to restore the saved network settings.' }
        }
    }
    $baseline = $script:ContainmentSecurityBaseline
    if ($null -eq $baseline -or $baseline.Token -cne $script:Session.Token -or $baseline.RuleName -cne $record.RuleName) {
        throw 'The IPv6 containment security baseline is missing. Disconnect and reconnect to verify a new rule.'
    }
    foreach ($store in @('ActiveStore', 'PersistentStore')) {
        $observedRules = $rules
        if ($store -eq 'PersistentStore') { $observedRules = @(Get-GephTunContainmentRule $record.RuleName 'PersistentStore') }
        if ($observedRules.Count -ne 1 -or $observedRules[0].DisplayName -cne $record.DisplayName) { throw 'The IPv6 containment security rule cannot be verified.' }
        $observed = Get-GephTunFirewallSecurityValues $observedRules[0]
        foreach ($field in @('Authentication', 'Encryption', 'OverrideBlockRules', 'LocalUser', 'RemoteUser', 'RemoteMachine')) {
            if (($null -eq $observed.$field) -ne ($null -eq $baseline.Values.$field) -or $observed.$field -cne $baseline.Values.$field) {
                throw 'The IPv6 containment security filter changed. Disconnecting to restore the saved network settings.'
            }
        }
    }
    Test-GephTunFirewallProfiles
}

function Get-GephTunFirewallSecurityValues($Rule) {
    $filters = @($Rule | Get-NetFirewallSecurityFilter -ErrorAction Stop)
    if ($filters.Count -ne 1) { throw 'The IPv6 containment security filter cannot be read uniquely.' }
    $values = [ordered]@{}
    foreach ($field in @('Authentication', 'Encryption', 'OverrideBlockRules', 'LocalUser', 'RemoteUser', 'RemoteMachine')) {
        $property = $filters[0].PSObject.Properties[$field]
        if ($null -eq $property -or $property.Value -is [array]) { throw 'An IPv6 containment security field is missing or not scalar.' }
        if ($null -eq $property.Value) { $values[$field] = $null }
        else { $values[$field] = [string]$property.Value }
    }
    return [pscustomobject]$values
}

function ConvertTo-GephTunFirewallRange([string]$Range) {
    # NetSecurity may reorder addresses or expand/compress IPv6 text. Compare
    # equivalent intervals rather than formatting returned by the provider.
    $parts = $Range.Split('-')
    if ($parts.Count -eq 2) {
        $first = Get-GephTunIpv6AddressBytes $parts[0]; $last = Get-GephTunIpv6AddressBytes $parts[1]
    } elseif ($parts.Count -eq 1) {
        $cidr = $Range.Split('/')
        $first = Get-GephTunIpv6AddressBytes $cidr[0]; $last = [byte[]]$first.Clone()
        if ($cidr.Count -eq 2) {
            if ($cidr[1] -notmatch '^\d{1,3}$' -or [int]$cidr[1] -gt 128) { throw 'The IPv6 containment address prefix cannot be verified.' }
            $bits = [int]$cidr[1]
            for ($i = 0; $i -lt 16; $i++) {
                $take = [Math]::Max(0, [Math]::Min(8, $bits))
                $mask = [int](256 - [Math]::Pow(2, 8 - $take))
                $first[$i] = [byte]($first[$i] -band $mask)
                $last[$i] = [byte]($first[$i] -bor (255 - $mask))
                $bits -= $take
            }
        } elseif ($cidr.Count -ne 1) { throw 'The IPv6 containment address range cannot be verified.' }
    } else { throw 'The IPv6 containment address range cannot be verified.' }
    if ((Compare-GephTunIpv6Bytes $first $last) -gt 0) { throw 'The IPv6 containment address range is reversed.' }
    return (ConvertTo-GephTunIpv6Text $first) + '-' + (ConvertTo-GephTunIpv6Text $last)
}

function Remove-GephTunContainment($Session) {
    if ($null -eq $Session -or -not $Session.PSObject.Properties['Containment'] -or $null -eq $Session.Containment) { return }
    $record = $Session.Containment
    $rules = @(Get-GephTunContainmentRule $record.RuleName)
    if ($rules.Count -gt 1) { throw 'More than one rule matches the saved GephTun IPv6 containment name.' }
    if ($rules.Count -eq 1) {
        if ($rules[0].DisplayName -ne $record.DisplayName) {
            throw 'The saved GephTun IPv6 containment rule was changed by another program. Review it before recovery.'
        }
        Remove-NetFirewallRule -Name $record.RuleName -PolicyStore PersistentStore -ErrorAction Stop
    }
    foreach ($profile in @($record.Profiles)) {
        $current = @(Get-NetFirewallProfile -PolicyStore PersistentStore -ErrorAction Stop | Where-Object { [string]$_.Name -eq $profile.Name })
        if ($current.Count -ne 1 -or [string]$current[0].Enabled -notin @('True', 'False')) { throw 'The saved firewall profile cannot be safely restored.' }
        if ([string]$current[0].Enabled -ne [string]$profile.WasEnabled) {
            # Enabled is GpoBoolean, not System.Boolean; bind its named value.
            Set-NetFirewallProfile -Name $profile.Name -Enabled ([string]$profile.WasEnabled) -PolicyStore PersistentStore -ErrorAction Stop
        }
        # A later retry must not replay profiles already restored successfully.
        $record.Profiles = @($record.Profiles | Where-Object { $_.Name -ne $profile.Name })
        Save-GephTunSession
    }
}

function Stop-GephTunOwnedProcess($Identity) {
    if ($null -eq $Identity) { return }
    $running = @(Get-Process -ErrorAction Stop | Where-Object { $_.Id -eq [int]$Identity.Id })
    if ($running.Count -eq 0) { return }
    $process = $running[0]
    try {
        # Acquire the kernel process handle before identity checks or hashing.
        # Retaining only a PID, or a Process object whose handle is still lazy,
        # could target a replacement process if Windows recycles the ID.
        $heldHandle = $process.get_Handle()
        if ($heldHandle -eq [IntPtr]::Zero) { throw 'The tunnel process handle could not be verified.' }
        $actual = [pscustomobject]@{ Id = $process.Id; StartUtc = $process.StartTime.ToUniversalTime().ToString('o'); Path = $process.Path }
        if ([string]::IsNullOrWhiteSpace($actual.Path)) { throw 'The tunnel process executable path could not be verified.' }
        if ($actual.StartUtc -eq $Identity.StartUtc -and $actual.Path -eq $Identity.Path) {
            # Recovery may use a moved package. Never use only the process name or ID.
            if ([IO.Path]::GetFileName($Identity.Path) -ne 'tun2socks-windows-amd64.exe') { throw 'Unexpected saved process identity.' }
            $hash = (Get-FileHash -LiteralPath $Identity.Path -Algorithm SHA256 -ErrorAction Stop).Hash
            if ($hash -ne $script:Session.TunnelSha256) { throw 'The running tunnel binary differs from the saved session.' }
            Stop-Process -InputObject $process -Force -ErrorAction Stop
        }
    } finally {
        if ($process -is [IDisposable]) { $process.Dispose() }
    }
}

function Find-GephTunUnrecordedProcess {
    # Recover the small gap between successful process creation and saving its PID.
    # Exact path, full random adapter token, start time and binary hash are required.
    if ($null -ne $script:Session.Tunnel) { return }
    if (-not $script:Session.PSObject.Properties['TunnelPath']) { return }
    $path = $script:Session.TunnelPath
    if ([IO.Path]::GetFileName($path) -ne 'tun2socks-windows-amd64.exe') { throw 'Invalid recovery executable path.' }
    # tun2socks 2.x parses flags with pflag: a single dash means a shorthand cluster,
    # so long flags must use the double-dash form or the process exits at startup.
    $needle = '--device ' + $script:Session.TunnelName + ' --proxy socks5://127.0.0.1:' + $script:Session.ProxyPort + ' --loglevel warning'
    $matches = @(Get-CimInstance Win32_Process -Filter "Name='tun2socks-windows-amd64.exe'" -ErrorAction Stop |
        Where-Object { $_.ExecutablePath -eq $path -and $_.CommandLine.EndsWith($needle, [StringComparison]::Ordinal) })
    if ($matches.Count -gt 1) { throw 'More than one process matches the saved tunnel token. Review recovery manually.' }
    if ($matches.Count -eq 1) {
        $identity = Get-GephTunProcessIdentity ([int]$matches[0].ProcessId)
        if ($identity.Path -ne $path) { throw 'The matching process changed before its identity could be confirmed.' }
        if ([DateTime]::Parse($identity.StartUtc).ToUniversalTime() -lt [DateTime]::Parse($script:Session.StartedUtc).ToUniversalTime()) { throw 'The matching process predates this session.' }
        # PID and executable path can both match a newly created replacement.
        # Bind the token-bearing CIM observation to this exact process lifetime.
        # CIM datetime has microsecond precision; Process.StartTime has 100 ns
        # ticks, so permit only the discarded sub-microsecond fraction.
        if (-not $matches[0].PSObject.Properties['CreationDate'] -or $matches[0].CreationDate -isnot [DateTime]) {
            throw 'The matching process creation time could not be verified.'
        }
        $observedStart = $matches[0].CreationDate.ToUniversalTime()
        $liveStart = [DateTime]::Parse($identity.StartUtc).ToUniversalTime()
        $startDifference = $liveStart.Ticks - $observedStart.Ticks
        if ($startDifference -lt 0 -or $startDifference -gt 9) { throw 'The matching process lifetime changed before its identity could be confirmed.' }
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $script:Session.TunnelSha256) { throw 'Recovery executable hash mismatch.' }
        $script:Session.Tunnel = $identity
        Save-GephTunSession
    }
}

function Restore-GephTunSession {
    if ($null -eq $script:Session) {
        $script:Session = Read-GephTunJson (Join-Path (Get-GephTunRoot) 'session.json')
    }
    if ($null -eq $script:Session) { return }
    # Schema 1 records are GephTun 1.3.0 sessions; they carry no containment
    # state and remain recoverable after upgrading to this version.
    if ($script:Session.Schema -notin @(1, 2) -or $script:Session.Token -notmatch '^[a-f0-9]{32}$' -or
        $script:Session.DnsTag -ne ('GephTun:' + $script:Session.Token)) {
        throw 'The recovery record is invalid. No network changes were attempted.'
    }
    Assert-GephTunRecoveryRecord $script:Session
    Remove-GephTunTunnelPermission
    try { Set-GephTunStatus 'Disconnecting' "Restoring this session's network changes..." } catch { }
    $errors = New-Object Collections.Generic.List[string]
    # Restore ordinary DNS first, while the relay is still alive.
    try { Remove-GephTunDnsPolicy $script:Session } catch { $errors.Add('DNS: ' + $_.Exception.Message) }
    # Remove traffic diversion before stopping the packet engine.
    $remaining = @()
    foreach ($entry in @($script:Session.Routes | Sort-Object @{Expression={ if ($_.Kind -eq 'Tunnel') { 0 } else { 1 } }})) {
        # If traffic diversion or DNS cleanup failed, Geph still needs its direct
        # upstream routes. Removing those bypasses can strand the retained engine.
        if ($entry.Kind -eq 'Bypass' -and $errors.Count -gt 0) { $remaining += $entry; continue }
        try { Remove-GephTunOwnedRoute $entry } catch { $remaining += $entry; $errors.Add('Route: ' + $_.Exception.Message) }
    }
    $script:Session.Routes = @($remaining)
    Save-GephTunSession
    if ($errors.Count -gt 0) {
        $message = 'Recovery needs attention. ' + ($errors -join ' | ')
        try { Set-GephTunStatus 'RecoveryRequired' $message } catch { }
        # Retain the packet engine and DNS forwarder until their routes/policy are gone.
        throw $message
    }
    # Containment is only removed once no diversion state remains above: while a
    # busy route still diverts traffic, blocking unintended IPv6 egress must
    # continue. A failure here keeps the rule for the recovery retry loop.
    try { Remove-GephTunContainment $script:Session } catch { $errors.Add('Containment: ' + $_.Exception.Message) }
    try { Find-GephTunUnrecordedProcess } catch { $errors.Add('Process recovery: ' + $_.Exception.Message) }
    try { Stop-GephTunOwnedProcess $script:Session.Tunnel } catch { $errors.Add('Process: ' + $_.Exception.Message) }
    if ($null -ne $script:Relay) { try { $script:Relay.Dispose() } catch { $errors.Add('DNS relay: ' + $_.Exception.Message) }; $script:Relay = $null }
    try { Clear-DnsClientCache -ErrorAction Stop } catch { try { Write-GephTunLog ('DNS cache refresh: ' + $_.Exception.Message) } catch { } }
    if ($errors.Count -gt 0) {
        $message = 'Recovery needs attention. ' + ($errors -join ' | ')
        try { Set-GephTunStatus 'RecoveryRequired' $message } catch { }
        throw $message
    }
    # Session-scoped cleanup only: WFP protection has a separate persistent lifetime.
    # 1.3.8 (D-009): every session-owned persistent mutation is gone, so the startup
    # recovery guard must not outlive the session. It is removed only after
    # all other surfaces succeeded - while any owned rule can still remain,
    # the guard must stay armed for a restart - and before the journal is
    # deleted, so a guard-removal failure stays retryable instead of
    # stranding a task or a rule.
    try { Unregister-GephTunBootGuard } catch {
        $message = 'Recovery needs attention. Boot guard: ' + $_.Exception.Message
        try { Set-GephTunStatus 'RecoveryRequired' $message } catch { }
        throw $message
    }
    $journalPath = Join-Path (Get-GephTunRoot) 'session.json'
    Assert-GephTunPlainPath $journalPath
    # All session diversion effects are gone, but the WFP blocker remains.
    # File.Delete is idempotent if another recovery
    # observer already removed the record, but still throws on real I/O denial.
    [IO.File]::Delete($journalPath)
    $script:Session = $null
    Close-GephTunProtectionLease
    try { Set-GephTunStatus 'Disconnected' 'Disconnected. The network changes made by this session have been removed.' } catch { }
}

function Assert-GephTunRecoveryRecord($Session) {
    # Treat a corrupt journal as a recovery error before touching any network
    # surface. Every deletion target must be narrow and tied to this session.
    try {
        if ($Session.PSObject.Properties['TunnelName'] -and $Session.TunnelName -cne ('GephTun-' + $Session.Token)) { throw 'The saved tunnel name does not match this session token.' }
        if ($Session.PSObject.Properties['TunnelPath']) {
            if ([IO.Path]::GetFileName($Session.TunnelPath) -cne 'tun2socks-windows-amd64.exe') { throw 'Invalid saved tunnel executable path.' }
            if ($null -ne $Session.Tunnel -and $Session.Tunnel.Path -ne $Session.TunnelPath) { throw 'The saved process ownership does not match the tunnel executable path.' }
        }
        foreach ($entry in @($Session.Routes)) {
            $parts = ([string]$entry.DestinationPrefix).Split('/')
            if ($parts.Count -ne 2 -or [int]$entry.InterfaceIndex -le 0 -or
                [string]::IsNullOrWhiteSpace($entry.InterfaceGuid) -or [int]$entry.RouteMetric -ne 3) { throw 'Invalid route ownership.' }
            $address = [Net.IPAddress]::Parse($parts[0]); $hop = [Net.IPAddress]::Parse($entry.NextHop)
            if ($address.AddressFamily -ne $hop.AddressFamily) { throw 'Invalid route family.' }
            if ($entry.Kind -eq 'Tunnel') {
                if ($entry.DestinationPrefix -notin @('0.0.0.0/1', '128.0.0.0/1', '::/1', '8000::/1') -or
                    $entry.NextHop -notin @('0.0.0.0', '::')) { throw 'Invalid tunnel prefix.' }
                if ([int]$entry.InterfaceIndex -ne [int]$Session.TunnelInterfaceIndex -or
                    $entry.InterfaceGuid -ne $Session.TunnelInterfaceGuid) { throw 'The tunnel route does not belong to the saved session adapter.' }
            } elseif ($entry.Kind -eq 'Bypass') {
                if ([int]$parts[1] -ne (8 * $address.GetAddressBytes().Length)) { throw 'Invalid bypass prefix.' }
            } else { throw 'Invalid route kind.' }
        }
        if ($Session.PSObject.Properties['Containment'] -and $null -ne $Session.Containment) {
            $record = $Session.Containment
            if ($record.RuleName -cne ('GephTun-IPv6-Contain-' + $Session.Token) -or
                $record.DisplayName -cne ('GephTun IPv6 containment ' + $Session.Token)) { throw 'Invalid firewall rule ownership.' }
            $names = @()
            foreach ($profile in @($record.Profiles)) {
                if ($profile.Name -notin @('Domain', 'Private', 'Public') -or $profile.Name -in $names -or
                    $profile.WasEnabled -isnot [bool] -or $profile.WasEnabled) { throw 'Invalid firewall profile recovery state.' }
                $names += $profile.Name
            }
        }
    } catch { throw ('The recovery record is invalid. No network changes were attempted. ' + $_.Exception.Message) }
}

function Test-GephTunPrefix([string]$Address, [string]$Prefix) {
    $parts = $Prefix.Split('/')
    $target = [Net.IPAddress]::Parse($Address).GetAddressBytes()
    $network = [Net.IPAddress]::Parse($parts[0]).GetAddressBytes()
    if ($target.Length -ne $network.Length) { return $false }
    $bits = [int]$parts[1]
    if ($bits -lt 0 -or $bits -gt 8 * $target.Length) { throw 'Invalid route prefix length.' }
    for ($i = 0; $i -lt $target.Length -and $bits -gt 0; $i++) {
        $take = [Math]::Min(8, $bits)
        $mask = 256 - [Math]::Pow(2, 8 - $take)
        if (($target[$i] -band [int]$mask) -ne ($network[$i] -band [int]$mask)) { return $false }
        $bits -= $take
    }
    return $true
}

function Get-GephTunOriginalRoutes {
    $interfaces = @(Get-NetIPInterface -ErrorAction Stop)
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
    @(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
        $route = $_
        $ipif = @($interfaces | Where-Object { $_.InterfaceIndex -eq $route.InterfaceIndex -and $_.AddressFamily -eq $route.AddressFamily } | Select-Object -First 1)
        $cost = [int]$route.RouteMetric
        if ($ipif.Count -gt 0) { $cost += [int]$ipif[0].InterfaceMetric }
        $adapter = @($adapters | Where-Object { $_.InterfaceIndex -eq $route.InterfaceIndex })
        $guid = ''
        if ($adapter.Count -eq 1) { $guid = $adapter[0].InterfaceGuid.ToString() }
        [pscustomobject]@{ DestinationPrefix = $route.DestinationPrefix; InterfaceIndex = [int]$route.InterfaceIndex; InterfaceGuid = $guid; NextHop = $route.NextHop; Cost = $cost }
    })
}

$script:RecoveredBypasses = $null

function Get-GephTunPeerRouteSnapshot($ProxyIdentity) {
    if (-not (Test-GephTunProcessIdentity $ProxyIdentity)) { Throw-GephTunTransient 'PROXY_UNAVAILABLE' 'The Geph process has stopped or restarted. Waiting for the same Geph installation.' }
    $install = [IO.Path]::GetDirectoryName($ProxyIdentity.Path)
    $related = @(Get-CimInstance Win32_Process -Filter "Name LIKE 'geph%'" -ErrorAction Stop |
        Where-Object { $_.ExecutablePath -and [IO.Path]::GetDirectoryName($_.ExecutablePath) -eq $install })
    if ($null -ne $script:ProtectionLease) {
        Assert-GephTunApprovedProxy $ProxyIdentity
        $approved=Get-GephTunProtectionConfiguration
        $related=@($related | Where-Object { $_.ExecutablePath -in @($approved.TrustedImages | ForEach-Object { $_.Path }) })
    }
    $processIds = @([int]$ProxyIdentity.Id) + @($related | ForEach-Object { [int]$_.ProcessId })
    $udp = @(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object {
        $_.OwningProcess -in $processIds -and -not [Net.IPAddress]::IsLoopback([Net.IPAddress]::Parse($_.LocalAddress))
    })
    if ($udp.Count -gt 0) { throw 'Geph has UDP sockets outside loopback whose server routes this wrapper cannot track. Use Geph native VPN mode for this configuration.' }
    $peers = @(Get-NetTCPConnection -ErrorAction Stop | Where-Object { $_.OwningProcess -in $processIds } |
        Where-Object { $_.State -in @('Established', 'SynSent') -and $_.RemoteAddress -notin @('0.0.0.0', '::', '::1', '127.0.0.1') })
    $snapshot = @()
    if ($null -ne $script:Session -and $script:Session.PSObject.Properties['OriginalRoutes']) { $snapshot = @($script:Session.OriginalRoutes) }
    else { $snapshot = @(Get-GephTunOriginalRoutes) }
    $tunnelIndex = 0
    if ($null -ne $script:Session -and $script:Session.PSObject.Properties['TunnelInterfaceIndex']) { $tunnelIndex = [int]$script:Session.TunnelInterfaceIndex }
    $result = @()
    foreach ($peer in $peers) {
        $remote = [Net.IPAddress]::Parse($peer.RemoteAddress)
        if ([Net.IPAddress]::IsLoopback($remote)) { continue }
        $v4 = $remote.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork
        $family = 'IPv6'; $prefixLength = 128
        if ($v4) { $family = 'IPv4'; $prefixLength = 32 }
        try { $addresses = @(Get-NetIPAddress -IPAddress $peer.LocalAddress -AddressFamily $family -ErrorAction Stop) }
        catch {
            Write-GephTunPeerDiagnostic $peer ('IP-address lookup failed: ' + $_.Exception.Message)
            Throw-GephTunTransient 'PEER_SNAPSHOT' 'A Geph connection address could not be observed while the physical network was changing.'
        }
        if ($addresses.Count -eq 0) {
            Write-GephTunPeerDiagnostic $peer 'No local IP-address record matched this socket.'
            Throw-GephTunTransient 'PEER_SNAPSHOT' 'A Geph connection lost its local IP-address mapping. Rechecking the physical network.'
        }
        $observations = New-Object 'Collections.Generic.List[string]'
        $physicalWithoutRoute = $false
        $found = $false
        foreach ($address in $addresses) {
            try { $adapter = Get-NetAdapter -InterfaceIndex $address.InterfaceIndex -IncludeHidden -ErrorAction Stop }
            catch {
                Write-GephTunPeerDiagnostic $peer ('Adapter lookup failed for interface ' + $address.InterfaceIndex + ': ' + $_.Exception.Message)
                Throw-GephTunTransient 'PEER_SNAPSHOT' 'The Geph connection adapter could not be read. Rechecking the physical network.'
            }
            if ($null -eq $adapter -or $adapter.Status -ne 'Up') {
                Write-GephTunPeerDiagnostic $peer ('Interface ' + $address.InterfaceIndex + ' is missing or not Up.')
                Throw-GephTunTransient 'PEER_SNAPSHOT' 'A Geph connection adapter is changing state. Rechecking the physical network.'
            }
            $adapterName = ''
            if ($adapter.PSObject.Properties['Name']) { $adapterName = [string]$adapter.Name }
            $observations.Add(('interface={0}; name={1}; hardware={2}; state={3}' -f $address.InterfaceIndex, $adapterName, $adapter.HardwareInterface, $adapter.Status))
            if (-not $adapter.HardwareInterface) { continue }
            $routes = @($snapshot | Where-Object { $_.InterfaceIndex -eq $address.InterfaceIndex -and (Test-GephTunPrefix $remote.ToString() $_.DestinationPrefix) } |
                Sort-Object @{Expression={ [int]$_.DestinationPrefix.Split('/')[1] };Descending=$true}, Cost)
            if ($routes.Count -eq 0) { $physicalWithoutRoute = $true; continue }
            if (-not $routes[0].PSObject.Properties['InterfaceGuid'] -or $routes[0].InterfaceGuid -ne $adapter.InterfaceGuid.ToString()) {
                Throw-GephTunTransient 'NETWORK_CHANGED' 'The physical adapter changed since its original route snapshot. A fresh session is required.'
            }
            $result += [pscustomobject]@{ Prefix = $remote.ToString() + '/' + $prefixLength; InterfaceIndex = [int]$address.InterfaceIndex; NextHop = $routes[0].NextHop }
            $found = $true
            break
        }
        if (-not $found -and $tunnelIndex -gt 0 -and @($addresses | Where-Object { [int]$_.InterfaceIndex -eq $tunnelIndex }).Count -gt 0) {
            # Geph formed this connection while the tunnel was up, so Windows captured
            # it on the tunnel adapter. Bypass the destination through the original
            # physical network. A new route cannot rebind an existing socket;
            # connectivity is verified separately while Geph retries.
            $tunnelAdapter = Get-NetAdapter -InterfaceIndex $tunnelIndex -ErrorAction Stop
            if ($tunnelAdapter.InterfaceGuid.ToString() -ne $script:Session.TunnelInterfaceGuid) {
                throw 'A captured Geph connection no longer belongs to the saved tunnel adapter.'
            }
            try { $physicalAdapter = Get-NetAdapter -InterfaceIndex $script:Session.OriginalNetwork.InterfaceIndex -IncludeHidden -ErrorAction Stop }
            catch {
                Write-GephTunPeerDiagnostic $peer ('Captured-peer physical adapter read failed: ' + $_.Exception.Message)
                Throw-GephTunTransient 'NETWORK_UNAVAILABLE' 'The physical adapter changed while validating a captured Geph connection.'
            }
            if ($null -eq $physicalAdapter -or $physicalAdapter.Status -ne 'Up') {
                Throw-GephTunTransient 'NETWORK_UNAVAILABLE' 'The physical adapter went down while validating a captured Geph connection.'
            }
            if (-not $physicalAdapter.HardwareInterface) { throw 'The saved physical interface now refers to an unsupported virtual adapter.' }
            if ($physicalAdapter.InterfaceGuid.ToString() -ne $script:Session.OriginalNetwork.InterfaceGuid) {
                Throw-GephTunTransient 'NETWORK_CHANGED' 'The physical adapter identity changed; a fresh session is required.'
            }
            $physical = @($snapshot | Where-Object { $_.InterfaceIndex -eq [int]$script:Session.OriginalNetwork.InterfaceIndex -and (Test-GephTunPrefix $remote.ToString() $_.DestinationPrefix) } |
                Sort-Object @{Expression={ [int]$_.DestinationPrefix.Split('/')[1] };Descending=$true}, Cost)
            if ($physical.Count -gt 0) {
                if (-not $physical[0].PSObject.Properties['InterfaceGuid'] -or $physical[0].InterfaceGuid -ne $physicalAdapter.InterfaceGuid.ToString()) {
                    Throw-GephTunTransient 'NETWORK_CHANGED' 'The physical adapter changed since its original route snapshot. A fresh session is required.'
                }
                $prefix = $remote.ToString() + '/' + $prefixLength
                $result += [pscustomobject]@{ Prefix = $prefix; InterfaceIndex = [int]$script:Session.OriginalNetwork.InterfaceIndex; NextHop = $physical[0].NextHop; Recovered = $true }
                $found = $true
            }
        }
        if (-not $found) {
            Write-GephTunPeerDiagnostic $peer (($observations -join ' | ') + '; physical interface without matching saved route=' + $physicalWithoutRoute)
            if ($physicalWithoutRoute -and $null -ne $script:Session) {
                Throw-GephTunTransient 'NETWORK_CHANGED' 'A Geph connection is on a physical network not covered by the saved route snapshot. A fresh session is required.'
            }
            throw 'A Geph server connection is using an unsupported adapter or address family. See the PeerValidation log entry for the exact connection and interface.'
        }
    }
    @($result | Sort-Object Prefix, InterfaceIndex, NextHop -Unique)
}

function Update-GephTunBypasses { Invoke-GephTunBypassRefresh }

function Test-GephTunInstalledRoutes {
    $activeRoutes = @(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop)
    foreach ($entry in @($script:Session.Routes | Where-Object { $_.Kind -eq 'Tunnel' })) {
        $adapter = Get-NetAdapter -InterfaceIndex $entry.InterfaceIndex -ErrorAction Stop
        if ($adapter.InterfaceGuid.ToString() -ne $entry.InterfaceGuid) { throw 'The tunnel network adapter changed.' }
        $routes = @($activeRoutes | Where-Object { $_.DestinationPrefix -eq $entry.DestinationPrefix -and $_.InterfaceIndex -eq $entry.InterfaceIndex -and $_.NextHop -eq $entry.NextHop -and [int]$_.RouteMetric -eq [int]$entry.RouteMetric })
        if ($routes.Count -ne 1) { throw 'The tunnel routes changed. Disconnecting to restore connectivity.' }
    }
    $selected = @(Find-NetRoute -RemoteIPAddress '1.1.1.1' -ErrorAction Stop)
    if (@($selected | Where-Object { $_.InterfaceIndex -eq $script:Session.TunnelInterfaceIndex }).Count -eq 0) {
        throw 'Windows is not routing the internet check through the tunnel.'
    }
}

function Test-GephTunDnsPolicy {
    # 1.3.8 (D-008 v3): tolerate a draining policy-store tombstone on read.
    $rules = $null
    for ($dnsPolicySettle = 1; $dnsPolicySettle -le 10; $dnsPolicySettle++) {
        try { $rules = @(Get-DnsClientNrptRule -ErrorAction Stop); break }
        catch {
            if ($dnsPolicySettle -lt 10 -and $_.Exception.Message -match 'marked for deletion') { [Threading.Thread]::Sleep(2000); continue }
            throw
        }
    }
    $owned = @($rules | Where-Object { $_.Comment -eq $script:Session.DnsTag })
    if ($rules.Count -ne 1 -or $owned.Count -ne 1 -or
        (@($owned[0].Namespace) -join ',') -ne '.' -or (@($owned[0].NameServers) -join ',') -ne '127.0.0.1') {
        throw 'The GephTun DNS routing rule changed. Disconnecting to restore the saved network settings.'
    }
    $effective = $null
    for ($effectiveSettle = 1; $effectiveSettle -le 10; $effectiveSettle++) {
        try { $effective = @(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop); break }
        catch {
            if ($effectiveSettle -lt 10 -and $_.Exception.Message -match 'marked for deletion') { [Threading.Thread]::Sleep(2000); continue }
            throw
        }
    }
    if ($effective.Count -ne 1 -or (@($effective[0].Namespace) -join ',') -ne '.' -or
        (@($effective[0].NameServers) -join ',') -ne '127.0.0.1') {
        throw 'Windows is no longer applying only the GephTun DNS forwarding policy. Disconnecting to restore connectivity.'
    }
}

function Test-GephTunPhysicalNetwork {
    $current = Get-GephTunDefaultRoutes
    if ($current.InterfaceIndex -ne $script:Session.OriginalNetwork.InterfaceIndex -or
        $current.InterfaceGuid -ne $script:Session.OriginalNetwork.InterfaceGuid -or
        $current.Gateway -ne $script:Session.OriginalNetwork.Gateway) {
        Throw-GephTunTransient 'NETWORK_CHANGED' 'The physical network or gateway changed. Recovering before reconnecting on the new network.'
    }
}

function Register-GephTunBootGuard {
    # 1.3.8 (D-009): the catch-all NRPT rule and the IPv6 containment rule
    # are PERSISTENT Windows state, but product cleanup only runs inside
    # product processes. A restart between connect and the next launch used
    # to leave a global DNS policy aimed at a dead local relay (machine-wide
    # name-resolution outage) plus an IPv6 egress block. Connect therefore
    # arms an AtStartup SYSTEM task, before the first persistent mutation,
    # that removes GephTun-owned policy whose session is not alive.
    # Registration failure is fail-closed: without this guard, persistent
    # DNS/firewall state must not be created.
    $packageScript = Join-Path $script:PackageRoot 'GephTun-BootReconcile.ps1'
    if (-not [IO.File]::Exists($packageScript)) { throw ('The Windows startup recovery script is missing from the installation: ' + $packageScript) }
    # The task must keep working even if the installation folder is removed
    # while a session is connected, so it runs a hash-verified copy from the
    # protected GephTun state tree instead of the installation folder.
    $stateScript = Join-Path (Get-GephTunRoot) 'GephTun-BootReconcile.ps1'
    [IO.File]::Copy($packageScript, $stateScript, $true)
    $scriptHash = (Get-FileHash -LiteralPath $packageScript -Algorithm SHA256).Hash
    if ((Get-FileHash -LiteralPath $stateScript -Algorithm SHA256).Hash -cne $scriptHash) {
        throw 'The startup recovery script copy in the GephTun state tree could not be verified.'
    }
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $stateScript + '"')
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
    $failure = $null
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            Register-ScheduledTask -TaskName 'GephTunBootReconcile' -TaskPath '\' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
            try { Write-GephTunLog 'Startup recovery task registered (GephTunBootReconcile).' } catch { }
            return
        } catch { $failure = $_.Exception.Message; [Threading.Thread]::Sleep(2000) }
    }
    throw ('The Windows startup recovery task could not be registered, so GephTun will not create persistent DNS or firewall state. ' + $failure)
}

function Unregister-GephTunBootGuard {
    # Idempotent teardown counterpart: a missing task is already the desired
    # state, so only real removal failures propagate to the recovery path.
    # The state-tree script copy goes away with the task - neither may linger
    # after a completed session.
    $removedTask = $false
    try {
        Unregister-ScheduledTask -TaskName 'GephTunBootReconcile' -TaskPath '\' -Confirm:$false -ErrorAction Stop
        $removedTask = $true
    } catch {
        if ($_.CategoryInfo.Category -eq 'ObjectNotFound') { $removedTask = $false }
        else { throw }
    }
    $remainingTasks = @()
    try { $remainingTasks = @(Get-ScheduledTask -TaskName 'GephTunBootReconcile' -TaskPath '\' -ErrorAction Stop) }
    catch { if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { throw } }
    if ($remainingTasks.Count -ne 0) { throw 'The startup recovery task is still present; its script must be preserved.' }
    if ($removedTask) { try { Write-GephTunLog 'Startup recovery task removed.' } catch { } }
    $stateScript = Join-Path (Get-GephTunRoot) 'GephTun-BootReconcile.ps1'
    if ([IO.File]::Exists($stateScript)) { [IO.File]::Delete($stateScript) }
}

function Start-GephTunSession([int]$Port = 0, [int]$OwnerProcessId = 0, [string]$OperationToken = '') {
    if ($OperationToken -and $OperationToken -cnotmatch '^[a-f0-9]{32}$') { throw 'Invalid connection operation token.' }
    $owner = $null
    if ($OwnerProcessId -gt 0) { $owner = Get-GephTunProcessIdentity $OwnerProcessId }
    $cancelPath = ''
    if ($OperationToken) { $cancelPath = Join-Path (Join-Path (Get-GephTunRoot) 'results') ($OperationToken + '.cancel.json') }
    $script:ConnectContext = [pscustomobject]@{ Token = $OperationToken; CancelPath = $cancelPath; Owner = $owner; DeadlineUtc = [DateTime]::UtcNow.AddSeconds(120) }
    try {
    Assert-GephTunConnectContinuing
    if ($null -eq $script:ProtectionLease) { Open-GephTunProtectionLease }
    Assert-GephTunProtection
    $preflight = Test-GephTunPreflight $Port
    Assert-GephTunConnectContinuing
    if ($null -ne $script:ConnectionIntent) {
        if ($script:ConnectionIntent.ProxyPath -and -not [string]::Equals(
            [string]$preflight.Proxy.Process.Path, [string]$script:ConnectionIntent.ProxyPath, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'The Geph installation changed. Choose Connect manually after verifying the new installation.'
        }
        $script:ConnectionIntent.ProxyPath = [string]$preflight.Proxy.Process.Path
        Write-GephTunJson (Join-Path (Get-GephTunRoot) 'connection-intent.json') $script:ConnectionIntent
    }
    $token = [guid]::NewGuid().ToString('N')
    $name = 'GephTun-' + $token
    $bin = Join-Path $script:PackageRoot 'bin\tun2socks-windows-amd64.exe'
    $script:Session = [pscustomobject]@{
        Schema = 2; Token = $token; StartedUtc = [DateTime]::UtcNow.ToString('o')
        Worker = (Get-GephTunProcessIdentity $PID); Owner = $owner
        ProxyPort = $preflight.Proxy.Port; ProxyProcess = $preflight.Proxy.Process
        OriginalNetwork = $preflight.Network; OriginalRoutes = @(Get-GephTunOriginalRoutes); Tunnel = $null; TunnelName = $name; TunnelPath = $bin
        TunnelInterfaceIndex = 0; TunnelInterfaceGuid = ''; TunnelSha256 = (Get-FileHash -LiteralPath $bin -Algorithm SHA256).Hash
        Routes = @(); DnsTag = 'GephTun:' + $token; DnsPlanned = $false; Containment = $null
    }
    $script:RecoveredBypasses = $null
    Initialize-GephTunBypassRegistry
    Save-GephTunSession
    try {
        Assert-GephTunConnectContinuing
        Register-GephTunBootGuard
        Set-GephTunStatus 'Connecting' 'Checking DNS forwarding and creating the network adapter...'
        # Bind before changing any routes or DNS policies. A busy port fails cleanly.
        $script:Relay = [GephTun.SocksDnsRelay]::Start([int]$script:Session.ProxyPort)
        Install-GephTunRememberedBypasses
        Update-GephTunBypasses
        Save-GephTunBypassCache -Force
        # Contain native IPv6 egress before any traffic is diverted. Geph's local
        # SOCKS proxy cannot transport IPv6, so IPv6 must never be tunneled or it
        # could silently bypass Geph once the tunnel routes are installed.
        Install-GephTunContainment
        Assert-GephTunConnectContinuing
        if (@(Get-NetAdapter -Name $name -ErrorAction SilentlyContinue).Count -gt 0) { throw 'An unexpected adapter name collision occurred.' }
        $stdout = Join-Path (Get-GephTunRoot) ('logs\tunnel-' + $token + '.out.log')
        $stderr = Join-Path (Get-GephTunRoot) ('logs\tunnel-' + $token + '.error.log')
        $tunnel = Start-Process -FilePath $bin -WorkingDirectory (Split-Path -Parent $bin) -ArgumentList @('--device', $name, '--proxy', ('socks5://127.0.0.1:' + $script:Session.ProxyPort), '--loglevel', 'warning') -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        $script:Session.Tunnel = Get-GephTunProcessIdentity $tunnel.Id
        Save-GephTunSession
        $adapter = $null
        $deadline = [DateTime]::UtcNow.AddSeconds(15)
        do {
            Assert-GephTunConnectContinuing
            if (-not (Test-GephTunProcessIdentity $script:Session.Tunnel)) { throw "The tunnel engine exited. See $stderr" }
            $adapter = Get-NetAdapter -Name $name -ErrorAction SilentlyContinue
            if ($null -ne $adapter) { break }
            Start-Sleep -Milliseconds 200
        } while ([DateTime]::UtcNow -lt $deadline)
        if ($null -eq $adapter) { throw 'The Wintun adapter did not become available within 15 seconds.' }
        $script:Session.TunnelInterfaceIndex = [int]$adapter.InterfaceIndex
        $script:Session.TunnelInterfaceGuid = $adapter.InterfaceGuid.ToString()
        Save-GephTunSession
        Assert-GephTunConnectContinuing
        $index = $script:Session.TunnelInterfaceIndex
        # 1.3.1: no IPv6 address or route is placed on the tunnel. Geph's local
        # proxy rejects IPv6 dials, so routing IPv6 into the tunnel only produced
        # failing connections and unstable Windows connectivity assessments.
        # The adapter's IPv6 stack is disabled and the session firewall rule
        # contains native IPv6 egress instead. The adapter is owned and destroyed
        # by the tunnel engine, so this binding change needs no journal entry.
        # NetAdapter binding cmdlets have no InterfaceIndex parameter. Use the
        # session's unguessable name after verifying its saved adapter identity.
        # 1.3.8 (D-008 v5): adapter enumeration reads the adapter-class
        # registry, where the PREVIOUS session's just-deleted adapter key can
        # still be tombstoned (ERROR_KEY_DELETED, "marked for deletion") - the
        # field-proven failure site of rapid connect/disconnect cycles. Bounded
        # retry; any other failure still fails Connect as-is.
        $currentAdapter = $null
        for ($adapterReadAttempt = 1; $adapterReadAttempt -le 8; $adapterReadAttempt++) {
            try { $currentAdapter = Get-NetAdapter -Name $name -ErrorAction Stop; break }
            catch {
                if ($adapterReadAttempt -lt 8 -and $_.Exception.Message -match 'marked for deletion') { [Threading.Thread]::Sleep(2000); continue }
                throw
            }
        }
        if ($currentAdapter.InterfaceGuid.ToString() -ne $script:Session.TunnelInterfaceGuid -or [int]$currentAdapter.InterfaceIndex -ne $index) {
            throw 'The tunnel adapter changed before IPv6 configuration.'
        }
        # 1.3.8 (D-008 v6): the binding disable writes to the adapter's
        # registry binding key, which can hit the draining tombstone of the
        # previous session's adapter (ERROR_KEY_DELETED) right after creation.
        # Bounded retry; any other failure still fails Connect as-is.
        $bindingDone = $false
        for ($bindingAttempt = 1; $bindingAttempt -le 8 -and -not $bindingDone; $bindingAttempt++) {
            try {
                Disable-NetAdapterBinding -Name $name -ComponentID ms_tcpip6 -ErrorAction Stop
                $bindingDone = $true
            } catch {
                if ($bindingAttempt -lt 8 -and $_.Exception.Message -match 'marked for deletion') { [Threading.Thread]::Sleep(2000); continue }
                throw
            }
        }
        # Binding changes can restart the adapter. Configure IPv4 afterward.
        $currentAdapter = $null
        for ($adapterReadAttempt = 1; $adapterReadAttempt -le 8; $adapterReadAttempt++) {
            try { $currentAdapter = Get-NetAdapter -Name $name -ErrorAction Stop; break }
            catch {
                if ($adapterReadAttempt -lt 8 -and $_.Exception.Message -match 'marked for deletion') { [Threading.Thread]::Sleep(2000); continue }
                throw
            }
        }
        if ($currentAdapter.InterfaceGuid.ToString() -ne $script:Session.TunnelInterfaceGuid -or [int]$currentAdapter.InterfaceIndex -ne $index -or
            -not (Test-GephTunProcessIdentity $script:Session.Tunnel)) { throw 'The tunnel adapter or process changed during IPv6 configuration.' }
        # All settings are on the new adapter; physical Wi-Fi/Ethernet settings are untouched.
        Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4 -Dhcp Disabled -AutomaticMetric Disabled -InterfaceMetric 3 -DadTransmits 0 -ErrorAction Stop
        New-NetIPAddress -InterfaceIndex $index -AddressFamily IPv4 -IPAddress '198.18.0.1' -PrefixLength 30 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
        # 1.3.8 (D-008 v4): per-interface DNS settings are registry-backed, and
        # after rapid cycles the fresh adapter's writes can hit a draining
        # tombstone left by the previous adapter's key (ERROR_KEY_DELETED).
        # Bounded retry; any other failure still fails Connect as-is.
        $adapterDnsDone = $false
        for ($adapterDnsAttempt = 1; $adapterDnsAttempt -le 5 -and -not $adapterDnsDone; $adapterDnsAttempt++) {
            try {
                Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses @('127.0.0.1') -ErrorAction Stop
                Set-DnsClient -InterfaceIndex $index -RegisterThisConnectionsAddress $false -ErrorAction Stop
                $adapterDnsDone = $true
            } catch {
                if ($adapterDnsAttempt -lt 5 -and $_.Exception.Message -match 'marked for deletion') { [Threading.Thread]::Sleep(2000); continue }
                throw
            }
        }
        Assert-GephTunConnectContinuing
        Add-GephTunTunnelPermission
        foreach ($prefix in @('0.0.0.0/1', '128.0.0.0/1')) { Assert-GephTunConnectContinuing; Add-GephTunOwnedRoute $prefix $index '0.0.0.0' 'Tunnel' }
        Assert-GephTunConnectContinuing
        $script:Session.DnsPlanned = $true
        Save-GephTunSession
        # 1.3.8 (D-008 v2): recreating the catch-all NRPT rule can collide with
        # the previous rule's tombstoned policy-store key after rapid
        # connect/disconnect cycles (ERROR_KEY_DELETED surfaces as "marked for
        # deletion"). The registry drain can outlast a single short retry, so
        # use three attempts with longer gaps; any other failure, or a
        # persistent one, still fails Connect with the original error.
        $nrptDone = $false
        for ($nrptAttempt = 1; $nrptAttempt -le 3 -and -not $nrptDone; $nrptAttempt++) {
            try {
                Add-DnsClientNrptRule -Namespace '.' -NameServers @('127.0.0.1') -Comment $script:Session.DnsTag -ErrorAction Stop | Out-Null
                $nrptDone = $true
            } catch {
                if ($nrptAttempt -lt 3 -and $_.Exception.Message -match 'marked for deletion') { [Threading.Thread]::Sleep(4000); continue }
                throw
            }
        }
        Assert-GephTunConnectContinuing
        Clear-DnsClientCache -ErrorAction Stop
        # 1.3.8 (D-007 v2): the connect-time loopback DNS probe gets the same
        # bounded re-verify as the steady-state heartbeat - a transient failure
        # under a relay-switch load ramp must not kill an otherwise healthy
        # connect. A persistent failure still fails Connect with its error.
        $connectProbeFailure = $null
        $connectProbeVerified = $false
        for ($connectProbeAttempt = 1; $connectProbeAttempt -le 3 -and -not $connectProbeVerified; $connectProbeAttempt++) {
            try {
                Resolve-DnsName -Name 'example.com' -Type A -Server '127.0.0.1' -DnsOnly -NoHostsFile -ErrorAction Stop | Out-Null
                $connectProbeVerified = $true
            } catch {
                $connectProbeFailure = $_.Exception.Message
                if ($connectProbeAttempt -lt 3) { [Threading.Thread]::Sleep(3000) }
            }
        }
        if (-not $connectProbeVerified) { Throw-GephTunTransient 'DNS_UNAVAILABLE' $connectProbeFailure }
        [GephTun.ProxyProbe]::TestDirect() | Out-Null
        Assert-GephTunConnectContinuing
        if (-not $script:Relay.Healthy) { throw 'The local DNS forwarder stopped.' }
        # The blocking end-to-end probe can outlive a network, proxy, policy or
        # firewall change. Re-read the mutable invariants before reporting success.
        Test-GephTunPhysicalNetwork
        if (-not (Test-GephTunProcessIdentity $script:Session.ProxyProcess)) { throw 'The Geph process has stopped or restarted. Reconnect Geph and try again.' }
        Test-GephTunDnsPolicy
        Test-GephTunInstalledRoutes
        Test-GephTunContainment
        Assert-GephTunProtection
        Assert-GephTunConnectContinuing
        Set-GephTunStatus 'Connected' 'Connected. TCP traffic is routed through Geph; DNS forwarding is active; IPv6 internet egress is contained.'
        return [pscustomobject]@{ Success = $true; Message = 'Connected. The tunnel keeps running in the background; Disconnect stops the tunnel but retains WFP protection.'; Details = @{ ProxyPort = $script:Session.ProxyPort; Adapter = $name; Network = $preflight.Network.Alias; Coverage = 'IPv4 TCP and DNS are tunneled through Geph. IPv6 is not tunneled: nonlocal IPv6 unicast, including NAT64 and private/site-local destinations, is blocked by an owned firewall rule except current Geph relay addresses. Loopback and narrowly scoped link-maintenance exceptions remain; ordinary LAN and native IPv6 application traffic are blocked by WFP. WFP physical egress permissions are restricted to approved Geph executables; route exceptions alone do not authorize other applications. The DNS relay also suppresses AAAA answers. General UDP compatibility is not verified.' } }
    } catch {
        $reason = $_.Exception.Message
        $startFailure = $_.Exception
        # 1.3.8: log the failing statement's position - the same Windows
        # registry-tombstone text can surface from several providers, and the
        # position makes field diagnosis exact.
        $position = ''
        try { if ($null -ne $_.InvocationInfo -and $_.InvocationInfo.PositionMessage) { $position = ' @' + ($_.InvocationInfo.PositionMessage -replace '\s+', ' ') } } catch { }
        try { Write-GephTunLog ('Connect failed: ' + $reason + $position) } catch { }
        try { Restore-GephTunSession } catch { throw "$reason Recovery also needs attention: $($_.Exception.Message)" }
        throw $startFailure
    }
    } finally {
        $script:ConnectContext = $null
        if ($null -eq $script:ConnectionIntent -and $cancelPath -and (Test-Path -LiteralPath $cancelPath)) {
            try { Assert-GephTunPlainPath $cancelPath; Remove-Item -LiteralPath $cancelPath -Force -ErrorAction Stop } catch { }
        }
    }
}

function Watch-GephTunCurrentSession {
    $lastProbe = (Get-GephTunHealthClock)
    $lastProtection = $lastProbe.AddSeconds(-20)
    $outage = $null
    $request = Join-Path (Get-GephTunRoot) 'disconnect.json'
    while ($null -ne $script:Session) {
        Start-Sleep -Milliseconds 1000
        if (Test-GephTunIntentStopRequested) { Write-GephTunLog 'Disconnect or interface exit requested; cancelling automatic reconnect.'; return }
        if (Test-Path -LiteralPath $request) {
            $stop = Read-GephTunJson $request
            Remove-Item -LiteralPath $request -Force
            if ($null -ne $stop -and $stop.PSObject.Properties['Token'] -and $stop.Token -eq $script:Session.Token) { return }
        }
        if ($null -ne $script:Session.Owner -and -not (Test-GephTunProcessIdentity $script:Session.Owner)) {
            Write-GephTunLog 'The user interface closed; disconnecting.'; return
        }
        if (-not (Test-GephTunProcessIdentity $script:Session.Tunnel)) { throw 'The tunnel engine stopped.' }
        if ($null -eq $script:Relay -or -not $script:Relay.Healthy) { throw 'The DNS forwarder stopped.' }
        Test-GephTunPhysicalNetwork
        $peerFailure = $null
        try { Update-GephTunBypasses }
        catch {
            if ($null -eq $script:ConnectionIntent -or (Get-GephTunFailureCode $_) -notin @('PEER_MISSING','PEER_SNAPSHOT')) { throw }
            $peerFailure = $_
        }
        # These are never waived during a grace period. Do not retry configuration
        # tampering, unknown ownership, DNS-policy changes or firewall failures.
        Sync-GephTunContainment
        Test-GephTunContainment
        Test-GephTunInstalledRoutes
        Test-GephTunDnsPolicy
        if (((Get-GephTunHealthClock) - $lastProtection).TotalSeconds -ge 20) {
            Assert-GephTunProtection
            $lastProtection=Get-GephTunHealthClock
        }
        if ($null -ne $peerFailure) {
            if ($null -eq $outage) { $outage = (New-GephTunOutageClock) }
            if ($outage.Elapsed.TotalSeconds -ge 45) { throw $peerFailure }
            Set-GephTunReconnectStatus 'Geph is briefly reconnecting. Existing verified routes, DNS policy and containment remain installed; traffic may stall. Disconnect cancels.'
            $lastProbe = (Get-GephTunHealthClock).AddSeconds(-20)
            continue
        }
        if (((Get-GephTunHealthClock) - $lastProbe).TotalSeconds -ge 20) {
            $probeFailure = $null
            $probeVerified = $false
            for ($probeAttempt = 1; $probeAttempt -le 3 -and -not $probeVerified; $probeAttempt++) {
                Assert-GephTunIntentContinuing
                try {
                    Resolve-DnsName -Name 'example.com' -Type A -Server '127.0.0.1' -DnsOnly -NoHostsFile -ErrorAction Stop | Out-Null
                    $probeVerified = $true
                } catch {
                    $probeFailure = $_.Exception.Message
                    if ($probeAttempt -lt 3) { Wait-GephTunProbeRetry }
                }
            }
            if (Test-GephTunIntentStopRequested) { return }
            if ($null -ne $script:Session.Owner -and -not (Test-GephTunProcessIdentity $script:Session.Owner)) {
                Write-GephTunLog 'The user interface closed; disconnecting.'; return
            }
            if (-not (Test-GephTunProcessIdentity $script:Session.Tunnel)) { throw 'The tunnel engine stopped.' }
            if ($null -eq $script:Relay -or -not $script:Relay.Healthy) { throw 'The DNS forwarder stopped.' }
            if (-not (Test-GephTunProcessIdentity $script:Session.ProxyProcess)) {
                Throw-GephTunTransient 'PROXY_UNAVAILABLE' 'The Geph process restarted while checking connectivity.'
            }
            Test-GephTunPhysicalNetwork
            Test-GephTunDnsPolicy
            Test-GephTunInstalledRoutes
            Test-GephTunContainment
            Assert-GephTunProtection
            if (-not $probeVerified) {
                $relayError = ''
                if ($script:Relay.PSObject.Properties['LastError']) { $relayError = [string]$script:Relay.LastError }
                $load = ''
                if ($script:Relay.PSObject.Properties['RejectedRequests']) {
                    $load = '; active=' + $script:Relay.ActiveRequests + '; high-water=' + $script:Relay.HighWaterRequests +
                        '; rejected=' + $script:Relay.RejectedRequests + '; upstream-failures=' + $script:Relay.UpstreamFailures +
                        '; last-error-utc=' + $script:Relay.LastErrorUtc
                }
                Write-GephTunLog ('DNS heartbeat failed: ' + $probeFailure + '; relay: ' + $relayError + $load)
                if ($null -eq $script:ConnectionIntent) { Throw-GephTunTransient 'DNS_UNAVAILABLE' $probeFailure }
                if ($null -eq $outage) { $outage = (New-GephTunOutageClock) }
                if ($outage.Elapsed.TotalSeconds -ge 45) { Throw-GephTunTransient 'DNS_UNAVAILABLE' ('DNS did not recover within the grace window: ' + $probeFailure) }
                Set-GephTunReconnectStatus 'DNS connectivity is interrupted. Existing verified protections remain installed; retrying before starting a fresh session. Disconnect cancels.'
                $lastProbe = (Get-GephTunHealthClock).AddSeconds(-15) # Retry after five seconds, not on every monitoring pass.
                continue
            }
            $lastProbe = (Get-GephTunHealthClock)
            if ($null -ne $outage) {
                # A successful DNS check plus current invariants ends the grace episode.
                $outage = $null
                $script:LastReconnectStatus = ''
                Set-GephTunStatus 'Connected' 'Connectivity recovered. TCP and DNS are routed through Geph; IPv6 containment is verified.'
            }
            else {
                $status = Read-GephTunJson (Join-Path (Get-GephTunRoot) 'status.json')
                if ($null -ne $status -and $status.Status -eq 'Connected' -and $status.WorkerPid -eq $PID -and
                    $status.WorkerStartUtc -eq $script:Session.Worker.StartUtc) {
                    $status.UpdatedUtc = $lastProbe.ToString('o')
                    Write-GephTunJson (Join-Path (Get-GephTunRoot) 'status.json') $status
                }
            }
        }
    }
}

function Request-GephTunDisconnect {
    $intent = Get-GephTunConnectionIntent
    if ($null -ne $intent -and (Test-GephTunProcessIdentity $intent.Worker)) {
        Write-GephTunJson (Join-Path (Get-GephTunRoot) 'disconnect-intent.json') @{ Token = $intent.Token }
        $ownedSession = Read-GephTunJson (Join-Path (Get-GephTunRoot) 'session.json')
        if ($null -ne $ownedSession -and $ownedSession.Worker.Id -eq $intent.Worker.Id -and
            $ownedSession.Worker.StartUtc -eq $intent.Worker.StartUtc) {
            Write-GephTunJson (Join-Path (Get-GephTunRoot) 'disconnect.json') @{ Token = $ownedSession.Token }
        }
        $deadline = [DateTime]::UtcNow.AddSeconds(45)
        do {
            Start-Sleep -Milliseconds 250
            $currentIntent = Get-GephTunConnectionIntent
            if ($null -eq $currentIntent -and -not (Test-Path -LiteralPath (Join-Path (Get-GephTunRoot) 'session.json'))) { return }
            if (-not (Test-GephTunProcessIdentity $intent.Worker)) { break }
        } while ([DateTime]::UtcNow -lt $deadline)
        if (Test-GephTunProcessIdentity $intent.Worker) { throw 'Disconnect is waiting for safe recovery. Automatic reconnect is cancelled; the controller was not force-killed.' }
    }
    $session = Read-GephTunJson (Join-Path (Get-GephTunRoot) 'session.json')
    if ($null -ne $session -and (Test-GephTunProcessIdentity $session.Worker)) {
        Write-GephTunJson (Join-Path (Get-GephTunRoot) 'disconnect.json') @{ Token = $session.Token }
        $deadline = [DateTime]::UtcNow.AddSeconds(45)
        do {
            Start-Sleep -Milliseconds 250
            if (-not (Test-Path -LiteralPath (Join-Path (Get-GephTunRoot) 'session.json'))) { return }
            if (-not (Test-GephTunProcessIdentity $session.Worker)) { break }
        } while ([DateTime]::UtcNow -lt $deadline)
        if (Test-GephTunProcessIdentity $session.Worker) { throw 'Disconnect is still waiting for the controller. Wait a moment and try again; the controller was not force-killed.' }
    }
    $mutex = Get-GephTunLock
    try {
        $script:Session = $null
        Restore-GephTunSession
        Clear-GephTunConnectionIntent
        if ($null -eq $script:Session) { Set-GephTunStatus 'Disconnected' 'Disconnected. No active GephTun session remains.' }
    } finally { Release-GephTunLock $mutex }
}

function Wait-GephTunRecovery {
    # Keep owned services alive if Windows refuses rollback; retry on user request
    # and periodically. Do not kill unrelated processes or erase the recovery record.
    while ($null -ne $script:Session) {
        try { Restore-GephTunSession; return } catch { try { Write-GephTunLog $_.Exception.Message } catch { } }
        if ($null -eq $script:Session) { return }
        $retryAt = [DateTime]::UtcNow.AddSeconds(30)
        do {
            Start-Sleep -Milliseconds 500
            $path = Join-Path (Get-GephTunRoot) 'disconnect.json'
            try {
                if (Test-Path -LiteralPath $path) {
                    $request = Read-GephTunJson $path
                    Remove-Item -LiteralPath $path -Force -ErrorAction Stop
                    if ($null -ne $request -and $request.PSObject.Properties['Token'] -and $request.Token -eq $script:Session.Token) { break }
                }
            } catch {
                # A locked, unreadable, or malformed request is not permission to
                # exit and destroy a DNS relay still required by an active rule.
                try { Write-GephTunLog ('Recovery request could not be read; periodic recovery will continue: ' + $_.Exception.Message) } catch { }
            }
        } while ([DateTime]::UtcNow -lt $retryAt)
    }
}

Export-ModuleMember -Function Initialize-GephTunStorage, Get-GephTunStatus, Test-GephTunPreflight,
    Start-GephTunSession, Watch-GephTunSession, Request-GephTunDisconnect, Restore-GephTunSession,
    Initialize-GephTunConnectionIntent, Clear-GephTunConnectionIntent,
    Wait-GephTunRecovery, Get-GephTunLock, Release-GephTunLock, Set-GephTunStatus, Write-GephTunLog, Write-GephTunJson, Get-GephTunRoot, Initialize-GephTunRequestDirectory,
    Get-GephTunProtectionStatus, Get-GephTunTransportCandidates, Enable-GephTunProtection, Disable-GephTunProtection,
    Open-GephTunProtectionLease, Close-GephTunProtectionLease
