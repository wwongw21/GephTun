#Requires -Version 5.1
[CmdletBinding()]
param([string]$PackageDirectory,[string]$ResultJson)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
if(-not $PackageDirectory){$PackageDirectory=Split-Path -Parent $PSScriptRoot}

class IdentitySafeguardsTestProcess : IDisposable {
    [int]$Id
    [DateTime]$StartTime
    [string]$Path
    [bool]$Disposed
    IdentitySafeguardsTestProcess([int]$ProcessId,[DateTime]$ProcessStart,[string]$ExecutablePath) {
        $this.Id=$ProcessId;$this.StartTime=$ProcessStart;$this.Path=$ExecutablePath;$this.Disposed=$false
    }
    [void] Dispose() { $this.Disposed=$true }
}

$modulePath=Join-Path $PackageDirectory 'GephTun.Core.psm1'
$results=New-Object 'Collections.Generic.List[object]'
$tokens=$null;$parseErrors=$null
$moduleAst=[Management.Automation.Language.Parser]::ParseFile($modulePath,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count -gt 0){throw 'Core module source could not be parsed.'}
$functionNames=@(
    'ConvertTo-GephTunProcessStartUtc','ConvertTo-GephTunProcessPath','Wait-GephTunProcessIdentityRetry',
    'Get-GephTunProcessIdentity','Get-GephTunVerifiedSpawnIdentity','Set-GephTunVerifiedSpawnIdentity',
    'Get-GephTunProcessIdentityState','Test-GephTunProcessIdentity','Wait-GephTunRecovery'
)
foreach($name in $functionNames){
    $definition=$moduleAst.Find({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
    if($null -eq $definition){throw "Expected function was not found in source: $name"}
    Invoke-Expression $definition.Extent.Text
}

$script:ProcessQueue=New-Object 'Collections.Generic.Queue[object]'
$script:ObservedProcesses=New-Object 'Collections.Generic.List[object]'
$script:ProcessCalls=0;$script:RetryWaits=0
function Get-Process {
    [CmdletBinding()]
    param([int]$Id)
    $script:ProcessCalls++
    if($script:ProcessQueue.Count -eq 0){throw 'Process fixture queue was exhausted.'}
    $item=$script:ProcessQueue.Dequeue()
    if($item -is [scriptblock]){& $item}
    $script:ObservedProcesses.Add($item)
    return $item
}
function Wait-GephTunProcessIdentityRetry { $script:RetryWaits++ }

function Assert-True($Condition,[string]$Message){if(-not $Condition){throw $Message}}
function Test-Case([string]$Name,[scriptblock]$Body){
    try { & $Body; $results.Add([pscustomobject]@{Name=$Name;Result='PASS';Detail=''}) }
    catch { $results.Add([pscustomobject]@{Name=$Name;Result='FAIL';Detail=$_.Exception.Message}) }
}
function Reset-ProcessFixture {
    $script:ProcessQueue=New-Object 'Collections.Generic.Queue[object]'
    $script:ObservedProcesses=New-Object 'Collections.Generic.List[object]'
    $script:ProcessCalls=0;$script:RetryWaits=0
}
function Add-TestProcess([int]$Id,[DateTime]$Start,[string]$Path){
    $process=[IdentitySafeguardsTestProcess]::new($Id,$Start,$Path)
    $script:ProcessQueue.Enqueue($process)
    return $process
}
function Assert-AllDisposed {
    foreach($process in $script:ObservedProcesses){Assert-True $process.Disposed 'An observed process handle was not disposed.'}
}
function Assert-Throws([scriptblock]$Action,[string]$MessagePattern){
    try { & $Action; throw 'Expected the operation to refuse this process identity.' }
    catch { if($_.Exception.Message -notlike $MessagePattern){throw $_} }
}

$baseStart=[DateTime]::SpecifyKind([DateTime]'2026-10-09T00:00:00.1234567',[DateTimeKind]::Utc)
$expectedPath='C:\Geph\tun2socks-windows-amd64.exe'

Test-Case 'A transient missing path resolves on the same process lifetime' {
    Reset-ProcessFixture
    $first=Add-TestProcess 42 $baseStart ''
    $second=Add-TestProcess 42 $baseStart $expectedPath
    $identity=Get-GephTunProcessIdentity 42
    Assert-True ($identity.Id -eq 42 -and $identity.Path -ceq $expectedPath -and (ConvertTo-GephTunProcessStartUtc $identity.StartUtc).Ticks -eq $baseStart.Ticks) 'The resolved identity changed its PID, path, or start time.'
    Assert-True ($script:ProcessCalls -eq 2 -and $script:RetryWaits -eq 1 -and $first.Disposed -and $second.Disposed) 'The missing-path retry was not bounded or did not dispose every observation.'
}

Test-Case 'A permanently missing path is refused after twelve disposed observations' {
    Reset-ProcessFixture
    for($i=0;$i -lt 12;$i++){Add-TestProcess 42 $baseStart ''|Out-Null}
    Assert-Throws {Get-GephTunProcessIdentity 42} '*path could not be verified*'
    Assert-True ($script:ProcessCalls -eq 12 -and $script:RetryWaits -eq 11 -and $script:ObservedProcesses.Count -eq 12) 'Missing-path retries exceeded or fell short of the bound.'
    Assert-AllDisposed
}

Test-Case 'A whitespace-only path is treated as missing and then refused' {
    Reset-ProcessFixture
    for($i=0;$i -lt 12;$i++){Add-TestProcess 42 $baseStart " `t "|Out-Null}
    Assert-Throws {Get-GephTunProcessIdentity 42} '*path could not be verified*'
    Assert-True ($script:ProcessCalls -eq 12 -and $script:RetryWaits -eq 11) 'Whitespace path handling was not bounded.'
    Assert-AllDisposed
}

Test-Case 'An exited process error propagates without retry' {
    Reset-ProcessFixture
    $script:ProcessQueue.Enqueue({throw [Management.Automation.ItemNotFoundException]::new('process exited')})
    Assert-Throws {Get-GephTunProcessIdentity 42} '*process exited*'
    Assert-True ($script:ProcessCalls -eq 1 -and $script:RetryWaits -eq 0) 'An exited process was retried.'
}

Test-Case 'An access denied error propagates without retry' {
    Reset-ProcessFixture
    $script:ProcessQueue.Enqueue({throw [UnauthorizedAccessException]::new('access denied')})
    Assert-Throws {Get-GephTunProcessIdentity 42} '*access denied*'
    Assert-True ($script:ProcessCalls -eq 1 -and $script:RetryWaits -eq 0) 'An access denied process read was retried.'
}

Test-Case 'A PID change during path retry is rejected and all observations are disposed' {
    Reset-ProcessFixture
    $first=Add-TestProcess 42 $baseStart ''
    $second=Add-TestProcess 43 $baseStart $expectedPath
    Assert-Throws {Get-GephTunProcessIdentity 42} '*identity changed*'
    Assert-True ($script:ProcessCalls -eq 2 -and $script:RetryWaits -eq 1 -and $first.Disposed -and $second.Disposed) 'A different PID was accepted or a handle was retained.'
}

Test-Case 'A process lifetime change during path retry is rejected and disposed' {
    Reset-ProcessFixture
    $laterStart=$baseStart.AddSeconds(1)
    $first=Add-TestProcess 42 $baseStart ''
    $second=Add-TestProcess 42 $laterStart $expectedPath
    Assert-Throws {Get-GephTunProcessIdentity 42} '*lifetime changed*'
    Assert-True ($script:ProcessCalls -eq 2 -and $script:RetryWaits -eq 1 -and $first.Disposed -and $second.Disposed) 'A replacement process lifetime was accepted or a handle was retained.'
}

Test-Case 'A malformed nonempty path is rejected without retry' {
    Reset-ProcessFixture
    $process=Add-TestProcess 42 $baseStart 'relative.exe'
    Assert-Throws {Get-GephTunProcessIdentity 42} '*missing or malformed*'
    Assert-True ($script:ProcessCalls -eq 1 -and $script:RetryWaits -eq 0 -and $process.Disposed) 'A malformed path was retried or its process handle was retained.'
}

Test-Case 'Startup saves a verified process identity and disposes both process objects' {
    Reset-ProcessFixture
    $observed=Add-TestProcess 123 $baseStart $expectedPath
    $spawned=[IdentitySafeguardsTestProcess]::new(123,$baseStart,$expectedPath)
    $session=[pscustomobject]@{Tunnel=$null}
    $identity=Set-GephTunVerifiedSpawnIdentity $session $spawned $expectedPath
    Assert-True ($session.Tunnel.Id -eq 123 -and $session.Tunnel.Path -ceq $expectedPath -and $identity.StartUtc -ceq $session.Tunnel.StartUtc) 'Startup did not save the verified identity.'
    Assert-True ($spawned.Disposed -and $observed.Disposed) 'Startup verification retained a process handle.'
}

foreach($case in @(
    [pscustomobject]@{Name='wrong PID';ObservedId=124;ObservedStart=$baseStart;ObservedPath=$expectedPath;SpawnedId=123;SpawnedStart=$baseStart;Expected='*identity changed*'},
    [pscustomobject]@{Name='wrong start time';ObservedId=123;ObservedStart=$baseStart.AddSeconds(1);ObservedPath=$expectedPath;SpawnedId=123;SpawnedStart=$baseStart;Expected='*lifetime changed*'},
    [pscustomobject]@{Name='wrong executable path';ObservedId=123;ObservedStart=$baseStart;ObservedPath='C:\Geph\other.exe';SpawnedId=123;SpawnedStart=$baseStart;Expected='*does not match*'}
)) {
    Test-Case ('Startup refuses '+$case.Name+' without changing the session') {
        Reset-ProcessFixture
        $observed=Add-TestProcess $case.ObservedId $case.ObservedStart $case.ObservedPath
        $spawned=[IdentitySafeguardsTestProcess]::new($case.SpawnedId,$case.SpawnedStart,$expectedPath)
        $session=[pscustomobject]@{Tunnel=$null}
        Assert-Throws {Set-GephTunVerifiedSpawnIdentity $session $spawned $expectedPath} $case.Expected
        Assert-True ($null -eq $session.Tunnel -and $spawned.Disposed -and $observed.Disposed) 'Bad startup identity was committed or a process handle was retained.'
    }
}

Test-Case 'The real startup path verifies identity before its next session save' {
    $startDefinition=$moduleAst.Find({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Start-GephTunSession'},$true)
    if($null -eq $startDefinition){throw 'Start-GephTunSession was not found.'}
    $commands=$startDefinition.Body.FindAll({param($node)$node -is [Management.Automation.Language.CommandAst]},$true)
    $launch=@($commands|Where-Object {$_.GetCommandName() -eq 'Start-Process'}|Select-Object -First 1)
    $verify=@($commands|Where-Object {$_.GetCommandName() -eq 'Set-GephTunVerifiedSpawnIdentity'}|Select-Object -First 1)
    if($launch.Count -ne 1 -or $verify.Count -ne 1){throw 'The startup launch or identity verification call was missing.'}
    $saveBetween=@($commands|Where-Object {$_.GetCommandName() -eq 'Save-GephTunSession' -and $_.Extent.StartOffset -gt $launch[0].Extent.StartOffset -and $_.Extent.StartOffset -lt $verify[0].Extent.StartOffset})
    $save=@($commands|Where-Object {$_.GetCommandName() -eq 'Save-GephTunSession' -and $_.Extent.StartOffset -gt $verify[0].Extent.StartOffset}|Select-Object -First 1)
    Assert-True ($launch[0].Extent.StartOffset -lt $verify[0].Extent.StartOffset -and $saveBetween.Count -eq 0 -and $save.Count -eq 1) 'Startup persisted session state before identity verification.'
    Assert-True (-not [regex]::IsMatch($startDefinition.Extent.Text,'\$script:Session\.Tunnel\s*=')) 'Startup assigned the tunnel identity outside the verification helper.'
}

Test-Case 'Unknown process identity remains UNKNOWN and liveness retains three attempts' {
    Reset-ProcessFixture
    for($i=0;$i -lt 3;$i++){$script:ProcessQueue.Enqueue({throw [UnauthorizedAccessException]::new('access denied')})}
    $saved=[pscustomobject]@{Id=42;StartUtc=$baseStart.ToString('o');Path=$expectedPath}
    Assert-True ((Get-GephTunProcessIdentityState $saved) -ceq 'UNKNOWN') 'An access-denied identity was not kept UNKNOWN.'
    Reset-ProcessFixture
    for($i=0;$i -lt 3;$i++){$script:ProcessQueue.Enqueue({throw [UnauthorizedAccessException]::new('access denied')})}
    Assert-True (-not (Test-GephTunProcessIdentity $saved) -and $script:ProcessCalls -eq 3) 'UNKNOWN did not retain the existing three-attempt liveness behavior.'
}

foreach($badPath in @('relative.exe','C:\')) {
    Test-Case ('A malformed process path remains UNKNOWN: '+$badPath) {
        Reset-ProcessFixture
        $process=Add-TestProcess 42 $baseStart $badPath
        $saved=[pscustomobject]@{Id=42;StartUtc=$baseStart.ToString('o');Path=$expectedPath}
        Assert-True ((Get-GephTunProcessIdentityState $saved) -ceq 'UNKNOWN') 'A malformed process path was classified as DEAD or ALIVE.'
        Assert-True ($script:ProcessCalls -eq 1 -and $script:RetryWaits -eq 0 -and $process.Disposed) 'Malformed path validation retried or retained a process handle.'
    }
}

Test-Case 'A process-not-found observation remains DEAD' {
    Reset-ProcessFixture
    $script:ProcessQueue.Enqueue({Write-Error -Message 'process exited' -Category ObjectNotFound -ErrorAction Stop})
    $saved=[pscustomobject]@{Id=42;StartUtc=$baseStart.ToString('o');Path=$expectedPath}
    Assert-True ((Get-GephTunProcessIdentityState $saved) -ceq 'DEAD' -and $script:ProcessCalls -eq 1) 'A process-not-found result was not classified as DEAD.'
}

Test-Case 'Recovery stays bounded and leaves persistent protection in place after policy failure' {
    $script:Session=[pscustomobject]@{Token='fixture'}
    $script:ProtectionLease=[pscustomobject]@{Open=$true}
    $script:RecoveryCalls=0;$script:RecoveryDelays=New-Object 'Collections.Generic.List[int]';$script:LeaseCloses=0;$script:RecoveryStatus='';$script:PersistentPolicy='Enabled'
    function Restore-GephTunSession {$script:RecoveryCalls++;throw 'Injected cleanup and policy failure'}
    function Write-GephTunLog([string]$Message) {}
    function Test-GephTunRecoveryCancelled {$false}
    function Wait-GephTunRecoveryDelay([int]$Milliseconds){$script:RecoveryDelays.Add($Milliseconds)}
    function Close-GephTunProtectionLease {$script:LeaseCloses++;$script:ProtectionLease=$null}
    function Set-GephTunStatus([string]$Status,[string]$Message){$script:RecoveryStatus=$Status+':'+$Message}
    Assert-Throws {Wait-GephTunRecovery} '*persistent protection was not disabled*'
    Assert-True ($script:RecoveryCalls -eq 3 -and ($script:RecoveryDelays -join ',') -eq '1000,2000') 'Recovery retry count or backoff changed.'
    Assert-True ($null -ne $script:Session -and $script:LeaseCloses -eq 1 -and $null -eq $script:ProtectionLease -and $script:PersistentPolicy -ceq 'Enabled') 'Recovery lost its journal, retained temporary permissions, or disabled persistent protection.'
    Assert-True ($script:RecoveryStatus -like 'RecoveryRequired:*') 'Recovery did not report the retained protection state.'
}

$failed=@($results|Where-Object {$_.Result -eq 'FAIL'})
$report=[pscustomobject]@{Schema=1;Total=$results.Count;Results=$results.ToArray();Passed=($results.Count-$failed.Count);Failed=$failed.Count}
$json=ConvertTo-Json -InputObject $report -Depth 8
if($ResultJson){Set-Content -LiteralPath $ResultJson -Value $json -Encoding UTF8}
Write-Output $json
if($failed.Count -gt 0){exit 1}
