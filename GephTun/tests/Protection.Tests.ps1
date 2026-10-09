#Requires -Version 5.1
# Module-level lease lifecycle checks. All native WFP behavior is a test double.
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
        $script:ProtectionObserved='Enabled'
        $lease=[pscustomobject]@{Closed=$false;Revoked=$false;VerifyFailure=$false;RevokeFailure=$false;Checks=0}
        $lease|Add-Member ScriptMethod Verify { $this.Checks++;if($this.VerifyFailure){throw 'Injected missing WFP baseline'} }
        $lease|Add-Member ScriptMethod RevokeTunnel {if($this.RevokeFailure){throw 'Injected revoke failure'};$this.Revoked=$true}
        $lease|Add-Member ScriptMethod Dispose {$this.Closed=$true}
        $script:FixtureLease=$lease;$script:ProtectionLease=$lease
        function script:Initialize-GephTunWfpTypes {throw 'Unexpected real native WFP call'}
        function script:Get-GephTunLock {throw 'Consent must be checked before any global state change'}
        function script:Request-GephTunDisconnect {throw 'Consent must be checked before disconnecting'}
    }
}
function Initialize-StartFixture {
    & $module {
        $script:Session=$null;$script:ProtectionLease=$null
        $script:S=[pscustomobject]@{Stage='';Restores=0;Saves=0;OpenFailure=$false;RecoveryFailure=$false;PersistentRemovals=0;PendingJournal=$false;ProcessStarted=$false}
        function script:Open-GephTunProtectionLease {$script:ProtectionLease=$script:FixtureLease;if($script:S.OpenFailure){throw 'Injected partial lease initialization'}}
        function script:Assert-GephTunProtection {if($script:S.Stage -eq 'cancel'){throw [OperationCanceledException]::new('cancelled after lease acquisition')}}
        function script:Assert-GephTunConnectContinuing {}
        function script:Test-GephTunPreflight($Port) {
            if($script:S.Stage -eq 'preflight'){throw 'Injected preflight failure'}
            [pscustomobject]@{Proxy=[pscustomobject]@{Port=9909;Process=[pscustomobject]@{Id=44;Path='fixture-geph.exe'}};Network=[pscustomobject]@{Alias='wifi';InterfaceIndex=7;InterfaceGuid='wifi';Gateway='192.0.2.1'}}
        }
        function script:Get-GephTunOriginalRoutes {@()}
        function script:Get-GephTunProcessIdentity($Id) {[pscustomobject]@{Id=$Id;Path='fixture.exe';StartUtc='2026-10-09T00:00:00.1234567Z'}}
        function script:Initialize-GephTunBypassRegistry {}
        function script:Save-GephTunSession {$script:S.Saves++}
        function script:Register-GephTunBootGuard {}
        function script:Set-GephTunStatus($Status,$Message) {}
        function script:New-GephTunDnsRelay($Port) {[pscustomobject]@{Healthy=$true}}
        function script:Install-GephTunRememberedBypasses {}
        function script:Update-GephTunBypasses {}
        function script:Save-GephTunBypassCache {}
        function script:Install-GephTunContainment {}
        function script:Get-NetAdapter {[CmdletBinding()]param($Name) if(-not $script:S.ProcessStarted){return};if($script:S.Stage -eq 'adapter'){throw 'Injected adapter failure'};[pscustomobject]@{InterfaceIndex=22;InterfaceGuid='tunnel'}}
        function script:Get-GephTunRoot {[IO.Path]::GetTempPath()}
        function script:Start-Process {[CmdletBinding()]param($FilePath,$WorkingDirectory,$ArgumentList,[switch]$PassThru,$WindowStyle,$RedirectStandardOutput,$RedirectStandardError);$script:S.ProcessStarted=$true;[pscustomobject]@{Id=123}}
        function script:Test-GephTunProcessIdentity($Identity) {$true}
        function script:Disable-NetAdapterBinding {[CmdletBinding()]param($Name,$ComponentID)}
        function script:Set-NetIPInterface {[CmdletBinding()]param($InterfaceIndex,$AddressFamily,$Dhcp,$AutomaticMetric,$InterfaceMetric,$DadTransmits)}
        function script:New-NetIPAddress {[CmdletBinding()]param($InterfaceIndex,$AddressFamily,$IPAddress,$PrefixLength,$PolicyStore)}
        function script:Set-DnsClientServerAddress {[CmdletBinding()]param($InterfaceIndex,$ServerAddresses)}
        function script:Set-DnsClient {[CmdletBinding()]param($InterfaceIndex,$RegisterThisConnectionsAddress)}
        function script:Add-GephTunTunnelPermission {}
        function script:Add-GephTunOwnedRoute($Prefix,$Index,$Hop,$Kind) {$script:Session.Routes+=@([pscustomobject]@{DestinationPrefix=$Prefix;InterfaceIndex=$Index;NextHop=$Hop;Kind=$Kind})}
        function script:Add-DnsClientNrptRule {[CmdletBinding()]param($Namespace,$NameServers,$Comment)}
        function script:Clear-DnsClientCache {[CmdletBinding()]param()}
        function script:Resolve-DnsName {[CmdletBinding()]param($Name,$Type,$Server,[switch]$DnsOnly,[switch]$NoHostsFile)}
        function script:Test-GephTunDirectTunnel {if($script:S.Stage -eq 'probe'){throw 'Injected late probe failure'}}
        function script:Test-GephTunPhysicalNetwork {}
        function script:Test-GephTunDnsPolicy {}
        function script:Test-GephTunInstalledRoutes {}
        function script:Test-GephTunContainment {}
        function script:Write-GephTunLog($Message) {}
        function script:Restore-GephTunSession {$script:S.Restores++;if($script:S.RecoveryFailure){throw 'Injected retained journal'};$script:Session=$null}
    }
}
function Test-Case($Name,[scriptblock]$Body){New-Fixture;try{& $Body;$results.Add([pscustomobject]@{Name=$Name;Result='PASS';Detail=''})}catch{$results.Add([pscustomobject]@{Name=$Name;Result='FAIL';Detail=$_.Exception.Message})}}
try {
Test-Case 'Normal close disposes only the temporary lease' {
    & $module {Close-GephTunProtectionLease;Close-GephTunProtectionLease}
    Assert-True (& $module {$script:FixtureLease.Closed -and $null -eq $script:ProtectionLease -and $script:ProtectionObserved -eq 'Enabled'}) 'Close incorrectly unlocked persistent protection.'
}
Test-Case 'Policy verification failure closes permissions and reports Unknown' {
    $failed=& $module {$script:FixtureLease.VerifyFailure=$true;try{Assert-GephTunProtection;$false}catch{$true}}
    Assert-True $failed 'Missing policy was accepted.'
    Assert-True (& $module {$script:FixtureLease.Closed -and $script:ProtectionObserved -eq 'Unknown'}) 'Missing policy was reported as protected.'
}
Test-Case 'No lease cannot count as a verified protected session' {
    $failed=& $module {$script:ProtectionLease=$null;try{Assert-GephTunProtection;$false}catch{$true}}
    Assert-True $failed 'A session without owned permissions was accepted.'
}
Test-Case 'Tunnel authorization is revoked before session resources are cleaned' {
    & $module {Remove-GephTunTunnelPermission}
    Assert-True (& $module {$script:FixtureLease.Revoked -and -not $script:FixtureLease.Closed}) 'Revocation did not target the tunnel permission.'
}
Test-Case 'A revoke error closes the full temporary lease instead of retaining obsolete access' {
    $failed=& $module {$script:FixtureLease.RevokeFailure=$true;try{Remove-GephTunTunnelPermission;$false}catch{$true}}
    Assert-True $failed 'Revoke failure was suppressed.'
    Assert-True (& $module {$script:FixtureLease.Closed}) 'Obsolete temporary permission was retained.'
}
Test-Case 'Persistent blocking cannot be enabled without explicit consent' {
    $message=& $module {try{Enable-GephTunProtection -GephExecutable @('C:\Geph\geph.exe');''}catch{$_.Exception.Message}}
    Assert-True ($message -eq 'Enabling persistent blocking requires explicit confirmation.') 'Consent was not checked first.'
}
Test-Case 'Persistent protection cannot be removed without explicit consent' {
    $message=& $module {try{Disable-GephTunProtection;''}catch{$_.Exception.Message}}
    Assert-True ($message -eq 'Explicit confirmation to allow direct internet is required.') 'Unlock was attempted before consent.'
}
foreach($stage in @('preflight','cancel','adapter','probe')) {
Test-Case ('Actual failed session start closes its acquired lease: '+$stage) {
    Initialize-StartFixture
    $failed=& $module {param($Stage)$script:S.Stage=$Stage;try{Start-GephTunSession|Out-Null;''}catch{$_.Exception.Message}} $stage
    Assert-True ($failed -match $(if($stage -eq 'cancel'){'cancelled after lease acquisition'}else{'Injected .*'+$stage+' failure'})) ('Expected setup checkpoint was not reached: '+$failed)
    Assert-True (& $module {$script:FixtureLease.Closed -and $null -eq $script:ProtectionLease -and $script:ProtectionObserved -eq 'Enabled'}) 'Failed start retained permissions or changed persistent protection.'
}}
Test-Case 'A successful actual session start retains its own permissions' {
    Initialize-StartFixture
    $ok=& $module {Start-GephTunSession}
    Assert-True $ok.Success 'Successful isolated setup failed.'
    Assert-True (& $module {-not $script:FixtureLease.Closed -and $null -ne $script:Session -and $null -ne $script:ProtectionLease}) 'Successful setup lost session permissions.'
}
Test-Case 'A partially acquired lease is closed if acquisition throws' {
    Initialize-StartFixture
    $failed=& $module {$script:S.OpenFailure=$true;try{Start-GephTunSession|Out-Null;$false}catch{$true}}
    Assert-True $failed 'Partial initialization failure was ignored.'
    Assert-True (& $module {$script:FixtureLease.Closed -and $null -eq $script:ProtectionLease}) 'Partially acquired lease survived.'
}
Test-Case 'Failed rollback retains the session journal but closes newly owned permissions' {
    Initialize-StartFixture
    $failed=& $module {$script:S.Stage='probe';$script:S.RecoveryFailure=$true;try{Start-GephTunSession|Out-Null;$false}catch{$true}}
    Assert-True $failed 'Partial rollback failure was hidden.'
    Assert-True (& $module {$null -ne $script:Session -and $script:FixtureLease.Closed}) 'Rollback lost its journal or retained newly owned access.'
}
Test-Case 'A failed direct start cannot close a preexisting controller lease' {
    Initialize-StartFixture
    & $module {$script:ProtectionLease=$script:FixtureLease;$script:S.Stage='preflight';try{Start-GephTunSession|Out-Null}catch{}}
    Assert-True (& $module {-not $script:FixtureLease.Closed -and $null -ne $script:ProtectionLease}) 'Another owner lost its permissions.'
}
Test-Case 'Starting over an existing session is refused without modifying its lease' {
    & $module {$script:Session=[pscustomobject]@{Token='existing'};try{Start-GephTunSession|Out-Null;throw 'Unexpected success'}catch{if($_.Exception.Message -eq 'Unexpected success'){throw}}}
    Assert-True (& $module {-not $script:FixtureLease.Closed -and $script:Session.Token -eq 'existing'}) 'Existing session was damaged.'
}
foreach($mode in @('CleanupFailure','PendingJournal','Recovered')) {
Test-Case ('Explicit protection disable requires completed recovery: '+$mode) {
    Initialize-StartFixture
    $result=& $module {param($Mode)
        function script:Request-GephTunDisconnect {if($script:S.Stage -eq 'CleanupFailure'){throw 'Precise recovery blocker'}}
        function script:Get-GephTunLock {[pscustomobject]@{Fixture=$true}}
        function script:Release-GephTunLock($Mutex) {}
        function script:Test-Path {[CmdletBinding()]param($LiteralPath) $script:S.PendingJournal}
        function script:Initialize-GephTunWfpTypes {}
        function script:Remove-GephTunPersistentProtection {$script:S.PersistentRemovals++}
        function script:Read-GephTunJson($Path) {[pscustomobject]@{Requested='Enabled'}}
        function script:Write-GephTunJson($Path,$Value) {}
        function script:Get-GephTunProtectionStatus {[pscustomobject]@{State='Disabled'}}
        $script:S.Stage=$Mode;$script:S.PendingJournal=$Mode -eq 'PendingJournal'
        try{Disable-GephTunProtection -AllowDirectInternet|Out-Null;$true}catch{$false}
    } $mode
    Assert-True ($result -eq ($mode -eq 'Recovered')) 'Disable ignored recovery state.'
    Assert-True (& $module {param($Expected)$script:S.PersistentRemovals -eq $Expected} $(if($mode -eq 'Recovered'){1}else{0})) 'Persistent blocking was removed before explicit completed recovery.'
}}
Test-Case 'A failed Dispose retains ownership and can be retried safely' {
    & $module {$script:FixtureLease|Add-Member ScriptMethod Dispose {if(-not $this.Closed){$this.Closed=$true;throw 'Injected close uncertainty'}} -Force;try{Close-GephTunProtectionLease}catch{}}
    Assert-True (& $module {$null -ne $script:ProtectionLease}) 'Uncertain close discarded its owner.'
    & $module {Close-GephTunProtectionLease;Close-GephTunProtectionLease}
    Assert-True (& $module {$null -eq $script:ProtectionLease}) 'Repeated close did not settle.'
}
Test-Case 'JSON process identity round trip retains fractional seconds and offsets' {
    $ok=& $module {
        $start=[DateTimeOffset]::Parse('2026-10-09T05:45:00.1234567+05:45')
        $r=[pscustomobject]@{Worker=[pscustomobject]@{StartUtc=$start.ToString('o')}}|ConvertTo-Json|ConvertFrom-Json
        $r=ConvertFrom-GephTunJsonDates $r
        (ConvertTo-GephTunProcessStartUtc $r.Worker.StartUtc).Ticks -eq $start.UtcDateTime.Ticks
    }
    Assert-True $ok 'Typed timestamp normalization lost precision.'
}
foreach($timestamp in @('2026-10-09T00:00:00.1234567Z','2026-10-09T05:45:00.1234567+05:45','2026-10-08T20:30:00.1234567-03:30')) {
Test-Case ('Core identity accepts equivalent JSON timestamp: '+$timestamp) {
    $state=& $module {param($Timestamp)
        function script:Get-GephTunProcessIdentity($Id) {[pscustomobject]@{Path='powershell.exe';StartUtc='2026-10-09T00:00:00.1234567Z'}}
        $identity=[pscustomobject]@{Id=42;Path='PowerShell.exe';StartUtc=$Timestamp}|ConvertTo-Json|ConvertFrom-Json
        Get-GephTunProcessIdentityState $identity
    } $timestamp
    Assert-True ($state -eq 'ALIVE') 'Equivalent precise timestamp was not ALIVE.'
}}
foreach($timestamp in @('bad','2026-10-09T00:00:00.1234567','2026-10-09T00:00:00.12345678Z','2026-10-09T00:00:00+25:00')) {
Test-Case ('Malformed timestamp never permits process cleanup: '+$timestamp) {
    $state=& $module {param($Timestamp)Get-GephTunProcessIdentityState ([pscustomobject]@{Id=42;Path='powershell.exe';StartUtc=$Timestamp})} $timestamp
    Assert-True ($state -eq 'UNKNOWN') 'Malformed identity was declared dead.'
}}
Test-Case 'Unspecified DateTime and unreadable process metadata remain UNKNOWN' {
    $ok=& $module {
        $a=Get-GephTunProcessIdentityState ([pscustomobject]@{Id=42;Path='powershell.exe';StartUtc=[DateTime]::SpecifyKind([DateTime]::UtcNow,[DateTimeKind]::Unspecified)})
        function script:Get-GephTunProcessIdentity($Id) {throw [UnauthorizedAccessException]::new('Fixture access denied')}
        $b=Get-GephTunProcessIdentityState ([pscustomobject]@{Id=42;Path='powershell.exe';StartUtc='2026-10-09T00:00:00Z'})
        $a -eq 'UNKNOWN' -and $b -eq 'UNKNOWN'
    }
    Assert-True $ok 'Uncertain process metadata authorized cleanup.'
}
Test-Case 'Actual process exit is DEAD and one tick of PID reuse is DEAD' {
    $ok=& $module {
        $idRecord=[pscustomobject]@{Id=42;Path='powershell.exe';StartUtc='2026-10-09T00:00:00.1234567Z'}
        function script:Get-GephTunProcessIdentity($Id) {throw [ArgumentException]::new('Fixture missing process')}
        $a=Get-GephTunProcessIdentityState $idRecord
        function script:Get-GephTunProcessIdentity($Id) {[pscustomobject]@{Path='powershell.exe';StartUtc='2026-10-09T00:00:00.1234568Z'}}
        $b=Get-GephTunProcessIdentityState $idRecord
        $a -eq 'DEAD' -and $b -eq 'DEAD'
    }
    Assert-True $ok 'Dead/reused process was not distinguished from uncertainty.'
}
} finally {if($null -ne $module){Remove-Module $module -Force}}
$failed=@($results|Where-Object Result -eq 'FAIL').Count
$report=[ordered]@{Version='1.5.0';CapturedUtc=[DateTime]::UtcNow.ToString('o');Scope='Actual PowerShell lease lifecycle with doubles. No native WFP calls or OS changes.';Total=$results.Count;Passed=$results.Count-$failed;Failed=$failed;Skipped=0;Tests=$results.ToArray()}
if($ResultJson){$output=Get-GephPackageFullPath $ResultJson;Assert-GephPackageOutput $output (Get-GephPackageFullPath $PackageDirectory);Write-GephPackageNewJson $output $report}
$results|Format-Table -AutoSize -Wrap
if($failed){exit 1}
