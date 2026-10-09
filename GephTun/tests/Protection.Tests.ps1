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
} finally {if($null -ne $module){Remove-Module $module -Force}}
$failed=@($results|Where-Object Result -eq 'FAIL').Count
$report=[ordered]@{Version='1.5.0';CapturedUtc=[DateTime]::UtcNow.ToString('o');Scope='Actual PowerShell lease lifecycle with doubles. No native WFP calls or OS changes.';Total=$results.Count;Passed=$results.Count-$failed;Failed=$failed;Skipped=0;Tests=$results.ToArray()}
if($ResultJson){$output=Get-GephPackageFullPath $ResultJson;Assert-GephPackageOutput $output (Get-GephPackageFullPath $PackageDirectory);Write-GephPackageNewJson $output $report}
$results|Format-Table -AutoSize -Wrap
if($failed){exit 1}
