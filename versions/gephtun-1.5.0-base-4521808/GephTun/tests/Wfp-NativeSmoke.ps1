#Requires -Version 5.1
#Requires -RunAsAdministrator
<# DESTRUCTIVE NETWORK TEST. Not part of Run-UpdateValidation.ps1.
   Requires a disposable Windows VM, snapshot and LOCAL console.
   Temporarily installs persistent/boot blocking. No scheduled unlock or service.
   A successful smoke test is NOT crash/reboot/leak qualification.
#>
[CmdletBinding()]
param([switch]$AllowNetworkDisruption,[Parameter(Mandatory=$true)][string]$ResultJson)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
if(-not $AllowNetworkDisruption){throw 'Read WINDOWS-ACCEPTANCE.md, use a disposable VM/local console, then specify -AllowNetworkDisruption.'}
if($env:SESSIONNAME -like 'RDP-*'){throw 'Do not run this test through Remote Desktop. Use the VM local console.'}
$root=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Package.Common.ps1')
$output=Get-GephPackageFullPath $ResultJson
Assert-GephPackageOutput $output (Get-GephPackageFullPath $root)
if(Test-Path -LiteralPath $output){throw 'Result path already exists.'}
if((Read-Host 'Snapshot ready, emergency unlock files retained locally? Type TEST BLOCKING') -cne 'TEST BLOCKING'){throw 'Cancelled before any WFP change.'}
if('GephTun.Security.WfpController' -as [type]){throw 'Run in a fresh PowerShell process.'}
Add-Type -Path (Join-Path $root 'GephTun.Wfp.cs')
$guard=New-Object Threading.Mutex($false,'Global\GephTun-Session-v1')
$owned=$false
try {
    try {$owned=$guard.WaitOne(0)} catch [Threading.AbandonedMutexException] {$owned=$true}
    if(-not $owned){throw 'Another GephTun operation is active. No test policy was installed.'}
$initial=[GephTun.Security.WfpController]::Inspect()
if($initial.State -ne 'Disabled'){throw 'Existing protection must not be changed by a test. Disable it explicitly first or use a fresh VM.'}
$installed=$false;$failure=$null;$cleanupError=$null;$observed=$null
try {
    $installed=$true;[GephTun.Security.WfpController]::Enable()
    $observed=[GephTun.Security.WfpController]::Inspect()
    if($observed.State -ne 'Enabled' -or $observed.PersistentFilters -le 0 -or $observed.TemporaryFilters -ne 0){throw 'Installed baseline was not verified.'}
    # Verify that a literal public-IP TCP connection is rejected. No DNS lookup or
    # credentials; an unavailable remote is not proof of blocking, so this remains
    # a smoke observation only, NOT a packet-level leak assertion.
    $client=New-Object Net.Sockets.TcpClient
    try {
        $pending=$client.BeginConnect('1.1.1.1',443,$null,$null)
        if($pending.AsyncWaitHandle.WaitOne(3000)){
            try{$client.EndConnect($pending)}catch{}
        }
        if($client.Connected){throw 'A direct TCP connection succeeded under the disconnected baseline.'}
    } finally {$client.Close()}
} catch {$failure=$_.Exception.Message}
finally {
    if($installed){try{[GephTun.Security.WfpController]::Disable($true)}catch{$cleanupError=$_.Exception.Message}}
}
$report=[ordered]@{Version='1.5.0';CapturedUtc=[DateTime]::UtcNow.ToString('o');Scope='Opt-in actual native WFP install/enumerate/remove smoke only. No crash/reboot/packet capture qualification.';Initial=$initial;InstalledObservation=$observed;Failure=$failure;CleanupError=$cleanupError;Result=$(if($failure -or $cleanupError){'FAIL'}else{'PASS'})}
Write-GephPackageNewJson $output $report
$report|ConvertTo-Json -Depth 8
if($cleanupError){Write-Warning 'NETWORK MAY STILL BE BLOCKED. Run Emergency-Unlock-GephTun.ps1 -AllowDirectInternet from the local console; retain the folder.'}
if($failure -or $cleanupError){exit 1}

} finally {if($owned){$guard.ReleaseMutex()};$guard.Dispose()}
