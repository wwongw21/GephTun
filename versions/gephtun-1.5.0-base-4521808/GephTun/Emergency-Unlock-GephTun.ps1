#Requires -Version 5.1
# Manual escape hatch. No service, scheduled unlock, force-kill or global firewall reset.
# Requires the local source file but NOT ProgramData, Core, the GUI or a valid journal.
[CmdletBinding()]
param([switch]$AllowDirectInternet)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
try {
    if (-not $AllowDirectInternet) { throw 'This explicitly removes GephTun blocking. First try normal Disconnect / Recover and Disable protection. To confirm direct internet exposure, run with -AllowDirectInternet.' }
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess) { throw 'Use 64-bit Windows PowerShell as administrator.' }
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    try { if (-not ([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator approval is required.' } }
    finally {$id.Dispose()}
    if (-not ('GephTun.Security.WfpController' -as [type])) {Add-Type -Path (Join-Path $PSScriptRoot 'GephTun.Wfp.cs')}
    [GephTun.Security.WfpController]::Disable($true)
    [GephTun.Security.WfpController]::Inspect() | ConvertTo-Json
    Write-Warning 'GephTun WFP blocking is removed. This script does not repair orphaned routes/DNS or delete the recovery journal. Run Disconnect / Recover afterward. No general Windows Firewall policy was reset.'
} catch {Write-Error $_ -ErrorAction Continue;exit 1}
