#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateRange(1,3600)][int]$DurationSeconds=240,
    [ValidateRange(100,10000)][int]$SampleMilliseconds=1000,
    [ValidateRange(0,10000)][int]$ForceGcEvery=0,
    [string]$FirewallRuleName,
    [string]$RemoteAddress='1.1.1.1',
    [string]$ResultJson
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Diagnostics.Common.ps1')
$parsed=$null
if(-not [Net.IPAddress]::TryParse($RemoteAddress,[ref]$parsed)){throw 'RemoteAddress must be an IP address; the diagnostic never resolves or contacts it.'}
$queries=[ordered]@{
    Processes={Get-CimInstance Win32_Process -Filter "Name LIKE 'geph%'" -ErrorAction Stop}
    Udp={Get-NetUDPEndpoint -ErrorAction Stop}
    Tcp={Get-NetTCPConnection -ErrorAction Stop}
    Routes={Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop}
    Adapters={Get-NetAdapter -ErrorAction Stop}
    SelectedRoute={Find-NetRoute -RemoteIPAddress $RemoteAddress -ErrorAction Stop}
    DnsRules={Get-DnsClientNrptRule -ErrorAction Stop}
    EffectiveDns={Get-DnsClientNrptPolicy -Effective -ErrorAction Stop}
}
if($FirewallRuleName){
    $queries.Firewall={
        $rule=Get-NetFirewallRule -Name $FirewallRuleName -ErrorAction Stop
        $null=$rule|Get-NetFirewallAddressFilter -ErrorAction Stop
        $null=$rule|Get-NetFirewallApplicationFilter -ErrorAction Stop
        $null=$rule|Get-NetFirewallServiceFilter -ErrorAction Stop
        $null=$rule|Get-NetFirewallPortFilter -ErrorAction Stop
        $null=$rule|Get-NetFirewallInterfaceFilter -ErrorAction Stop
        $null=Get-NetFirewallRule -Name $FirewallRuleName -PolicyStore PersistentStore -ErrorAction Stop
    }
}
$samples=[Collections.Generic.List[object]]::new()
$timer=[Diagnostics.Stopwatch]::StartNew();$iterations=0;$gcCount=0
do{
    $iterations++;$checks=@(foreach($name in $queries.Keys){
        try{$null=& $queries[$name];[pscustomobject]@{Name=$name;Result='READ';Error=''}}
        catch{[pscustomobject]@{Name=$name;Result='UNKNOWN';Error=$_.Exception.Message}}
    })
    if($ForceGcEvery -gt 0 -and $iterations%$ForceGcEvery -eq 0){
        [GC]::Collect();[GC]::WaitForPendingFinalizers();[GC]::Collect();$gcCount++
    }
    $samples.Add([pscustomobject]@{CapturedUtc=[DateTime]::UtcNow.ToString('o');Iteration=$iterations;ElapsedSeconds=$timer.Elapsed.TotalSeconds;ForcedCollections=$gcCount;Process=(Get-DiagnosticProcess $PID);Queries=$checks})
    $remaining=$DurationSeconds-$timer.Elapsed.TotalSeconds
    if($remaining -le 0){break}
    [Threading.Thread]::Sleep([int][Math]::Min($SampleMilliseconds,$remaining*1000))
}while($true)
$timer.Stop()
Write-DiagnosticResult ([ordered]@{Kind='GephTunCimWorkload';CapturedUtc=[DateTime]::UtcNow.ToString('o');Samples=$samples.ToArray();Scope='Read-only provider workload in this process; proxy memory observations do not prove a product leak.'}) $ResultJson
