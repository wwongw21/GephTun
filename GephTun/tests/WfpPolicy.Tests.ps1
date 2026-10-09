#Requires -Version 5.1
# Pure policy-plan assertions and Marshal layout checks. Does NOT call WFP or alter networking.
[CmdletBinding()]
param([string]$PackageDirectory,[string]$ResultJson)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
if(-not $PackageDirectory){$PackageDirectory=Split-Path -Parent $PSScriptRoot}
. (Join-Path $PSScriptRoot 'Package.Common.ps1')
if('GephTun.Security.WfpPolicy' -as [type]){throw 'Run this suite in a fresh process.'}
$source=Join-Path $PackageDirectory 'GephTun.Wfp.cs'
$options=@{Path=$source;ErrorAction='Stop'}
if($PSVersionTable.PSVersion.Major -ge 6){$options.CompilerOptions='/langversion:5'}
Add-Type @options
$results=New-Object 'Collections.Generic.List[object]'
function Assert-True($Value,[string]$Message){if(-not $Value){throw $Message}}
function Test-Case($Name,[scriptblock]$Body){try{& $Body;$results.Add([pscustomobject]@{Name=$Name;Result='PASS';Detail=''})}catch{$results.Add([pscustomobject]@{Name=$Name;Result='FAIL';Detail=$_.Exception.Message})}}
$policy=[GephTun.Security.WfpPolicy]
$base=@($policy::Baseline('C:\Windows\System32\svchost.exe'))
$transport=@($policy::Transport([string[]]@('C:\Geph\geph5-client.exe'),[System.UInt64[]]@(111)))
$tunnel=@($policy::Tunnel(222))
function Evaluate($Rules,[guid]$Layer,[hashtable]$Packet){
    $matches=@(foreach($rule in $Rules){
        if($rule.Boot -or $rule.Layer -ne $Layer){continue}
        $ok=$true
        foreach($c in $rule.Conditions){
            $key=$c.Field.ToString()
            if(-not $Packet.ContainsKey($key)){$ok=$false;break}
            $value=$Packet[$key]
            if($c.Type -eq 12){if($value -cne $c.Image){$ok=$false;break}}
            elseif($c.Type -eq 257){
                $bytes=[Net.IPAddress]::Parse([string]$value).GetAddressBytes();$bits=[int]$c.Bytes[16]
                if($bytes.Length -ne 16){$ok=$false;break}
                for($i=0;$i -lt 16 -and $bits -gt 0;$i++){
                    $n=[Math]::Min(8,$bits);$mask=(255 -shl (8-$n)) -band 255
                    if(($bytes[$i] -band $mask) -ne ($c.Bytes[$i] -band $mask)){$ok=$false;break};$bits-=$n
                }
            }
            elseif($c.Match -eq 6){if(([System.UInt64]$value -band $c.Number) -ne $c.Number){$ok=$false;break}}
            elseif($c.Match -eq 8){if(([System.UInt64]$value -band $c.Number) -ne 0){$ok=$false;break}}
            elseif([System.UInt64]$value -ne $c.Number){$ok=$false;break}
        }
        if($ok){$rule}
    })
    $matches=@($matches | Sort-Object Weight -Descending)
    if($matches.Count -eq 0){return 'NO_POLICY'}
    if($matches[0].Permit){return 'PERMIT'};return 'BLOCK'
}
function Packet([string]$Image='C:\Other\browser.exe',[int]$Protocol=6,[System.UInt64]$Local=111,[System.UInt64]$Next=111,[int]$Flags=0){
    $packet=@{}
    $packet[$policy::App.ToString()]=$Image
    $packet[$policy::Protocol.ToString()]=$Protocol
    $packet[$policy::LocalInterface.ToString()]=$Local
    $packet[$policy::NextHop.ToString()]=$Next
    $packet[$policy::Arrival.ToString()]=$Next
    $packet[$policy::Flags.ToString()]=$Flags
    $packet[$policy::LocalPort.ToString()]=51000
    $packet[$policy::RemotePort.ToString()]=443
    $packet[$policy::RemoteAddress.ToString()]='2001:db8::1'
    return $packet
}
Test-Case 'Lease LUID types resolve on PowerShell 5.1 and match the native managed signature' {
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PackageDirectory 'GephTun.Protection.ps1'),[ref]$tokens,[ref]$errors)
    Assert-True ($errors.Count -eq 0) 'Protection module failed to parse.'
    $legacyAliases=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.TypeConstraintAst] -and $node.TypeName.FullName -match '^(ulong|ushort|uint)(\[\])?$'},$true))
    Assert-True ($legacyAliases.Count -eq 0) 'A PowerShell 7-only unsigned alias was reintroduced into runtime protection.'
    $types=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.TypeConstraintAst] -and $node.TypeName.FullName -eq 'System.UInt64[]'},$true))
    Assert-True ($types.Count -eq 1 -and $types[0].TypeName.GetReflectionType() -eq [System.UInt64[]]) 'Runtime LUID conversion does not resolve to the exact UInt64 array type.'
    $method=[GephTun.Security.WfpController].GetMethod('OpenLease')
    Assert-True ($method.GetParameters()[1].ParameterType -eq [System.UInt64[]]) 'Native managed lease signature differs from the PowerShell conversion.'
    Assert-True (([System.UInt64[]]@(111)).GetType() -eq [System.UInt64[]]) 'The policy-plan fixture cannot construct portable unsigned LUIDs.'
}
Test-Case 'x64 native layouts match the declared SDK offsets' {[GephTun.Security.WfpController]::AssertLayout()}
Test-Case 'All rule keys are unique and weights are legal range indexes' {
    $all=@($base+$transport+$tunnel)
    Assert-True (@($all.Key|Sort-Object -Unique).Count -eq $all.Count) 'Duplicate rule key.'
    Assert-True (@($all|Where-Object {$_.Weight -gt 15}).Count -eq 0) 'Illegal FWP_UINT8 weight.'
}
Test-Case 'Boot plan has four non-loopback IP blocking rules and no permits' {
    $boot=@($base|Where-Object Boot)
    Assert-True ($boot.Count -eq 4 -and @($boot|Where-Object Permit).Count -eq 0) 'Boot policy is not closed.'
    foreach($r in $boot){Assert-True ($r.Conditions.Count -eq 1 -and $r.Conditions[0].Match -eq 8 -and $r.Conditions[0].Number -eq 1) 'Unexpected boot exception.'}
}
foreach($family in @('Connect4','Connect6','Accept4','Accept6','Forward4','Forward6')){
    Test-Case ('Disconnected '+$family+' has a deny fallback'){
        $layer=[GephTun.Security.WfpPolicy].GetField($family).GetValue($null)
        Assert-True ((Evaluate $base $layer (Packet)) -eq 'BLOCK') 'Direct traffic was permitted.'
    }
}
foreach($protocol in @(6,17,1,58)){
    Test-Case ('Ordinary physical protocol '+$protocol+' remains blocked with a live Geph lease'){
        Assert-True ((Evaluate ($base+$transport+$tunnel) $policy::Connect4 (Packet -Protocol $protocol)) -eq 'BLOCK') 'Ordinary direct traffic escaped.'
    }
}
Test-Case 'Geph TCP is permitted only on its approved physical path' {
    Assert-True ((Evaluate ($base+$transport) $policy::Connect4 (Packet -Image 'C:\Geph\geph5-client.exe')) -eq 'PERMIT') 'Expected transport permit absent.'
    Assert-True ((Evaluate ($base+$transport) $policy::Connect4 (Packet -Image 'C:\Geph\geph5-client.exe' -Next 333)) -eq 'BLOCK') 'New unapproved interface inherited permission.'
}
Test-Case 'The same remote IP does not grant a browser or PowerShell transport permission' {
    foreach($image in @('C:\Other\browser.exe','C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe')){
        Assert-True ((Evaluate ($base+$transport) $policy::Connect4 (Packet -Image $image)) -eq 'BLOCK') 'Destination route became a global permit.'
    }
}
Test-Case 'Geph UDP is not silently enabled' {Assert-True ((Evaluate ($base+$transport) $policy::Connect4 (Packet -Image 'C:\Geph\geph5-client.exe' -Protocol 17)) -eq 'BLOCK') 'Unsupported UDP allowed.'}
Test-Case 'Tunnel TCP requires both current local and next-hop LUID' {
    Assert-True ((Evaluate ($base+$transport+$tunnel) $policy::Connect4 (Packet -Local 222 -Next 222)) -eq 'PERMIT') 'Tunnel TCP not permitted.'
    Assert-True ((Evaluate ($base+$transport+$tunnel) $policy::Connect4 (Packet -Local 222 -Next 111)) -eq 'BLOCK') 'A tunnel-sourced direct fallback was allowed.'
    Assert-True ((Evaluate ($base+$transport+$tunnel) $policy::Connect4 (Packet -Local 444 -Next 444)) -eq 'BLOCK') 'A stale or unrelated tunnel was allowed.'
}
Test-Case 'Removing the temporary tunnel plan restores blocking' {Assert-True ((Evaluate ($base+$transport) $policy::Connect4 (Packet -Local 222 -Next 222)) -eq 'BLOCK') 'Persistent fallback missing.'}
Test-Case 'Removing every temporary permission also blocks Geph internet' {Assert-True ((Evaluate $base $policy::Connect4 (Packet -Image 'C:\Geph\geph5-client.exe')) -eq 'BLOCK') 'Worker death would retain Geph permission.'}
Test-Case 'Arrival-interface alternative requires reauthorization' {
    $p=Packet -Local 222 -Next 0;$p[$policy::Arrival.ToString()]=222
    Assert-True ((Evaluate ($base+$tunnel) $policy::Connect4 $p) -eq 'BLOCK') 'Arrival condition alone permitted a new connection.'
    $p[$policy::Flags.ToString()]=4
    Assert-True ((Evaluate ($base+$tunnel) $policy::Connect4 $p) -eq 'PERMIT') 'Expected inbound reauthorization alternative missing.'
}
Test-Case 'Application IPv6 remains blocked even with a live IPv4 tunnel' {Assert-True ((Evaluate ($base+$transport+$tunnel) $policy::Connect6 (Packet -Local 222 -Next 222)) -eq 'BLOCK') 'Application IPv6 was allowed.'}
Test-Case 'DHCP permit is restricted to system host, UDP and client/server ports' {
    $p=Packet -Image 'C:\Windows\System32\svchost.exe' -Protocol 17
    $p[$policy::LocalPort.ToString()]=68;$p[$policy::RemotePort.ToString()]=67
    Assert-True ((Evaluate $base $policy::Connect4 $p) -eq 'PERMIT') 'DHCP maintenance missing.'
    $p[$policy::RemotePort.ToString()]=53
    Assert-True ((Evaluate $base $policy::Connect4 $p) -eq 'BLOCK') 'DHCP exception became direct DNS permission.'
}
Test-Case 'IPv6 neighbor maintenance does not permit global ICMPv6' {
    $p=Packet -Protocol 58;$p[$policy::LocalPort.ToString()]=135;$p[$policy::RemotePort.ToString()]=0
    $p[$policy::RemoteAddress.ToString()]='ff02::1:ff00:1'
    Assert-True ((Evaluate $base $policy::Connect6 $p) -eq 'PERMIT') 'Neighbor discovery permit missing.'
    $p[$policy::RemoteAddress.ToString()]='2001:db8::1'
    Assert-True ((Evaluate $base $policy::Connect6 $p) -eq 'BLOCK') 'Global ICMPv6 was permitted.'
}
Test-Case 'Loopback remains available while disconnected' {Assert-True ((Evaluate $base $policy::Connect4 (Packet -Flags 1)) -eq 'PERMIT') 'Loopback missing.'}
Test-Case 'Zero interface and empty transport lists are rejected' {
    $rejected=0
    try{$null=$policy::Tunnel(0)}catch{$rejected++}
    try{$null=$policy::Transport([string[]]@(),[System.UInt64[]]@(111))}catch{$rejected++}
    try{$null=$policy::Transport([string[]]@('C:\Geph\geph.exe'),[System.UInt64[]]@(0))}catch{$rejected++}
    Assert-True ($rejected -eq 3) 'Unsafe inputs were accepted.'
}
$failed=@($results|Where-Object Result -eq 'FAIL').Count
$report=[ordered]@{Version='1.5.0';CapturedUtc=[DateTime]::UtcNow.ToString('o');Scope='Actual managed WFP policy compiler inputs and Marshal layouts. NO native WFP API, installed filters, or leak test.';SourceSha256=(Get-FileHash $source -Algorithm SHA256).Hash;Total=$results.Count;Passed=$results.Count-$failed;Failed=$failed;Skipped=0;Tests=$results.ToArray()}
if($ResultJson){$output=Get-GephPackageFullPath $ResultJson;Assert-GephPackageOutput $output (Get-GephPackageFullPath $PackageDirectory);Write-GephPackageNewJson $output $report}
$results|Format-Table -AutoSize -Wrap
if($failed){exit 1}
