#Requires -Version 5.1
# In-memory protocol regression; no sockets, administrator rights or trust changes.
[CmdletBinding()]
param([string]$PackageDirectory, [string]$ResultJson)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
if(-not $PackageDirectory){$PackageDirectory=Split-Path -Parent $PSScriptRoot}
if('GephTun.ProxyProbe' -as [type]){throw 'Run this suite in a fresh PowerShell process.'}
$source=Join-Path $PackageDirectory 'GephTun.Network.cs'
if($PSVersionTable.PSVersion.Major -ge 6){Add-Type -Path $source -CompilerOptions '/langversion:5'}else{Add-Type -Path $source}
$type=[GephTun.ProxyProbe].Assembly.GetType('GephTun.DnsProtocol',$true)
$method=$type.GetMethod('RemoveIpv6Records',[Reflection.BindingFlags]'Static,NonPublic')
if($null -eq $method){throw 'The actual DNS filter could not be found.'}
function U16([byte[]]$Data,[int]$Offset){
    if($Offset -lt 0 -or $Offset+2 -gt $Data.Length){throw 'Truncated field.'}
    return (([int]$Data[$Offset] -shl 8) -bor [int]$Data[$Offset+1])
}
function Skip-Name([byte[]]$Data,[int]$Offset){
    while($Offset -lt $Data.Length){
        $length=[int]$Data[$Offset]
        if($length -eq 0){return $Offset+1}
        if(($length -band 192) -eq 192){if($Offset+2 -gt $Data.Length){throw 'Truncated pointer.'};return $Offset+2}
        if($length -gt 63 -or $Offset+1+$length -gt $Data.Length){throw 'Invalid name.'}
        $Offset+=1+$length
    }
    throw 'Unterminated name.'
}
$cases=(Get-Content -LiteralPath (Join-Path $PSScriptRoot 'dns-mandatory-fixtures.json') -Raw -Encoding UTF8 | ConvertFrom-Json).Tests
$results=New-Object 'Collections.Generic.List[object]'
foreach($case in $cases){
    try{
        $inputBytes=[Convert]::FromBase64String($case.WireBase64)
        $arguments=[object[]]::new(1);$arguments[0]=$inputBytes
        $outputBytes=[byte[]]$method.Invoke($null,$arguments)
        $count=U16 $outputBytes 6
        if($count -ne $case.ExpectedAnswers){throw ('Expected '+$case.ExpectedAnswers+' answers; got '+$count)}
        if($count -gt 0){
            $header=Skip-Name $outputBytes ((Skip-Name $outputBytes 12)+4)
            $recordType=U16 $outputBytes $header
            if($case.PSObject.Properties['ExpectedType']){
                if($recordType -ne $case.ExpectedType){throw 'An unrelated record was not preserved.'}
                $rdlen=U16 $outputBytes ($header+8)
                if($rdlen -ne 4 -or ([Net.IPAddress]::new([byte[]]$outputBytes[($header+10)..($header+13)])).ToString() -ne '192.0.2.42'){throw 'The unrelated A value changed.'}
            }
            else{
                if($recordType -notin @(64,65)){throw 'Expected a service-binding record.'}
                $end=$header+10+(U16 $outputBytes ($header+8))
                $offset=Skip-Name $outputBytes ($header+12)
                $keys=New-Object 'Collections.Generic.List[int]'
                $mandatory=New-Object 'Collections.Generic.List[int]'
                while($offset -lt $end){
                    $key=U16 $outputBytes $offset;$length=U16 $outputBytes ($offset+2);$value=$offset+4
                    if($value+$length -gt $end){throw 'Output SvcParam is truncated.'}
                    $keys.Add($key)
                    if($key -eq 0){for($i=0;$i -lt $length;$i+=2){$mandatory.Add((U16 $outputBytes ($value+$i)))}}
                    if($key -eq 1 -and ([Convert]::ToBase64String([byte[]]$outputBytes[$value..($value+$length-1)])) -ne 'Amgy'){throw 'The ALPN value changed.'}
                    if($key -eq 4 -and ([Convert]::ToBase64String([byte[]]$outputBytes[$value..($value+$length-1)])) -ne 'wAACAQ=='){throw 'The IPv4 hint changed.'}
                    $offset=$value+$length
                }
                if(($keys.ToArray() -join ',') -cne (@($case.ExpectedKeys) -join ',')){throw 'Unexpected output SvcParam keys.'}
                foreach($required in $mandatory){if(-not $keys.Contains($required)){throw 'Output mandatory list references an absent key.'}}
                if($keys.Contains(6)){throw 'IPv6 hint leaked through the filter.'}
            }
        }
        $results.Add([pscustomobject]@{Name=$case.Name;Result='PASS';Detail=''})
    }catch{$results.Add([pscustomobject]@{Name=$case.Name;Result='FAIL';Detail=$_.Exception.Message})}
}
$failed=@($results | Where-Object Result -eq 'FAIL').Count
$report=[ordered]@{CapturedUtc=[DateTime]::UtcNow.ToString('o');Version='1.5.0';Scope='Actual C#5 DNS filter; in-memory fixtures only; no Windows networking.';SourceSha256=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash;PowerShellVersion=$PSVersionTable.PSVersion.ToString();Total=$results.Count;Passed=$results.Count-$failed;Failed=$failed;Skipped=0;Tests=$results.ToArray()}
if($ResultJson){
    . (Join-Path $PSScriptRoot 'Package.Common.ps1')
    $output=Get-GephPackageFullPath $ResultJson
    Assert-GephPackageOutput $output (Get-GephPackageFullPath $PackageDirectory)
    Write-GephPackageNewJson $output $report
}
$results | Format-Table -AutoSize -Wrap
if($failed){exit 1}
