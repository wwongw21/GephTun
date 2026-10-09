#Requires -Version 5.1
# Targeted regression for D-001: RemoveIpv6Records must strip ipv6hint from
# HTTPS/SVCB records, preserve other SvcParams, and drop unparseable SVCB data.
param([string]$PackageRoot)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if (-not $PackageRoot) { $PackageRoot = Split-Path -Parent $PSScriptRoot }
Add-Type -Path (Join-Path $PackageRoot 'GephTun.Network.cs')
$failures = New-Object 'System.Collections.Generic.List[string]'
function Assert-True2($Condition, [string]$Message) { if (-not $Condition) { $failures.Add($Message) } }

function New-Name([string]$Name) {
    $bytes = New-Object 'System.Collections.Generic.List[byte]'
    foreach ($label in $Name.Split('.')) { if ($label) { $bytes.Add([byte]$label.Length); foreach ($ch in $label.ToCharArray()) { $bytes.Add([byte][int][char]$ch) } } }
    $bytes.Add(0)
    return $bytes.ToArray()
}
function U16([int]$Value) { return [byte[]]@([byte]($Value -shr 8), [byte]($Value -band 255)) }

function Build-HttpsResponse([bool]$WithIpv6Hint, [bool]$Malformed, [bool]$AlsoARecord) {
    # answer: name(www.example.com) type65 class1 ttl300 rdlength rdata
    $name = New-Name 'www.example.com'
    $target = New-Name 'svc.example.net'   # target name inside RDATA (uncompressed)
    $rdata = New-Object 'System.Collections.Generic.List[byte]'
    $rdata.AddRange([byte[]]@(0, 1))        # SvcPriority = 1
    $rdata.AddRange([byte[]]$target)
    # alpn param: key=1 len=4 value h2,h3
    $rdata.AddRange([byte[]]@(0, 1, 0, 5, 104, 50, 44, 104, 51))
    if ($WithIpv6Hint) {
        # ipv6hint param: key=6 len=16 value 2606:4700:4700::1111
        $rdata.AddRange([byte[]]@(0, 6, 0, 16, 0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11))
    }
    if ($Malformed) { $rdata.AddRange([byte[]]@(0, 3)) }  # truncated param header
    $msg = New-Object 'System.Collections.Generic.List[byte]'
    $msg.AddRange([byte[]]@(0x12, 0x34, 0x80, 0x00, 0, 1, 0, 0, 0, 0, 0, 0))
    $msg.AddRange([byte[]](New-Name 'www.example.com'))
    $msg.AddRange([byte[]]@(0, 65, 0, 1))   # question type HTTPS + class
    $msg.AddRange([byte[]](New-Name 'www.example.com'))
    $msg.AddRange([byte[]]@(0, 65, 0, 1))   # answer type HTTPS + class
    $msg.AddRange([byte[]]@(0, 0, 1, 44))   # ttl 300
    $msg.AddRange([byte[]](U16 $rdata.Count))
    $msg.AddRange([byte[]]$rdata.ToArray())
    if ($AlsoARecord) {
        $msg[6] = 0; $msg[7] = 2
        $msg.AddRange([byte[]](New-Name 'www.example.com'))
        $msg.AddRange([byte[]]@(0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 93, 184, 216, 34))
    }
    else { $msg[6] = 0; $msg[7] = 1 }
    return $msg.ToArray()
}

# Case 1: HTTPS with ipv6hint -> hint stripped, alpn kept, record kept
$resp1 = Build-HttpsResponse $true $false $false
$asm = [GephTun.ProxyProbe].Assembly
$type = $asm.GetType('GephTun.DnsProtocol')
# DnsProtocol is likely the enclosing/nested type of RemoveIpv6Records; find it.
$holder = $null
foreach ($t in $asm.GetTypes()) {
    $m = $t.GetMethod('RemoveIpv6Records', [System.Reflection.BindingFlags]'NonPublic,Public,Static')
    if ($m) { $holder = $t; break }
}
if ($null -eq $holder) { throw 'RemoveIpv6Records not found via reflection' }
$method = $holder.GetMethod('RemoveIpv6Records', [System.Reflection.BindingFlags]'NonPublic,Public,Static')
$invoke1 = [object[]]::new(1); $invoke1[0] = [byte[]]$resp1
$filtered1 = [byte[]]$method.Invoke($null, $invoke1)
$blob1 = [byte[]]$filtered1
$hasHintKey = $false
for ($i = 0; $i -lt $blob1.Length - 4; $i++) {
    if ($blob1[$i] -eq 0 -and $blob1[$i+1] -eq 6) {
        $ln = ($blob1[$i+2] -shl 8) + $blob1[$i+3]
        if ($ln -eq 16) { $hasHintKey = $true }
    }
}
$hasAlpn = $false
for ($i = 0; $i -lt $blob1.Length - 4; $i++) {
    if ($blob1[$i] -eq 0 -and $blob1[$i+1] -eq 1 -and $blob1[$i+2] -eq 0 -and $blob1[$i+3] -eq 5) { $hasAlpn = $true }
}
$ancount1 = ($blob1[6] -shl 8) + $blob1[7]
Assert-True2 (-not $hasHintKey) 'ipv6hint still present after filtering'
Assert-True2 $hasAlpn 'alpn param lost during filtering'
Assert-True2 ($ancount1 -eq 1) ('HTTPS record dropped entirely (ANCOUNT=' + $ancount1 + ')')

# Case 2: malformed SVCB RDATA -> record dropped
$resp2 = Build-HttpsResponse $true $true $false
$invoke2 = [object[]]::new(1); $invoke2[0] = [byte[]]$resp2
$filtered2 = [byte[]]$method.Invoke($null, $invoke2)
$ancount2 = ($filtered2[6] -shl 8) + $filtered2[7]
Assert-True2 ($ancount2 -eq 0) ('malformed SVCB record not dropped (ANCOUNT=' + $ancount2 + ')')

# Case 3: response with both an A record and an HTTPS-with-hint record
$resp3 = Build-HttpsResponse $true $false $true
$invoke3 = [object[]]::new(1); $invoke3[0] = [byte[]]$resp3
$filtered3 = [byte[]]$method.Invoke($null, $invoke3)
$ancount3 = ($filtered3[6] -shl 8) + $filtered3[7]
Assert-True2 ($ancount3 -eq 2) ('both records should be kept (ANCOUNT=' + $ancount3 + ')')
$hint3 = $false
for ($i = 0; $i -lt $filtered3.Length - 4; $i++) {
    if ($filtered3[$i] -eq 0 -and $filtered3[$i+1] -eq 6 -and $filtered3[$i+2] -eq 0 -and $filtered3[$i+3] -eq 16) { $hint3 = $true }
}
Assert-True2 (-not $hint3) 'ipv6hint present in mixed response'

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Output ('FAIL: ' + $_) }
    exit 1
}
Write-Output 'D-001 TARGETED REGRESSION: ALL PASS'
exit 0
