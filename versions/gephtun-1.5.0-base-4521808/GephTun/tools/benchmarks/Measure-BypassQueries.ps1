# Portable, read-only provider-call measurement for the real bypass updater.
# Windows CIM providers and every possible mutation are replaced in module scope.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$OriginalModule,
    [Parameter(Mandatory=$true)][string]$CandidateModule,
    [Parameter(Mandatory=$true)][string]$ResultJson
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$measurements = New-Object Collections.Generic.List[object]
$sourceRows = New-Object Collections.Generic.List[object]
foreach ($source in @([pscustomobject]@{ Label = 'Input-1.3.5'; Path = $OriginalModule }, [pscustomobject]@{ Label = 'Candidate-1.3.6'; Path = $CandidateModule })) {
    $path = [IO.Path]::GetFullPath($source.Path)
    $sourceRows.Add([pscustomobject]@{ Label = $source.Label; Path = $path; Sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash })
    $module = Import-Module $path -Force -PassThru -DisableNameChecking
    try {
        foreach ($count in @(1, 24)) {
            foreach ($recovered in @($false, $true)) {
                $row = & $module {
                    param($PeerCount, $Recovered)
                    $script:Measurements = [pscustomobject]@{ Routes = 0; Adapters = 0 }
                    $script:MeasuredPeers = @(for ($i = 1; $i -le $PeerCount; $i++) {
                        [pscustomobject]@{ Prefix = ('203.0.113.' + $i + '/32'); InterfaceIndex = 7; NextHop = '192.168.1.1'; Recovered = $Recovered }
                    })
                    $script:Session = [pscustomobject]@{
                        ProxyProcess = [pscustomobject]@{ Id = 300; StartUtc = 'fixture'; Path = '/fixture/geph' }
                        Routes = @($script:MeasuredPeers | ForEach-Object {
                            [pscustomobject]@{ DestinationPrefix = $_.Prefix; InterfaceIndex = 7; InterfaceGuid = 'fixture-guid'; NextHop = $_.NextHop; RouteMetric = 3; Kind = 'Bypass' }
                        })
                    }
                    function script:Get-GephTunPeerRoutes { param($ProxyIdentity) $script:MeasuredPeers }
                    function script:Get-NetRoute { [CmdletBinding()] param($PolicyStore) $script:Measurements.Routes++; $script:Session.Routes }
                    function script:Get-NetAdapter { [CmdletBinding()] param($InterfaceIndex) $script:Measurements.Adapters++; [pscustomobject]@{ InterfaceGuid = 'fixture-guid' } }
                    function script:Add-GephTunOwnedRoute { throw 'Measurement cannot add routes.' }
                    function script:Write-GephTunLog { param($Message) }
                    for ($pass = 0; $pass -lt 10; $pass++) { Update-GephTunBypasses }
                    [pscustomobject]@{ Peers = $PeerCount; RecoveredPeers = $Recovered; Passes = 10; RouteProviderCalls = $script:Measurements.Routes; AdapterProviderCalls = $script:Measurements.Adapters }
                } $count $recovered
                $row | Add-Member -NotePropertyName Source -NotePropertyValue $source.Label
                $measurements.Add($row)
            }
        }
    } finally { Remove-Module $module -Force }
}
$report = [ordered]@{
    CapturedUtc = [DateTime]::UtcNow.ToString('o')
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    Platform = [Environment]::OSVersion.Platform.ToString()
    ScriptSha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
    Sources = $sourceRows.ToArray()
    Measurements = $measurements.ToArray()
    Boundary = 'Actual Update-GephTunBypasses function; mocked provider results and calls. Deterministic query counts only, with no claim about native Windows CPU, RAM, latency, throughput, or energy.'
}
[IO.File]::WriteAllText([IO.Path]::GetFullPath($ResultJson), (ConvertTo-Json $report -Depth 8), (New-Object Text.UTF8Encoding($false)))
$measurements | Format-Table Source, Peers, RecoveredPeers, Passes, RouteProviderCalls, AdapterProviderCalls -AutoSize
