# Portable allocation and file-read microbenchmark; never loads WinForms or a controller.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BaselineUi,
    [Parameter(Mandatory = $true)][string]$UpdatedUi,
    [Parameter(Mandatory = $true)][string]$ResultJson,
    [ValidateRange(100, 10000)][int]$Iterations = 1000
)
$ErrorActionPreference = 'Stop'
foreach ($source in @(@{ Path = $BaselineUi; Name = 'Read-BaselineSnapshot' }, @{ Path = $UpdatedUi; Name = 'Read-UpdatedSnapshot' })) {
    $tokens = $null; $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile([IO.Path]::GetFullPath($source.Path), [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
    $functions = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Read-UiTextSnapshot' }, $true))
    if ($functions.Count -ne 1) { throw 'Expected exactly one production snapshot reader.' }
    . ([scriptblock]::Create(($functions[0].Extent.Text -replace '^function Read-UiTextSnapshot', ('function ' + $source.Name))))
}
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('GephTun-allocation-' + [guid]::NewGuid().ToString('N') + '.json')
$payload = '{"Status":"Connected","Message":"Tunnel connected; TCP traffic uses the local proxy.","ProxyPort":9909,"WorkerPid":1234,"WorkerStartUtc":"2026-09-17T10:00:00.0000000Z","StartedUtc":"2026-09-17T10:00:00.0000000Z","UpdatedUtc":"2026-09-17T10:00:30.0000000Z"}'
$rounds = [Collections.Generic.List[object]]::new()
try {
    [IO.File]::WriteAllText($fixture, $payload, [Text.UTF8Encoding]::new($false))
    foreach ($name in @('Read-BaselineSnapshot', 'Read-UpdatedSnapshot')) {
        for ($index = 0; $index -lt 100; $index++) { $null = & $name -Path $fixture -MaximumBytes 262144 }
    }
    for ($round = 1; $round -le 5; $round++) {
        $order = @('Read-BaselineSnapshot', 'Read-UpdatedSnapshot')
        if ($round % 2 -eq 0) { [array]::Reverse($order) }
        foreach ($name in $order) {
            [GC]::Collect(); [GC]::WaitForPendingFinalizers(); [GC]::Collect()
            $watch = [Diagnostics.Stopwatch]::new()
            $allocatedBefore = [GC]::GetAllocatedBytesForCurrentThread()
            $watch.Start()
            for ($index = 0; $index -lt $Iterations; $index++) { $observed = & $name -Path $fixture -MaximumBytes 262144 }
            $watch.Stop()
            $bytesAllocated = [GC]::GetAllocatedBytesForCurrentThread() - $allocatedBefore
            if ($observed -cne $payload) { throw 'The timed reader lost data.' }
            $rounds.Add([pscustomobject]@{
                Reader = $name; Round = $round; Iterations = $Iterations
                ElapsedMilliseconds = $watch.Elapsed.TotalMilliseconds
                ManagedBytesAllocatedOnCurrentThread = $bytesAllocated
                ManagedBytesPerRead = $bytesAllocated / $Iterations
            })
        }
    }
}
finally { if ([IO.File]::Exists($fixture)) { [IO.File]::Delete($fixture) } }
$summary = foreach ($name in @('Read-BaselineSnapshot', 'Read-UpdatedSnapshot')) {
    $samples = @($rounds | Where-Object Reader -eq $name)
    $allocationMedian = @($samples.ManagedBytesPerRead | Sort-Object)[2]
    $timeMedian = @($samples.ElapsedMilliseconds | Sort-Object)[2]
    [pscustomobject]@{ Reader = $name; MedianManagedBytesPerRead = $allocationMedian; MedianMillisecondsPer1000Reads = $timeMedian * 1000 / $Iterations }
}
$report = [ordered]@{
    Runtime = $PSVersionTable.PSVersion.ToString(); Platform = [Environment]::OSVersion.Platform.ToString()
    GeneratedUtc = [DateTime]::UtcNow.ToString('o'); StatusFixtureUtf8Bytes = [Text.Encoding]::UTF8.GetByteCount($payload)
    IterationsPerRound = $Iterations; MeasuredRoundsPerReader = 5; WarmupReadsPerReader = 100
    AllocationReductionPercent = 100 * (1 - $summary[1].MedianManagedBytesPerRead / $summary[0].MedianManagedBytesPerRead)
    Scope = 'Single-thread managed allocation and warmed local file reads on this Linux PowerShell 7 host. Does not measure native Windows UI resident memory, tunnel-worker CPU or networking throughput.'
    Sources = @(
        @{ Kind = 'original 1.3.5 UI'; Sha256 = (Get-FileHash -LiteralPath $BaselineUi -Algorithm SHA256).Hash.ToLowerInvariant() },
        @{ Kind = 'updated UI'; Sha256 = (Get-FileHash -LiteralPath $UpdatedUi -Algorithm SHA256).Hash.ToLowerInvariant() }
    )
    Summary = @($summary); Rounds = $rounds.ToArray()
}
[IO.File]::WriteAllText([IO.Path]::GetFullPath($ResultJson), ($report | ConvertTo-Json -Depth 8))
$summary | Format-Table | Out-String | Write-Output
Write-Output ('Managed allocation reduction: ' + [Math]::Round($report.AllocationReductionPercent, 2) + ' percent')
