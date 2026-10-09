#Requires -Version 5.1
[CmdletBinding()]
param([string]$PackageDirectory, [Parameter(Mandatory=$true)][string]$ResultJson, [switch]$SourceTree)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
# $PSScriptRoot is empty while param() defaults are evaluated on Windows
# PowerShell 5.1 -File runs; resolve the default in the script body instead.
if (-not $PackageDirectory) { $PackageDirectory = Split-Path -Parent $PSScriptRoot }
. (Join-Path $PSScriptRoot 'Package.Common.ps1')
$root = Get-GephPackageFullPath $PackageDirectory
$output = Get-GephPackageFullPath $ResultJson
Assert-GephPackageOutput $output $root
$files = Get-GephPackageInventory $root -SourceTree:$SourceTree
$results = New-Object 'Collections.Generic.List[object]'
$sources = @(foreach ($relative in @($files.Keys | Sort-Object)) {
    if (Test-GephPackageSource $relative) {
        [pscustomobject]@{ Path = $relative; Sha256 = (Get-FileHash -LiteralPath $files[$relative].FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
    }
})
foreach ($source in $sources) {
    $relative = $source.Path
    $file = $files[$relative]
    if ($file.Extension -in @('.ps1','.psm1')) {
        $tokens = $null; $errors = $null
        [void][Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
        $passed = @($errors).Count -eq 0
        $detail = (@($errors) | Out-String).Trim()
    } elseif ($file.Extension -eq '.cs') {
        try {
            if ($PSVersionTable.PSVersion.Major -ge 6) { Add-Type -Path $file.FullName -CompilerOptions '/langversion:5' }
            else { Add-Type -Path $file.FullName }
            $passed = $true; $detail = 'C# language version 5; current host .NET only.'
        }
        catch { $passed = $false; $detail = $_.Exception.Message }
    } else { continue }
    if ((Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -ne $source.Sha256) { $passed = $false; $detail = 'Source changed while validation was running.' }
    $results.Add([pscustomobject]@{ File = $relative; Passed = $passed; Detail = $detail; Sha256 = $source.Sha256 })
}
# A successful parser run must describe one stable snapshot, including additions/deletions.
$after = Get-GephPackageInventory $root -SourceTree:$SourceTree
$afterSources = @($after.Keys | Where-Object { Test-GephPackageSource $_ })
if ($afterSources.Count -ne $sources.Count) { throw 'Source set changed while validation was running.' }
foreach ($source in $sources) { Assert-GephPackageHashMatches $source.Path $source.Sha256 $after }
$failed = @($results | Where-Object { -not $_.Passed })
$report = [ordered]@{
    CapturedUtc = [DateTime]::UtcNow.ToString('o'); PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    Platform = [Environment]::OSVersion.Platform.ToString(); Total = $results.Count
    Passed = $results.Count-$failed.Count; Failed = $failed.Count
    Scope = 'PowerShell parser and C#5 compile on the current host; no Windows runtime or live network acceptance.'
    Sources = $sources; Tests = $results.ToArray()
}
Assert-GephPackageOutput $output $root
Write-GephPackageNewJson $output $report
if ($failed.Count) { $failed | Format-List; throw 'Source validation failed.' }
Write-Output ('{0} parser/compile checks passed.' -f $results.Count)
