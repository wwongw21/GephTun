#Requires -Version 5.1
# Read-only package integrity and truthful evidence verification. Not a signature.
[CmdletBinding()]
param([string]$PackageDirectory,[switch]$Quiet,[switch]$SourceTree)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
if(-not $PackageDirectory){$PackageDirectory=$PSScriptRoot}
. (Join-Path $PSScriptRoot 'tests/Package.Common.ps1')
$root=Get-GephPackageFullPath $PackageDirectory
$files=Get-GephPackageInventory $root -SourceTree:$SourceTree
$manifest=Get-Content -LiteralPath (Join-Path $root 'PACKAGE-MANIFEST.json') -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-GephPackageRelease $manifest
Assert-GephPackageArray $manifest 'Files'
$seen=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach($entry in $manifest.Files){
    $relative=[string]$entry.Path
    Assert-GephPackageRelative $relative
    if($relative -eq 'PACKAGE-MANIFEST.json' -or -not $seen.Add($relative)){throw ('Duplicate or unsafe manifest member: '+$relative)}
    Assert-GephPackageCount $entry.Bytes ($relative+' Bytes')
    Assert-GephPackageHashMatches $relative $entry.Sha256 $files
    if([long]$entry.Bytes -ne $files[$relative].Length){throw ('Size mismatch: '+$relative)}
}
if($files.Count -ne $seen.Count+1){throw 'Unlisted files found. Keep logs, outputs and personal files outside the installation.'}
foreach($name in @('RELEASE.json','DEPENDENCIES.json','QUALIFICATION.json','tests/current-validation.json','tests/static-results.json',
    'GephTun.Wfp.cs','GephTun.Protection.ps1','GephTun.Bypasses.ps1',
    'Protection-GephTun.ps1','Protection-GephTun.cmd','Emergency-Unlock-GephTun.ps1',
    'tests/WfpPolicy.Tests.ps1','tests/Bypasses.Tests.ps1','tests/Protection.Tests.ps1','tests/Wfp-NativeSmoke.ps1',
    'GephTun.Core.psm1','GephTun.Resilience.ps1','GephTun.Network.cs','GephTun.Worker.ps1','GephTun.WorkerHost.ps1',
    'GephTun-BootReconcile.ps1','GephTun.UI.ps1','Launch-GephTun.cmd','Launch-GephTun.ps1','Start-GephTun.cmd','Stop-GephTun.cmd',
    'Verify-GephTun.ps1','tests/Run-UpdateValidation.ps1','tests/Resilience.Tests.ps1','tests/DnsMandatory.Tests.ps1','tests/BootRecovery.Tests.ps1',
    'bin/tun2socks-windows-amd64.exe','bin/wintun.dll')){
    if(-not $seen.Contains($name)){throw ('Required member missing: '+$name)}
}
$release=Get-Content -LiteralPath (Join-Path $root 'RELEASE.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$dependencies=Get-Content -LiteralPath (Join-Path $root 'DEPENDENCIES.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$qualification=Get-Content -LiteralPath (Join-Path $root 'QUALIFICATION.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$validation=Get-Content -LiteralPath (Join-Path $root 'tests/current-validation.json') -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-GephPackageRelease $release
foreach($field in @('Package','Version','Status','Date','InputArchiveSha256')){
    if($release.$field -cne $manifest.$field){throw ('Manifest/release disagreement: '+$field)}
}
if($dependencies.Version -cne $release.Version -or $qualification.Version -cne $release.Version -or $validation.Version -cne $release.Version){throw 'Release versions disagree.'}
if($release.ProductionQualified -isnot [bool] -or $release.ProductionQualified -or
    $qualification.ProductionQualified -isnot [bool] -or $qualification.ProductionQualified -or
    $qualification.NativeWindowsAcceptance -cne 'NOT_RUN' -or $validation.NativeWindowsAcceptance -cne 'NOT_RUN' -or
    $validation.PowerShellExecution -cne 'NOT_RUN' -or $validation.CSharpCompilation -cne 'NOT_RUN' -or
    $validation.Mode -cne 'STATIC_SOURCE_REVIEW'){
    throw 'This candidate cannot claim unperformed PowerShell, C# or native Windows qualification.'
}
# Bind the exact current source set without pretending an unexecuted suite passed.
$sourceNames=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
Assert-GephPackageArray $validation 'Sources'
foreach($source in $validation.Sources){
    if(-not (Test-GephPackageSource $source.Path) -or -not $sourceNames.Add([string]$source.Path)){throw 'Invalid or duplicate source evidence.'}
    Assert-GephPackageHashMatches $source.Path $source.Sha256 $files
}
$actualSources=@($files.Keys | Where-Object { Test-GephPackageSource $_ })
if($actualSources.Count -ne $sourceNames.Count){throw 'Source evidence does not cover the complete current source set.'}
foreach($name in $actualSources){if(-not $sourceNames.Contains($name)){throw ('Unbound source: '+$name)}}
Assert-GephPackageArray $qualification 'Sources'
$qualifiedNames=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach($source in $qualification.Sources){
    if(-not $qualifiedNames.Add([string]$source.Path) -or -not $sourceNames.Contains([string]$source.Path)){throw 'Qualification source set is invalid.'}
    Assert-GephPackageHashMatches $source.Path $source.Sha256 $files
}
if($qualifiedNames.Count -ne $sourceNames.Count){throw 'Qualification source set is incomplete.'}
foreach($record in @($qualification.Evidence)+@($validation.Evidence)){Assert-GephPackageHashMatches $record.Path $record.Sha256 $files}
$static=Get-Content -LiteralPath (Join-Path $root 'tests/static-results.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if($static.Kind -cne 'StaticSourceChecks' -or $static.Failed -ne 0 -or $static.Total -lt 1 -or $static.Passed -ne $static.Total){throw 'Static evidence has failures or an invalid scope.'}
if(@($static.Tests).Count -ne $static.Total -or @($static.Tests | Where-Object Result -ne 'PASS').Count -ne 0){throw 'Static test counts are inconsistent.'}
# Verify the unchanged pinned native dependencies, including architecture headers.
if(@($dependencies.Binaries).Count -ne 2){throw 'Exactly two native dependencies are required.'}
$binaryNames=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach($binary in $dependencies.Binaries){
    if($binary.File -notin @('tun2socks-windows-amd64.exe','wintun.dll') -or -not $binaryNames.Add([string]$binary.File)){throw 'Unexpected or duplicate dependency.'}
    Assert-GephPackageHashMatches ('bin/'+$binary.File) $binary.Sha256 $files
    $reader=New-Object IO.BinaryReader([IO.File]::OpenRead((Join-Path (Join-Path $root 'bin') $binary.File)))
    try{
        if($reader.ReadUInt16() -ne 0x5a4d){throw 'Invalid Windows binary.'}
        $reader.BaseStream.Position=0x3c;$offset=$reader.ReadUInt32()
        if($offset -gt $reader.BaseStream.Length-6){throw 'Invalid PE header offset.'}
        $reader.BaseStream.Position=$offset
        if($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne 0x8664){throw 'Native dependency is not AMD64.'}
    }finally{$reader.Dispose()}
}
if(-not $Quiet){Write-Host ('GephTun {0}: integrity PASS for {1} files. {2} STATIC checks passed. PowerShell/C# execution and native Windows acceptance were NOT RUN; this is not production qualification.' -f $release.Version,$seen.Count,$static.Passed)}
[pscustomobject]@{Success=$true;Version=$release.Version;Files=$seen.Count;StaticChecks=$static.Passed;PowerShellExecution='NOT_RUN';CSharpCompilation='NOT_RUN';NativeWindowsAcceptance='NOT_RUN';ProductionQualified=$false;Scope='Integrity and static-source evidence only.'}
