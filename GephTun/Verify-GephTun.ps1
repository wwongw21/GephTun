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
    'tests/IdentitySafeguards.Tests.ps1','tests/Verify-IdentityCandidate.Tests.ps1','tests/Package.Tests.ps1',
    'bin/tun2socks-windows-amd64.exe','bin/wintun.dll')){
    if(-not $seen.Contains($name)){throw ('Required member missing: '+$name)}
}
$release=Get-Content -LiteralPath (Join-Path $root 'RELEASE.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$dependencies=Get-Content -LiteralPath (Join-Path $root 'DEPENDENCIES.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$qualification=Get-Content -LiteralPath (Join-Path $root 'QUALIFICATION.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$validation=Get-Content -LiteralPath (Join-Path $root 'tests/current-validation.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$static=Get-Content -LiteralPath (Join-Path $root 'tests/static-results.json') -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-GephPackageRelease $release
foreach($field in @('Package','Version','Status','Date','InputArchiveSha256')){
    if($release.$field -cne $manifest.$field){throw ('Manifest/release disagreement: '+$field)}
}
if($dependencies.Version -cne $release.Version -or $qualification.Version -cne $release.Version -or
    $validation.Version -cne $release.Version -or $static.Version -cne $release.Version){throw 'Release versions disagree.'}
$revision=[string]$release.CandidateRevision
if([string]::IsNullOrWhiteSpace($revision) -or $manifest.CandidateRevision -cne $revision -or
    $qualification.CandidateRevision -cne $revision -or $validation.CandidateRevision -cne $revision -or
    $static.CandidateRevision -cne $revision){throw 'Candidate revision identities disagree.'}
if($release.ProductionQualified -isnot [bool] -or $release.ProductionQualified -or
    $manifest.ProductionQualified -isnot [bool] -or $manifest.ProductionQualified -or
    $manifest.NativeWindowsAcceptance -cne 'NOT_RUN' -or $manifest.BehavioralChecks -cne 'NOT_RUN' -or
    $qualification.ProductionQualified -isnot [bool] -or $qualification.ProductionQualified -or
    $validation.ProductionQualified -isnot [bool] -or $validation.ProductionQualified -or
    $static.ProductionQualified -isnot [bool] -or $static.ProductionQualified -or
    $qualification.Schema -ne 3 -or $qualification.PowerShellExecution -cne 'NOT_RUN_FOR_REPAIRED_CANDIDATE' -or
    $qualification.CSharpCompilation -cne 'PASS_TWO_UNCHANGED_SOURCES_COMPILE_ONLY' -or
    $qualification.NativeWindowsAcceptance -cne 'NOT_RUN' -or $validation.NativeWindowsAcceptance -cne 'NOT_RUN' -or
    $static.NativeWindowsAcceptance -cne 'NOT_RUN' -or $qualification.CoverageComplete -isnot [bool] -or
    $qualification.CoverageComplete -or $validation.CoverageComplete -isnot [bool] -or $validation.CoverageComplete){
    throw 'Unqualified candidate evidence is inconsistent or claims completed qualification.'
}
if($validation.Schema -cne 'GephTun.IdentityCandidate.LocalValidation.v1' -or
    $validation.Status -cne 'UNQUALIFIED_RUNNER_RECEIPT_GATE_REPAIR_TESTS_NOT_RUN' -or
    $validation.PowerShellParsing -cne 'NOT_RUN_FOR_REPAIRED_CANDIDATE' -or
    $validation.CSharpCompilation -cne 'PASS_TWO_UNCHANGED_SOURCES_COMPILE_ONLY' -or
    $validation.FocusedIdentityBehaviorTests -cne 'NOT_RUN_FOR_REPAIRED_CANDIDATE' -or
    $validation.VerifierIntegrityTests -cne 'PREPARED_NOT_RUN_EXECUTION_POLICY_RESTRICTED' -or
    $validation.FullRegressionSuite -cne 'NOT_RUN' -or $validation.LiveTests -ne 0){
    throw 'Current unqualified validation record is missing, stale, or overstates performed work.'
}
if($validation.PSObject.Properties.Name -contains 'FinalParseReceiptSha256'){
    throw 'This repaired revision has no fresh PowerShell parse receipt; stale parse claims are not accepted.'
}
if($validation.PSObject.Properties.Name -contains 'BehavioralBlockedReceiptSha256'){
    throw 'The prior blocked receipt belongs to revision 1; it is not current evidence for this repaired revision.'
}
if($static.Schema -cne 'GephTun.IdentityCandidate.StaticResults.v2' -or
    $static.Status -cne 'STATIC_REPAIR_REVIEW_ONLY' -or
    $static.PowerShellParseFiles -cne 'NOT_RUN_FOR_REPAIRED_CANDIDATE' -or
    $static.BehaviorTests -cne 'NOT_RUN_FOR_REPAIRED_CANDIDATE' -or $static.LiveTests -ne 0){
    throw 'Static results do not describe this unqualified candidate revision.'
}
# Bind the exact current source set. These hashes identify the candidate; they
# do not claim that any source or behavioral test passed.
$sourceNames=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
Assert-GephPackageArray $qualification 'Sources'
foreach($source in $qualification.Sources){
    if(-not (Test-GephPackageSource $source.Path) -or -not $sourceNames.Add([string]$source.Path)){throw 'Invalid or duplicate source evidence.'}
    Assert-GephPackageHashMatches $source.Path $source.Sha256 $files
}
$actualSources=@($files.Keys | Where-Object { Test-GephPackageSource $_ })
if($actualSources.Count -ne $sourceNames.Count){throw 'Candidate source hashes do not cover the complete current source set.'}
foreach($name in $actualSources){if(-not $sourceNames.Contains($name)){throw ('Unbound source: '+$name)}}
Assert-GephPackageArray $qualification 'Evidence'
$evidenceNames=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach($record in $qualification.Evidence){
    if($record.Path -notin @('tests/current-validation.json','tests/static-results.json') -or -not $evidenceNames.Add([string]$record.Path)){throw 'Candidate evidence set is unexpected or duplicated.'}
    Assert-GephPackageHashMatches $record.Path $record.Sha256 $files
}
if($evidenceNames.Count -ne 2){throw 'Candidate validation evidence is incomplete.'}
# The current validation format references external receipts by SHA-256. Check
# both the bytes and their narrow, non-qualifying claims before accepting them.
if($validation.ExternalReceiptsRoot -cne '../evidence'){throw 'Unexpected external receipt directory.'}
$receiptRoot=[IO.Path]::GetFullPath((Join-Path $root $validation.ExternalReceiptsRoot))
if(Test-GephPackageWithin $receiptRoot $root){throw 'External receipts must remain outside the installable package.'}
$csharpReceiptPath=Join-Path $receiptRoot 'CSHARP-COMPILE-RECEIPT.json'
if(-not (Test-Path -LiteralPath $csharpReceiptPath -PathType Leaf)){throw 'The required external compile-only receipt is missing.'}
if((Get-FileHash -LiteralPath $csharpReceiptPath -Algorithm SHA256).Hash -cne $validation.CSharpCompileReceiptSha256){throw 'The external compile-only receipt is stale or changed.'}
$csharpReceipt=Get-Content -LiteralPath $csharpReceiptPath -Raw -Encoding UTF8 | ConvertFrom-Json
if($csharpReceipt.Schema -cne 'GephTun.IdentityCandidate.CSharpCompile.v1' -or
    @($csharpReceipt.Files).Count -ne 2 -or $csharpReceipt.NativeAPICalls -ne 0 -or
    $csharpReceipt.NetworkConnections -ne 0 -or $csharpReceipt.ModuleImported -ne $false){throw 'Compile-only receipt has an invalid scope.'}
$compiledNames=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach($entry in $csharpReceipt.Files){
    if($entry.Status -cne 'PASS_COMPILE_ONLY' -or $entry.Name -notin @('GephTun.Network.cs','GephTun.Wfp.cs') -or -not $compiledNames.Add([string]$entry.Name)){throw 'Compile-only receipt has an unexpected result.'}
    Assert-GephPackageHashMatches $entry.Name $entry.Sha256 $files
}
if($compiledNames.Count -ne 2){throw 'Compile-only receipt does not cover the exact unchanged C# files.'}
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
if(-not $Quiet){Write-Host ('GephTun {0} ({1}): package integrity PASS for {2} files. PowerShell parsing and behavior tests for this repair revision were NOT RUN; native Windows acceptance was NOT_RUN. This is not production qualification.' -f $release.Version,$revision,$seen.Count)}
[pscustomobject]@{Success=$true;Version=$release.Version;CandidateRevision=$revision;Files=$seen.Count;StaticReview=$static.Status;PowerShellParsing=$validation.PowerShellParsing;CSharpCompilation=$validation.CSharpCompilation;FocusedIdentityBehaviorTests=$validation.FocusedIdentityBehaviorTests;VerifierIntegrityTests=$validation.VerifierIntegrityTests;NativeWindowsAcceptance='NOT_RUN';ProductionQualified=$false;Scope='Package integrity and exact unqualified evidence hashes only.'}
