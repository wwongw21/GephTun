#Requires -Version 5.1
# Runs each test in a separate PowerShell process. Never changes live network policy.
[CmdletBinding()]
param([string]$PackageDirectory,[string]$OutputDirectory)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
if(-not $PackageDirectory){$PackageDirectory=Split-Path -Parent $PSScriptRoot}
. (Join-Path $PSScriptRoot 'Package.Common.ps1')
$root=Get-GephPackageFullPath $PackageDirectory
if(-not $OutputDirectory){$OutputDirectory=Join-Path ([IO.Path]::GetTempPath()) ('GephTun-150-validation-'+[guid]::NewGuid().ToString('N'))}
$output=Get-GephPackageFullPath $OutputDirectory
Assert-GephPackageOutput $output $root
if(Test-Path -LiteralPath $output){throw 'Use a new output directory so existing evidence is not overwritten.'}
[void][IO.Directory]::CreateDirectory($output)
$engine=(Get-Process -Id $PID).Path
if([IO.Path]::GetFileNameWithoutExtension($engine) -notin @('powershell','pwsh')){throw 'Run this script with powershell.exe or pwsh, not an embedded host.'}
$suites=@(
    [pscustomobject]@{Name='Source';File='Validate-Source.ps1';RootArgument='-PackageDirectory'},
    [pscustomobject]@{Name='WfpPolicy';File='WfpPolicy.Tests.ps1';RootArgument='-PackageDirectory'},
    [pscustomobject]@{Name='Bypasses';File='Bypasses.Tests.ps1';RootArgument='-PackageDirectory'},
    [pscustomobject]@{Name='Protection';File='Protection.Tests.ps1';RootArgument='-PackageDirectory'},
    [pscustomobject]@{Name='Resilience';File='Resilience.Tests.ps1';RootArgument='-PackageDirectory'},
    [pscustomobject]@{Name='Controller';File='Controller.Tests.ps1';RootArgument='-PackageDirectory'},
    [pscustomobject]@{Name='DnsMandatory';File='DnsMandatory.Tests.ps1';RootArgument='-PackageDirectory'},
    [pscustomobject]@{Name='BootRecovery';File='BootRecovery.Tests.ps1';RootArgument='-BootScriptPath'},
    [pscustomobject]@{Name='IdentitySafeguards';File='IdentitySafeguards.Tests.ps1';RootArgument='-PackageDirectory'},
    [pscustomobject]@{Name='CandidateVerifier';File='Verify-IdentityCandidate.Tests.ps1';RootArgument='-PackageDirectory'},
    [pscustomobject]@{Name='Package';File='Package.Tests.ps1';RootArgument='-PackageDirectory'}
)

# Pure receipt validation: only inspect the supplied JSON-shaped object.
# Kept separate so synthetic fixtures can test the gate without starting suites.
function Get-GephValidationIntegerCount($Value,[string]$Name){
    if($null -eq $Value){throw ('Suite receipt count is missing: '+$Name)}
    if($Value -is [bool]){throw ('Suite receipt count is not an integer: '+$Name)}
    if($Value.GetType().FullName -notin @('System.Byte','System.SByte','System.Int16','System.UInt16','System.Int32','System.UInt32','System.Int64','System.UInt64')){
        throw ('Suite receipt count is missing or not an integer: '+$Name)
    }
    $number=[decimal]$Value
    if($number -lt 0 -or $number -gt [long]::MaxValue){throw ('Suite receipt count is outside the valid range: '+$Name)}
    return [long]$number
}
function Assert-GephValidationSuiteReceipt($Record){
    if($null -eq $Record){throw 'Suite receipt is empty.'}
    $totalProperty=$Record.PSObject.Properties['Total']
    $passedProperty=$Record.PSObject.Properties['Passed']
    $failedProperty=$Record.PSObject.Properties['Failed']
    if($null -eq $totalProperty -or $null -eq $passedProperty -or $null -eq $failedProperty){
        throw 'Suite receipt is missing Total, Passed, or Failed.'
    }
    $total=Get-GephValidationIntegerCount $totalProperty.Value 'Total'
    $passed=Get-GephValidationIntegerCount $passedProperty.Value 'Passed'
    $failed=Get-GephValidationIntegerCount $failedProperty.Value 'Failed'
    if($total -lt 1 -or ([decimal]$passed+[decimal]$failed) -ne $total){throw 'Suite receipt counts are incomplete or inconsistent.'}
    $skippedProperty=$Record.PSObject.Properties['Skipped']
    if($null -ne $skippedProperty -and (Get-GephValidationIntegerCount $skippedProperty.Value 'Skipped') -ne 0){
        throw 'Suite receipt reports skipped tests.'
    }
    $statusProperty=$Record.PSObject.Properties['Status']
    if($null -ne $statusProperty -and ($statusProperty.Value -isnot [string] -or $statusProperty.Value -cne 'PASS')){
        throw 'Suite receipt status is not PASS.'
    }
    $caseProperties=New-Object 'Collections.Generic.List[string]'
    foreach($caseName in @('Tests','Results')){
        if($null -ne $Record.PSObject.Properties[$caseName]){$caseProperties.Add($caseName)}
    }
    if($caseProperties.Count -ne 1){throw 'Suite receipt must contain exactly one Tests or Results array.'}
    $caseProperty=$Record.PSObject.Properties[$caseProperties[0]]
    if($caseProperty.Value -isnot [Array] -or $caseProperty.Value.Count -lt 1){throw 'Suite case results must be a nonempty array.'}
    if($caseProperty.Value.Count -ne $total){throw 'Suite case count does not match Total.'}
    foreach($case in $caseProperty.Value){
        if($null -eq $case){throw 'Suite receipt contains an empty case result.'}
        $resultProperty=$case.PSObject.Properties['Result']
        $casePassedProperty=$case.PSObject.Properties['Passed']
        if($null -ne $resultProperty -and ($resultProperty.Value -isnot [string] -or $resultProperty.Value -cne 'PASS')){
            throw 'A suite case did not report PASS.'
        }
        if($null -ne $casePassedProperty -and ($casePassedProperty.Value -isnot [bool] -or -not $casePassedProperty.Value)){
            throw 'A suite case did not report Passed=true.'
        }
        if($null -eq $resultProperty -and $null -eq $casePassedProperty){throw 'Suite case result has no recognized pass field.'}
    }
    if($passed -ne $total -or $failed -ne 0){throw 'Suite counts disagree with passing case results.'}
    return [pscustomobject]@{Total=$total;Passed=$passed;Failed=$failed;CaseCount=$caseProperty.Value.Count}
}

$results=New-Object 'Collections.Generic.List[object]'
foreach($suite in $suites){
    $receipt=Join-Path $output ($suite.Name+'.json')
    $log=Join-Path $output ($suite.Name+'.txt')
    $argument=$root
    if($suite.RootArgument -eq '-BootScriptPath'){$argument=Join-Path $root 'GephTun-BootReconcile.ps1'}
    # Inherit the host execution policy. This runner never overrides it.
    $arguments=@('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path (Join-Path $root 'tests') $suite.File),$suite.RootArgument,$argument,'-ResultJson',$receipt)
    Write-Host ('Running '+$suite.Name+' in a fresh process...')
    # Merge textual output only. Exit code and receipt are independently checked.
    $previousPreference=$ErrorActionPreference
    $code=-1
    try { $ErrorActionPreference='Continue'; & $engine @arguments *> $log; $code=$LASTEXITCODE }
    finally { $ErrorActionPreference=$previousPreference }
    $record=$null;$problem=''
    try {
        if(-not (Test-Path -LiteralPath $receipt)){throw 'No receipt was produced.'}
        $record=Get-Content -LiteralPath $receipt -Raw -Encoding UTF8 | ConvertFrom-Json
        Assert-GephValidationSuiteReceipt $record|Out-Null
        if($code -ne 0){throw ('Process exited with code '+$code)}
    }catch{$problem=$_.Exception.Message}
    $results.Add([pscustomobject]@{Suite=$suite.Name;ExitCode=$code;Result=$(if($problem){'FAIL'}else{'PASS'});Detail=$problem;Receipt=$receipt;Log=$log})
}
$failed=@($results|Where-Object Result -eq 'FAIL').Count
$summary=[ordered]@{Version='1.5.0';CapturedUtc=[DateTime]::UtcNow.ToString('o');HostPowerShell=$PSVersionTable.PSVersion.ToString();Platform=[Environment]::OSVersion.Platform.ToString();ExecutionPolicyOverrideUsed=$false;Scope='Parser/C# compilation, managed WFP policy plan, mocked bypass/protection/controller/recovery, in-memory DNS, identity safeguards, candidate verifier integrity fixtures, and package-integrity tests. No live tunnel, reboot, TLS/network or UI acceptance.';NativeWindowsAcceptance='NOT_RUN';ProductionQualified=$false;Total=$results.Count;Passed=$results.Count-$failed;Failed=$failed;Suites=$results.ToArray()}
Write-GephPackageNewJson (Join-Path $output 'summary.json') $summary
$results|Format-Table -AutoSize -Wrap
Write-Host ('Results: '+$output)
Write-Host 'This runner does not alter the bundled historical/static qualification metadata or certify a production release.'
if($failed){exit 1}
