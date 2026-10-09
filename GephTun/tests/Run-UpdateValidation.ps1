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
    [pscustomobject]@{Name='Package';File='Package.Tests.ps1';RootArgument='-PackageDirectory'}
)
$results=New-Object 'Collections.Generic.List[object]'
foreach($suite in $suites){
    $receipt=Join-Path $output ($suite.Name+'.json')
    $log=Join-Path $output ($suite.Name+'.txt')
    $argument=$root
    if($suite.RootArgument -eq '-BootScriptPath'){$argument=Join-Path $root 'GephTun-BootReconcile.ps1'}
    $arguments=@('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',(Join-Path (Join-Path $root 'tests') $suite.File),$suite.RootArgument,$argument,'-ResultJson',$receipt)
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
        if($record.Total -lt 1 -or $record.Failed -ne 0 -or $record.Passed -ne $record.Total){throw 'Suite reported failures or incomplete execution.'}
        if($code -ne 0){throw ('Process exited with code '+$code)}
    }catch{$problem=$_.Exception.Message}
    $results.Add([pscustomobject]@{Suite=$suite.Name;ExitCode=$code;Result=$(if($problem){'FAIL'}else{'PASS'});Detail=$problem;Receipt=$receipt;Log=$log})
}
$failed=@($results|Where-Object Result -eq 'FAIL').Count
$summary=[ordered]@{Version='1.5.0';CapturedUtc=[DateTime]::UtcNow.ToString('o');HostPowerShell=$PSVersionTable.PSVersion.ToString();Platform=[Environment]::OSVersion.Platform.ToString();Scope='Parser/C# compilation, managed WFP policy plan, mocked bypass/protection/controller/recovery, in-memory DNS, package-integrity tests. No live tunnel, reboot, TLS/network or UI acceptance.';NativeWindowsAcceptance='NOT_RUN';ProductionQualified=$false;Total=$results.Count;Passed=$results.Count-$failed;Failed=$failed;Suites=$results.ToArray()}
Write-GephPackageNewJson (Join-Path $output 'summary.json') $summary
$results|Format-Table -AutoSize -Wrap
Write-Host ('Results: '+$output)
Write-Host 'This runner does not alter the bundled historical/static qualification metadata or certify a production release.'
if($failed){exit 1}
