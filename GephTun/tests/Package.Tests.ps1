#Requires -Version 5.1
# Temporary copies only; no networking, administration or runtime-module import.
[CmdletBinding()]
param([string]$PackageDirectory,[string]$ResultJson)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
if(-not $PackageDirectory){$PackageDirectory=Split-Path -Parent $PSScriptRoot}
. (Join-Path $PSScriptRoot 'Package.Common.ps1')
$root=Get-GephPackageFullPath $PackageDirectory
$workspace=Join-Path ([IO.Path]::GetTempPath()) ('GephTun-package-tests-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($workspace)
$results=New-Object 'Collections.Generic.List[object]'
function Test-Case($Name,[scriptblock]$Body){
    try{& $Body;$results.Add([pscustomobject]@{Name=$Name;Result='PASS';Detail=''})}
    catch{$results.Add([pscustomobject]@{Name=$Name;Result='FAIL';Detail=$_.Exception.Message})}
}
function Assert-Rejected([string]$Folder){
    $failed=$false
    try{& (Join-Path $root 'Verify-GephTun.ps1') -PackageDirectory $Folder -Quiet | Out-Null}catch{$failed=$true}
    if(-not $failed){throw 'Corrupted package was accepted.'}
}
$copy=Join-Path $workspace 'GephTun'
try{
    Copy-Item -LiteralPath $root -Destination $copy -Recurse
    Test-Case 'Complete current package verifies' { & (Join-Path $root 'Verify-GephTun.ps1') -PackageDirectory $copy -Quiet | Out-Null }
    Test-Case 'Modified runtime source is rejected' {
        $path=Join-Path $copy 'GephTun.Resilience.ps1';$bytes=[IO.File]::ReadAllBytes($path)
        try{[IO.File]::AppendAllText($path,"`n# modified");Assert-Rejected $copy}finally{[IO.File]::WriteAllBytes($path,$bytes)}
    }
    Test-Case 'Missing resilience helper is rejected' {
        $path=Join-Path $copy 'GephTun.Resilience.ps1';$bytes=[IO.File]::ReadAllBytes($path)
        try{[IO.File]::Delete($path);Assert-Rejected $copy}finally{[IO.File]::WriteAllBytes($path,$bytes)}
    }
    Test-Case 'Unlisted installation files are rejected' {
        $path=Join-Path $copy 'unexpected.txt'
        try{[IO.File]::WriteAllText($path,'unexpected');Assert-Rejected $copy}finally{[IO.File]::Delete($path)}
    }
    Test-Case 'Forged production qualification is rejected' {
        $path=Join-Path $copy 'QUALIFICATION.json';$bytes=[IO.File]::ReadAllBytes($path)
        try{[IO.File]::WriteAllText($path,'{"ProductionQualified":true}');Assert-Rejected $copy}finally{[IO.File]::WriteAllBytes($path,$bytes)}
    }
    Test-Case 'Unsafe Windows archive paths are rejected' {
        foreach($name in @('../escape','a\b','CON','x:stream','a/../b','trail.','/rooted')){
            $failed=$false;try{Assert-GephPackageRelative $name}catch{$failed=$true}
            if(-not $failed){throw ('Unsafe path accepted: '+$name)}
        }
    }
    Test-Case 'An output inside the package is rejected' {
        $failed=$false;try{Assert-GephPackageOutput (Join-Path $copy 'receipt.json') $copy}catch{$failed=$true}
        if(-not $failed){throw 'Evidence output could overwrite the installation.'}
    }
}finally{
    # workspace is an unguessable directory created above, never a user-supplied root.
    if([IO.Directory]::Exists($workspace)){Remove-Item -LiteralPath $workspace -Recurse -Force}
}
$failed=@($results|Where-Object Result -eq 'FAIL').Count
$report=[ordered]@{Version='1.5.0';CapturedUtc=[DateTime]::UtcNow.ToString('o');Scope='Package integrity and temporary corruption fixtures; no runtime execution.';Total=$results.Count;Passed=$results.Count-$failed;Failed=$failed;Skipped=0;Tests=$results.ToArray()}
if($ResultJson){$output=Get-GephPackageFullPath $ResultJson;Assert-GephPackageOutput $output $root;Write-GephPackageNewJson $output $report}
$results|Format-Table -AutoSize -Wrap
if($failed){exit 1}
