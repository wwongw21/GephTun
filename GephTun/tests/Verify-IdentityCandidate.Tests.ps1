#Requires -Version 5.1
[CmdletBinding()]
param([string]$PackageDirectory,[string]$ResultJson)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
if(-not $PackageDirectory){$PackageDirectory=Split-Path -Parent $PSScriptRoot}
$root=[IO.Path]::GetFullPath($PackageDirectory)
$external=Join-Path (Split-Path -Parent $root) 'evidence'
$workspace=Join-Path ([IO.Path]::GetTempPath()) ('GephTun-identity-verifier-tests-'+[guid]::NewGuid().ToString('N'))
$results=New-Object 'Collections.Generic.List[object]'
[void][IO.Directory]::CreateDirectory($workspace)

# Extract only the receipt gate's pure functions from the runner. The suite
# never invokes the runner or starts any of its system/test child processes.
$runnerPath=Join-Path $root 'tests/Run-UpdateValidation.ps1'
$runnerTokens=$null;$runnerParseErrors=$null
$runnerAst=[Management.Automation.Language.Parser]::ParseFile($runnerPath,[ref]$runnerTokens,[ref]$runnerParseErrors)
if($runnerParseErrors.Count -gt 0){throw 'Runner source could not be parsed for the pure receipt tests.'}
foreach($helperName in @('Get-GephValidationIntegerCount','Assert-GephValidationSuiteReceipt')){
    $helper=$runnerAst.Find({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $helperName},$true)
    if($null -eq $helper){throw ('Pure receipt helper was not found in runner source: '+$helperName)}
    Invoke-Expression $helper.Extent.Text
}

function Add-Result([string]$Name,[scriptblock]$Body){
    $before=@(Get-ChildItem -LiteralPath $workspace -Force -Directory|ForEach-Object FullName)
    try{& $Body;$results.Add([pscustomobject]@{Name=$Name;Result='PASS';Detail=''})}
    catch{$results.Add([pscustomobject]@{Name=$Name;Result='FAIL';Detail=$_.Exception.Message})}
    finally{
        foreach($folder in @(Get-ChildItem -LiteralPath $workspace -Force -Directory)){
            if($folder.FullName -notin $before){Remove-Item -LiteralPath $folder.FullName -Recurse -Force}
        }
    }
}
function New-Fixture{
    $packageCopy=Join-Path $workspace ('package-'+[guid]::NewGuid().ToString('N'))
    $receiptCopy=Join-Path $workspace ('evidence-'+[guid]::NewGuid().ToString('N'))
    Copy-Item -LiteralPath $root -Destination $packageCopy -Recurse
    Copy-Item -LiteralPath $external -Destination $receiptCopy -Recurse
    # The validator expects a sibling named evidence beside the package folder.
    $fixture=Join-Path $workspace ('fixture-'+[guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($fixture)
    $finalPackage=Join-Path $fixture 'GephTun'
    Move-Item -LiteralPath $packageCopy -Destination $finalPackage
    Move-Item -LiteralPath $receiptCopy -Destination (Join-Path $fixture 'evidence')
    return $finalPackage
}
function Write-Json([string]$Path,$Value){
    $json=ConvertTo-Json -InputObject $Value -Depth 16
    [IO.File]::WriteAllText($Path,$json,(New-Object Text.UTF8Encoding($false)))
}
function Get-Sha256([string]$Path){return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash}
function Update-IntegrityAfterValidationEdit([string]$Fixture){
    $validationPath=Join-Path $Fixture 'tests/current-validation.json'
    $qualificationPath=Join-Path $Fixture 'QUALIFICATION.json'
    $manifestPath=Join-Path $Fixture 'PACKAGE-MANIFEST.json'
    $qualification=Get-Content -LiteralPath $qualificationPath -Raw -Encoding UTF8|ConvertFrom-Json
    foreach($record in $qualification.Evidence){
        if($record.Path -ceq 'tests/current-validation.json'){$record.Sha256=Get-Sha256 $validationPath}
    }
    Write-Json $qualificationPath $qualification
    $manifest=Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8|ConvertFrom-Json
    foreach($entry in $manifest.Files){
        if($entry.Path -ceq 'tests/current-validation.json'){$entry.Bytes=(Get-Item -LiteralPath $validationPath).Length;$entry.Sha256=Get-Sha256 $validationPath}
        if($entry.Path -ceq 'QUALIFICATION.json'){$entry.Bytes=(Get-Item -LiteralPath $qualificationPath).Length;$entry.Sha256=Get-Sha256 $qualificationPath}
    }
    Write-Json $manifestPath $manifest
}
function Assert-ValidatorRejects([string]$Fixture){
    $rejected=$false
    try{& (Join-Path $Fixture 'Verify-GephTun.ps1') -PackageDirectory $Fixture -Quiet|Out-Null}catch{$rejected=$true}
    if(-not $rejected){throw 'Verifier accepted an invalid candidate fixture.'}
}
function Assert-ReceiptRejected($Receipt){
    $rejected=$false
    try{Assert-GephValidationSuiteReceipt $Receipt|Out-Null}catch{$rejected=$true}
    if(-not $rejected){throw 'Receipt validator accepted an incomplete or malformed suite record.'}
}

try{
    Add-Result 'A complete Results receipt schema is accepted' {
        $record=ConvertFrom-Json '{"Total":2,"Passed":2,"Failed":0,"Results":[{"Result":"PASS"},{"Result":"PASS"}]}'
        $summary=Assert-GephValidationSuiteReceipt $record
        if($summary.Total -ne 2 -or $summary.CaseCount -ne 2){throw 'Receipt summary did not match the two passing cases.'}
    }
    Add-Result 'A complete Tests receipt schema with Passed booleans is accepted' {
        $record=ConvertFrom-Json '{"Total":2,"Passed":2,"Failed":0,"Tests":[{"Passed":true},{"Passed":true}]}'
        $summary=Assert-GephValidationSuiteReceipt $record
        if($summary.Total -ne 2 -or $summary.CaseCount -ne 2){throw 'Receipt summary did not match the two passing cases.'}
    }
    Add-Result 'Matching Result and Passed fields are accepted' {
        $record=ConvertFrom-Json '{"Total":1,"Passed":1,"Failed":0,"Tests":[{"Result":"PASS","Passed":true}]}'
        $summary=Assert-GephValidationSuiteReceipt $record
        if($summary.Total -ne 1 -or $summary.CaseCount -ne 1){throw 'Receipt summary did not match the passing case.'}
    }
    Add-Result 'Contradictory Result and Passed fields are rejected' {
        Assert-ReceiptRejected (ConvertFrom-Json '{"Total":1,"Passed":1,"Failed":0,"Tests":[{"Result":"PASS","Passed":false}]}')
    }
    Add-Result 'Nonboolean Passed is rejected when Result is present' {
        Assert-ReceiptRejected (ConvertFrom-Json '{"Total":1,"Passed":1,"Failed":0,"Tests":[{"Result":"PASS","Passed":"true"}]}')
        Assert-ReceiptRejected (ConvertFrom-Json '{"Total":1,"Passed":1,"Failed":0,"Tests":[{"Result":"PASS","Passed":1}]}')
        Assert-ReceiptRejected (ConvertFrom-Json '{"Total":1,"Passed":1,"Failed":0,"Tests":[{"Result":"PASS","Passed":null}]}')
    }
    Add-Result 'Truncated case results are rejected despite passing aggregate counts' {
        Assert-ReceiptRejected (ConvertFrom-Json '{"Total":2,"Passed":2,"Failed":0,"Tests":[{"Result":"PASS"}]}')
    }
    Add-Result 'Missing case results are rejected despite passing aggregate counts' {
        Assert-ReceiptRejected (ConvertFrom-Json '{"Total":2,"Passed":2,"Failed":0}')
    }
    Add-Result 'An empty case array is rejected' {
        Assert-ReceiptRejected (ConvertFrom-Json '{"Total":1,"Passed":1,"Failed":0,"Tests":[]}')
    }
    Add-Result 'Missing Total is rejected' {
        Assert-ReceiptRejected (ConvertFrom-Json '{"Passed":2,"Failed":0,"Results":[{"Result":"PASS"},{"Result":"PASS"}]}')
    }
    Add-Result 'Non-integer and negative suite counts are rejected' {
        Assert-ReceiptRejected (ConvertFrom-Json '{"Total":2.5,"Passed":2.5,"Failed":0,"Tests":[{"Result":"PASS"},{"Result":"PASS"}]}')
        Assert-ReceiptRejected (ConvertFrom-Json '{"Total":-1,"Passed":-1,"Failed":0,"Tests":[{"Result":"PASS"}]}')
        Assert-ReceiptRejected (ConvertFrom-Json '{"Total":true,"Passed":true,"Failed":0,"Tests":[{"Result":"PASS"}]}')
        Assert-ReceiptRejected (ConvertFrom-Json '{"Total":1,"Passed":true,"Failed":0,"Tests":[{"Result":"PASS"}]}')
        Assert-ReceiptRejected (ConvertFrom-Json '{"Total":1,"Passed":2,"Failed":-1,"Tests":[{"Result":"PASS"}]}')
    }
    Add-Result 'A failed case cannot be hidden by passing aggregate counts' {
        Assert-ReceiptRejected (ConvertFrom-Json '{"Total":2,"Passed":2,"Failed":0,"Results":[{"Result":"PASS"},{"Result":"FAIL"}]}')
    }
    Add-Result 'A blocked or skipped receipt is rejected' {
        Assert-ReceiptRejected (ConvertFrom-Json '{"Total":1,"Passed":1,"Failed":0,"Skipped":1,"Tests":[{"Result":"PASS"}]}')
        Assert-ReceiptRejected (ConvertFrom-Json '{"Total":1,"Passed":1,"Failed":0,"Status":"BLOCKED","Tests":[{"Result":"PASS"}]}')
        Assert-ReceiptRejected (ConvertFrom-Json '{"Total":1,"Passed":1,"Failed":0,"Status":"FAIL","Tests":[{"Result":"PASS"}]}')
    }
    Add-Result 'Intact current unqualified candidate is accepted' {
        $fixture=New-Fixture
        $result=& (Join-Path $fixture 'Verify-GephTun.ps1') -PackageDirectory $fixture -Quiet
        if($null -eq $result -or -not $result.Success -or $result.ProductionQualified){throw 'Verifier did not return an unqualified integrity result.'}
    }
    Add-Result 'A changed source file is rejected' {
        $fixture=New-Fixture
        [IO.File]::AppendAllText((Join-Path $fixture 'GephTun.Core.psm1'),"`n# changed fixture")
        Assert-ValidatorRejects $fixture
    }
    Add-Result 'A missing source file is rejected' {
        $fixture=New-Fixture
        [IO.File]::Delete((Join-Path $fixture 'GephTun.Core.psm1'))
        Assert-ValidatorRejects $fixture
    }
    Add-Result 'A missing required current-validation field is rejected after integrity hashes are refreshed' {
        $fixture=New-Fixture
        $path=Join-Path $fixture 'tests/current-validation.json'
        $validation=Get-Content -LiteralPath $path -Raw -Encoding UTF8|ConvertFrom-Json
        $validation.PSObject.Properties.Remove('FocusedIdentityBehaviorTests')
        Write-Json $path $validation
        Update-IntegrityAfterValidationEdit $fixture
        Assert-ValidatorRejects $fixture
    }
    Add-Result 'A stale candidate revision is rejected after integrity hashes are refreshed' {
        $fixture=New-Fixture
        $path=Join-Path $fixture 'tests/current-validation.json'
        $validation=Get-Content -LiteralPath $path -Raw -Encoding UTF8|ConvertFrom-Json
        $validation.CandidateRevision='identity-safeguards-1'
        Write-Json $path $validation
        Update-IntegrityAfterValidationEdit $fixture
        Assert-ValidatorRejects $fixture
    }
    Add-Result 'A blocked identity test cannot be relabeled as PASS' {
        $fixture=New-Fixture
        $path=Join-Path $fixture 'tests/current-validation.json'
        $validation=Get-Content -LiteralPath $path -Raw -Encoding UTF8|ConvertFrom-Json
        $validation.FocusedIdentityBehaviorTests='PASS'
        Write-Json $path $validation
        Update-IntegrityAfterValidationEdit $fixture
        Assert-ValidatorRejects $fixture
    }
    Add-Result 'A changed external receipt is rejected' {
        $fixture=New-Fixture
        [IO.File]::AppendAllText((Join-Path (Split-Path -Parent $fixture) 'evidence/CSHARP-COMPILE-RECEIPT.json'),"`n ")
        Assert-ValidatorRejects $fixture
    }
    Add-Result 'A missing external receipt is rejected' {
        $fixture=New-Fixture
        [IO.File]::Delete((Join-Path (Split-Path -Parent $fixture) 'evidence/CSHARP-COMPILE-RECEIPT.json'))
        Assert-ValidatorRejects $fixture
    }
    Add-Result 'The standard runner includes identity and verifier suites without an execution-policy override' {
        $runner=Get-Content -LiteralPath (Join-Path $root 'tests/Run-UpdateValidation.ps1') -Raw -Encoding UTF8
        if($runner -notmatch "Name='IdentitySafeguards';File='IdentitySafeguards\.Tests\.ps1'" -or
            $runner -notmatch "Name='CandidateVerifier';File='Verify-IdentityCandidate\.Tests\.ps1'" -or
            $runner.Contains('-ExecutionPolicy')){
            throw 'Runner suite registration or inherited-policy contract is incorrect.'
        }
    }
    $failed=@($results|Where-Object Result -eq 'FAIL').Count
    $report=[ordered]@{Schema='GephTun.IdentityCandidate.VerifierTests.v1';Version='1.5.0';CandidateRevision='identity-safeguards-verifier-repair-3';Scope='Pure runner receipt-helper fixtures, temporary package-copy verifier checks, and static runner enumeration only; no full runner invocation, runtime module import, native call, network, driver, service, administrator action, or policy override.';Total=$results.Count;Passed=$results.Count-$failed;Failed=$failed;Skipped=0;Tests=$results.ToArray()}
    if($ResultJson){[IO.File]::WriteAllText($ResultJson,(ConvertTo-Json -InputObject $report -Depth 12),(New-Object Text.UTF8Encoding($false)))}
    $results|Format-Table -AutoSize -Wrap
    if($failed){exit 1}
}finally{
    # Remove only the unique temporary folder created by this test script.
    if([IO.Directory]::Exists($workspace)){Remove-Item -LiteralPath $workspace -Recurse -Force}
}
