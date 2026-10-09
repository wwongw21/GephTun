#Requires -Version 5.1
<##
    Bounded W02 NRPT conflict fixture.

    This helper is deliberately separate from the unavailable external P04
    controller. It owns one unique invalid namespace and comment, never accepts
    a caller-supplied namespace, and never removes a rule by namespace or by a
    broad provider-wide pattern. Dot-source with -LibraryOnly to use the
    function in a test double; invoke with -Run to perform the Windows check.
##>
[CmdletBinding()]
param(
    [string]$OutputJson,
    [switch]$Run,
    [switch]$LibraryOnly
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'

# Package.Common owns the path and no-redirection checks used by the release
# harness.  Keep all fixture evidence outside the complete package tree so a
# failed run cannot replace a source file or an embedded receipt.
. (Join-Path $PSScriptRoot 'Package.Common.ps1')
$script:NrptPackageRoot=Get-GephPackageFullPath (Split-Path -Parent $PSScriptRoot)

function Resolve-NrptEvidencePath {
    param([Parameter(Mandatory=$true)][string]$Path,[switch]$RequireNew)
    $full=Get-GephPackageFullPath $Path
    Assert-GephPackageNoRedirect $full
    if (Test-GephPackageWithin $full $script:NrptPackageRoot) { throw 'NRPT fixture evidence must be outside the complete package tree.' }
    if ($full -eq [IO.Path]::GetPathRoot($full)) { throw 'A filesystem root cannot be used as evidence output.' }
    if ($RequireNew) { Assert-GephPackageOutput $full $script:NrptPackageRoot }
    return $full
}

function Write-NrptCheckpoint {
    param([string]$Path,$Value)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    $full=Resolve-NrptEvidencePath $Path
    $parent=[IO.Path]::GetDirectoryName($full)
    if (-not [IO.Directory]::Exists($parent)) { [IO.Directory]::CreateDirectory($parent)|Out-Null }
    Assert-GephPackageNoRedirect $full
    # Each checkpoint is an immutable CreateNew record. A logging failure
    # cannot prevent provider removal or erase the last known identity.
    Write-GephPackageNewJson $full $Value
}

function Get-NrptFixtureObservation($Rule) {
    [pscustomobject]@{
        Name=[string]$Rule.Name
        Namespace=@($Rule.Namespace | ForEach-Object { [string]$_ })
        NameServers=@($Rule.NameServers | ForEach-Object { [string]$_ })
        Comment=[string]$Rule.Comment
    }
}

function Invoke-NrptConflictFixture {
    [CmdletBinding()]
    param(
        [scriptblock]$GetRules = { Get-DnsClientNrptRule -ErrorAction Stop },
        [scriptblock]$AddRule = { param($Namespace,$NameServers,$Comment) Add-DnsClientNrptRule -Namespace $Namespace -NameServers $NameServers -Comment $Comment -ErrorAction Stop | Out-Null },
        [scriptblock]$RemoveRule = { param($Name) Remove-DnsClientNrptRule -Name $Name -Force -ErrorAction Stop },
        [Parameter(Mandatory=$true)][scriptblock]$Check,
        [string]$OutputPath,
        [string]$CheckpointPath,
        [string]$IdentityPath
    )
    # Validate every output path before the first provider query or mutation.
    # An interrupted process leaves the checkpoint as the durable ownership
    # record; it is deliberately not removed by this helper.
    if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
        $OutputPath=Resolve-NrptEvidencePath $OutputPath -RequireNew
        if ([string]::IsNullOrWhiteSpace($CheckpointPath)) { $CheckpointPath=$OutputPath+'.progress.json' }
        if ([string]::IsNullOrWhiteSpace($IdentityPath)) { $IdentityPath=$OutputPath+'.identity.json' }
    }
    if (-not [string]::IsNullOrWhiteSpace($CheckpointPath)) {
        $CheckpointPath=Resolve-NrptEvidencePath $CheckpointPath -RequireNew
    }
    if (-not [string]::IsNullOrWhiteSpace($IdentityPath)) {
        $IdentityPath=Resolve-NrptEvidencePath $IdentityPath -RequireNew
    }
    $tag='GephTun-Harness-'+[guid]::NewGuid().ToString('N')
    $namespace='.gephtun-'+[guid]::NewGuid().ToString('N')+'.invalid'
    if ($namespace -notmatch '^\.gephtun-[0-9a-f]{32}\.invalid$' -or $namespace -eq '.') { throw 'Generated NRPT namespace failed the scoped-fixture contract.' }
    $result=[ordered]@{
        Kind='GephTunNrptConflictFixture';Schema=1;CapturedUtc=[DateTime]::UtcNow.ToString('o')
        Status='RUNNING';Halted=$false;FeatureResult='NOT_RUN';CleanupResult='NOT_RUN'
        Namespace=$namespace;Comment=$tag;RuleName='';BaselineRules=@();RemainingRules=@();Actions=@();Error=''
        Scope='One unique invalid namespace and comment; exact Name cleanup; no global policy cleanup.'
    }
    $actions=New-Object 'Collections.Generic.List[object]'
    $identity=$null
    $baseline=@()
    $mutationAttempted=$false
    try {
        $baseline=@(& $GetRules | ForEach-Object { Get-NrptFixtureObservation $_ })
        $result.BaselineRules=$baseline
        $actions.Add([pscustomobject]@{Name='BaselineQuery';Result='PASS';Detail=('Observed {0} NRPT rule(s).' -f $baseline.Count)})
        if ($baseline.Count -gt 0) {
            $result.Status='BLOCKED_BY_BASELINE_CONFLICT';$result.Halted=$true
            $result.FeatureResult='NOT_RUN';$result.CleanupResult='NOT_NEEDED'
            $result.Error='Existing NRPT policy was present before fixture creation; no mutation was attempted.'
            $result.Actions=$actions.ToArray()
            return [pscustomobject]$result
        }
        # Record a conservative attempted-mutation marker immediately before
        # the provider call. If the process dies after this point, the durable
        # intent identifies the only rule namespace/comment that recovery may
        # inspect, even when identity capture never runs.
        Write-NrptCheckpoint $CheckpointPath ([ordered]@{Phase='INTENT_RECORDED';CapturedUtc=[DateTime]::UtcNow.ToString('o');Namespace=$namespace;Comment=$tag;RuleName='';MutationAttempted=$true})
        $mutationAttempted=$true
        & $AddRule $namespace @('127.0.0.1') $tag
        $actions.Add([pscustomobject]@{Name='Create';Result='PASS';Detail='Scoped NRPT fixture creation returned.'})
        $created=@(& $GetRules | Where-Object { [string]$_.Comment -eq $tag -and @($_.Namespace) -contains $namespace })
        if ($created.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$created[0].Name)) { throw 'NRPT fixture identity was not uniquely observed after creation.' }
        $identity=Get-NrptFixtureObservation $created[0]
        $result.RuleName=$identity.Name
        Write-NrptCheckpoint $IdentityPath ([ordered]@{Phase='IDENTITY_CAPTURED';CapturedUtc=[DateTime]::UtcNow.ToString('o');Namespace=$namespace;Comment=$tag;RuleName=$identity.Name;MutationAttempted=$true})
        $actions.Add([pscustomobject]@{Name='IdentityQuery';Result='PASS';Detail=('Captured exact rule Name/GUID: '+$identity.Name)})
        try {
            & $Check $identity | Out-Null
            $result.FeatureResult='PASS'
            $actions.Add([pscustomobject]@{Name='ProductCheck';Result='PASS';Detail='Conflict callback completed.'})
        }
        catch {
            $result.FeatureResult='FAIL';$result.Error=$_.Exception.Message
            $actions.Add([pscustomobject]@{Name='ProductCheck';Result='FAIL';Detail=$_.Exception.Message})
        }
    }
    catch {
        $result.FeatureResult='FAIL';if ([string]::IsNullOrWhiteSpace($result.Error)) {$result.Error=$_.Exception.Message}
        $actions.Add([pscustomobject]@{Name='Fixture';Result='FAIL';Detail=$_.Exception.Message})
    }
    finally {
        # A created rule must be cleaned up even when the product Check throws.
        # If identity capture failed after creation, query and remove only rules
        # carrying this helper's own random comment.  A baseline refusal made
        # no mutation and therefore must not perform a cleanup sweep.
        if ($mutationAttempted) {
          try {
            if ($null -ne $identity) {
                & $RemoveRule $identity.Name
                $actions.Add([pscustomobject]@{Name='RemoveExactName';Result='PASS';Detail=('Removed exact rule Name/GUID: '+$identity.Name)})
            }
            else {
                $fallback=@(& $GetRules | Where-Object { [string]$_.Comment -eq $tag })
                foreach ($rule in $fallback) {
                    if ([string]::IsNullOrWhiteSpace([string]$rule.Name)) { throw 'Own-comment fallback observed a rule without a Name/GUID.' }
                    & $RemoveRule ([string]$rule.Name)
                }
                $actions.Add([pscustomobject]@{Name='RemoveOwnCommentFallback';Result='PASS';Detail=('Removed {0} rule(s) carrying only this fixture comment.' -f $fallback.Count)})
            }
            # If a duplicate own-comment rule appeared during the callback,
            # remove only that own tag by its individually observed Name.
            $leftovers=@(& $GetRules | Where-Object { ([string]$_.Comment -eq $tag) -or ($null -ne $identity -and [string]$_.Name -eq $identity.Name) })
            foreach ($rule in $leftovers) {
                if ([string]$rule.Name -eq [string]$(if($null -ne $identity){$identity.Name}else{''})) { continue }
                if ([string]$rule.Comment -ne $tag) { continue }
                if ([string]::IsNullOrWhiteSpace([string]$rule.Name)) { throw 'Own-comment duplicate observed without a Name/GUID; refusing an empty removal target.' }
                & $RemoveRule ([string]$rule.Name)
            }
            $remaining=@(& $GetRules | Where-Object { ([string]$_.Comment -eq $tag) -or ($null -ne $identity -and [string]$_.Name -eq $identity.Name) })
            $result.RemainingRules=@($remaining | ForEach-Object { Get-NrptFixtureObservation $_ })
            if ($remaining.Count -ne 0) { throw 'NRPT fixture remained after exact-name/comment cleanup.' }
            $result.CleanupResult='PASS'
            $actions.Add([pscustomobject]@{Name='CleanupVerification';Result='PASS';Detail='Independent re-query proved the fixture absent.'})
        }
        catch {
            $result.CleanupResult='FAIL';$result.Status='HALTED';$result.Halted=$true
            $result.Error=if ([string]::IsNullOrWhiteSpace($result.Error)) {$_.Exception.Message} else {$result.Error+'; cleanup: '+$_.Exception.Message}
            try {
                $observed=@(& $GetRules | Where-Object { ([string]$_.Comment -eq $tag) -or ($null -ne $identity -and [string]$_.Name -eq $identity.Name) })
                $result.RemainingRules=@($observed | ForEach-Object { Get-NrptFixtureObservation $_ })
            } catch { }
            $actions.Add([pscustomobject]@{Name='CleanupVerification';Result='TEARDOWN-UNVERIFIED';Detail=$_.Exception.Message})
          }
        }
        else {
            $result.CleanupResult='NOT_NEEDED'
        }
    }
    if ($result.Status -eq 'RUNNING') {
        if ($result.FeatureResult -eq 'PASS' -and $result.CleanupResult -eq 'PASS') {$result.Status='PASS'}
        else {$result.Status='FAIL'}
    }
    $result.Actions=$actions.ToArray()
    return [pscustomobject]$result
}

function Write-NrptFixtureResult([string]$Path,$Result) {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'An external -OutputJson path is required.' }
    $full=Resolve-NrptEvidencePath $Path -RequireNew
    # CreateNew closes the check/write race: a second process cannot replace
    # an evidence file after validation.
    Write-GephPackageNewJson $full $Result
    return $full
}

if (-not $LibraryOnly) {
    if ([string]::IsNullOrWhiteSpace($OutputJson)) { throw 'Supply -OutputJson outside the package tree.' }
    # Resolve and reject unsafe or pre-existing evidence paths before the host
    # gate and, especially, before any Windows NRPT provider call.
    $outputPath=Resolve-NrptEvidencePath $OutputJson -RequireNew
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        $blocked=[pscustomobject][ordered]@{Kind='GephTunNrptConflictFixture';Schema=1;CapturedUtc=[DateTime]::UtcNow.ToString('o');Status='BLOCKED_BY_HOST';Halted=$true;FeatureResult='BLOCKED_BY_HOST';CleanupResult='NOT_RUN';Namespace='';Comment='';RuleName='';BaselineRules=@();RemainingRules=@();Actions=@([pscustomobject]@{Name='HostGate';Result='BLOCKED_BY_HOST';Detail='Windows PowerShell and DNS Client provider are required; no mutation was attempted.'});Error='';Scope='Windows-only scoped NRPT fixture.'}
        $written=Write-NrptFixtureResult $outputPath $blocked;Write-Output ('Saved '+$written);exit 2
    }
    if (-not $Run) {
        $notRun=[pscustomobject][ordered]@{Kind='GephTunNrptConflictFixture';Schema=1;CapturedUtc=[DateTime]::UtcNow.ToString('o');Status='NOT_RUN';Halted=$false;FeatureResult='NOT_RUN';CleanupResult='NOT_RUN';Namespace='';Comment='';RuleName='';BaselineRules=@();RemainingRules=@();Actions=@([pscustomobject]@{Name='RunGate';Result='NOT_RUN';Detail='Supply -Run to enable the disposable Windows fixture.'});Error='';Scope='Windows-only scoped NRPT fixture.'}
        $written=Write-NrptFixtureResult $outputPath $notRun;Write-Output ('Saved '+$written);exit 2
    }
    $checkpointPath=Resolve-NrptEvidencePath ($outputPath+'.progress.json') -RequireNew
    $identityPath=Resolve-NrptEvidencePath ($outputPath+'.identity.json') -RequireNew
    try {
        $modulePath=Join-Path (Split-Path -Parent $PSScriptRoot) 'GephTun.Core.psm1'
        Import-Module -Name $modulePath -Force -ErrorAction Stop
        $check={
            param($identity)
            try {
                $null=Test-GephTunPreflight -Port 0
            }
            catch {
                if ($_.Exception.Message -like '*Existing DNS routing policy was found*') { return }
                throw ('Product preflight rejected the fixture for an unexpected reason: '+$_.Exception.Message)
            }
            throw 'Product preflight unexpectedly accepted the NRPT conflict fixture.'
        }
        $runResult=Invoke-NrptConflictFixture -Check $check -OutputPath $outputPath -CheckpointPath $checkpointPath -IdentityPath $identityPath
    }
    catch {
        $runResult=[pscustomobject][ordered]@{Kind='GephTunNrptConflictFixture';Schema=1;CapturedUtc=[DateTime]::UtcNow.ToString('o');Status='FAIL';Halted=$false;FeatureResult='FAIL';CleanupResult='NOT_NEEDED';Namespace='';Comment='';RuleName='';BaselineRules=@();RemainingRules=@();Actions=@([pscustomobject]@{Name='Harness';Result='FAIL';Detail=$_.Exception.Message});Error=$_.Exception.Message;Scope='Windows-only scoped NRPT fixture.'}
    }
    $written=Write-NrptFixtureResult $outputPath $runResult;Write-Output ('Saved '+$written)
    if ($runResult.Status -eq 'PASS') { exit 0 }
    if ($runResult.Status -eq 'HALTED') { exit 3 }
    exit 1
}
