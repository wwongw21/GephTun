#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string[]]$ReferenceDirectories,
    [string]$PackageDirectory,
    [string[]]$Files=@('GephTun.Core.psm1','GephTun.Network.cs','GephTun.UI.ps1','GephTun.Worker.ps1','GephTun.WorkerHost.ps1','GephTun-BootReconcile.ps1','Launch-GephTun.ps1'),
    [string]$ResultJson
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Diagnostics.Common.ps1')
if(-not $PackageDirectory){$PackageDirectory=$script:DiagnosticPackageRoot}
$package=Get-GephPackageFullPath $PackageDirectory
$rows=@(foreach($referenceDirectory in $ReferenceDirectories){
    $reference=Get-GephPackageFullPath $referenceDirectory
    foreach($relative in $Files){
        Assert-GephPackageRelative $relative
        $left=Join-Path $package $relative;$right=Join-Path $reference $relative
        $state='UNKNOWN';$errorText='';$leftHash=$null;$rightHash=$null
        try{
            Assert-GephPackageNoRedirect $left;Assert-GephPackageNoRedirect $right
            $leftHash=(Get-FileHash -LiteralPath $left -Algorithm SHA256 -ErrorAction Stop).Hash
            $rightHash=(Get-FileHash -LiteralPath $right -Algorithm SHA256 -ErrorAction Stop).Hash
            $state=$(if($leftHash -eq $rightHash){'MATCH'}else{'DIFFERENT'})
        }catch{$errorText=$_.Exception.Message}
        [pscustomobject]@{File=$relative;Reference=$reference;State=$state;PackageSha256=$leftHash;ReferenceSha256=$rightHash;Error=$errorText}
    }
})
Write-DiagnosticResult ([ordered]@{Kind='GephTunFileComparison';CapturedUtc=[DateTime]::UtcNow.ToString('o');PackageDirectory=$package;Rows=$rows;Scope='File identity comparison; modified bytes are not a qualification result.'}) $ResultJson
