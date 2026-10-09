#Requires -Version 5.1
# CI orchestration only. Product tests execute as a disposable standard user.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$PackageDirectory,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [ValidateSet('powershell.exe','pwsh.exe')][string]$PowerShellExecutable = 'powershell.exe',
    [switch]$Child
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'This CI helper requires a disposable Windows runner.'
}
$package = [IO.Path]::GetFullPath($PackageDirectory)
$output = [IO.Path]::GetFullPath($OutputDirectory)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $administrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} finally { $identity.Dispose() }

if ($Child) {
    try {
        if ($administrator) { throw 'Refusing to run product tests with administrator rights.' }
        # Windows may inherit the elevated parent's TEMP path. Give isolated
        # fixtures a directory this standard account can actually write.
        $temporary = Join-Path $output 'temporary'
        [void][IO.Directory]::CreateDirectory($temporary)
        $env:TEMP=$temporary; $env:TMP=$temporary
        [ordered]@{PowerShell=$PSVersionTable.PSVersion.ToString();Platform=[Environment]::OSVersion.VersionString;Administrator=$administrator;NativeWindowsAcceptance='NOT_RUN';ProductionQualified=$false} |
            ConvertTo-Json | Set-Content -LiteralPath (Join-Path $output 'host.json') -Encoding UTF8
        Write-Host ('Isolated validation host: ' + $PSVersionTable.PSVersion + '; standard user; no live network acceptance.')
        $verification = & (Join-Path $package 'Verify-GephTun.ps1') -PackageDirectory $package
        $verification | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $output 'verification.json') -Encoding UTF8
        # The default runner names nine isolated suites; no native smoke, protection
        # command, tunnel launcher or emergency-unlock entry point is invoked here.
        $global:LASTEXITCODE = 0
        & (Join-Path $package 'tests/Run-UpdateValidation.ps1') -PackageDirectory $package -OutputDirectory (Join-Path $output 'suites')
        exit $LASTEXITCODE
    } catch {
        $_ | Out-String | Set-Content -LiteralPath (Join-Path $output 'child-failure.txt') -Encoding UTF8
        Write-Error $_ -ErrorAction Continue
        exit 1
    }
}

if (-not $administrator) { throw 'Runner setup needs administrator rights to create a standard test account.' }
if (Test-Path -LiteralPath $output) { throw 'Use a fresh output directory; previous evidence must not be overwritten.' }
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$repositoryPrefix = $repository.TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
if ($output.Equals($repository, [StringComparison]::OrdinalIgnoreCase) -or
    $output.StartsWith($repositoryPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'CI evidence must be outside the checkout.'
}
[void][IO.Directory]::CreateDirectory($output)
$engine = (Get-Command $PowerShellExecutable -CommandType Application -ErrorAction Stop).Source
$account = $null
$testExitCode = 1
try {
    $userName = 'GephTunCI' + [guid]::NewGuid().ToString('N').Substring(0,8)
    $password = ConvertTo-SecureString ('Gt!9' + [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')) -AsPlainText -Force
    $account = New-LocalUser -Name $userName -Password $password -Description 'Disposable GephTun isolated CI test account'
    $users = Get-LocalGroup -SID 'S-1-5-32-545'
    $membership = @(Get-LocalGroupMember -Group $users.Name | Where-Object { $_.SID.Value -eq $account.SID.Value })
    if ($membership.Count -eq 0) { Add-LocalGroupMember -Group $users.Name -Member $account }
    # Grant source read/execute and evidence write access only. Never add the
    # account to Administrators or Network Configuration Operators.
    & icacls.exe $repository /grant ('*' + $account.SID.Value + ':(OI)(CI)RX') /T /Q
    if ($LASTEXITCODE -ne 0) { throw 'Could not grant source read access to the isolated account.' }
    & icacls.exe $output /grant ('*' + $account.SID.Value + ':(OI)(CI)M') /T /Q
    if ($LASTEXITCODE -ne 0) { throw 'Could not grant evidence access to the isolated account.' }
    $credential = New-Object Management.Automation.PSCredential(($env:COMPUTERNAME + '\' + $userName), $password)
    $arguments = @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
        '-File',('"{0}"' -f $PSCommandPath),'-Child',
        '-PackageDirectory',('"{0}"' -f $package),'-OutputDirectory',('"{0}"' -f $output))
    $stdout = Join-Path $output 'launcher.stdout.log'
    $stderr = Join-Path $output 'launcher.stderr.log'
    $process = Start-Process -FilePath $engine -ArgumentList $arguments -Credential $credential -LoadUserProfile `
        -WorkingDirectory $repository -RedirectStandardOutput $stdout -RedirectStandardError $stderr -Wait -PassThru
    try {
        $process.WaitForExit(); $process.Refresh()
        if ($null -eq $process.ExitCode) { throw 'The isolated test process did not report an exit code.' }
        $testExitCode = $process.ExitCode
    } finally { $process.Dispose() }
    foreach ($log in @($stdout,$stderr)) {
        if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log | ForEach-Object { Write-Host $_ } }
    }
} catch {
    $_ | Out-String | Set-Content -LiteralPath (Join-Path $output 'setup-failure.txt') -Encoding UTF8
    throw
} finally {
    if ($null -ne $account) {
        try { Remove-LocalUser -SID $account.SID -ErrorAction Stop }
        catch { $_ | Out-String | Set-Content -LiteralPath (Join-Path $output 'account-cleanup-failure.txt') -Encoding UTF8; throw }
    }
}
exit $testExitCode
