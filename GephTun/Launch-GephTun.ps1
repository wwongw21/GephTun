#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Show', 'Connect', 'Disconnect')]
    [string]$InitialAction = 'Show'
)

# Paths are passed as quoted -File arguments. PowerShell binds argument values
# as data, so spaces, apostrophes, and command-looking characters never become
# executable PowerShell syntax.
$ErrorActionPreference = 'Stop'
$script:InstallDirectory = [IO.Path]::GetFullPath($PSScriptRoot)
$uiPath = Join-Path $script:InstallDirectory 'GephTun.UI.ps1'

function Show-LaunchError {
    param([string]$Message)
    try {
        Add-Type -AssemblyName System.Windows.Forms
        [void][System.Windows.Forms.MessageBox]::Show(
            $Message, 'GephTun',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error)
    }
    catch { Write-Error $Message -ErrorAction Continue }
}

function Assert-UiScriptReadable {
    param([Parameter(Mandatory=$true)][string]$Path)
    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count) { throw ('GephTun.UI.ps1 is not a valid PowerShell script: ' + (($parseErrors | Select-Object -First 1).Message)) }
}

function Test-ElevationCancelled {
    param([Exception]$Exception)
    while ($null -ne $Exception) {
        if ($Exception -is [System.ComponentModel.Win32Exception] -and $Exception.NativeErrorCode -eq 1223) { return $true }
        $Exception = $Exception.InnerException
    }
    return $false
}

try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitOperatingSystem) {
        throw 'GephTun requires 64-bit Windows on an Intel or AMD PC.'
    }
    if (-not [System.IO.File]::Exists($uiPath)) {
        throw 'GephTun.UI.ps1 is missing. Extract the complete GephTun folder and try again.'
    }
    # Catch a truncated or corrupted UI script before a hidden/UAC child is
    # started, so the existing launch error dialog remains actionable.
    Assert-UiScriptReadable $uiPath

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
        $isAdministrator = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    finally { $identity.Dispose() }

    $nativeHost = $PSVersionTable.PSEdition -eq 'Desktop' -and [Environment]::Is64BitProcess -and
        [Threading.Thread]::CurrentThread.GetApartmentState() -eq [Threading.ApartmentState]::STA
    if ($isAdministrator -and $nativeHost) {
        & $uiPath -InitialAction $InitialAction
        if (-not $?) { exit 1 }
        return
    }

    $windowsDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
    $powershellPath = Join-Path $windowsDirectory 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not [Environment]::Is64BitProcess) {
        $powershellPath = Join-Path $windowsDirectory 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    }
    if (-not [IO.File]::Exists($powershellPath)) { throw '64-bit Windows PowerShell could not be found.' }
    # Start-Process on Windows PowerShell 5.1 joins ArgumentList elements
    # without adding quotes. Quote the script path before passing it so an
    # extraction directory containing spaces remains a single argument.
    $arguments = @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-Sta', '-WindowStyle', 'Hidden', '-File', ('"{0}"' -f $uiPath),
        '-InitialAction', $InitialAction
    )
    $launchArguments = @{ FilePath = $powershellPath; ArgumentList = $arguments; ErrorAction = 'Stop'; PassThru = $true }
    if (-not $isAdministrator) { $launchArguments.Verb = 'RunAs' }
    $launched = Start-Process @launchArguments
    $launched.Dispose()
}
catch {
    if (Test-ElevationCancelled $_.Exception) {
        Show-LaunchError 'Administrator access was cancelled. GephTun needs it to manage the tunnel and restore network settings.'
    }
    else { Show-LaunchError $_.Exception.Message }
    exit 1
}
