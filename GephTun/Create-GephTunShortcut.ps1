#Requires -Version 5.1
[CmdletBinding()]
param([string]$ShortcutPath)

$ErrorActionPreference = 'Stop'
$installDirectory = [IO.Path]::GetFullPath($PSScriptRoot)
if (-not $ShortcutPath) {
    $ShortcutPath = Join-Path (Split-Path -Parent $installDirectory) 'GephTun.lnk'
}
$ShortcutPath = [IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ShortcutPath))
# Local shortcuts contain absolute paths. Keep them outside the sealed package
# and recreate them after moving or extracting the application.
if ($ShortcutPath.StartsWith($installDirectory + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Save the shortcut beside the GephTun folder or on your desktop, outside the package.'
}
if ([IO.Path]::GetExtension($ShortcutPath) -ine '.lnk' -or (Test-Path -LiteralPath $ShortcutPath)) {
    throw 'Choose a new .lnk path; existing files will not be replaced.'
}
$launcher = Join-Path $installDirectory 'Launch-GephTun.ps1'
$icon = Join-Path $installDirectory 'assets\GephTun.ico'
foreach ($path in @($launcher, $icon)) {
    if (-not [IO.File]::Exists($path)) { throw ('Required application file is missing: ' + $path) }
}
$windowsDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
$powershellPath = Join-Path $windowsDirectory 'System32\WindowsPowerShell\v1.0\powershell.exe'
$shell = $null
$shortcut = $null
try {
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($ShortcutPath)
    $shortcut.TargetPath = $powershellPath
    # Match the existing .cmd launcher, including its process-only policy flag.
    $shortcut.Arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Sta -WindowStyle Hidden -File "{0}" -InitialAction Show' -f $launcher
    $shortcut.WorkingDirectory = $installDirectory
    $shortcut.IconLocation = $icon + ',0'
    $shortcut.Description = 'Open GephTun'
    $shortcut.WindowStyle = 7
    $shortcut.Save()
    Write-Output $ShortcutPath
}
finally {
    if ($null -ne $shortcut) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shortcut) }
    if ($null -ne $shell) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell) }
}
