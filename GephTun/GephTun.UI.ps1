#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Show', 'Connect', 'Disconnect')]
    [string]$InitialAction = 'Show'
)

# Windows PowerShell 5.1 / .NET Framework WinForms. Network work runs in child
# worker processes; this process owns only the UI and one-second polling timer.
$ErrorActionPreference = 'Stop'
$script:InstallDirectory = [IO.Path]::GetFullPath($PSScriptRoot)
if (-not [IO.Directory]::Exists($script:InstallDirectory)) {
    throw 'The GephTun installation directory is unavailable. Extract the complete GephTun folder and try again.'
}
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'GephTun requires Windows. Open Launch-GephTun.cmd on a supported Windows PC.'
}
if ($PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitProcess -or
    [Threading.Thread]::CurrentThread.GetApartmentState() -ne [Threading.ApartmentState]::STA) {
    & (Join-Path $script:InstallDirectory 'Launch-GephTun.ps1') -InitialAction $InitialAction
    return
}
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
$isAdministrator = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
$identity.Dispose()
if (-not $isAdministrator) {
    & (Join-Path $script:InstallDirectory 'Launch-GephTun.ps1') -InitialAction $InitialAction
    return
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class GephTunDpi {
    [DllImport("user32.dll")]
    public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool DestroyIcon(IntPtr handle);
}
'@
    [void][GephTunDpi]::SetProcessDPIAware()
}
catch {
    # The host may already have set its DPI mode.
}
[System.Windows.Forms.Application]::EnableVisualStyles()
[System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)

$script:StateDirectory = Join-Path $env:ProgramData 'GephTun'
$script:ResultDirectory = Join-Path $script:StateDirectory 'results'
$script:RequestSessionId = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
$script:RequestDirectory = Join-Path (Join-Path $script:StateDirectory 'ui-requests') ([string]$script:RequestSessionId)
$script:LogDirectory = Join-Path $script:StateDirectory 'logs'
$script:StatusPath = Join-Path $script:StateDirectory 'status.json'
$script:SessionPath = Join-Path $script:StateDirectory 'session.json'
$script:IntentPath = Join-Path $script:StateDirectory 'connection-intent.json'
$script:WorkerPath = Join-Path $script:InstallDirectory 'GephTun.Worker.ps1'
$script:WorkerHostPath = Join-Path $script:InstallDirectory 'GephTun.WorkerHost.ps1'
$script:CorePath = Join-Path $script:InstallDirectory 'GephTun.Core.psm1'
$script:ReleasePath = Join-Path $script:InstallDirectory 'RELEASE.json'
$script:Utf8 = [System.Text.UTF8Encoding]::new($false)
$script:UiMutex = $null
$script:OwnsUiMutex = $false
$script:Operations = [System.Collections.Generic.List[object]]::new()
$script:LastState = $null
$script:StartupState = $null
$script:UiStatus = 'Checking'
$script:UiStartedUtc = [DateTime]::UtcNow
$script:ClosingRequested = $false
$script:DisconnectQueued = $false
$script:AllowClose = $false
$script:Polling = $false
$script:InitialActionPending = $InitialAction
$script:StartupFinished = $false
$script:LastStateLogKey = ''
$script:LastPollError = ''
$script:UnreadableSnapshotPolls = 0
$script:UiRequestHistory = @{}
$script:UiRequestSequence = 0
$script:LastActionFailure = $null
$script:TrayIcon = $null
$script:TrayMenu = $null
$script:TrayIcons = $null
$script:TrayIconKind = ''
$script:TrayNoticeShown = $false
$script:UiTrayEventsConnected = $false

function Get-StateProperty {
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return $Default }
    return $property.Value
}

function ConvertTo-UiUtc {
    param($Value)
    # JSON readers differ: 5.1 can return a string while newer PowerShell can
    # return a DateTime. Stringifying DateTime loses its UTC offset.
    if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime }
    if ($Value -is [DateTime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [DateTime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
        return $Value.ToUniversalTime()
    }
    return [DateTimeOffset]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal).UtcDateTime
}

function Enter-UiMutex {
    param([string]$Name)
    # An existing kernel object can outlive its owner. Acquire it instead of
    # assuming that object existence means a working UI is listening.
    $mutex = [System.Threading.Mutex]::new($false, $Name)
    $acquired = $false
    try {
        try { $acquired = $mutex.WaitOne(0) }
        catch [System.Threading.AbandonedMutexException] { $acquired = $true }
        return [pscustomobject]@{ Mutex = $mutex; Acquired = $acquired }
    }
    catch { $mutex.Dispose(); throw }
}

function Write-UiRequest {
    param([ValidateSet('Show', 'Connect', 'Disconnect')][string]$Action)
    $request = [ordered]@{ Action = $Action; SessionId = $script:RequestSessionId; CreatedUtc = [DateTime]::UtcNow.ToString('o') }
    $requestPath = Join-Path $script:RequestDirectory ([Guid]::NewGuid().ToString('N') + '.json')
    Write-GephTunJson $requestPath $request
}

function Read-UiTextSnapshot {
    param([string]$Path, [ValidateRange(1, 262144)][int]$MaximumBytes)
    # FileInfo.Attributes returns -1 for a missing file, which also sets the
    # ReparsePoint bit. GetAttributes throws a typed IO exception instead, so
    # an atomic-replacement collision follows the caller's retry path.
    $attributes = [IO.File]::GetAttributes($Path)
    if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The file is redirected.'
    }
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        ([IO.FileShare]::Read -bor [IO.FileShare]::Write -bor [IO.FileShare]::Delete))
    try {
        if ($stream.Length -gt $MaximumBytes) { throw 'The file is too large.' }
        $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::UTF8)
        try {
            # Keep routine status polls off the large-object heap. A status file
            # is normally small; allocating the full 256-KiB character limit
            # here used more than half a MiB on every one-second poll.
            # The bounded chunks also reject a file that grows during the read.
            $buffer = [char[]]::new([Math]::Min(4096, $MaximumBytes + 1))
            $text = [Text.StringBuilder]::new([Math]::Min([int]$stream.Length, $buffer.Length))
            while ($true) {
                $remaining = $MaximumBytes - $text.Length
                $take = [Math]::Min($buffer.Length, $remaining + 1)
                $count = $reader.ReadBlock($buffer, 0, $take)
                if ($count -gt $remaining) { throw 'The file is too large.' }
                [void]$text.Append($buffer, 0, $count)
                if ($count -lt $take) { return $text.ToString() }
            }
        } finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
}

function Get-UiRequestAction {
    param($Request, [DateTime]$NowUtc = [DateTime]::UtcNow)
    $action = [string](Get-StateProperty $Request 'Action' '')
    if ($action -notin @('Show', 'Connect', 'Disconnect')) { return '' }
    if ((Get-StateProperty $Request 'SessionId' -1) -ne $script:RequestSessionId) { return '' }
    try {
        $created = ConvertTo-UiUtc (Get-StateProperty $Request 'CreatedUtc' '')
        if ($created -lt $script:UiStartedUtc) { return '' }
        $age = ($NowUtc - $created).TotalSeconds
        if ($age -lt -10 -or $age -gt 120) { return '' }
    }
    catch { return '' }
    return $action
}

function ConvertTo-ProcessArgument {
    param([Parameter(Mandatory=$true)][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { throw 'A process argument cannot be empty.' }
    if ($Value.IndexOf([char]0) -ge 0 -or $Value.IndexOf('"') -ge 0) {
        throw 'A process argument contains an unsupported character.'
    }
    # A trailing backslash would escape the closing quote in the Windows
    # command-line parser. Double only trailing separators; interior path
    # characters remain ordinary data.
    if ($Value.EndsWith([IO.Path]::DirectorySeparatorChar) -or $Value.EndsWith([IO.Path]::AltDirectorySeparatorChar)) {
        return '"' + $Value + [string][IO.Path]::DirectorySeparatorChar + '"'
    }
    return '"' + $Value + '"'
}

try {
    if (-not [System.IO.File]::Exists($script:CorePath) -or -not [System.IO.File]::Exists($script:WorkerPath) -or
        -not [System.IO.File]::Exists($script:WorkerHostPath)) {
        throw 'GephTun.Core.psm1, GephTun.Worker.ps1, or GephTun.WorkerHost.ps1 is missing. Extract the complete GephTun folder and try again.'
    }
    Import-Module $script:CorePath -Force -ErrorAction Stop
    $null = Initialize-GephTunStorage
    [void][System.IO.Directory]::CreateDirectory($script:ResultDirectory)
    $script:RequestDirectory = Initialize-GephTunRequestDirectory -SessionId $script:RequestSessionId
    $instance = Enter-UiMutex 'Local\GephTun.UI'
    $script:UiMutex = $instance.Mutex
    $script:OwnsUiMutex = $instance.Acquired
    if (-not $script:OwnsUiMutex) {
        Write-UiRequest -Action $InitialAction
        $script:UiMutex.Dispose()
        return
    }
}
catch {
    if ($null -ne $script:UiMutex) {
        if ($script:OwnsUiMutex) { $script:UiMutex.ReleaseMutex() }
        $script:UiMutex.Dispose()
    }
    [void][System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'GephTun could not start', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    exit 1
}

try {
$script:Palette = @{
    Background = [System.Drawing.ColorTranslator]::FromHtml('#F2F5F9')
    Navy       = [System.Drawing.ColorTranslator]::FromHtml('#12243D')
    Text       = [System.Drawing.ColorTranslator]::FromHtml('#162B43')
    Muted      = [System.Drawing.ColorTranslator]::FromHtml('#53657B')
    Blue       = [System.Drawing.ColorTranslator]::FromHtml('#1767D2')
    Green      = [System.Drawing.ColorTranslator]::FromHtml('#167348')
    Amber      = [System.Drawing.ColorTranslator]::FromHtml('#956200')
    Red        = [System.Drawing.ColorTranslator]::FromHtml('#B42B37')
    Neutral    = [System.Drawing.ColorTranslator]::FromHtml('#6B7788')
}

function New-UiLabel {
    param([string]$Text, [single]$Size = 10, [bool]$Bold = $false)
    $label = [System.Windows.Forms.Label]::new()
    $style = [System.Drawing.FontStyle]::Regular
    if ($Bold) { $style = [System.Drawing.FontStyle]::Bold }
    $label.Font = [System.Drawing.Font]::new('Segoe UI', $Size, $style)
    $label.Text = $Text
    $label.ForeColor = $script:Palette.Text
    $label.AutoSize = $true
    $label.AutoEllipsis = $false
    $label.Dock = [System.Windows.Forms.DockStyle]::Fill
    $label.Padding = [System.Windows.Forms.Padding]::new(0, 2, 0, 2)
    $label.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $label.Margin = [System.Windows.Forms.Padding]::new(0)
    $label.UseMnemonic = $false
    return $label
}

function New-UiButton {
    param([string]$Text, [string]$AccessibleName, [bool]$Primary = $false)
    $button = [System.Windows.Forms.Button]::new()
    $button.Text = $Text
    $button.AccessibleName = $AccessibleName
    $button.AutoSize = $true
    $button.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
    $button.Dock = [System.Windows.Forms.DockStyle]::None
    $button.Padding = [System.Windows.Forms.Padding]::new(14, 7, 14, 7)
    $button.Margin = [System.Windows.Forms.Padding]::new(0, 5, 10, 5)
    $button.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $button.FlatAppearance.BorderSize = 1
    $button.FlatAppearance.BorderColor = [System.Drawing.ColorTranslator]::FromHtml('#C3CEDB')
    $button.Font = [System.Drawing.Font]::new('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
    $button.BackColor = [System.Drawing.Color]::White
    $button.ForeColor = $script:Palette.Text
    $button.Cursor = [System.Windows.Forms.Cursors]::Hand
    if ($Primary) {
        $button.BackColor = $script:Palette.Blue
        $button.ForeColor = [System.Drawing.Color]::White
        $button.FlatAppearance.BorderSize = 0
    }
    return $button
}

function Get-UiBuildLabel {
    param([string]$ReleasePath)
    try {
        if (-not [IO.File]::Exists($ReleasePath) -or
            (([IO.File]::GetAttributes($ReleasePath) -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { return 'version unavailable' }
        $stream = [IO.FileStream]::new($ReleasePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::Read -bor [IO.FileShare]::Delete))
        try {
            if ($stream.Length -gt 32768) { return 'version unavailable' }
            $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::UTF8)
            try {
                $buffer = [char[]]::new(8193)
                $count = $reader.ReadBlock($buffer, 0, $buffer.Length)
                if ($count -gt 8192) { return 'version unavailable' }
                $release = ([string]::new($buffer, 0, $count)) | ConvertFrom-Json -ErrorAction Stop
            } finally { $reader.Dispose() }
        } finally { $stream.Dispose() }
        $version = Get-StateProperty $release 'Version' ''
        if ($version -isnot [string] -or $version -cnotmatch '\A[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?:-[0-9A-Za-z.-]{1,32})?\z') { return 'version unavailable' }
        if ((Get-StateProperty $release 'ProductionQualified' $true) -eq $false) { return ($version + ' (test candidate)') }
        return $version
    }
    catch { return 'version unavailable' }
}

function Initialize-UiWindow {
# Build the entire 96-DPI control tree before permitting automatic scaling.
$script:LayoutUpdating = $true
$script:UiInputEventsConnected = $false
$script:UiBuildLabel = Get-UiBuildLabel $script:ReleasePath
$script:Form = [System.Windows.Forms.Form]::new()
$script:Form.SuspendLayout()
$script:Form.Text = 'GephTun - ' + $script:UiBuildLabel
$script:Form.ClientSize = [System.Drawing.Size]::new(940, 770)
$script:Form.MinimumSize = [System.Drawing.Size]::new(460, 400)
$script:Form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
$script:Form.BackColor = $script:Palette.Background
$script:Form.Font = [System.Drawing.Font]::new('Segoe UI', 10)
$script:Form.Icon = [System.Drawing.SystemIcons]::Application
$script:Form.AccessibleName = 'GephTun desktop controller'

$header = [System.Windows.Forms.TableLayoutPanel]::new()
$header.SuspendLayout()
$header.AutoSize = $true
$header.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
$script:HeaderPanel = $header
$header.Dock = [System.Windows.Forms.DockStyle]::Top
$header.BackColor = $script:Palette.Navy
$header.Padding = [System.Windows.Forms.Padding]::new(26, 12, 26, 13)
$header.ColumnCount = 2
$header.RowCount = 3
[void]$header.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new([System.Windows.Forms.SizeType]::Percent, 100))
[void]$header.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new([System.Windows.Forms.SizeType]::AutoSize))
[void]$header.RowStyles.Add([System.Windows.Forms.RowStyle]::new([System.Windows.Forms.SizeType]::AutoSize))
[void]$header.RowStyles.Add([System.Windows.Forms.RowStyle]::new([System.Windows.Forms.SizeType]::AutoSize))
[void]$header.RowStyles.Add([System.Windows.Forms.RowStyle]::new([System.Windows.Forms.SizeType]::AutoSize))
$title = New-UiLabel 'GephTun' 24 $true
$script:AppTitle = $title
$title.AccessibleName = 'GephTun'
$title.ForeColor = [System.Drawing.Color]::White
$subtitle = New-UiLabel 'Route app traffic through Geph' 10
$script:AppSubtitle = $subtitle
$subtitle.ForeColor = [System.Drawing.ColorTranslator]::FromHtml('#CCD9ED')
$adminLabel = New-UiLabel 'Administrator' 9 $true
$script:AdminLabel = $adminLabel
$adminLabel.Margin = [System.Windows.Forms.Padding]::new(12, 0, 0, 0)
$adminLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
$adminLabel.ForeColor = [System.Drawing.ColorTranslator]::FromHtml('#CCD9ED')
$header.Controls.Add($title, 0, 0)
$header.Controls.Add($subtitle, 0, 1)
$header.Controls.Add($adminLabel, 1, 0)
$header.SetColumnSpan($subtitle, 2)

$script:BodyViewport = [System.Windows.Forms.Panel]::new()
$script:BodyViewport.Dock = [System.Windows.Forms.DockStyle]::Fill
$script:BodyViewport.AutoScroll = $true
$script:BodyViewport.TabStop = $false
$body = [System.Windows.Forms.TableLayoutPanel]::new()
$body.SuspendLayout()
$body.AutoSize = $true
$body.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
$body.Dock = [System.Windows.Forms.DockStyle]::Top
$script:ContentPanel = $body
$body.Padding = [System.Windows.Forms.Padding]::new(26, 14, 26, 14)
$body.ColumnCount = 1
$body.RowCount = 7
[void]$body.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new([System.Windows.Forms.SizeType]::Percent, 100))
foreach ($row in 1..7) {
    [void]$body.RowStyles.Add([System.Windows.Forms.RowStyle]::new([System.Windows.Forms.SizeType]::AutoSize))
}
# Only Activity receives spare height. Every text row still sizes to content.
$body.RowStyles[5].SizeType = [System.Windows.Forms.SizeType]::Percent
$body.RowStyles[5].Height = 100

$intro = New-UiLabel "1. Connect Geph in local-proxy mode first.`r`n2. Check the proxy, then connect the tunnel." 10
$script:IntroLabel = $intro
$intro.Margin = [System.Windows.Forms.Padding]::new(0, 0, 0, 10)
$intro.ForeColor = $script:Palette.Muted
$intro.TextAlign = [System.Drawing.ContentAlignment]::TopLeft
$body.Controls.Add($intro, 0, 0)

$statusCard = [System.Windows.Forms.TableLayoutPanel]::new()
$statusCard.SuspendLayout()
$statusCard.AutoSize = $true
$statusCard.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
$script:StatusCard = $statusCard
$statusCard.Dock = [System.Windows.Forms.DockStyle]::Fill
$statusCard.BackColor = [System.Drawing.Color]::White
$statusCard.Padding = [System.Windows.Forms.Padding]::new(16, 10, 16, 10)
$statusCard.Margin = [System.Windows.Forms.Padding]::new(0, 0, 0, 12)
$statusCard.ColumnCount = 2
$statusCard.RowCount = 3
[void]$statusCard.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new([System.Windows.Forms.SizeType]::AutoSize))
[void]$statusCard.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new([System.Windows.Forms.SizeType]::Percent, 100))
foreach ($row in 1..3) { [void]$statusCard.RowStyles.Add([System.Windows.Forms.RowStyle]::new([System.Windows.Forms.SizeType]::AutoSize)) }
$script:StatusDot = New-UiLabel ([char]0x25CF) 17 $true
$script:StatusDot.Margin = [System.Windows.Forms.Padding]::new(0, 0, 10, 0)
$script:StatusDot.ForeColor = $script:Palette.Blue
$script:StatusTitle = New-UiLabel 'Checking network state' 16 $true
$script:StatusTitle.AccessibleName = 'Tunnel connection status'
$script:StatusMessage = New-UiLabel 'Checking whether a previous session needs recovery...' 10
$script:StatusMessage.ForeColor = $script:Palette.Muted
$script:StatusMessage.AccessibleName = 'Tunnel status details'
$script:StatusMessage.AutoEllipsis = $false
$script:PortDetailLabel = New-UiLabel 'Local SOCKS5 proxy on 127.0.0.1' 9
$script:PortDetailLabel.ForeColor = $script:Palette.Muted
$statusCard.Controls.Add($script:StatusDot, 0, 0)
$statusCard.Controls.Add($script:StatusTitle, 1, 0)
$statusCard.Controls.Add($script:StatusMessage, 1, 1)
$statusCard.Controls.Add($script:PortDetailLabel, 1, 2)
$body.Controls.Add($statusCard, 0, 1)

$proxyCard = [System.Windows.Forms.TableLayoutPanel]::new()
$proxyCard.SuspendLayout()
$proxyCard.AutoSize = $true
$proxyCard.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
$script:ProxyCard = $proxyCard
$proxyCard.Dock = [System.Windows.Forms.DockStyle]::Fill
$proxyCard.BackColor = [System.Drawing.Color]::White
$proxyCard.Padding = [System.Windows.Forms.Padding]::new(16, 6, 16, 6)
$proxyCard.Margin = [System.Windows.Forms.Padding]::new(0, 0, 0, 10)
$proxyCard.ColumnCount = 1
$proxyCard.RowCount = 3
[void]$proxyCard.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new([System.Windows.Forms.SizeType]::Percent, 100))
foreach ($row in 1..3) { [void]$proxyCard.RowStyles.Add([System.Windows.Forms.RowStyle]::new([System.Windows.Forms.SizeType]::AutoSize)) }
$proxyTitle = New-UiLabel 'Local proxy' 10 $true
$script:ProxyTitle = $proxyTitle
$proxyCard.Controls.Add($proxyTitle, 0, 0)
$proxyOptions = [System.Windows.Forms.FlowLayoutPanel]::new()
$proxyOptions.Dock = [System.Windows.Forms.DockStyle]::Fill
$proxyOptions.Margin = [System.Windows.Forms.Padding]::new(0)
$proxyOptions.AutoSize = $true
$proxyOptions.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
$proxyOptions.WrapContents = $true
$script:ProxyOptions = $proxyOptions
$script:AutoPort = [System.Windows.Forms.RadioButton]::new()
$script:AutoPort.Text = '&Auto-detect'
$script:AutoPort.AccessibleName = 'Auto-detect local SOCKS5 proxy port'
$script:AutoPort.AutoSize = $true
$script:AutoPort.Margin = [System.Windows.Forms.Padding]::new(0, 4, 18, 4)
$script:AutoPort.Checked = $true
$script:AutoPort.TabIndex = 0
$script:ManualPort = [System.Windows.Forms.RadioButton]::new()
$script:ManualPort.Text = 'Use &port'
$script:ManualPort.AccessibleName = 'Use a specific local SOCKS5 proxy port'
$script:ManualPort.AutoSize = $true
$script:ManualPort.Margin = [System.Windows.Forms.Padding]::new(0, 4, 8, 4)
$script:ManualPort.TabIndex = 1
$script:PortNumber = [System.Windows.Forms.NumericUpDown]::new()
$script:PortNumber.Minimum = 1
$script:PortNumber.Maximum = 65535
$script:PortNumber.Value = 9909
$script:PortNumber.Enabled = $false
$script:PortNumber.AutoSize = $true
$script:PortNumber.Width = 102
$script:PortNumber.Margin = [System.Windows.Forms.Padding]::new(0, 2, 0, 2)
$script:PortNumber.AccessibleName = 'Local SOCKS5 proxy port number'
$script:PortNumber.TabIndex = 2
$loopbackLabel = New-UiLabel 'SOCKS5 at 127.0.0.1' 9
$loopbackLabel.Dock = [System.Windows.Forms.DockStyle]::None
$loopbackLabel.Margin = [System.Windows.Forms.Padding]::new(0, 3, 0, 3)
$loopbackLabel.ForeColor = $script:Palette.Muted
# Radio buttons deliberately share one parent so selecting Manual or Auto
# remains mutually exclusive, including keyboard navigation after wrapping.
$script:PortNumber.Margin = [System.Windows.Forms.Padding]::new(0, 2, 18, 2)
$proxyOptions.Controls.AddRange([System.Windows.Forms.Control[]]@($script:AutoPort, $script:ManualPort, $script:PortNumber, $loopbackLabel))
$proxyCard.Controls.Add($proxyOptions, 0, 1)
$script:ProxyHint = New-UiLabel 'Use the SOCKS5 port from Geph if auto-detect cannot find it.' 9
$script:ProxyHint.ForeColor = $script:Palette.Muted
$script:ProxyHint.AutoEllipsis = $false
$proxyCard.Controls.Add($script:ProxyHint, 0, 2)
$body.Controls.Add($proxyCard, 0, 2)

$actions = [System.Windows.Forms.FlowLayoutPanel]::new()
$actions.AutoSize = $true
$actions.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
$actions.WrapContents = $true
$actions.Dock = [System.Windows.Forms.DockStyle]::Fill
$actions.Margin = [System.Windows.Forms.Padding]::new(0)
$script:ActionsPanel = $actions
$script:CheckButton = New-UiButton 'Chec&k' 'Check the local proxy'
$script:ConnectButton = New-UiButton '&Connect' 'Connect GephTun' $true
$script:DisconnectButton = New-UiButton '&Disconnect / Recover' 'Disconnect and recover network settings'
$script:ProtectionButton = New-UiButton '&Protection...' 'Manage WFP protection and explicit direct-internet unlock'
$script:LogsButton = New-UiButton 'Open &logs' 'Open the GephTun log folder'
$script:LogsButton.Margin = [System.Windows.Forms.Padding]::new(0, 5, 0, 5)
$script:CheckButton.TabIndex = 3
$script:ConnectButton.TabIndex = 4
$script:DisconnectButton.TabIndex = 5
$script:LogsButton.TabIndex = 6
$actions.Controls.Add($script:CheckButton)
$actions.Controls.Add($script:ConnectButton)
$actions.Controls.Add($script:DisconnectButton)
$actions.Controls.Add($script:ProtectionButton)
$actions.Controls.Add($script:LogsButton)
$body.Controls.Add($actions, 0, 3)

$activityTitle = New-UiLabel 'Activity' 10 $true
$script:ActivityTitle = $activityTitle
$activityTitle.Margin = [System.Windows.Forms.Padding]::new(0, 5, 0, 4)
$body.Controls.Add($activityTitle, 0, 4)
$script:Activity = [System.Windows.Forms.RichTextBox]::new()
$script:Activity.Dock = [System.Windows.Forms.DockStyle]::Fill
$script:Activity.MinimumSize = [System.Drawing.Size]::new(0, 140)
$script:Activity.Height = 160
$script:Activity.Margin = [System.Windows.Forms.Padding]::new(0)
$script:Activity.ReadOnly = $true
$script:Activity.BackColor = [System.Drawing.Color]::White
$script:Activity.ForeColor = $script:Palette.Text
$script:Activity.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$script:Activity.Font = [System.Drawing.Font]::new('Consolas', 9)
$script:Activity.DetectUrls = $false
$script:Activity.WordWrap = $true
$script:Activity.ScrollBars = [System.Windows.Forms.RichTextBoxScrollBars]::Vertical
$script:Activity.AccessibleName = 'GephTun activity log, read only'
$script:Activity.TabIndex = 7
$body.Controls.Add($script:Activity, 0, 5)
$footer = New-UiLabel "IPv4 TCP + DNS with explicit WFP protection. Test candidate: live Windows leak/reboot validation is still required.`r`nDisconnect and Exit KEEP blocking. Use Protection to explicitly allow direct internet. Automatic crash recovery is not installed." 9
$script:FooterLabel = $footer
$footer.Margin = [System.Windows.Forms.Padding]::new(0, 12, 0, 0)
$footer.ForeColor = $script:Palette.Muted
$body.Controls.Add($footer, 0, 6)

$script:BodyViewport.Controls.Add($body)
$script:Form.Controls.Add($script:BodyViewport)
$script:Form.Controls.Add($header)
$script:toolTips = [System.Windows.Forms.ToolTip]::new()
$toolTips.SetToolTip($script:CheckButton, 'Verify that a local SOCKS5 proxy is reachable before connecting.')
$toolTips.SetToolTip($script:ConnectButton, 'Start a protected tunnel. Enable WFP protection first using Protection...')
$toolTips.SetToolTip($script:DisconnectButton, 'Stop the tunnel and restore session settings. WFP blocking stays enabled until explicitly disabled.')
$toolTips.SetToolTip($script:LogsButton, $script:LogDirectory)

# Font and all controls now exist; resume one consistent DPI layout.
$script:Form.AutoScaleDimensions = [System.Drawing.SizeF]::new(96, 96)
$script:Form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi
foreach ($panel in @($statusCard, $proxyCard, $body, $header)) { $panel.ResumeLayout($false) }
$script:Form.ResumeLayout($true)
$script:LayoutUpdating = $false
$script:BodyViewport.Add_SizeChanged({ Update-UiLayout })
$script:Form.Add_Layout({ Update-UiLayout })
foreach ($control in @($title, $subtitle, $adminLabel, $intro, $script:StatusTitle, $script:StatusMessage,
    $script:PortDetailLabel, $proxyTitle, $script:ProxyHint, $activityTitle, $footer, $script:DisconnectButton)) {
    $control.Add_TextChanged({ Update-UiLayout })
    $control.Add_FontChanged({ Update-UiLayout })
}
Update-UiLayout
}

function Get-UiWrapWidth {
    param([int]$Width, [int]$Padding = 0, [int]$Reserved = 0)
    return [Math]::Max(16, $Width - $Padding - $Reserved)
}

function Set-UiWrapWidth {
    param($Control, [int]$Width)
    $widthLimit = Get-UiWrapWidth $Width
    if ($Control.MaximumSize.Width -ne $widthLimit -or $Control.MaximumSize.Height -ne 0) {
        $Control.MaximumSize = [System.Drawing.Size]::new($widthLimit, 0)
    }
}

function Update-UiLayout {
    # AutoSize decides text heights. Only the available width is constrained;
    # fixed text rows and ellipsis must never clip scaled fonts or error text.
    if ($script:LayoutUpdating -or $null -eq $script:Form -or $script:Form.IsDisposed) { return }
    $script:LayoutUpdating = $true
    $script:ContentPanel.SuspendLayout()
    try {
        $headerWidth = Get-UiWrapWidth $script:Form.ClientSize.Width $script:HeaderPanel.Padding.Horizontal
        $titleWidth = [System.Windows.Forms.TextRenderer]::MeasureText($script:AppTitle.Text, $script:AppTitle.Font).Width + $script:AppTitle.Padding.Horizontal
        $adminWidth = [System.Windows.Forms.TextRenderer]::MeasureText($script:AdminLabel.Text, $script:AdminLabel.Font).Width + $script:AdminLabel.Padding.Horizontal + $script:AdminLabel.Margin.Horizontal
        $stackHeader = $titleWidth + $adminWidth -gt $headerWidth
        $script:HeaderPanel.SuspendLayout()
        try {
            # At large fonts or narrow widths the administrator badge must move
            # below the title instead of forcing GephTun to wrap in mid-word.
            if ($stackHeader) {
                $script:HeaderPanel.SetCellPosition($script:AdminLabel, [System.Windows.Forms.TableLayoutPanelCellPosition]::new(0, 2))
                $script:HeaderPanel.SetColumnSpan($script:AdminLabel, 2)
                $script:HeaderPanel.SetColumnSpan($script:AppTitle, 2)
                $script:AdminLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
                Set-UiWrapWidth $script:AppTitle $headerWidth
            }
            else {
                $script:HeaderPanel.SetColumnSpan($script:AppTitle, 1)
                $script:HeaderPanel.SetColumnSpan($script:AdminLabel, 1)
                $script:HeaderPanel.SetCellPosition($script:AdminLabel, [System.Windows.Forms.TableLayoutPanelCellPosition]::new(1, 0))
                $script:AdminLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
                Set-UiWrapWidth $script:AppTitle (Get-UiWrapWidth $headerWidth 0 $adminWidth)
            }
            Set-UiWrapWidth $script:AdminLabel (Get-UiWrapWidth $headerWidth $script:AdminLabel.Margin.Horizontal)
            Set-UiWrapWidth $script:AppSubtitle $headerWidth
        }
        finally { $script:HeaderPanel.ResumeLayout($true) }
        $script:HeaderPanel.PerformLayout()
        $script:Form.PerformLayout()
        # Reserve scrollbar width even before it appears, avoiding wrap/scroll
        # oscillation as a long status pushes the footer below the viewport.
        $width = Get-UiWrapWidth $script:BodyViewport.ClientSize.Width 0 ([System.Windows.Forms.SystemInformation]::VerticalScrollBarWidth)
        $script:ContentPanel.MinimumSize = [System.Drawing.Size]::new($width, [Math]::Max(0, $script:BodyViewport.ClientSize.Height))
        $script:ContentPanel.MaximumSize = [System.Drawing.Size]::new($width, 0)
        $script:ContentPanel.Width = $width
        $bodyWidth = Get-UiWrapWidth $width $script:ContentPanel.Padding.Horizontal
        foreach ($control in @($script:IntroLabel, $script:ActivityTitle, $script:FooterLabel)) { Set-UiWrapWidth $control $bodyWidth }
        $dotWidth = $script:StatusDot.GetPreferredSize([System.Drawing.Size]::Empty).Width + $script:StatusDot.Margin.Horizontal
        $statusWidth = Get-UiWrapWidth $bodyWidth $script:StatusCard.Padding.Horizontal $dotWidth
        foreach ($control in @($script:StatusTitle, $script:StatusMessage, $script:PortDetailLabel)) { Set-UiWrapWidth $control $statusWidth }
        $proxyWidth = Get-UiWrapWidth $bodyWidth $script:ProxyCard.Padding.Horizontal
        foreach ($control in @($script:ProxyTitle, $script:ProxyHint, $script:ProxyOptions)) { Set-UiWrapWidth $control $proxyWidth }
        Set-UiWrapWidth $script:ActionsPanel $bodyWidth
        foreach ($button in @($script:CheckButton, $script:ConnectButton, $script:DisconnectButton, $script:ProtectionButton, $script:LogsButton)) {
            Set-UiWrapWidth $button (Get-UiWrapWidth $bodyWidth $button.Margin.Horizontal)
        }
        # A text-only font change must still leave room for a five-digit port
        # and the native spinner arrows; its height remains font-driven.
        $digitsWidth = [System.Windows.Forms.TextRenderer]::MeasureText('65535', $script:PortNumber.Font).Width
        $portWidth = $digitsWidth + [System.Windows.Forms.SystemInformation]::VerticalScrollBarWidth + $script:PortNumber.Padding.Horizontal + 12
        $script:PortNumber.MinimumSize = [System.Drawing.Size]::new($portWidth, 0)
        $script:PortNumber.Width = $portWidth
        $script:Activity.MinimumSize = [System.Drawing.Size]::new(0, [Math]::Max(100, $script:Activity.Font.Height * 6))
    }
    finally {
        $script:ContentPanel.ResumeLayout($true)
        $script:LayoutUpdating = $false
    }
}

Initialize-UiWindow

function New-TrayStatusIcon {
    param([string]$Kind)
    $fill = $script:Palette.Neutral
    switch ($Kind) {
        'Connected' { $fill = $script:Palette.Green; break }
        'Busy' { $fill = $script:Palette.Blue; break }
        'Warning' { $fill = $script:Palette.Amber; break }
        'Error' { $fill = $script:Palette.Red; break }
    }
    $bitmap = [System.Drawing.Bitmap]::new(32, 32)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $brush = [System.Drawing.SolidBrush]::new($fill)
    $pen = [System.Drawing.Pen]::new($script:Palette.Navy, [single]3)
    $outline = [System.Drawing.Drawing2D.GraphicsPath]::new()
    try {
        $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $graphics.Clear([System.Drawing.Color]::Transparent)
        $outline.AddEllipse(4, 4, 24, 24)
        $graphics.FillPath($brush, $outline)
        $graphics.DrawPath($pen, $outline)
        # FromHandle does not own the HICON. Clone into an owned managed icon,
        # then destroy the temporary native handle on every construction path.
        $handle = $bitmap.GetHicon()
        $borrowedIcon = $null
        try {
            $borrowedIcon = [System.Drawing.Icon]::FromHandle($handle)
            $icon = [System.Drawing.Icon]$borrowedIcon.Clone()
        }
        finally {
            if ($null -ne $borrowedIcon) { $borrowedIcon.Dispose() }
            [void][GephTunDpi]::DestroyIcon($handle)
        }
    }
    finally {
        $outline.Dispose()
        $pen.Dispose()
        $brush.Dispose()
        $graphics.Dispose()
        $bitmap.Dispose()
    }
    return $icon
}

$script:TrayIcons = @{
    Idle      = New-TrayStatusIcon 'Idle'
    Busy      = New-TrayStatusIcon 'Busy'
    Connected = New-TrayStatusIcon 'Connected'
    Warning   = New-TrayStatusIcon 'Warning'
    Error     = New-TrayStatusIcon 'Error'
}
$script:TrayOpenItem = [System.Windows.Forms.ToolStripMenuItem]::new('&Open GephTun')
$script:TrayConnectItem = [System.Windows.Forms.ToolStripMenuItem]::new('&Connect')
$script:TrayDisconnectItem = [System.Windows.Forms.ToolStripMenuItem]::new('&Disconnect / Recover')
$script:TrayLogsItem = [System.Windows.Forms.ToolStripMenuItem]::new('Open &logs')
$script:TrayExitItem = [System.Windows.Forms.ToolStripMenuItem]::new('E&xit (keep protection)')
$script:TrayProtectionItem = [System.Windows.Forms.ToolStripMenuItem]::new('&Protection / explicit unlock...')
$script:TrayMenu = [System.Windows.Forms.ContextMenuStrip]::new()
[void]$script:TrayMenu.Items.Add($script:TrayOpenItem)
[void]$script:TrayMenu.Items.Add([System.Windows.Forms.ToolStripSeparator]::new())
[void]$script:TrayMenu.Items.Add($script:TrayConnectItem)
[void]$script:TrayMenu.Items.Add($script:TrayDisconnectItem)
[void]$script:TrayMenu.Items.Add([System.Windows.Forms.ToolStripSeparator]::new())
[void]$script:TrayMenu.Items.Add($script:TrayLogsItem)
[void]$script:TrayMenu.Items.Add($script:TrayProtectionItem)
[void]$script:TrayMenu.Items.Add([System.Windows.Forms.ToolStripSeparator]::new())
[void]$script:TrayMenu.Items.Add($script:TrayExitItem)
$script:TrayIcon = [System.Windows.Forms.NotifyIcon]::new()
$script:TrayIcon.Icon = $script:TrayIcons.Idle
$script:TrayIcon.Text = 'GephTun'
$script:TrayIcon.ContextMenuStrip = $script:TrayMenu
$script:TrayIcon.Visible = $true

function Add-Activity {
    param([string]$Message, [string]$Kind = 'Info')
    if ([string]::IsNullOrWhiteSpace($Message)) { return }
    if ($script:Activity.TextLength -gt 100000) {
        $text = $script:Activity.Text
        $cutAt = $text.IndexOf("`n", [Math]::Min(25000, $text.Length - 1))
        if ($cutAt -ge 0) { $script:Activity.Text = $text.Substring($cutAt + 1) }
    }
    $script:Activity.SelectionStart = $script:Activity.TextLength
    $script:Activity.SelectionLength = 0
    $color = $script:Palette.Text
    if ($Kind -eq 'Error') { $color = $script:Palette.Red }
    elseif ($Kind -eq 'Success') { $color = $script:Palette.Green }
    elseif ($Kind -eq 'Warning') { $color = $script:Palette.Amber }
    $script:Activity.SelectionColor = $color
    $script:Activity.AppendText(('[' + [DateTime]::Now.ToString('HH:mm:ss') + '] ' + $Message.Trim() + "`r`n"))
    $script:Activity.SelectionStart = $script:Activity.TextLength
    $script:Activity.ScrollToCaret()
}

function Test-OperationPending {
    param([string]$Action = '')
    foreach ($operation in $script:Operations) {
        if ($Action -ne '' -and $operation.Action -ne $Action) { continue }
        if (-not $operation.ResultReceived) { return $true }
        # A Connect worker also supervises recovery after a failed start. Once
        # its result is reported, it must not block Disconnect / Recover.
        if ($operation.Action -ne 'Connect') {
            try { if (-not $operation.Process.HasExited) { return $true } } catch { }
        }
    }
    return $false
}

function Request-PendingConnectCancellation {
    foreach ($operation in $script:Operations) {
        if ($operation.Action -ne 'Connect' -or $operation.ResultReceived -or $operation.CancelRequested) { continue }
        try {
            Write-GephTunJson $operation.CancelFile @{ Token = $operation.Token }
            $operation.CancelRequested = $true
            $operation.LastCancelError = ''
            Add-Activity 'Connection cancellation requested. Waiting for safe recovery.' 'Warning'
        }
        catch {
            # Permission or sharing failures are not permission to kill the
            # supervisor. Keep Disconnect available/queued and retry when its
            # session journal appears or the user requests recovery again.
            $cancelError = $_.Exception.Message
            if ($cancelError -ne $operation.LastCancelError) {
                $operation.LastCancelError = $cancelError
                Add-Activity ('Could not record startup cancellation: ' + $cancelError + ' Disconnect will still wait for safe recovery.') 'Warning'
            }
        }
    }
}

function Test-DisconnectCanStart {
    if (Test-OperationPending 'Disconnect') { return $false }
    if ((Test-OperationPending 'Check') -or (Test-OperationPending 'Status')) { return $false }
    # A starting session can consume a session-specific stop request immediately.
    # Before its recovery journal exists, cancellation is latched by its token.
    if ((Test-OperationPending 'Connect') -and -not [IO.File]::Exists($script:SessionPath) -and -not [IO.File]::Exists($script:IntentPath)) { return $false }
    return $true
}

function Test-WorkerIdentity {
    param($State)
    $workerId = 0
    if (-not [int]::TryParse([string](Get-StateProperty $State 'WorkerPid' ''), [ref]$workerId) -or $workerId -le 0) { return $false }
    $startValue = Get-StateProperty $State 'WorkerStartUtc' ''
    if ([string]::IsNullOrWhiteSpace([string]$startValue)) { return $false }
    $workerProcess = $null
    try {
        $expectedStart = ConvertTo-UiUtc $startValue
        $workerProcess = [System.Diagnostics.Process]::GetProcessById($workerId)
        if ($workerProcess.HasExited) { return $false }
        # Both values come from Process.StartTime and round-trip UTC strings.
        # A nearby creation time is still a different process lifetime.
        return ($workerProcess.StartTime.ToUniversalTime().Ticks -eq $expectedStart.Ticks)
    }
    catch { return $false }
    finally { if ($null -ne $workerProcess) { $workerProcess.Dispose() } }
}

function Update-Controls {
    $busy = (Test-OperationPending) -or $script:DisconnectQueued
    $sessionActive = $script:UiStatus -in @('Connected', 'Connecting', 'Reconnecting', 'Disconnecting')
    $canConfigure = -not $busy -and -not $sessionActive -and -not [IO.File]::Exists($script:SessionPath) -and -not [IO.File]::Exists($script:IntentPath) -and -not $script:ClosingRequested -and $script:StartupFinished
    $script:AutoPort.Enabled = $canConfigure
    $script:ManualPort.Enabled = $canConfigure
    $script:PortNumber.Enabled = $canConfigure -and $script:ManualPort.Checked
    $script:CheckButton.Enabled = $canConfigure
    $script:ConnectButton.Enabled = $canConfigure -and $script:UiStatus -in @('Disconnected', 'Error')
    $script:DisconnectButton.Enabled = -not (Test-OperationPending 'Disconnect') -and -not $script:DisconnectQueued -and -not $script:ClosingRequested -and $script:StartupFinished
    if ($script:ClosingRequested) { $script:DisconnectButton.Text = 'Restoring network...' }
    else { $script:DisconnectButton.Text = '&Disconnect / Recover' }
    if ($null -eq $script:TrayIcon) { return }
    $trayKind = 'Idle'
    $trayStatus = 'Disconnected'
    switch ($script:UiStatus) {
        'Checking' { $trayKind = 'Busy'; $trayStatus = 'Checking network state' }
        'Connecting' { $trayKind = 'Busy'; $trayStatus = 'Connecting' }
        'Reconnecting' { $trayKind = 'Warning'; $trayStatus = 'Reconnecting - traffic may be direct' }
        'Connected' { $trayKind = 'Connected'; $trayStatus = 'Connected' }
        'Disconnecting' { $trayKind = 'Warning'; $trayStatus = 'Disconnecting' }
        'RecoveryRequired' { $trayKind = 'Warning'; $trayStatus = 'Recovery required' }
        'Error' { $trayKind = 'Error'; $trayStatus = 'Needs attention' }
    }
    if ($script:ClosingRequested) {
        $trayKind = 'Warning'
        $trayStatus = 'Restoring network before exit'
    }
    if ($trayKind -ne $script:TrayIconKind) {
        $script:TrayIconKind = $trayKind
        $script:TrayIcon.Icon = $script:TrayIcons[$trayKind]
    }
    $trayText = 'GephTun - ' + $trayStatus
    if ($trayText.Length -gt 63) { $trayText = $trayText.Substring(0, 63) }
    $script:TrayIcon.Text = $trayText
    $script:TrayOpenItem.Enabled = $true
    $script:TrayConnectItem.Enabled = $script:ConnectButton.Enabled
    $script:TrayDisconnectItem.Enabled = $script:DisconnectButton.Enabled
    $script:TrayLogsItem.Enabled = $true
    $script:TrayExitItem.Enabled = -not $script:ClosingRequested
}

function Show-Status {
    param([string]$Status, [string]$Message, $State = $null)
    $script:UiStatus = $Status
    $color = $script:Palette.Neutral
    $titleText = 'Disconnected'
    switch ($Status) {
        'Checking' { $titleText = 'Checking network state'; $color = $script:Palette.Blue }
        'Connecting' { $titleText = 'Connecting...'; $color = $script:Palette.Blue }
        'Reconnecting' { $titleText = 'Reconnecting...'; $color = $script:Palette.Amber }
        'Connected' { $titleText = 'Connected'; $color = $script:Palette.Green }
        'Disconnecting' { $titleText = 'Disconnecting...'; $color = $script:Palette.Amber }
        'RecoveryRequired' { $titleText = 'Recovery required'; $color = $script:Palette.Amber }
        'Error' { $titleText = 'Needs attention'; $color = $script:Palette.Red }
    }
    if ($script:ClosingRequested) {
        $titleText = 'Restoring network before closing...'
        $color = $script:Palette.Amber
    }
    $script:StatusTitle.Text = $titleText
    $script:StatusTitle.ForeColor = $color
    $script:StatusDot.ForeColor = $color
    $protectionLabel=[string](Get-StateProperty $State 'ProtectionState' 'Unknown')
    $script:StatusMessage.Text = $Message + ' [WFP policy: ' + $protectionLabel + '; see Protection for a fresh check.]'
    $toolTips.SetToolTip($script:StatusMessage, $Message)
    $port = Get-StateProperty $State 'ProxyPort' 0
    $detail = 'Local SOCKS5 proxy on 127.0.0.1'
    if ([int]$port -gt 0) { $detail = 'Local proxy: 127.0.0.1:' + [string]$port }
    $started = Get-StateProperty $State 'StartedUtc' ''
    if ($Status -eq 'Connected' -and [string]$started -ne '') {
        try {
            $localStart = (ConvertTo-UiUtc $started).ToLocalTime()
            $detail += '   |   Connected at ' + $localStart.ToString('HH:mm')
        }
        catch { }
    }
    $script:PortDetailLabel.Text = $detail
    $key = $Status + '|' + $Message
    if ($key -ne $script:LastStateLogKey) {
        $script:LastStateLogKey = $key
        $kind = 'Info'
        if ($Status -eq 'Connected') { $kind = 'Success' }
        elseif ($Status -eq 'RecoveryRequired') { $kind = 'Warning' }
        elseif ($Status -eq 'Error') { $kind = 'Error' }
        Add-Activity ($titleText + ': ' + $Message) $kind
        if ($null -ne $script:TrayIcon -and -not $script:Form.Visible -and $Status -in @('Connected', 'RecoveryRequired', 'Error')) {
            try {
                $tipIcon = [System.Windows.Forms.ToolTipIcon]::Warning
                if ($Status -eq 'Connected') { $tipIcon = [System.Windows.Forms.ToolTipIcon]::Info }
                $script:TrayIcon.ShowBalloonTip(8000, 'GephTun: ' + $titleText, $Message, $tipIcon)
            }
            catch { }
        }
    }
    Update-Controls
}

function Read-TunnelStatus {
    try {
        # The worker atomically replaces this file. Do not gate the read with
        # File.Exists: during replacement the destination can be absent for a
        # moment, and that observation must use the same bounded retry path as
        # every other transient file collision.
        $state = $null
        $read = $false
        $readFailureCount = 0
        $onlyMissingReadFailures = $true
        $attemptLimit = 3
        if ($script:LastPollError -ne '') { $attemptLimit = 1 }
        for ($attempt = 0; $attempt -lt $attemptLimit; $attempt++) {
            try {
                $text = Read-UiTextSnapshot -Path $script:StatusPath -MaximumBytes 262144
                $state = $text | ConvertFrom-Json -ErrorAction Stop
                $read = $true
                break
            }
            catch [System.IO.IOException] {
                $readFailureCount++
                $baseException = $_.Exception.GetBaseException()
                if ($baseException -isnot [System.IO.FileNotFoundException] -and
                    $baseException -isnot [System.IO.DirectoryNotFoundException]) {
                    $onlyMissingReadFailures = $false
                }
                if ($attempt -eq ($attemptLimit - 1)) { break }
                Start-Sleep -Milliseconds 120
            }
        }
        if (-not $read) {
            # A startup result may safely provide an initial disconnected view,
            # but a cached Connected/active state must never mask a missing
            # status snapshot. The worker's journal remains authoritative below.
            $startupStatus = [string](Get-StateProperty $script:StartupState 'Status' '')
            if ($null -ne $script:StartupState -and $startupStatus -eq 'Disconnected' -and
                $readFailureCount -gt 0 -and $onlyMissingReadFailures) {
                $state = $script:StartupState
                $read = $true
            }
            elseif (-not $script:StartupFinished -or (Test-OperationPending 'Status')) {
                Show-Status 'Checking' 'Waiting for the worker to verify saved network state.'
                return
            }
            elseif (-not $onlyMissingReadFailures -and $null -ne $script:LastState -and
                (Get-StateProperty $script:LastState 'Status' '') -in @('Connected', 'Connecting', 'Reconnecting', 'Disconnecting', 'Checking') -and
                (Test-WorkerIdentity $script:LastState)) {
                # 1.3.8 (D-005): the snapshot exists but could not be opened (a
                # sharing collision, not stable absence) while its supervisor is
                # still alive. Hold the last presentation and retry on the next
                # tick instead of flashing RecoveryRequired; escalate only after
                # a sustained failure window so a busy file never becomes a
                # false recovery claim.
                $script:UnreadableSnapshotPolls = 1 + $(if ($null -ne $script:UnreadableSnapshotPolls) { $script:UnreadableSnapshotPolls } else { 0 })
                if ($script:UnreadableSnapshotPolls -lt 10) {
                    Show-Status ([string](Get-StateProperty $script:LastState 'Status' '')) 'Refreshing the tunnel status snapshot; the file is momentarily busy.'
                    return
                }
                $message = 'The tunnel status snapshot stayed unreadable for ten consecutive updates.'
                $script:LastPollError = $message
                $logKey = 'RecoveryRequired|' + $message
                if ($script:LastStateLogKey -ne $logKey) {
                    $script:LastStateLogKey = $logKey
                    Add-Activity ('Recovery required: ' + $message) 'Error'
                }
                Show-Status 'RecoveryRequired' $message
                return
            }
            else {
                $message = 'The tunnel status snapshot could not be read.'
                if ($null -ne $script:LastActionFailure) { $message = $script:LastActionFailure.Message + ' ' + $message }
                # Keep this failure visible and let the next timer tick use the
                # single-attempt recovery path; throwing here would replace the
                # specific action error with generic interface text.
                $script:LastPollError = $message
                $logKey = 'RecoveryRequired|' + $message
                if ($script:LastStateLogKey -ne $logKey) {
                    $script:LastStateLogKey = $logKey
                    Add-Activity ('Recovery required: ' + $message) 'Error'
                }
                Show-Status 'RecoveryRequired' $message
                return
            }
        }
        $status = [string](Get-StateProperty $state 'Status' '')
        if ($status -notin @('Disconnected', 'Checking', 'Connecting', 'Reconnecting', 'Connected', 'Disconnecting', 'RecoveryRequired', 'Error')) {
            throw 'The status file contains an unrecognized tunnel state.'
        }
        $message = [string](Get-StateProperty $state 'Message' '')
        # A status snapshot can lag journal creation/removal. A remaining saved
        # session must never be presented as safe to reconnect or exit.
        if ($status -eq 'Disconnected' -and [IO.File]::Exists($script:SessionPath)) {
            $status = 'RecoveryRequired'
            $message = 'A saved session still needs recovery. Select Disconnect / Recover before reconnecting or exiting.'
        }
        if ($status -eq 'Disconnected' -and [IO.File]::Exists($script:IntentPath)) {
            $status = 'Reconnecting'
            $message = 'The connection controller is still active. WFP blocking remains installed between sessions. Disconnect cancels retries.'
        }
        if ($status -in @('Connected', 'Connecting', 'Reconnecting', 'Disconnecting') -and -not (Test-WorkerIdentity $state)) {
            $status = 'RecoveryRequired'
            $message = 'The tunnel supervisor is no longer running. Select Disconnect / Recover to restore network settings.'
        }
        if ($status -eq 'Connected') {
            try {
                $updatedUtc = ConvertTo-UiUtc (Get-StateProperty $state 'UpdatedUtc' '')
                $healthAge = ([DateTime]::UtcNow - $updatedUtc).TotalSeconds
                if ($healthAge -gt 90 -or $healthAge -lt -10) { throw 'The health confirmation is stale.' }
            }
            catch {
                $status = 'RecoveryRequired'
                $message = 'The supervisor has not confirmed tunnel health recently. Use Disconnect / Recover, then reconnect.'
            }
        }
        $script:LastState = $state
        $script:UnreadableSnapshotPolls = 0
        if ($message -eq '') {
            if ($status -eq 'Disconnected') { $message = 'Connect Geph in local-proxy mode, then check the local proxy.' }
            else { $message = 'Waiting for an update from the tunnel worker.' }
        }
        if ((Test-OperationPending 'Disconnect') -or $script:DisconnectQueued) {
            $status = 'Disconnecting'
            $message = 'Restoring saved network settings. Waiting for the worker to confirm completion.'
        }
        elseif ((Test-OperationPending 'Connect') -and $status -in @('Disconnected', 'Error', 'Checking')) {
            $status = 'Connecting'
            $message = 'Verifying the local proxy and preparing the tunnel.'
        }
        elseif ((Test-OperationPending 'Check') -and $status -eq 'Disconnected') {
            $status = 'Checking'
            $message = 'Verifying the local SOCKS5 proxy and network requirements.'
        }
        if ($null -ne $script:LastActionFailure -and $status -in @('Disconnected', 'Error') -and -not (Test-OperationPending)) {
            $status = 'Error'
            $message = $script:LastActionFailure.Message
        }
        Show-Status $status $message $state
        $script:LastPollError = ''
    }
    catch {
        Show-Status 'RecoveryRequired' 'Tunnel state cannot be read. Select Disconnect / Recover to verify and restore network settings.'
        $errorMessage = $_.Exception.Message
        if ($errorMessage -ne $script:LastPollError) {
            $script:LastPollError = $errorMessage
            Add-Activity ('State read error: ' + $errorMessage) 'Error'
        }
    }
}

function Open-ProtectionWindow {
    try {
        $scriptPath=Join-Path $script:InstallDirectory 'Protection-GephTun.ps1'
        $arguments=@('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-Sta','-File',(ConvertTo-ProcessArgument $scriptPath),'-Action','Show')
        $child=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $arguments -PassThru
        $child.Dispose()
    } catch { Add-Activity ('Could not open protection controls: '+$_.Exception.Message) 'Error' }
}

function Get-SelectedProxyPort {
    # Both radios share a parent. Preserve the selected manual value across
    # resizing/wrapping; Auto always selects the worker's auto-detect value 0.
    if ($script:ManualPort.Checked) { return [int]$script:PortNumber.Value }
    return 0
}

function Start-WorkerAction {
    param([ValidateSet('Check', 'Connect', 'Disconnect', 'Status')][string]$Action)
    if ($Action -eq 'Disconnect') {
        $script:InitialActionPending = 'Show'
        Request-PendingConnectCancellation
    }
    if ($Action -in @('Check', 'Connect') -and ($script:ClosingRequested -or $script:DisconnectQueued)) { return }
    if (Test-OperationPending $Action) { return }
    if ($Action -eq 'Disconnect' -and -not (Test-DisconnectCanStart)) {
        if ($script:DisconnectQueued) { return }
        $script:DisconnectQueued = $true
        Add-Activity 'Disconnect is queued while the current operation stops safely.'
        Show-Status 'Disconnecting' 'Cancellation is requested. Waiting for the worker to finish safely, then verifying network recovery.'
        return
    }
    if ($Action -in @('Check', 'Connect') -and (Test-OperationPending)) { return }
    if ($Action -in @('Check', 'Connect') -and [IO.File]::Exists($script:SessionPath)) {
        Add-Activity 'A saved session still needs Disconnect / Recover before another proxy check or connection.' 'Warning'
        return
    }
    if ($Action -eq 'Connect' -and $script:UiStatus -notin @('Disconnected', 'Error')) {
        Add-Activity 'Connect is unavailable until the current session is disconnected and recovered.' 'Warning'
        return
    }
    $script:LastActionFailure = $null
    if ($Action -eq 'Disconnect') { $script:DisconnectQueued = $false }
    $port = Get-SelectedProxyPort
    $token = [Guid]::NewGuid().ToString('N')
    $resultFile = Join-Path $script:ResultDirectory ($token + '.json')
    $captureFile = Join-Path $script:LogDirectory ('ui-worker-' + $token + '.log')
    $ownerId = $PID
    # Windows PowerShell 5.1 exposes only ProcessStartInfo.Arguments (no
    # ArgumentList). Quote every path and pass operation values as parameters;
    # the static host owns stream capture and writes a failure result if the
    # worker cannot produce one.
    $arguments = @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-Sta', '-WindowStyle', 'Hidden', '-File', (ConvertTo-ProcessArgument $script:WorkerHostPath),
        '-ResultFile', (ConvertTo-ProcessArgument $resultFile),
        '-CaptureFile', (ConvertTo-ProcessArgument $captureFile),
        '-Action', $Action, '-Port', [string]$port, '-OwnerProcessId', [string]$ownerId,
        '-OperationToken', $token
    )
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $process.StartInfo.FileName = Join-Path $PSHOME 'powershell.exe'
    $process.StartInfo.Arguments = $arguments -join ' '
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.CreateNoWindow = $true
    $process.StartInfo.WorkingDirectory = $script:InstallDirectory
    try {
        [void]$process.Start()
        $script:Operations.Add([PSCustomObject]@{
            Action = $Action
            Process = $process
            ResultFile = $resultFile
            CaptureFile = $captureFile
            Token = $token
            CancelFile = Join-Path $script:ResultDirectory ($token + '.cancel.json')
            CancelRequested = $false
            SlowNoticeShown = $false
            LastResultError = ''
            LastCancelError = ''
            ResultReceived = $false
            ResultSuccess = $false
            StartedUtc = [DateTime]::UtcNow
        })
        $portDescription = 'auto-detect'
        if ($port -gt 0) { $portDescription = '127.0.0.1:' + $port }
        if ($Action -in @('Check', 'Connect')) { Add-Activity ($Action + ' requested; proxy ' + $portDescription + '.') }
        else { Add-Activity ($Action + ' requested.') }
        if ($Action -eq 'Connect') { Show-Status 'Connecting' 'Starting the worker and verifying the local proxy.' }
        elseif ($Action -eq 'Disconnect') { Show-Status 'Disconnecting' 'Stopping the tunnel and restoring saved network settings.' }
        elseif ($Action -eq 'Check') {
            $script:ProxyHint.Text = 'Checking the local SOCKS5 proxy...'
            $script:ProxyHint.ForeColor = $script:Palette.Blue
        }
        Update-Controls
    }
    catch {
        $process.Dispose()
        Add-Activity ('Could not start ' + $Action + ': ' + $_.Exception.Message) 'Error'
        if ($Action -eq 'Status') { $script:StartupFinished = $true }
        $script:LastActionFailure = @{ Message = ('Could not start ' + $Action + '. ' + $_.Exception.Message) }
        if ($script:ClosingRequested) { $script:ClosingRequested = $false }
        Show-Status 'Error' ('Could not start the worker. ' + $_.Exception.Message)
    }
}

function Complete-WorkerResult {
    param($Operation, [bool]$Success, [string]$Message, $Details = $null)
    $Operation.ResultReceived = $true
    $Operation.ResultSuccess = $Success
    $kind = 'Error'
    if ($Success) { $kind = 'Success' }
    Add-Activity ($Operation.Action + ': ' + $Message) $kind
    if ($Success) { $script:LastActionFailure = $null }
    else { $script:LastActionFailure = @{ Message = ($Operation.Action + ' failed: ' + $Message) } }
    if ($null -ne $Details) {
        if ($Details -is [string]) { Add-Activity $Details }
        else { Add-Activity ($Details | ConvertTo-Json -Depth 8) }
    }
    if ($Operation.Action -eq 'Status') {
        $script:StartupFinished = $true
        if ($Success -and $null -ne $Details -and $null -ne $Details.PSObject.Properties['Status']) {
            $script:StartupState = $Details
        }
    }
    if ($Operation.Action -eq 'Check') {
        if ($Success) {
            $checkedPort = [int](Get-StateProperty $Details 'ProxyPort' 0)
            $script:ProxyHint.Text = 'Proxy check passed. Ready to connect.'
            if ($checkedPort -gt 0) { $script:ProxyHint.Text = 'Verified proxy 127.0.0.1:' + $checkedPort + '. Ready to connect.' }
            $script:ProxyHint.ForeColor = $script:Palette.Green
        }
        else {
            $script:ProxyHint.Text = 'Check failed. See Activity for details.'
            $script:ProxyHint.ForeColor = $script:Palette.Red
        }
        $toolTips.SetToolTip($script:ProxyHint, $Message)
    }
    if (-not $Success -and $Operation.Action -eq 'Disconnect' -and $script:ClosingRequested) {
        $script:ClosingRequested = $false
        [void][System.Windows.Forms.MessageBox]::Show(
            ('Network recovery did not complete. GephTun will stay open so you can retry Disconnect / Recover.' + "`r`n`r`n" + $Message),
            'Recovery needs attention', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    }
    Update-Controls
}

function Read-OneWorkerResult {
    param($Operation)
    if ($Operation.ResultReceived -or -not [System.IO.File]::Exists($Operation.ResultFile)) { return }
    try {
        $result = (Read-UiTextSnapshot -Path $Operation.ResultFile -MaximumBytes 65536) | ConvertFrom-Json -ErrorAction Stop
        $successProperty = $result.PSObject.Properties['Success']
        if ($null -eq $successProperty -or $successProperty.Value -isnot [bool]) { throw 'The worker result did not include a valid success flag.' }
        $details = Get-StateProperty $result 'Details'
        if ($successProperty.Value -and $Operation.Action -eq 'Status') {
            $reportedStatus = [string](Get-StateProperty $details 'Status' '')
            if ($reportedStatus -notin @('Disconnected', 'Checking', 'Connecting', 'Reconnecting', 'Connected', 'Disconnecting', 'RecoveryRequired', 'Error')) {
                throw 'The status result did not include a recognized tunnel state.'
            }
        }
        if ($successProperty.Value -and $Operation.Action -eq 'Check') {
            $reportedPort = 0
            if (-not [int]::TryParse([string](Get-StateProperty $details 'ProxyPort' ''), [ref]$reportedPort) -or
                $reportedPort -lt 1 -or $reportedPort -gt 65535) {
                throw 'The proxy check result did not include a valid verified proxy port.'
            }
        }
        # Validate action-specific fields before latching ResultReceived. A
        # malformed success must not suppress the later worker-exit failure.
        $message = [string](Get-StateProperty $result 'Message' 'The worker completed.')
        Complete-WorkerResult $Operation ([bool]$successProperty.Value) $message $details
    }
    catch {
        # Retry a partial result on the next tick, but surface a stable error.
        # A worker exit receives one final read before reporting a missing result.
        $readError = $_.Exception.Message
        if ($readError -ne $Operation.LastResultError) {
            $Operation.LastResultError = $readError
            Add-Activity ('Could not read ' + $Operation.Action + ' result: ' + $readError) 'Warning'
        }
    }
}

function Read-WorkerResults {
    foreach ($operation in $script:Operations.ToArray()) {
        Read-OneWorkerResult $operation
        $hasExited = $false
        try { $hasExited = $operation.Process.HasExited } catch { $hasExited = $true }
        if (-not $hasExited -and -not $operation.ResultReceived -and -not $operation.SlowNoticeShown -and
            ([DateTime]::UtcNow - $operation.StartedUtc).TotalSeconds -ge 45) {
            $operation.SlowNoticeShown = $true
            Add-Activity ($operation.Action + ' is taking longer than expected. GephTun is still responding; open logs for details. Disconnect requests safe cancellation and recovery.') 'Warning'
        }
        if ($hasExited) {
            Read-OneWorkerResult $operation
            if (-not $operation.ResultReceived) {
                $exitCode = 'unknown'
                try { $exitCode = [string]$operation.Process.ExitCode } catch { }
                $details = $null
                if ([System.IO.File]::Exists($operation.CaptureFile)) {
                    $details = (Get-Content -LiteralPath $operation.CaptureFile -Tail 25 -ErrorAction SilentlyContinue) -join "`r`n"
                }
                Complete-WorkerResult $operation $false ('The worker exited without a readable result (exit code ' + $exitCode + '). Open logs for details.') $details
            }
            Remove-Item -LiteralPath $operation.ResultFile -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $operation.CancelFile -Force -ErrorAction SilentlyContinue
            $operation.Process.Dispose()
            [void]$script:Operations.Remove($operation)
        }
    }
}

function Bring-WindowForward {
    if ($script:Form.WindowState -eq [System.Windows.Forms.FormWindowState]::Minimized) {
        $script:Form.WindowState = [System.Windows.Forms.FormWindowState]::Normal
    }
    $script:Form.Show()
    $script:Form.Activate()
}

function Read-UiRequests {
    $now = [DateTime]::UtcNow
    # Successful deletion removes receipts immediately. Bound retained entries
    # to slightly beyond the 120-second validity window if deletion stays denied.
    foreach ($name in @($script:UiRequestHistory.Keys)) {
        if (($now - $script:UiRequestHistory[$name].FirstSeenUtc).TotalSeconds -gt 130) {
            $script:UiRequestHistory.Remove($name)
        }
    }
    $script:UiRequestSequence++
    $pollSequence = $script:UiRequestSequence
    $files = @(Get-ChildItem -LiteralPath $script:RequestDirectory -Filter '*.json' -File -ErrorAction SilentlyContinue)
    $fresh = New-Object 'System.Collections.Generic.List[object]'
    $retained = New-Object 'System.Collections.Generic.List[object]'
    foreach ($file in $files) {
        $wasKnown = $script:UiRequestHistory.ContainsKey($file.Name)
        if (-not $wasKnown) {
            $script:UiRequestSequence++
            $script:UiRequestHistory[$file.Name] = @{ Consumed = $false; Error = ''; FirstSeenUtc = $now; FirstSeenSequence = $script:UiRequestSequence; LastAttemptUtc = [DateTime]::MinValue; LastAttemptSequence = 0 }
            $fresh.Add($file)
        }
        else { $retained.Add($file) }
    }
    # Materialize every candidate before applying the 20-file cap. When old
    # retained work exists, reserve one slot for a fresh request while giving
    # the other slots to the oldest retries. This prevents an unreadable or
    # undeletable batch from starving a later Disconnect indefinitely.
    $selected = New-Object 'System.Collections.Generic.List[object]'
    $retainedOrdered = @($retained | Sort-Object @{ Expression = { $script:UiRequestHistory[$_.Name].LastAttemptSequence } }, @{ Expression = { $script:UiRequestHistory[$_.Name].FirstSeenSequence } }, Name)
    $freshOrdered = @($fresh | Sort-Object @{ Expression = { $script:UiRequestHistory[$_.Name].FirstSeenSequence } }, Name)
    if ($retainedOrdered.Count -gt 0 -and $freshOrdered.Count -gt 0) {
        foreach ($file in @($retainedOrdered | Select-Object -First 19)) { $selected.Add($file) }
        $selected.Add($freshOrdered[0])
    }
    else {
        foreach ($file in @($retainedOrdered + $freshOrdered | Select-Object -First 20)) { $selected.Add($file) }
    }
    foreach ($file in $selected) {
        $record = $script:UiRequestHistory[$file.Name]
        $record.LastAttemptUtc = $now
        $record.LastAttemptSequence = $pollSequence
        try {
            # A consumed request must never replay after a temporary deletion
            # failure, even if the user has started a different session meanwhile.
            if ($record.Consumed) { continue }
            if ($file.Name -notmatch '^[a-f0-9]{32}\.json$' -or $file.Length -gt 4096 -or
                $file.LastWriteTimeUtc -lt $now.AddSeconds(-120) -or
                ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                $record.Consumed = $true
                continue
            }
            $request = (Read-UiTextSnapshot -Path $file.FullName -MaximumBytes 4096) | ConvertFrom-Json -ErrorAction Stop
            $requestAction = Get-UiRequestAction $request $now
            # Record consumption before dispatch. Retrying deletion is cleanup,
            # never authorization to execute Connect or Disconnect for a second time.
            $record.Consumed = $true
            $record.Error = ''
            if ($requestAction -eq '') { continue }
            Bring-WindowForward
            if ($requestAction -eq 'Disconnect') { Start-WorkerAction 'Disconnect' }
            elseif ($requestAction -eq 'Connect' -and -not $script:ClosingRequested -and -not $script:DisconnectQueued) {
                if (-not $script:StartupFinished -or (Test-OperationPending 'Check') -or (Test-OperationPending 'Status')) {
                    $script:InitialActionPending = 'Connect'
                }
                else { Start-WorkerAction 'Connect' }
            }
        }
        catch [IO.IOException] {
            # A sharing collision does not consume a still-valid launcher request.
            $readError = $_.Exception.Message
            if ($record.Error -ne $readError) {
                $record.Error = $readError
                Add-Activity ('A launcher request is temporarily unreadable and will be retried: ' + $readError) 'Warning'
            }
        }
        catch {
            $record.Consumed = $true
            Add-Activity ('Could not read a launcher request: ' + $_.Exception.Message) 'Warning'
        }
        finally {
            if ($record.Consumed) {
                try {
                    Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
                    $script:UiRequestHistory.Remove($file.Name)
                }
                catch {
                    $deleteError = $_.Exception.Message
                    if ($record.Error -ne $deleteError) {
                        $record.Error = $deleteError
                        Add-Activity ('A handled launcher request is waiting for file cleanup; its action will not repeat: ' + $deleteError) 'Warning'
                    }
                }
            }
        }
    }
}

function Invoke-DeferredUiAction {
    if (-not $script:StartupFinished -or $script:InitialActionPending -eq 'Show' -or (Test-OperationPending)) { return }
    $nextAction = $script:InitialActionPending
    $script:InitialActionPending = 'Show'
    if ($nextAction -eq 'Connect' -and ($script:ClosingRequested -or $script:DisconnectQueued)) { return }
    Start-WorkerAction $nextAction
}

function Continue-Close {
    if (-not $script:ClosingRequested) { return }
    if ((Test-OperationPending) -or $script:DisconnectQueued) { return }
    Read-TunnelStatus
    if ($script:StartupFinished -and $script:UiStatus -eq 'Disconnected' -and -not [IO.File]::Exists($script:SessionPath) -and -not [IO.File]::Exists($script:IntentPath)) {
        $script:AllowClose = $true
        $script:Form.Close()
    }
    elseif ($script:UiStatus -eq 'RecoveryRequired' -or $script:UiStatus -eq 'Error') {
        $script:ClosingRequested = $false
        Add-Activity 'Recovery still needs attention. Retry Disconnect / Recover before closing.' 'Warning'
        Update-Controls
    }
}

function Request-AppExit {
    # The only supported way to quit while a session may be active: restore the
    # network first, then close. Hiding the window keeps everything running.
    if ($script:AllowClose) { return }
    if ($script:ClosingRequested) { Bring-WindowForward; return }
    # Recheck immediately: the last timer paint is not evidence that a journal
    # or session has stayed absent since the user last saw Disconnected.
    Read-TunnelStatus
    if ($script:StartupFinished -and $script:UiStatus -eq 'Disconnected' -and -not (Test-OperationPending) -and
        -not $script:DisconnectQueued -and -not [IO.File]::Exists($script:SessionPath) -and -not [IO.File]::Exists($script:IntentPath)) {
        $script:AllowClose = $true
        $script:Form.Close()
        return
    }
    Bring-WindowForward
    $script:ClosingRequested = $true
    $script:InitialActionPending = 'Show'
    Add-Activity 'Exit requested. Restoring network settings before GephTun closes.'
    Start-WorkerAction 'Disconnect'
    Update-Controls
}

function Reset-ProxyHint {
    $script:ProxyHint.Text = 'Use the SOCKS5 port from Geph if auto-detect cannot find it.'
    $script:ProxyHint.ForeColor = $script:Palette.Muted
    $toolTips.SetToolTip($script:ProxyHint, $null)
}

function Initialize-UiInputEvents {
    # Keep the real input wiring callable by the isolated native harness. Do
    # not attach duplicate handlers if initialization is requested twice.
    if ($script:UiInputEventsConnected) { return }
    $script:UiInputEventsConnected = $true
    $script:AutoPort.Add_CheckedChanged({ Reset-ProxyHint })
    $script:ManualPort.Add_CheckedChanged({ Reset-ProxyHint; Update-Controls })
    $script:PortNumber.Add_ValueChanged({ Reset-ProxyHint })
    $script:CheckButton.Add_Click({ Start-WorkerAction 'Check' })
    $script:ConnectButton.Add_Click({ Start-WorkerAction 'Connect' })
    $script:DisconnectButton.Add_Click({ Start-WorkerAction 'Disconnect' })
    $script:ProtectionButton.Add_Click({ Open-ProtectionWindow })
    $script:LogsButton.Add_Click({ Open-LogFolder })
}

function Open-LogFolder {
    try {
        # Explorer uses the normal desktop shell; no elevation verb is requested.
        $explorer = [System.Diagnostics.ProcessStartInfo]::new()
        $explorer.FileName = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)) 'explorer.exe'
        $explorer.Arguments = '"' + $script:LogDirectory + '"'
        $explorer.UseShellExecute = $true
        [void][System.Diagnostics.Process]::Start($explorer)
    }
    catch { Add-Activity ('Could not open the log folder: ' + $_.Exception.Message) 'Error' }
}

function Initialize-UiTrayEvents {
    if ($script:UiTrayEventsConnected) { return }
    $script:UiTrayEventsConnected = $true
    $script:TrayIcon.Add_DoubleClick({ Bring-WindowForward })
    $script:TrayIcon.Add_MouseClick({
        param($sender, $eventArgs)
        if ($eventArgs.Button -eq [System.Windows.Forms.MouseButtons]::Left) { Bring-WindowForward }
    })
    $script:TrayOpenItem.Add_Click({ Bring-WindowForward })
    $script:TrayConnectItem.Add_Click({ Start-WorkerAction 'Connect' })
    $script:TrayDisconnectItem.Add_Click({ Start-WorkerAction 'Disconnect' })
    $script:TrayLogsItem.Add_Click({ Open-LogFolder })
    $script:TrayProtectionItem.Add_Click({ Open-ProtectionWindow })
    $script:TrayExitItem.Add_Click({ Request-AppExit })
}

Initialize-UiInputEvents
Initialize-UiTrayEvents

$script:Timer = [System.Windows.Forms.Timer]::new()
$script:Timer.Interval = 1000
$script:Timer.Add_Tick({
    if ($script:Polling) { return }
    $script:Polling = $true
    try {
        Read-WorkerResults
        Read-TunnelStatus
        Read-UiRequests
        if ($script:DisconnectQueued -and (Test-DisconnectCanStart)) {
            $script:DisconnectQueued = $false
            Start-WorkerAction 'Disconnect'
        }
        Invoke-DeferredUiAction
        Continue-Close
        Update-Controls
    }
    catch {
        Add-Activity ('Interface update failed: ' + $_.Exception.Message) 'Error'
        Show-Status 'RecoveryRequired' 'The interface could not verify tunnel state. Use Disconnect / Recover.'
        if ($script:ClosingRequested) { $script:ClosingRequested = $false }
    }
    finally { $script:Polling = $false }
})

$script:Form.Add_Shown({
    $workingArea = [System.Windows.Forms.Screen]::FromControl($script:Form).WorkingArea
    $availableWidth = [Math]::Max(1, $workingArea.Width - 32)
    $availableHeight = [Math]::Max(1, $workingArea.Height - 32)
    $script:Form.MinimumSize = [System.Drawing.Size]::new(
        [Math]::Min($script:Form.MinimumSize.Width, $availableWidth),
        [Math]::Min($script:Form.MinimumSize.Height, $availableHeight))
    $script:Form.Size = [System.Drawing.Size]::new(
        [Math]::Min($script:Form.Width, $availableWidth),
        [Math]::Min($script:Form.Height, $availableHeight))
    $script:Form.Location = [System.Drawing.Point]::new(
        $workingArea.X + [int](($workingArea.Width - $script:Form.Width) / 2),
        $workingArea.Y + [int](($workingArea.Height - $script:Form.Height) / 2))
    Add-Activity ('GephTun ' + $script:UiBuildLabel + ' is ready. Connect Geph in local-proxy mode first.')
    Add-Activity ('Diagnostic logs: ' + $script:LogDirectory)
    Read-TunnelStatus
    Start-WorkerAction 'Status'
    $script:Timer.Start()
})

function Handle-FormClosing {
    param($sender, $eventArgs)
    if ($script:AllowClose) { return }
    $reason = $eventArgs.CloseReason
    if ($reason -eq [System.Windows.Forms.CloseReason]::WindowsShutDown -or
        $reason -eq [System.Windows.Forms.CloseReason]::TaskManagerClosing) {
        # Let Windows shut down. The tunnel supervisor watches this process and
        # restores the network settings by itself when the interface is gone.
        $script:AllowClose = $true
        return
    }
    if ($script:ClosingRequested) { $eventArgs.Cancel = $true; return }
    # Closing the window keeps GephTun and the tunnel running in the tray.
    # Exiting (and disconnecting first) is done from the tray menu.
    $eventArgs.Cancel = $true
    if ($script:Form.WindowState -eq [System.Windows.Forms.FormWindowState]::Minimized) {
        $script:Form.WindowState = [System.Windows.Forms.FormWindowState]::Normal
    }
    $script:Form.Hide()
    if (-not $script:TrayNoticeShown) {
        $script:TrayNoticeShown = $true
        try {
            $script:TrayIcon.ShowBalloonTip(
                8000, 'GephTun is still running',
                'The tunnel keeps working in the background. Double-click the tray icon to reopen GephTun; use Exit in its menu to disconnect and quit.',
                [System.Windows.Forms.ToolTipIcon]::Info)
        }
        catch { }
    }
}
$script:Form.Add_FormClosing({ param($sender, $eventArgs); Handle-FormClosing $sender $eventArgs })

Update-Controls
[System.Windows.Forms.Application]::Run($script:Form)
}
finally {
    if ($null -ne $script:Timer) {
        $script:Timer.Stop()
        $script:Timer.Dispose()
    }
    if ($null -ne $toolTips) { $toolTips.Dispose() }
    if ($null -ne $script:TrayIcon) {
        # Remove the tray icon immediately; Windows would keep a ghost entry otherwise.
        $script:TrayIcon.Visible = $false
        $script:TrayIcon.Dispose()
    }
    if ($null -ne $script:TrayMenu) { $script:TrayMenu.Dispose() }
    if ($null -ne $script:TrayIcons) {
        foreach ($statusIcon in $script:TrayIcons.Values) { $statusIcon.Dispose() }
    }
    foreach ($operation in $script:Operations.ToArray()) {
        # Never terminate the supervisor here: it owns recovery and also watches
        # this UI process, including crashes and forced window termination.
        $operation.Process.Dispose()
    }
    if ($script:OwnsUiMutex) { $script:UiMutex.ReleaseMutex() }
    if ($null -ne $script:UiMutex) { $script:UiMutex.Dispose() }
    if ($null -ne $script:Form) { $script:Form.Dispose() }
}
