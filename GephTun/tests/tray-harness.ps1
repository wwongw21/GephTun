# Actual production UI helpers, exercised in an isolated Windows desktop.
# No elevation, worker launch, protected state-directory access, or network changes.
# Run: powershell.exe -NoProfile -Sta -ExecutionPolicy Bypass -File tests\tray-harness.ps1
# Native tray appearance, actual display scaling, UAC and live recovery still need manual QA.
[CmdletBinding()]
param([string]$UiPath, [string]$ResultJson, [string]$ScreenshotDirectory)
# $PSScriptRoot is empty while param() defaults are evaluated on Windows
# PowerShell 5.1 -File runs; resolve the default in the script body instead.
if (-not $UiPath) { $UiPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'GephTun.UI.ps1' }
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:HarnessStartedUtc = [DateTime]::UtcNow.ToString('o')
$script:PassedCount = 0
$script:LayoutScenarios = 0
$script:LayoutFontFactors = @(1.0, 1.5, 2.0)
$script:LayoutWidths = @(940, 640)
$script:LayoutMessageCases = 5
$script:ExpectedLayoutScenarios = $script:LayoutFontFactors.Count * $script:LayoutWidths.Count * $script:LayoutMessageCases
$script:NativeControlsExecuted = $false
$script:ObservedGraphicsDpi = $null
$failures = New-Object 'Collections.Generic.List[string]'
$script:ReportStream = $null
$script:HarnessSourcePath = $PSCommandPath
function Get-HarnessFullPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'A nonempty output path is required.' }
    return [IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path))
}
function Assert-HarnessNewPath {
    param([string]$Path, [string[]]$ProtectedPaths = @())
    $target = Get-HarnessFullPath $Path
    foreach ($source in $ProtectedPaths) {
        if ($target.Equals((Get-HarnessFullPath $source), [StringComparison]::OrdinalIgnoreCase)) { throw 'A harness output cannot replace its input source.' }
    }
    $cursor = $target
    while ($cursor) {
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction SilentlyContinue
        if ($null -ne $item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw ('A redirected output path is not supported: ' + $cursor) }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
    if ([IO.File]::Exists($target) -or [IO.Directory]::Exists($target)) { throw ('Harness output already exists; choose a fresh path: ' + $target) }
    return $target
}
function New-HarnessOutputFile {
    param([string]$Path, [string[]]$ProtectedPaths = @())
    $target = Assert-HarnessNewPath $Path $ProtectedPaths
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
    # CreateNew also rejects a competing writer arriving after path validation.
    return [IO.FileStream]::new($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
}
function New-HarnessScreenshotDirectory {
    param([string]$Path, [string[]]$ProtectedPaths = @())
    $target = Assert-HarnessNewPath $Path $ProtectedPaths
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
    # No -Force: an earlier run or competing directory must never be reused.
    $null = New-Item -ItemType Directory -Path $target -ErrorAction Stop
    return $target
}
function Write-HarnessReport {
    param([string]$Status, [string]$Reason = '')
    if ($null -eq $script:ReportStream) { return }
    $sourceHash = ''; $harnessHash = ''
    try { $sourceHash = (Get-FileHash -LiteralPath $UiPath -Algorithm SHA256).Hash.ToLowerInvariant() } catch { }
    try { $harnessHash = (Get-FileHash -LiteralPath $script:HarnessSourcePath -Algorithm SHA256).Hash.ToLowerInvariant() } catch { }
    $report = [ordered]@{
        Kind = 'GephTunNativeLayoutAndTrayHarness'; Result = $Status; Reason = $Reason
        StartedUtc = $script:HarnessStartedUtc; FinishedUtc = [DateTime]::UtcNow.ToString('o')
        Runtime = $PSVersionTable.PSVersion.ToString(); Platform = [Environment]::OSVersion.Platform.ToString()
        Passed = $script:PassedCount; Failed = $failures.Count; LayoutScenarios = $script:LayoutScenarios
        ExpectedLayoutScenarios = $script:ExpectedLayoutScenarios
        LayoutMatrix = @{ FontSizeFactors = @($script:LayoutFontFactors); Widths = @($script:LayoutWidths); MessageCases = $script:LayoutMessageCases }
        NativeControlsExecuted = $script:NativeControlsExecuted; ObservedGraphicsDpi = $script:ObservedGraphicsDpi
        Scope = 'Isolated production layout at two widths and three font-size factors, production control enablement and input/tray handlers, plus tray lifecycle. Font factors and graphics DPI receipts do not establish per-monitor DPI correctness or full application acceptance.'
        NativeApplicationAcceptance = 'NOT_RUN'; NetworkMutationsPerformed = $false
        Failures = $failures.ToArray(); UiSha256 = $sourceHash; HarnessSha256 = $harnessHash
    }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($report | ConvertTo-Json -Depth 8))
    # Only rewrite the handle reserved by this run, never reopen an existing path.
    $script:ReportStream.Position = 0
    $script:ReportStream.SetLength(0)
    $script:ReportStream.Write($bytes, 0, $bytes.Length)
    $script:ReportStream.Flush()
}
try {
    $UiPath = Get-HarnessFullPath $UiPath
    $protectedPaths = @($UiPath, $script:HarnessSourcePath)
    # Validate all destinations before creating any native controls or outputs.
    if ($ResultJson) { $ResultJson = Assert-HarnessNewPath $ResultJson $protectedPaths }
    if ($ScreenshotDirectory) { $ScreenshotDirectory = Assert-HarnessNewPath $ScreenshotDirectory $protectedPaths }
    if ($ResultJson -and $ScreenshotDirectory -and $ResultJson.Equals($ScreenshotDirectory, [StringComparison]::OrdinalIgnoreCase)) { throw 'Report and screenshot outputs need different paths.' }
    if ($ScreenshotDirectory) { $ScreenshotDirectory = New-HarnessScreenshotDirectory $ScreenshotDirectory $protectedPaths }
    if ($ResultJson) {
        $script:ReportStream = New-HarnessOutputFile $ResultJson $protectedPaths
        Write-HarnessReport 'RUNNING' 'This run has not completed; an interrupted RUNNING receipt is not a pass.'
    }
}
catch {
    $failure = 'Harness output validation failed before native checks: ' + $_.Exception.Message
    $failures.Add($failure)
    Write-Output ('FAIL   ' + $failure)
    if ($null -ne $script:ReportStream) {
        try { Write-HarnessReport 'FAIL' $failure } finally { $script:ReportStream.Dispose() }
    }
    exit 1
}
$blockedReason = ''
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    $blockedReason = 'An interactive Windows desktop is required; this host cannot execute native WinForms checks.'
}
elseif ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -lt 1 -or [IntPtr]::Size -ne 8) {
    $blockedReason = 'Run the target Windows PowerShell 5.1 x64 runtime for application qualification.'
}
elseif ([Threading.Thread]::CurrentThread.GetApartmentState() -ne [Threading.ApartmentState]::STA -or -not [Environment]::UserInteractive) {
    $blockedReason = 'Run powershell.exe -Sta in an interactive Windows desktop session.'
}
if ($blockedReason) {
    try { Write-HarnessReport 'BLOCKED_BY_HOST' $blockedReason } finally { if ($null -ne $script:ReportStream) { $script:ReportStream.Dispose() } }
    Write-Output ('NOT_RUN: ' + $blockedReason)
    exit 2
}
function Assert-True {
    param([bool]$Condition, [string]$Name)
    if ($Condition) { Write-Output ('PASS   ' + $Name); $script:PassedCount++ }
    else { Write-Output ('FAIL   ' + $Name); $failures.Add($Name) }
}
$script:TrayIcons = @{}
$script:TrayIcon = $null
$script:TrayIconKind = ''
$script:Form = $null
$script:toolTips = $null
$trayMenu = $null
$script:SessionPath = Join-Path ([IO.Path]::GetTempPath()) ('GephTun-tray-fixture-' + [guid]::NewGuid().ToString('N') + '.json')
try {
    # Match production process initialization before constructing any controls.
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class GephTunDpi {
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll", SetLastError=true)] public static extern bool DestroyIcon(IntPtr icon);
}
'@
    [void][GephTunDpi]::SetProcessDPIAware()
    [System.Windows.Forms.Application]::EnableVisualStyles()
    [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)
    $tokens = $null; $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($UiPath, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
    foreach ($name in @('Get-StateProperty', 'ConvertTo-UiUtc', 'Get-UiBuildLabel', 'New-TrayStatusIcon',
        'Handle-FormClosing', 'Bring-WindowForward', 'Request-AppExit', 'Continue-Close', 'New-UiLabel',
        'New-UiButton', 'Initialize-UiWindow', 'Get-UiWrapWidth', 'Set-UiWrapWidth', 'Update-UiLayout',
        'Get-SelectedProxyPort', 'Reset-ProxyHint', 'Update-Controls', 'Show-Status', 'Add-Activity',
        'Initialize-UiInputEvents', 'Initialize-UiTrayEvents')) {
        $match = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | Where-Object Name -eq $name)
        if ($match.Count -ne 1) { throw "Cannot find one production function: $name" }
        . ([scriptblock]::Create($match[0].Extent.Text))
    }
    $script:Palette = @{
        Background = [Drawing.Color]::WhiteSmoke; Text = [Drawing.Color]::Black; Muted = [Drawing.Color]::DimGray
        Navy = [Drawing.Color]::Navy; Blue = [Drawing.Color]::Blue; Green = [Drawing.Color]::Green
        Amber = [Drawing.Color]::Orange; Red = [Drawing.Color]::Red; Neutral = [Drawing.Color]::Gray
    }
    $script:ReleasePath = Join-Path (Split-Path -Parent $UiPath) 'RELEASE.json'
    $script:MockPending = $false
    $script:MockAction = ''
    $script:ActionDispatch = New-Object 'Collections.Generic.List[string]'
    $script:AllowClose = $false
    $script:ClosingRequested = $false
    $script:TrayNoticeShown = $false
    $script:DisconnectQueued = $false
    $script:InitialActionPending = 'Show'
    $script:UiStatus = 'Disconnected'
    $script:StartupFinished = $true
    $script:LastStateLogKey = ''
    $script:LogDirectory = [IO.Path]::GetTempPath()
    function Test-OperationPending { param([string]$Action = '') return $script:MockPending }
    function Start-WorkerAction {
        param([string]$Action)
        $script:MockAction = $Action
        $script:ActionDispatch.Add($Action + ':' + (Get-SelectedProxyPort))
    }
    function Open-LogFolder { $script:ActionDispatch.Add('Logs') }
    function Read-TunnelStatus { } # State is supplied by this isolated, non-network harness.

    # Build actual controls and attach the actual production input handlers.
    # Font-size stress is separate from launches at real Windows display scaling.
    $unicodePath = 'C:\Users\' + [char]0x6D4B + [char]0x8BD5 + '\' + [char]0x05E9 + [char]0x05DC + [char]0x05D5 + [char]0x05DD
    $messages = @(
        'Connect Geph in local-proxy mode, then check the local proxy.',
        "Disconnected: No MSFT_NetFirewallRule objects found with property 'InstanceID' equal to 'GephTun-IPv6-Contain-f350eb3c307846e1b3856dc9ce7a2637'. Verify the value of the property and retry. No saved GephTun session remains.",
        ('Unusually long recovery identifier: ' + ('a' * 600)),
        ('The file at ' + $unicodePath + '\GephTun is unavailable. Select Disconnect / Recover to verify saved network settings.'),
        'Connect Geph in local-proxy mode, then check the local proxy.'
    )
    if ($messages.Count -ne $script:LayoutMessageCases) { throw 'The native message cases do not match the declared layout matrix.' }
    foreach ($factor in $script:LayoutFontFactors) {
        foreach ($width in $script:LayoutWidths) {
            $customFonts = New-Object 'Collections.Generic.List[System.Drawing.Font]'
            $script:UiStatus = 'Disconnected'
            # A real application process starts with an empty log key. Each
            # new fixture window also owns a new, empty Activity control.
            $script:LastStateLogKey = ''
            Initialize-UiWindow
            $script:NativeControlsExecuted = $true
            try {
                Initialize-UiInputEvents
                Initialize-UiInputEvents
                Update-Controls
                $script:Form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::None
                $script:Form.MinimumSize = [System.Drawing.Size]::new(320, 300)
                $script:Form.ClientSize = [System.Drawing.Size]::new($width, 520)
                $controls = New-Object 'Collections.Generic.List[System.Windows.Forms.Control]'
                $controls.Add($script:Form)
                for ($index = 0; $index -lt $controls.Count; $index++) {
                    foreach ($child in $controls[$index].Controls) { $controls.Add($child) }
                }
                # Snapshot fonts before changing parents so inherited Font changes
                # cannot multiply a child's factor a second time.
                $fontInputs = @(foreach ($control in $controls) { [pscustomobject]@{ Control = $control; Font = $control.Font } })
                $script:LayoutUpdating = $true
                foreach ($entry in $fontInputs) {
                    $font = [System.Drawing.Font]::new($entry.Font.FontFamily, [single]($entry.Font.SizeInPoints * $factor), $entry.Font.Style)
                    $customFonts.Add($font)
                    $entry.Control.Font = $font
                }
                $script:LayoutUpdating = $false
                $script:Form.Show()
                [System.Windows.Forms.Application]::DoEvents()
                if ($null -eq $script:ObservedGraphicsDpi) {
                    $graphics = $script:Form.CreateGraphics()
                    try { $script:ObservedGraphicsDpi = @{ X = $graphics.DpiX; Y = $graphics.DpiY } } finally { $graphics.Dispose() }
                }
                Assert-True ($script:Form.Text -eq ('GephTun - ' + (Get-UiBuildLabel $script:ReleasePath))) 'Window title identifies validated release metadata'
                $script:AutoPort.Checked = $true
                $script:ManualPort.Checked = $true
                Assert-True ((-not $script:AutoPort.Checked) -and $script:ManualPort.Checked -and $script:PortNumber.Enabled) 'Selecting Manual exclusively enables the port through production events'
                $script:PortNumber.Value = 12345
                Assert-True ((Get-SelectedProxyPort) -eq 12345) 'Manual selection forwards the chosen port'
                Assert-True ([Object]::ReferenceEquals($script:AutoPort.Parent, $script:ManualPort.Parent)) 'Auto and Manual retain one native radio-button group'
                $script:ManualPort.Select()
                $nextSelected = $script:Form.SelectNextControl($script:ManualPort, $true, $true, $true, $false)
                Assert-True ($nextSelected -and $script:PortNumber.ContainsFocus) 'Keyboard traversal reaches the enabled manual port after Manual'
                $script:ActionDispatch.Clear()
                $script:CheckButton.PerformClick()
                $script:ConnectButton.PerformClick()
                $script:DisconnectButton.PerformClick()
                $script:LogsButton.PerformClick()
                Assert-True (($script:ActionDispatch -join ',') -eq 'Check:12345,Connect:12345,Disconnect:12345,Logs') 'Native button clicks dispatch once through production handlers'
                $script:AutoPort.Checked = $true
                Assert-True ($script:AutoPort.Checked -and (-not $script:ManualPort.Checked) -and (-not $script:PortNumber.Enabled)) 'Selecting Auto exclusively disables the manual port through production events'
                $script:CheckButton.PerformClick()
                Assert-True ($script:ActionDispatch[-1] -eq 'Check:0' -and $script:PortNumber.Value -eq 12345) 'Auto dispatches detection while retaining the manual value'
                $script:MockPending = $true
                Update-Controls
                $dispatchCount = $script:ActionDispatch.Count
                $script:CheckButton.PerformClick()
                $script:ConnectButton.PerformClick()
                Assert-True ((-not $script:CheckButton.Enabled) -and (-not $script:ConnectButton.Enabled) -and $script:ActionDispatch.Count -eq $dispatchCount) 'Pending work disables duplicate Check and Connect clicks'
                $script:MockPending = $false
                [IO.File]::WriteAllText($script:SessionPath, '{}')
                Update-Controls
                Assert-True ((-not $script:ConnectButton.Enabled) -and (-not $script:ManualPort.Enabled) -and $script:DisconnectButton.Enabled) 'A saved journal leaves recovery accessible and disables reconfiguration'
                [IO.File]::Delete($script:SessionPath)
                Update-Controls
                $caseIndex = 0
                foreach ($message in $messages) {
                    $caseIndex++
                    if ($caseIndex -eq 1 -or $caseIndex -eq $messages.Count) { $script:Form.ClientSize = [System.Drawing.Size]::new($width, 900) }
                    else { $script:Form.ClientSize = [System.Drawing.Size]::new($width, 520) }
                    $state = 'RecoveryRequired'
                    if ($caseIndex -eq 1 -or $caseIndex -eq $messages.Count) { $state = 'Disconnected' }
                    elseif ($caseIndex -eq 4) { $state = 'Error' }
                    $script:ClosingRequested = ($caseIndex -eq 3)
                    Show-Status $state $message
                    Update-UiLayout
                    $script:Form.PerformLayout()
                    [System.Windows.Forms.Application]::DoEvents()
                    Update-UiLayout
                    $script:LayoutScenarios++
                    $context = "font factor $factor, width $width, message $caseIndex"
                    Assert-True ($script:StatusMessage.Text -eq $message -and $script:Activity.Text.Contains($message)) ('Full provider message survives in status and native activity text / ' + $context)
                    foreach ($label in @($script:AppTitle, $script:AppSubtitle, $script:IntroLabel, $script:StatusTitle,
                        $script:StatusMessage, $script:PortDetailLabel, $script:ProxyTitle, $script:ProxyHint, $script:FooterLabel)) {
                        $preferred = $label.GetPreferredSize([System.Drawing.Size]::new($label.Width, 0))
                        Assert-True ($label.Height -ge $preferred.Height) ('Full text height: ' + $label.Text.Substring(0, [Math]::Min(24, $label.Text.Length)) + ' / ' + $context)
                        Assert-True ($label.Left -ge 0 -and $label.Right -le ($label.Parent.ClientSize.Width - $label.Parent.Padding.Right)) ('Label stays inside parent width / ' + $context)
                    }
                    Assert-True ($script:AppTitle.Bottom -le $script:AppSubtitle.Top) ('Header title and subtitle do not overlap / ' + $context)
                    $singleLineTitleHeight = [System.Windows.Forms.TextRenderer]::MeasureText($script:AppTitle.Text, $script:AppTitle.Font).Height + $script:AppTitle.Padding.Vertical
                    Assert-True ($script:AppTitle.Height -le $singleLineTitleHeight) ('The GephTun title remains on one line at the tested width and font / ' + $context)
                    Assert-True ($script:AdminLabel.Bottom -le $script:HeaderPanel.ClientSize.Height - $script:HeaderPanel.Padding.Bottom) ('Administrator text remains inside the responsive header / ' + $context)
                    Assert-True ($script:StatusTitle.Bottom -le $script:StatusMessage.Top -and $script:StatusMessage.Bottom -le $script:PortDetailLabel.Top) ('Status heading, message and proxy details do not overlap / ' + $context)
                    Assert-True ($script:ContentPanel.Width -le $script:BodyViewport.ClientSize.Width -and -not $script:BodyViewport.HorizontalScroll.Visible) ('Long text stays within the vertical scrolling viewport / ' + $context)
                    foreach ($button in @($script:CheckButton, $script:ConnectButton, $script:DisconnectButton, $script:LogsButton)) {
                        $buttonPreferred = $button.GetPreferredSize([System.Drawing.Size]::new($button.Width, 0))
                        Assert-True ($button.Height -ge $buttonPreferred.Height -and $button.Right -le $script:ActionsPanel.ClientSize.Width) ('Action label stays inside its wrapping panel / ' + $context)
                    }
                    $portTextWidth = [System.Windows.Forms.TextRenderer]::MeasureText('65535', $script:PortNumber.Font).Width
                    Assert-True ($script:PortNumber.Width -ge $portTextWidth + [System.Windows.Forms.SystemInformation]::VerticalScrollBarWidth) ('Five-digit port and spinner fit the chosen font / ' + $context)
                    if ($caseIndex -eq 3) { $longContentHeight = $script:ContentPanel.Height }
                    if ($caseIndex -eq $messages.Count) { Assert-True ($script:ContentPanel.Height -le [Math]::Max($longContentHeight, $script:BodyViewport.ClientSize.Height)) ('Content shrinks after a long message and window resize / ' + $context) }
                    if ($caseIndex -eq 2 -or $caseIndex -eq 3) { Assert-True ($script:StatusMessage.Height -gt $script:StatusMessage.Font.Height) ('Long error wraps to multiple lines / ' + $context) }
                    if ($script:ContentPanel.Height -gt $script:BodyViewport.ClientSize.Height) {
                        Assert-True $script:BodyViewport.VerticalScroll.Visible ('Overflow remains reachable by vertical scrolling / ' + $context)
                    }
                    if ($ScreenshotDirectory) {
                        # Earlier control bitmaps retained keyboard-test scrolling
                        # and captured only the bottom controls. Start each image
                        # at the top so header and status repairs can be inspected.
                        $script:Form.ActiveControl = $null
                        $script:BodyViewport.AutoScrollPosition = [System.Drawing.Point]::new(0, 0)
                        $capture = [System.Drawing.Bitmap]::new($script:Form.Width, $script:Form.Height)
                        try {
                            $script:Form.DrawToBitmap($capture, [System.Drawing.Rectangle]::new(0, 0, $capture.Width, $capture.Height))
                            $filename = 'layout-font-' + [string]$factor + '-width-' + $width + '-case-' + $caseIndex + '.png'
                            $imageStream = New-HarnessOutputFile (Join-Path $ScreenshotDirectory $filename) $protectedPaths
                            try { $capture.Save($imageStream, [System.Drawing.Imaging.ImageFormat]::Png) } finally { $imageStream.Dispose() }
                        } finally { $capture.Dispose() }
                    }
                }
            }
            finally {
                $script:LayoutUpdating = $true
                $script:toolTips.Dispose()
                $script:Form.Dispose()
                foreach ($font in $customFonts) { $font.Dispose() }
                $script:LayoutUpdating = $false
                $script:ClosingRequested = $false
            }
        }
    }
    Assert-True ($script:LayoutScenarios -eq $script:ExpectedLayoutScenarios) 'Every declared native layout scenario completed'
    foreach ($kind in @('Idle', 'Busy', 'Connected', 'Warning', 'Error')) { $script:TrayIcons[$kind] = New-TrayStatusIcon $kind }
    Assert-True ($script:TrayIcons.Count -eq 5 -and $script:TrayIcons.Connected.Width -gt 0) 'Production tray icons build as managed icons after temporary HICON cleanup'
    $trayMenu = [System.Windows.Forms.ContextMenuStrip]::new()
    $script:TrayOpenItem = [System.Windows.Forms.ToolStripMenuItem]::new('&Open GephTun')
    $script:TrayConnectItem = [System.Windows.Forms.ToolStripMenuItem]::new('&Connect')
    $script:TrayDisconnectItem = [System.Windows.Forms.ToolStripMenuItem]::new('&Disconnect / Recover')
    $script:TrayLogsItem = [System.Windows.Forms.ToolStripMenuItem]::new('Open &logs')
    $script:TrayExitItem = [System.Windows.Forms.ToolStripMenuItem]::new('E&xit')
    $trayMenu.Items.AddRange([System.Windows.Forms.ToolStripItem[]]@($script:TrayOpenItem, $script:TrayConnectItem, $script:TrayDisconnectItem, $script:TrayLogsItem, $script:TrayExitItem))
    $script:TrayIcon = [System.Windows.Forms.NotifyIcon]::new()
    $script:TrayIcon.Icon = $script:TrayIcons.Idle
    $script:TrayIcon.ContextMenuStrip = $trayMenu
    $script:TrayIcon.Visible = $true
    $script:LastStateLogKey = ''
    Initialize-UiWindow
    Initialize-UiInputEvents
    $script:UiTrayEventsConnected = $false
    Initialize-UiTrayEvents
    Initialize-UiTrayEvents
    $script:Form.Add_FormClosing({ param($sender, $eventArgs); Handle-FormClosing $sender $eventArgs })
    Update-Controls
    $script:Form.Show()
    $script:ActionDispatch.Clear()
    $script:TrayConnectItem.PerformClick()
    $script:TrayDisconnectItem.PerformClick()
    $script:TrayLogsItem.PerformClick()
    Assert-True (($script:ActionDispatch -join ',') -eq 'Connect:0,Disconnect:0,Logs') 'Native tray menu clicks dispatch once through production handlers'
    $script:Form.Close()
    Assert-True ((-not $script:Form.IsDisposed) -and (-not $script:Form.Visible) -and $script:TrayNoticeShown) 'Production user-close handler hides the window without exiting'
    $script:TrayOpenItem.PerformClick()
    Assert-True $script:Form.Visible 'Production tray Open restores a hidden window'
    foreach ($reason in @('WindowsShutDown', 'TaskManagerClosing')) {
        $script:AllowClose = $false
        $eventArgs = [pscustomobject]@{ CloseReason = $reason; Cancel = $false }
        Handle-FormClosing $script:Form $eventArgs
        Assert-True ((-not $eventArgs.Cancel) -and $script:AllowClose) ('Production close handler permits ' + $reason)
    }
    $script:AllowClose = $false
    $script:ClosingRequested = $true
    $eventArgs = [pscustomobject]@{ CloseReason = 'UserClosing'; Cancel = $false }
    Handle-FormClosing $script:Form $eventArgs
    Assert-True ($eventArgs.Cancel -and $script:Form.Visible) 'Closing during recovery keeps the window available'
    $script:ClosingRequested = $false
    $script:UiStatus = 'Connected'
    Update-Controls
    Assert-True ((-not $script:TrayConnectItem.Enabled) -and $script:TrayDisconnectItem.Enabled) 'Tray offers recovery rather than duplicate connection during an active session'
    $script:MockAction = ''
    $dispatchBeforeExit = $script:ActionDispatch.Count
    $script:TrayExitItem.PerformClick()
    Assert-True ($script:ClosingRequested -and $script:MockAction -eq 'Disconnect' -and $script:ActionDispatch.Count -eq ($dispatchBeforeExit + 1) -and $script:ActionDispatch[-1] -eq 'Disconnect:0' -and (-not $script:Form.IsDisposed)) 'Production tray Exit requests Disconnect before closing an active session'
    $script:MockPending = $true
    $script:UiStatus = 'Disconnected'
    Continue-Close
    Assert-True (-not $script:Form.IsDisposed) 'Exit waits for pending work even when a cached status is disconnected'
    $script:MockPending = $false
    $script:UiStatus = 'RecoveryRequired'
    Continue-Close
    Assert-True ((-not $script:ClosingRequested) -and (-not $script:Form.IsDisposed)) 'Incomplete recovery cancels Exit and leaves the UI available'
    $script:UiStatus = 'Disconnected'
    Update-Controls
    $dispatchBeforeCleanExit = $script:ActionDispatch.Count
    $script:TrayExitItem.PerformClick()
    Assert-True ($script:Form.IsDisposed -and $script:ActionDispatch.Count -eq $dispatchBeforeCleanExit) 'Production tray Exit closes a safely disconnected window'
}
catch {
    $failure = 'Harness execution error: ' + $_.Exception.Message + ' at ' + $_.ScriptStackTrace
    $failures.Add($failure)
    Write-Output ('FAIL   ' + $failure)
}
finally {
    # Cleanup failures must also leave a failure receipt rather than erase the run.
    foreach ($resource in @($script:TrayIcon, $trayMenu, $script:toolTips, $script:Form) + @($script:TrayIcons.Values)) {
        if ($null -ne $resource) {
            try { $resource.Dispose() } catch { $failures.Add('Harness cleanup error: ' + $_.Exception.Message) }
        }
    }
    try { if ([IO.File]::Exists($script:SessionPath)) { [IO.File]::Delete($script:SessionPath) } } catch { $failures.Add('Fixture cleanup error: ' + $_.Exception.Message) }
}
$status = 'PASS'
if ($failures.Count) { $status = 'FAIL' }
try { Write-HarnessReport $status } finally { if ($null -ne $script:ReportStream) { $script:ReportStream.Dispose() } }
Write-Output ('RESULT: ' + $script:PassedCount + ' passed; ' + $failures.Count + ' failed; native application acceptance still NOT_RUN')
if ($failures.Count) { exit 1 }
