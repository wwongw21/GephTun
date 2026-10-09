#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Show','Enable','Disable','Status')][string]$Action='Show',
    [string[]]$GephExecutable,
    [switch]$AllowBlocking,
    [switch]$AllowDirectInternet
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess) { throw 'Use 64-bit Windows PowerShell on Windows.' }
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    try { $admin=([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
    finally { $id.Dispose() }
    if (-not $admin) {
        if ($Action -ne 'Show') { throw 'Open Windows PowerShell as administrator for command-line protection changes.' }
        $child=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -PassThru -ArgumentList @(
            '-NoProfile','-ExecutionPolicy','Bypass','-Sta','-File',('"'+$PSCommandPath+'"'),'-Action','Show')
        $child.Dispose();return
    }
    Import-Module (Join-Path $PSScriptRoot 'GephTun.Core.psm1') -Force
    Initialize-GephTunStorage
    switch ($Action) {
        'Status' { Get-GephTunProtectionStatus | ConvertTo-Json -Depth 6; return }
        'Enable' {
            if (-not $AllowBlocking) { throw 'Specify -AllowBlocking after reading README.md and retaining Emergency-Unlock-GephTun.ps1 locally.' }
            if (-not $GephExecutable) { throw 'Supply the exact reviewed executable path(s) with -GephExecutable. The GUI can show running Geph candidates.' }
            Enable-GephTunProtection -GephExecutable $GephExecutable -AllowBlocking | ConvertTo-Json -Depth 6;return
        }
        'Disable' {
            Disable-GephTunProtection -AllowDirectInternet:$AllowDirectInternet | ConvertTo-Json -Depth 6;return
        }
    }
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [Windows.Forms.Application]::EnableVisualStyles()
    $form=New-Object Windows.Forms.Form
    $form.Text='GephTun 1.5.0 - WFP protection (test candidate)'
    $form.ClientSize=New-Object Drawing.Size(630,360)
    $form.StartPosition='CenterScreen'
    $form.AutoScaleMode='Dpi'
    $text=New-Object Windows.Forms.TextBox
    $text.Multiline=$true;$text.ReadOnly=$true;$text.ScrollBars='Vertical';$text.Dock='Fill'
    $text.Font=New-Object Drawing.Font('Segoe UI',10)
    $panel=New-Object Windows.Forms.FlowLayoutPanel
    $panel.Dock='Bottom';$panel.Height=88;$panel.Padding=New-Object Windows.Forms.Padding(10);$panel.WrapContents=$true
    $enable=New-Object Windows.Forms.Button;$enable.Text='Enable protection';$enable.AutoSize=$true
    $disable=New-Object Windows.Forms.Button;$disable.Text='Disable protection / allow direct internet';$disable.AutoSize=$true
    $refresh=New-Object Windows.Forms.Button;$refresh.Text='Refresh status';$refresh.AutoSize=$true
    $close=New-Object Windows.Forms.Button;$close.Text='Close';$close.AutoSize=$true
    foreach ($button in @($enable,$disable,$refresh,$close)) { [void]$panel.Controls.Add($button) }
    $form.Controls.Add($text);$form.Controls.Add($panel)
    $refreshState={
        $status=Get-GephTunProtectionStatus
        $text.Text=('WFP policy: '+$status.State+"`r`n"+$status.Detail+"`r`n`r`n"+
            'Enabling protection blocks ordinary direct internet, LAN access and unsupported traffic. Disconnect and tray Exit do not disable it. Blocking persists across crashes and reboot; automatic crash recovery is NOT installed.'+"`r`n`r`n"+
            'Connect temporarily permits only the reviewed Geph executables and the verified tunnel path. Outside a live Connect/Check worker, even Geph bootstrap is blocked. Keep this folder and the emergency unlock script.'+"`r`n`r`n"+
            'This Windows test candidate has not passed live leak/reboot acceptance. Use a disposable VM with local console access first.')
    }
    $refresh.Add_Click($refreshState)
    $close.Add_Click({$form.Close()})
    $enable.Add_Click({
        try {
            $paths=@(Get-GephTunTransportCandidates)
            $message="The following exact executable paths will be trusted for Geph TCP transport while a controller runs:`r`n`r`n"+($paths -join "`r`n")+
                "`r`n`r`nEnable persistent blocking? Other internet traffic will stop until GephTun connects. Disconnect, Exit and reboot WILL NOT unlock it. This is an unqualified test candidate."
            $answer=[Windows.Forms.MessageBox]::Show($form,$message,'Enable WFP protection?',[Windows.Forms.MessageBoxButtons]::YesNo,[Windows.Forms.MessageBoxIcon]::Warning,[Windows.Forms.MessageBoxDefaultButton]::Button2)
            if ($answer -ne [Windows.Forms.DialogResult]::Yes) { return }
            $enable.Enabled=$false;$disable.Enabled=$false
            Enable-GephTunProtection -GephExecutable $paths -AllowBlocking | Out-Null
            & $refreshState
        } catch { [void][Windows.Forms.MessageBox]::Show($form,$_.Exception.Message,'Protection was not confirmed',[Windows.Forms.MessageBoxButtons]::OK,[Windows.Forms.MessageBoxIcon]::Error) }
        finally { $enable.Enabled=$true;$disable.Enabled=$true }
    })
    $disable.Add_Click({
        $answer=[Windows.Forms.MessageBox]::Show($form,'Disconnect / Recover, then REMOVE GephTun blocking and allow direct internet? This exposes your ordinary connection.','Explicitly disable protection?',[Windows.Forms.MessageBoxButtons]::YesNo,[Windows.Forms.MessageBoxIcon]::Warning,[Windows.Forms.MessageBoxDefaultButton]::Button2)
        if ($answer -ne [Windows.Forms.DialogResult]::Yes) { return }
        try { $enable.Enabled=$false;$disable.Enabled=$false;Disable-GephTunProtection -AllowDirectInternet | Out-Null;& $refreshState }
        catch { [void][Windows.Forms.MessageBox]::Show($form,$_.Exception.Message,'Unlock needs attention',[Windows.Forms.MessageBoxButtons]::OK,[Windows.Forms.MessageBoxIcon]::Error) }
        finally { $enable.Enabled=$true;$disable.Enabled=$true }
    })
    & $refreshState
    [void]$form.ShowDialog()
    $form.Dispose()
} catch {
    Write-Error $_ -ErrorAction Continue
    if ($Action -eq 'Show') { try { Add-Type -AssemblyName System.Windows.Forms;[void][Windows.Forms.MessageBox]::Show($_.Exception.Message,'GephTun protection') } catch {} }
    exit 1
}
