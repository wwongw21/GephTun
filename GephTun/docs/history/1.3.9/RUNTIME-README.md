# GephTun 1.3.9

GephTun routes Windows IPv4 TCP traffic and DNS through your connected Geph local SOCKS proxy. Windows 11 x64 and built-in Windows PowerShell 5.1 are required.

**This repaired candidate is pending live Windows qualification.** Isolated engineering checks do not prove real connection, sleep or reboot behavior.

## Start and stop

1. Finish **Disconnect / Recover** in an older running version before replacing its folder.
2. Connect Geph in local-proxy mode, with its native VPN mode off.
3. Run **Launch-GephTun.cmd**, approve the administrator prompt, choose **Check**, then **Connect**.
4. Use **Disconnect / Recover** when finished. Closing the window hides it to the tray; tray **Exit** waits for recovery.

Start-GephTun.cmd requests Connect; Stop-GephTun.cmd requests recovery. Keep runtime files together while running. No Python, Go, installer, updater or background service is needed.

## Limits and recovery

IPv4 TCP and DNS are supported targets. General UDP/QUIC, games/calls, ICMP and guest networks are unqualified. IPv6 is contained rather than tunneled, with verified relay exceptions. There is no general kill switch: successful recovery restores direct internet.

Owned changes are recorded before application. A protected startup recovery script is armed before persistent DNS/firewall changes. Unverified cleanup preserves recovery files. Reopen the app and choose **Disconnect / Recover** if a saved session remains.

Do not delete %ProgramData%\GephTun, broadly reset firewall rules, remove unrelated adapters or move a running installation to force a clean appearance. A failed recovery stays visible and retryable.

## Verify

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Verify-GephTun.ps1
~~~

This checks file identity and engineering evidence bindings. A locally editable manifest is not a publisher signature; integrity PASS does not establish live qualification. The separate engineering package contains source, tests and the acceptance plan.

Logs stay local under %ProgramData%\GephTun and may contain local paths, adapter details and peer addresses. Nothing is uploaded.
