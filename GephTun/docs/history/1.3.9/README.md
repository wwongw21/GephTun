# GephTun 1.3.9

GephTun routes Windows IPv4 TCP traffic and DNS through a separately connected Geph local SOCKS proxy. This version repairs recovery failure handling and consolidates the project into one local Git repository.

**This is a repaired candidate, pending live Windows qualification.** Isolated results are in VALIDATION.md and tests/current-validation.json. Passing these tests does not establish real tunnel, sleep, or reboot behavior.

## Everyday use

Windows 11 x64 and built-in Windows PowerShell 5.1 are required. The runtime needs no Python, Go, PowerShell 7, installer, updater or background service.

1. Finish **Disconnect / Recover** in a running older version before replacing it.
2. Connect Geph in local-proxy mode, with its native VPN mode off.
3. Run **Launch-GephTun.cmd** and approve the administrator prompt.
4. Choose **Check**, then **Connect**. If needed, enter the actual SOCKS5 port.
5. Use **Disconnect / Recover** when finished. Closing the window hides it to the tray; tray **Exit** waits for recovery.

Start-GephTun.cmd requests connection; Stop-GephTun.cmd requests recovery. Keep the installation together while running.

## Coverage and recovery

- IPv4 TCP and DNS are the supported target. General UDP/QUIC, calls/games, ICMP and guest networks such as WSL/Hyper-V are unqualified.
- DNS uses a loopback-only relay and tagged Windows DNS policy. Physical adapter DNS settings are preserved. A busy DNS port blocks startup.
- IPv6 is contained rather than tunneled, with verified Geph relay exceptions. Local IPv6 services and independently validating DNSSEC clients can be affected.
- There is no general kill switch. Successful recovery restores direct internet.
- Connect arms a protected startup recovery script before persistent network changes. Unverified cleanup preserves the recovery path.
- After a crash/restart, reopen the app and use **Disconnect / Recover** if a saved session remains. Do not delete %ProgramData%\GephTun or broadly reset networking to force a clean appearance.

## Verify this checkout

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Verify-GephTun.ps1 -SourceTree
~~~

The explicit **-SourceTree** option excludes only root Git/instruction metadata. Extracted packages use the verifier without that option and reject unlisted files. Integrity PASS checks identity and bound evidence; it is not a publisher signature or live production PASS.

## Isolated validation and builds

Use installed Python 3 for the loopback protocol suite. Outputs must be outside the source.

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-IsolatedValidation.ps1 -OutputDirectory C:\Users\William\Documents\GephTun-Builds -SourceTree -BuildPackages
~~~

The runner copies one snapshot, runs controller, UI logic, network mocks, packaging, acceptance-comparison, diagnostic and parser/compiler suites, collects fresh evidence and checks engineering/runtime archives. Failures and skips are preserved. It does not change Windows networking/trust, launch the real app, sleep or reboot.

Add **-PublishReports** only when intentionally refreshing this checkout's generated evidence. Source hashes are checked before publishing; commit refreshed reports with their source.

Live qualification is separately arranged under WINDOWS-PRODUCTION-TEST-PLAN.md. ProductionQualified remains false until applicable live scenarios pass on the exact candidate bytes.

## Engineering records

- docs/RECONCILIATION-REPORT.md explains integration and cleanup gates.
- RECONCILIATION.json records every original file/directory disposition.
- docs/archive-index.json locates the verified recovery archive.
- docs/HISTORY.md distinguishes historical claims and superseded attempts.
- tools/diagnostics/README.md describes read-only troubleshooting.
- third_party/BUILD-TUN2SOCKS.md retains the pinned offline rebuild instructions.

No remote is configured; nothing is pushed or uploaded automatically.
