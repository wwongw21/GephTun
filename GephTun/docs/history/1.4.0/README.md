# GephTun 1.4.0 — network-resilience update

**Complete Windows test candidate, built from the uploaded 1.3.9 source. Not production-qualified.** This package includes the application, native dependencies, source, regression tests, licenses and an integrity manifest. It is a script-based Windows application, not a new standalone executable or installer.

This update is designed to recover from Wi-Fi changes and short Geph/DNS interruptions instead of permanently disconnecting at the first failed observation. It also repairs mandatory HTTPS/SVCB DNS filtering and avoids new global firewall-profile changes.

## Start here

Windows 11 x64, built-in Windows PowerShell 5.1, administrator approval, and a separately connected Geph local SOCKS proxy are required. Geph's own native VPN mode must be off. The normal application needs no Python, Go, PowerShell 7, compilation command or installer. The C# helper is compiled by the Windows runtime when needed.

1. In the older GephTun, finish **Disconnect / Recover**, then choose tray **Exit**. Keep a backup; do not overwrite a running installation or delete its recovery state.
2. Extract the entire ZIP into a new local folder. Keep its contents together; do not launch from inside the ZIP. Run the included tests in a disposable Windows VM or non-critical machine before relying on this candidate.
3. Connect Geph in local-proxy mode. Open **Launch-GephTun.cmd**, approve elevation, select **Check**, then **Connect**. Enter the correct local SOCKS port when necessary.
4. **Disconnect / Recover** cancels automatic retries and restores the session's changes. Window X hides to the tray; tray Exit cancels and waits for recovery. Start-GephTun.cmd and Stop-GephTun.cmd remain available.

**There is no general kill switch. Successful cleanup restores ordinary direct internet. During a clean-session automatic reconnect, traffic may go directly outside Geph until Connected is verified again. Existing application TCP connections may need to reconnect. Do not use this candidate where continuous blocking outside the tunnel is required.**

## What changed

| Area | 1.4.0 behavior |
|---|---|
| Wi-Fi/network changes | Recognized transient network failures request verified cleanup, then a completely new preflight and session on the stable network. Old routing snapshots are never blindly reused. |
| Brief peer/DNS outages | Up to a 45-second grace budget while the existing routes, DNS policy and containment remain installed and are checked. Traffic may stall. |
| Bounded reconnect | After successful cleanup: 180-second budget, three fresh setup attempts, and no more than three recovery cycles within ten minutes. One more Connect is an explicit user action. |
| Cancel during transitions | A worker-owned connection-intent token remains valid between old-session cleanup and new-session setup. Disconnect and owner exit cancel retries. |
| Better diagnostics | Logs include the rejected socket's local/remote address, process and validation details; DNS failures include relay load/error counters. No telemetry is sent externally. |
| DNS filtering | Records requiring the removed ipv6hint are discarded rather than emitting an inconsistent mandatory list. Other valid parameters and unaffected records are retained. |
| Firewall baseline | Disabled or unverifiable local firewall profiles are refused before changes. This version no longer enables global profiles. Legacy journal restoration remains available through Recover. |
| UI and packaging | Reconnecting status, direct-traffic warning, visible test-candidate label, complete manifest, separate current evidence and historical 1.3.9 receipts. |

Budgets are checked between operations; Windows providers and network calls can delay a checkpoint. They are not hard real-time deadlines. Initial startup still requires a working Geph proxy. Automatic reconnect applies to established sessions and only to the explicit transient allow-list; tunnel-engine failure, unverified ownership, policy tampering, a different Geph executable path, and incomplete cleanup require attention rather than blind retries.

This application does not select Wi-Fi networks, edit Wi-Fi profiles, install/change wireless drivers, reset Windows networking, control Geph's own user interface, or become a boot-time VPN service.

## Coverage and limits

IPv4 TCP and DNS are the supported target. IPv6 is contained rather than tunneled, with existing Geph relay-address exceptions; those destination exceptions apply to all applications. Local IPv6 remains subject to the existing design. General UDP/QUIC, games/calls, ICMP, WSL/Hyper-V/guest networks, captive portals and other VPN combinations are not qualified. DNS rewriting can affect independently validating DNSSEC clients. The upload's native tun2socks and Wintun binaries are retained, not rebuilt or claimed to be the latest versions.

Protected startup recovery remains session-scoped. Failed cleanup preserves recoverable state rather than pretending success. Following a crash/reboot, reopen the program and choose **Disconnect / Recover** if needed. For legacy sessions that changed global firewall profiles, boot cleanup keeps its recovery task/script and requires explicit Recover instead of guessing at later administrator changes. Do not delete `%ProgramData%\GephTun` to suppress a recovery warning.

## Verification and tests

From the extracted GephTun folder:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Verify-GephTun.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-UpdateValidation.ps1
```

The verifier checks integrity and the scope of the bundled evidence. The test runner starts fresh PowerShell processes for parser/C# compile checks, controller/resilience doubles, in-memory DNS fixtures, isolated boot recovery and package corruption fixtures. It writes a new results directory under TEMP by default, never into the installation. Neither command establishes live Windows acceptance or rewrites the bundled qualification metadata.

**Executed here:** Python static/source-invariant, DNS-input-structure, native-header/hash and package-integrity checks only. **Not executed here:** PowerShell parsing/execution, C# compilation, actual DNS-filter regressions, UI, TLS/network tests, real connection/reconnect, sleep/reboot, or a long-session soak. A Linux authoring environment without PowerShell/.NET cannot certify this Windows program. See `VALIDATION.md`, `tests/static-results.json`, and `WINDOWS-ACCEPTANCE.md`.

Developer rebuild: Python 3.10+ `python tools/release_tool.py check .` or `python tools/release_tool.py build . --output /a/new/GephTun-1.4.0-Windows-Test-Candidate.zip`. Build updates static evidence and manifests, but never promotes native qualification. See `docs/ENGINEERING.md`.

## Diagnostics

Application status/logs remain under `%ProgramData%\GephTun`. `GephTun.log` and its `.previous` rotation preserve the termination reason. Status **Reconnecting** is not proof of a working tunnel: it can mean verified-old-session grace or a cleaned, direct-network interval. Read its message. Disconnect waits for safe cleanup; an unresponsive provider is not permission to force-kill the controller.

`docs/history/1.3.9/` contains explicitly historical evidence and tooling retained for audit. No old pass count is presented as a test of 1.4.0. Native dependency licenses and source provenance are in `licenses/` and `third_party/`.
