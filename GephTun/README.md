# GephTun 1.5.0 — WFP protection and upstream-bypass update

**Complete Windows test candidate. NOT production-qualified.** Based on the uploaded 1.4.0 candidate. Includes application source, launchers, the original pinned native dependencies, a native WFP API implementation, Windows regression suites, and integrity evidence.

**Do not enable this candidate on your main computer or over Remote Desktop before disposable-VM testing.** Enabling its blocking policy can leave the machine offline, including after reboot. Keep this entire folder, the emergency unlock script, local administrator access, and a VM snapshot. No live Windows/WFP/leak/reboot test has been performed in the authoring environment.

## What was implemented

**WFP kill switch:** persistent runtime deny filters plus separate boot-time deny filters; loopback and narrowly scoped DHCP/IPv6 neighbor maintenance exceptions. A live controller opens temporary permissions for explicitly reviewed, hash-pinned Geph executables on verified physical interfaces, then authorizes the current IPv4 TCP tunnel interface. Dynamic permissions disappear when their WFP session closes; the persistent block is not deliberately removed by Disconnect, Exit, ordinary recovery, or reconnect. A separate explicit unlock removes GephTun's private policy.

**Upstream bypass improvements:** a protected cache of recent validated endpoints, tied to the approved Geph image, preloads up to 128 addresses before tunnel diversion using a fresh gateway snapshot. A bounded route registry reuses verified routes, aggregates normal updates, flags persistently captured sockets, and retires only unused owned routes after a five-minute grace period. Borrowed routes are not removed. Cache entries expire after 24 hours and are limited to 512.

**Not implemented:** an automatic crash-recovery service, restarting a dead controller, an automatic reboot connection, a custom callout driver, or modification of Geph's own socket creation. These are not hidden behind a new version label. Automatic crash recovery is explicitly a future recommendation in `docs/RECOMMENDATIONS.md`.

New, previously unseen Geph endpoints may still need a validated route repair and a Geph socket retry. The supplied Geph packaging archive does not include the engine implementation needed to protect every socket before it is created. The update reduces avoidable repeated repairs and log floods; it does not guarantee their complete elimination.

## Important behavior changes

| Action or condition | 1.5.0 behavior |
|---|---|
| Before you enable protection | No GephTun WFP policy is installed; ordinary networking is unchanged by this feature. |
| Connect | Refuses an unprotected session. Requires an explicitly enabled, verified WFP policy and reviewed Geph executable list. |
| Connected | Grants the approved Geph transport path and current IPv4 TCP tunnel path. Unsupported direct application traffic is denied by the installed policy. |
| DNS/peer interruption or network reconnect | Existing 1.4.0 bounded recovery remains; blocking is not deliberately lifted while old routes are replaced. |
| Disconnect / Recover | Stops/reconciles the tunnel. **Keeps WFP blocking installed.** |
| Tray Exit or controller crash | Does not unlock protection. Temporary permissions close or are removed by WFP session rundown. There is no crash restart service. |
| Reboot | Boot/runtime blocking is intended to persist. No auto-connect is installed; reopen GephTun and recover/connect as needed. This transition must pass Windows acceptance before it is relied upon. |
| Disable protection / allow direct internet | An explicit, confirmed operation. Normal route recovery must finish first; then only GephTun-owned WFP policy is removed. |

A displayed `Enabled` value means that expected policy objects and conditions were read back successfully. It is NOT an independent packet-leak test. `Unknown` is not a protected/connected success state.

## Upgrade safely

1. In 1.4.0 or 1.3.9, finish **Disconnect / Recover**, then use **tray Exit**. X only hides the window. Keep the old folder and recovery state; do not overwrite running code or delete `%ProgramData%\GephTun`.
2. Extract this ZIP into a separate local folder. Do not start from inside the ZIP. The main folder is `GephTun`.
3. Run the read-only verification and isolated tests below on a disposable Windows 11 x64 VM. Resolve failures before any live connection or policy installation.
4. Retain the emergency unlock files and snapshot. Complete `WINDOWS-ACCEPTANCE.md` before using this candidate for privacy-sensitive sessions.

## Verification — does not enable blocking

In Windows PowerShell, from the extracted `GephTun` folder:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Verify-GephTun.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-UpdateValidation.ps1
```

The first verifies hashes and truthful evidence. The second executes parser/C# compile checks, managed WFP policy-plan tests, mocked bypass/protection/resilience/controller tests, in-memory DNS tests, isolated boot recovery and package corruption fixtures. It writes a unique results folder under TEMP, outside the installation. It does not install WFP filters or run the native smoke test.

The optional `tests/Wfp-NativeSmoke.ps1` is destructive, separately consent-gated, and only for a disposable VM/local console. See `WINDOWS-ACCEPTANCE.md`. A passing smoke result is not leak/reboot qualification.

## Enabling protection and connecting

Windows 11 x64, Windows PowerShell 5.1, administrator approval, and a separately installed Geph local SOCKS proxy are required. Geph's native VPN mode must be off. Leave Windows firewall profiles enabled; this version does not silently change global profile settings.

Start Geph in local-proxy mode. Run **Protection-GephTun.cmd**, or choose **Protection...** in the GephTun window/tray. Select **Enable protection** only after the VM tests. Review the exact executable paths shown and accept persistent blocking. The UI discovers candidates but does not silently trust every process named Geph.

Then open **Launch-GephTun.cmd**, confirm **1.5.0 (test candidate)** in the title, and choose **Connect**. The Connect worker grants temporary Geph TCP bootstrap permission before testing the local proxy. Check also uses a temporary Geph lease when protection is enabled; those permissions close when Check completes.

**While protection is enabled but no Connect/Check worker runs, Geph itself does not have a standing internet exception.** It may show disconnected until the worker opens its lease. If the Geph installation requires ordinary system DNS or an external login flow to bootstrap, it may not become ready within the bounded setup window. No broad DNS or browser exception is silently added. Explicitly disable protection for login/bootstrap when necessary, then review/re-enable it. Compatibility with your actual Geph installation is a mandatory acceptance test.

After a Geph update changes approved binaries, the pinned-image check refuses the old trust record. Disconnect, explicitly disable protection, review the new paths/version, then re-enable it. This candidate does not auto-approve changed executable hashes.

## Deliberately restore ordinary internet

Choose **Protection... → Disable protection / allow direct internet**. Confirm the warning. That operation first requests normal Disconnect / Recover, then removes the private WFP policy only if it is safe to proceed. Disabling protection exposes your ordinary connection.

From an administrator PowerShell in the package folder:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Protection-GephTun.ps1 -Action Disable -AllowDirectInternet
```

If the normal interface or protected state cannot be read, the standalone local emergency tool uses the native helper without importing the controller or reading ProgramData:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Emergency-Unlock-GephTun.ps1 -AllowDirectInternet
```

It requires administrator rights and refuses to remove persistent filters while a live controller still has temporary filters. Finish Disconnect/Exit first. It does not reset Windows Firewall, repair all old routes/DNS, terminate arbitrary processes, or remove unknown foreign policy. After emergency unlock, run normal Recover for any leftover tunnel state. Keep this folder until unlock is verified. A VM snapshot/local console is the last-resort safety net for an unqualified native implementation; restarting Windows or deleting the folder is not an unlock mechanism.

## Scope and remaining limitations

This is a host IPv4 TCP plus DNS tunnel. Ordinary direct IPv4/IPv6 application internet, direct DNS/DoH/DoT, and unsupported UDP/QUIC are intended to be denied rather than silently bypassed. Loopback, narrow DHCP and local IPv6 neighbor maintenance are explicit exceptions, not a promise that zero packets leave the host. LAN access is intentionally restricted.

Geph's reviewed executable identities get TCP transport permission on the current physical-interface list, not only to particular relay IPs. Treat those executables as trusted; do not approve arbitrary renamed programs. Hash/open-file checks are not a publisher signature or protection against an administrator, kernel attacker, or malicious replacement of the installation hierarchy.

An ordinary application connecting to an IP that has a Geph destination bypass may be blocked, not magically rerouted through the tunnel; WFP does not make Windows host routes per-process. No generic PowerShell/browser exception is installed. Existing socket, route-change, IPv6, BFE-restart and reboot behavior require the acceptance matrix. WSL/Hyper-V/vSwitch/guest traffic, other VPNs, nonstandard security products, captive portals, network boot, driver compromise, and enforced enterprise policy are not qualified.

The persistent blocking policy is independent of the old boot cleanup task, which remains session-scoped. `RecoveryRequired` can still require manual attention; no new service or crash watchdog is installed. If you later run an older GephTun copy while this policy is enabled, it will not know how to manage these permissions. Explicitly disable protection before rolling back.

## Evidence

Executed here: Python source/lexical assertions, Python syntax, DNS INPUT structure, native binary pins/PE headers, manifest/source/evidence binding and ZIP corruption-rejection checks. NOT executed here: PowerShell parsing/execution, C# compilation, native WFP calls, actual policy-plan/regression tests, live tunnel connections, leak/crash/reboot checks, UI or long-session soak. The authoring host has no usable PowerShell/.NET Windows toolchain. Earlier receipts under `docs/history/` are historical, not passes for this build.

See `VALIDATION.md`, `docs/WFP-DESIGN.md`, `docs/BYPASS-DESIGN.md`, and `docs/RECOMMENDATIONS.md`. The two native tunnel dependencies were retained unchanged, not updated or independently rebuilt. Code and licenses are included.
