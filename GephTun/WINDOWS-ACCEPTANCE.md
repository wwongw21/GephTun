# Windows acceptance — mandatory before a protection claim

**Current status: NOT_RUN. This file is a test plan, not evidence of passes.** Use a disposable Windows 11 x64 VM with a snapshot, local console and local administrator account. Never run destructive tests from Remote Desktop or on a machine whose network you cannot restore. Keep the complete package and emergency unlock instructions outside transient downloads. Do not delete old recovery state.

## Gate 1: non-mutating/default suite

Run Verify-GephTun.ps1 and tests/Run-UpdateValidation.ps1 as shown in README.md. The runner compiles/parses actual current sources in fresh processes and runs nine isolated suites: Source, WfpPolicy, Bypasses, Protection, Resilience, Controller, DnsMandatory, BootRecovery and Package. Native WFP is not called by the default suites. Keep the results outside the installation. A parser or compiler error blocks all further deployment.

## Gate 2: explicit native smoke

On the disposable VM/local console only:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Wfp-NativeSmoke.ps1 -AllowNetworkDisruption -ResultJson "$env:TEMP\GephTun-150-native-smoke.json"
```

Read the warning and type TEST BLOCKING. This test refuses an existing GephTun WFP policy, installs a new baseline transaction, reads it back, observes a literal-IP TCP attempt, and removes only the policy it attempted to install in finally. No scheduled unlock is installed. Loss of the process before finally can leave persistent blocking: use the retained emergency unlock tool or restore the snapshot. A remote server being unavailable is not proof that the block worked; this is only an installation/removal smoke test, not packet-level qualification.

Verify the explicit unlock again: no owned sublayer/filter, ordinary networking restored, no session journal or unrelated policy altered. Test partial API failure before commit and ensure the transaction leaves no partial policy.

## Gate 3: real traffic and failure matrix

For each case, record source ZIP/hash, Windows build, Geph exact version/hash, interface identities, event/log timestamps, actual WFP state, and an external or independently located packet capture. Generate ordinary IPv4 TCP, IPv6, UDP/QUIC, port-53 DNS, HTTPS DNS and existing long-lived flows. Define the allowed DHCP/NDP/Geph transport traffic so it is not misreported as application leakage.

| Scenario | Required assertion |
|---|---|
| Disabled → Enable with existing direct TCP/UDP flows | Ordinary direct flows cease under the baseline, not just newly opened sockets. |
| Disconnected protected state | No ordinary direct internet; local control works; DHCP/neighbor exceptions remain narrowly scoped. |
| Geph bootstrap and real connection | Exact reviewed Geph TCP paths can reconnect; another app/PowerShell using the same relay IP cannot use that permission. No broad system DNS fallback. |
| Current tunnel | IPv4 TCP and relay DNS work; direct application IPv6/UDP and LAN behavior match the documented policy. |
| DNS interruption / peer rotation | Bounded retry; no deliberate unlock; no policy drift; unknown endpoints generate bounded useful diagnostics. |
| WK-5G → WK, gateway loss, Ethernet insertion | Old permission is retired; new session route/LUID generation is validated; no application direct fallback. |
| Existing-flow route change | An old tunnel source with a physical next hop is not authorized; inbound-triggered reauthorization behaves correctly. |
| Disconnect, tray Exit | Baseline persists; temporary permissions disappear; ordinary internet remains blocked. |
| Worker crash (controlled VM test) | Dynamic permits disappear by session rundown. Persistent baseline remains. **No automatic restart expected.** Manual Recover/Connect works. |
| Tunnel/DNS process death | Baseline remains; failure is visible; no direct fallback. |
| Reboot, BFE stop/start and security-software coexistence | Correct boot/runtime policy and disabled-flag behavior; no claimed-protected gap. No auto-connect expected. |
| Tampered/removed filter, duplicate lease, interface replacement | Controller reports uncertainty/failure, closes its dynamic permissions and never silently unlocks. |
| Changed Geph binary / stale cache | Trust is refused pending explicit review; cache is not routing authority. |
| Explicit unlock / emergency unlock | User consent required, only owned policy removed, no active temporary owner bypassed; documented route recovery still works. |
| Rollback/update | Explicit unlock before old-version launch; no orphan policy; preserve recovery journal and foreign routes/firewall state. |
| At least 24-hour endpoint-rotation soak | Registry/cache bounded; route retirement does not break live transport; aggregate logs remain useful. |

A failure of a required privacy assertion prevents release promotion. Do not fix it by granting powershell.exe or all destinations broad physical egress. WSL/VM/vSwitch/raw-driver combinations are excluded unless separately designed and tested. A source assertion, successful API return or green UI alone is not this acceptance evidence.
