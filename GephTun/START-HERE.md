# Start here — GephTun 1.5.0 WFP test candidate

**Do not enable on a primary or remote-only machine before VM tests. Persistent blocking survives Disconnect, Exit and reboot. Keep the emergency unlock files locally.**

Read README.md. Complete the old version's Disconnect / Recover and tray Exit, then extract this package separately. Verify the manifest and run `tests\Run-UpdateValidation.ps1` before attempting native WFP or tunnel use. The default runner never installs blocking.

For a local, disposable Windows VM: take a snapshot, review WINDOWS-ACCEPTANCE.md, then start Geph in local-proxy mode, use **Protection-GephTun.cmd → Enable protection**, review the exact executable paths, and confirm. Open **Launch-GephTun.cmd → Connect**. Confirm version 1.5.0 (test candidate).

**Disconnect / Recover keeps protection.** Use **Protection → Disable protection / allow direct internet** for a deliberate unlock. Administrator CLI alternative: `Protection-GephTun.ps1 -Action Disable -AllowDirectInternet`. Standalone fallback: `Emergency-Unlock-GephTun.ps1 -AllowDirectInternet`; it requires the local C# helper and refuses active temporary-controller policy.

Automatic crash recovery is NOT implemented. It is documented as a later recommendation. Windows parsing, C# compilation and native/leak/reboot acceptance have NOT been performed by the author. Matching hashes are not execution evidence.
