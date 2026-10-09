# Test the corrected candidate in Windows Sandbox

The candidate remains unqualified. These instructions run isolated regressions,
not native WFP or leak acceptance. Do not run the native smoke script, live
protection controls, emergency unlock, or opt-in NRPT mutation fixture.

1. On a Windows 11 host with Windows Sandbox available, check out
   `fix/gephtun-1.5.0-recovery` and verify its commit. Keep the original candidate
   in a separate folder; do not replace a currently protected installation.
2. Create `GephTun-isolated.wsb` on the host. Replace `C:\Source\GephTun` with
   the **repository root**, which contains `.github` and the inner `GephTun`.

   ```xml
   <Configuration>
     <Networking>Disable</Networking>
     <ClipboardRedirection>Disable</ClipboardRedirection>
     <MappedFolders>
       <MappedFolder>
         <HostFolder>C:\Source\GephTun</HostFolder>
         <SandboxFolder>C:\CandidateInput</SandboxFolder>
         <ReadOnly>true</ReadOnly>
       </MappedFolder>
     </MappedFolders>
   </Configuration>
   ```

3. Start that Sandbox. In its administrator Windows PowerShell window, copy
   the source to disposable writable storage. The CI helper needs a writable
   checkout to grant its standard test account read access; do not run it
   directly against the read-only mapping.

   ```powershell
   Copy-Item -LiteralPath C:\CandidateInput -Destination C:\GephTunWorkspace -Recurse
   Set-Location C:\GephTunWorkspace
   powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass `
     -File .\.github\scripts\Test-GephTunCandidate.ps1 `
     -PackageDirectory C:\GephTunWorkspace\GephTun `
     -OutputDirectory C:\GephTunEvidence-PS51 `
     -PowerShellExecutable powershell.exe
   if ($LASTEXITCODE -ne 0) { throw 'Isolated Windows PowerShell 5.1 validation failed.' }
   Get-Content C:\GephTunEvidence-PS51\host.json
   Get-Content C:\GephTunEvidence-PS51\suites\summary.json
   ```

   The parent helper creates/removes a disposable **local standard account**
   and grants only source read access and evidence write access. Product tests
   run in the child process; it refuses an administrator token. No test changes
   real scheduled tasks, WFP filters, routes, or DNS. The only intended real
   system changes are that disposable account, checkout/evidence ACL grants,
   and files inside the Sandbox. A logon/ACL failure must fail the run, never
   bypass the nonadministrator guard.

4. For PowerShell 7, prepare Microsoft's Windows x64 PowerShell ZIP on the host,
   verify it against the official release SHA-256 manifest, and include it in a
   separate read-only mapping. Extract it inside the Sandbox, add that extracted
   directory to PATH in the parent window, and repeat the helper command using
   `-PowerShellExecutable pwsh.exe` and a fresh output directory such as
   `C:\GephTunEvidence-PS7`. Record the actual PowerShell version in `host.json`.
   PowerShell 7 is not assumed to be preinstalled in Sandbox. Do not enable
   Sandbox networking merely to make these isolated tests run.
5. Require `Administrator=false` in each host receipt, nine passing suites,
   no failed or skipped cases, nonempty per-suite JSON, and zero process exit.
   Review `.txt` suite logs and launcher stdout/stderr; setup/child/account
   cleanup failures have separate `.txt` files. Preserve results outside the
   package before closing Sandbox; for example export them using a separately
   configured evidence mapping after reviewing its host write destination.
6. Close Sandbox to discard its state. Do not interpret a passing isolated run
   as permission to mark `ProductionQualified=true`.

## Recovery expectations exercised by the doubles

Live workers preserve their guards even through fractional-second JSON and UTC
offset conversions. Unknown identity refuses cleanup. Failed setup closes only
its newly owned temporary lease. Recovery stops after three failed attempts,
retains blocking and journal, reports the blocker, and permits a subsequent
explicit operator retry after the dependency is repaired. Competing routes
must select the intended physical host route. Foreign/unreadable recovery tasks
are never removed. These assertions run against actual PowerShell functions
with isolated OS boundaries.

## Separate acceptance still required

Windows-only native WFP installation, IPv4/IPv6/DNS/UDP packet leaks, controller
and tunnel crashes, reboot under SYSTEM, adapter/gateway changes, physical
network route selection, moved-package recovery, and explicit real protection
controls are **NOT TESTED** by the instructions above. Use a separately approved,
disposable network acceptance environment with an independent capture point.
The existing production/acceptance plans are historical or pending guidance,
not passing evidence for this candidate. No automatic background service or
controller restart was implemented.
