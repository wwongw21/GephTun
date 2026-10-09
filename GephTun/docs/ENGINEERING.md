# Engineering — GephTun 1.5.0

Runtime remains script-based Windows PowerShell 5.1 with .NET Framework C# helper compilation. Native WFP structures are explicitly x64 and checked with Marshal.SizeOf/OffsetOf before API use. No service/callout driver is installed; automatic crash recovery is deferred.

`GephTun.Protection.ps1` owns policy configuration/consent and dynamic lease lifecycle. `GephTun.Wfp.cs` owns native policy operations. `GephTun.Bypasses.ps1` owns bounded route registry/cache/logging. Core/Resilience integrate these at setup, checks, recovery and reconnect; UI exposes a separate Protection window. `Emergency-Unlock-GephTun.ps1` avoids Core/ProgramData dependency.

Run `python tools/release_tool.py static .` for source-only checks, `python tools/release_tool.py seal .` for truthful static evidence/manifests, or `python tools/release_tool.py build . --output /outside/package/GephTun-1.5.0-Windows-Test-Candidate.zip`. `check` verifies a sealed folder; `verify-zip` verifies a built archive. Never write results inside the installation. Python 3.10+, standard library. This tooling cannot turn a static check into Windows qualification.

Windows: `tests/Run-UpdateValidation.ps1` defaults to isolated, non-mutating suites; native smoke remains explicit and separate. Do not reuse old test receipts for changed source. Before changing layer/condition identifiers, compare Microsoft SDK declarations and target-Windows behavior. Do not let the persistent blocker share a dynamic worker lifetime or accidentally delete it from recovery.
