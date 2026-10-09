# Read-only diagnostics

These tools replace the September 30 scripts' fixed PIDs/paths and hidden errors. They never import the controller or change networking. Restricted reads appear as UNKNOWN/PARTIAL, not empty successful results.

Optional **-ResultJson** must be a new file outside the source.

- **Get-GephTunDiagnostics.ps1**: select Processes, Memory, Events, State or Log with **-Sections**; use **-ProcessIds**, **-StateDirectory**, **-EventDays**, **-MaximumEvents** and **-LogTailBytes**.
- **Compare-GephTunFiles.ps1**: supply **-ReferenceDirectories**, optionally **-PackageDirectory** and **-Files**. Missing/unreadable files are unknown; hashes establish identity only.
- **Measure-CimWorkload.ps1**: choose **-DurationSeconds**, **-SampleMilliseconds**, **-ForceGcEvery** and optional **-FirewallRuleName**. It samples itself; a proxy workload does not prove a product leak.
- **Get-GephTunCleanupState.ps1**: checks processes, saved journal, guard copy, task and mutex before folder removal. It does not recover or certify Windows networking normalcy.
- **tests/Measure-WindowsResources.ps1**: sample selected PIDs into an external CSV; start-time binding prevents PID-reuse confusion.

~~~powershell
.\tools\diagnostics\Get-GephTunDiagnostics.ps1 -Sections Processes,Memory
.\tools\diagnostics\Get-GephTunDiagnostics.ps1 -Sections State,Log
.\tools\diagnostics\Compare-GephTunFiles.ps1 -ReferenceDirectories C:\GephTun-Reference
.\tools\diagnostics\Measure-CimWorkload.ps1 -DurationSeconds 60 -ForceGcEvery 30
~~~

Protected information may need administrator access. Tools do not request elevation or suppress denied reads. Process commands/logs can contain private local details; nothing is uploaded.
