# Retained engineering microbenchmarks

Parameterized helpers and the network fixture were retained from the verified Desktop history:

- Measure-BypassQueries.ps1 compares controller query counts with supplied modules and isolated doubles.
- Measure-UiSnapshot.ps1 compares snapshot readers in supplied UI files.
- Measure-NetworkHelper.ps1 uses supplied C# source and performance-fixtures.json, substituting a nonprivileged loopback port.

These are optional measurements, not live acceptance. Keep outputs outside the source and use new paths. Allocation measurements need an allocation-counter runtime such as PowerShell 7; the application still targets Windows PowerShell 5.1.

RECONCILIATION.json records original hashes/paths. Linux-workspace-specific wrappers remain archived; pinned offline rebuilding remains under third_party.
