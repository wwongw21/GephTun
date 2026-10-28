# GephTun source versions

Main contains the current 1.5.0 Windows test-candidate source in GephTun/.
It combines the former documentation main with the preserved public candidate
history and the reviewed icon/identity-safeguard source updates.

This is an UNQUALIFIED test candidate. ProductionQualified remains false.
The current isolated Windows PowerShell source/regression suites and package
integrity checks pass. Live WFP, tunnel/leak, sleep/reboot and complete desktop
acceptance are not established. Do not enable persistent blocking on a primary
machine; use the documented disposable VM/local-console acceptance procedure.

The former public 1.5.0 package remains separately under
versions/gephtun-1.5.0-base-4521808/GephTun/. Earlier main documentation is retained
under docs/history/. The independent 1.3.12 runtime is preserved separately and
is not replaced by this 1.5.0 test candidate.

From the current GephTun directory, run Verify-GephTun.ps1 -SourceTree and
tests/Run-UpdateValidation.ps1 for read-only integrity/isolated checks.
The external compile-only receipt under evidence/ is required for verification.
No private installation media, model payloads or local application data is
included in this public source update.
