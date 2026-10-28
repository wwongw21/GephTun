# Windows acceptance — GephTun 1.3.9

This candidate is pending live qualification. Isolated checks and file identity do not establish real routing, firewall enforcement, DNS or power-boundary recovery.

Arrange a separate session before changing real networking, sleeping or rebooting. Use an extracted package with its exact ZIP hash recorded. Preserve baseline, source identity, failed attempts, skips and cleanup receipts.

Follow WINDOWS-PRODUCTION-TEST-PLAN.md. Stop on unverified cleanup and retain recovery files; do not broadly clear state to make the machine appear clean.

Collect-WindowsAcceptance.ps1 captures baseline, connected or recovered state from a clean extracted package. It does not connect/disconnect, reboot, certify a scenario or replace independent cleanup verification.
