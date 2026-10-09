# GephTun 1.3.9 reconciliation audit

Desktop matched all 859 listed files and the tested historical 1.3.8 extraction. Neither original folder had Git history. The final engineering copy retained a 1.3.7 manifest while its other files matched the 1.3.8 baseline.

The baseline was imported into local main and tagged baseline-1.3.8. Both complete folders were archived and every archived file was read and hashed against the original before changes.

## Recovery repairs

Isolated doubles reproduced failed enumeration being treated as empty, task removal after failed rule cleanup, and guard-script deletion after failed task removal.

The repaired boot script shares the controller session mutex, distinguishes confirmed dead workers from unreadable identity, reads both providers before removal, and rechecks owned policy afterward. Incomplete cleanup preserves the task and script. The installed script remains intact; only the protected state copy self-deletes after task absence is confirmed.

Task registration, removal and verification are scoped to the exact root task location, protecting same-named tasks elsewhere. Normal disconnect now also verifies task absence. Scheduler errors cannot become a clean preflight; permission errors containing “not found” cannot masquerade as confirmed absence. Foreign rules, live-session policy, entry points, supervision intervals and networking scope remain protected.

## Evidence and packaging

Controller receipts bind the boot script and its regression suite. Fresh parser evidence cannot rebind an old controller run onto changed recovery.

Explicit source-tree inventory excludes only root repository/instruction metadata. Extracted delivery checks remain strict, including injected unlisted files. The network driver uses a process-local Windows execution policy; no machine policy or certificate store is changed.

Diagnostic regressions cover unavailable measurements, bounded logs, denied reads, protected outputs and cleanup refusals.

## Limits

VALIDATION.md and tests/current-validation.json record fresh results and skips. Real tunnel, native application UI, sleep and reboot tests are excluded.

Historical receipts remain unchanged, including two malformed JSON files and earlier failures. The evidence index records their limits and supersession claims. The changed 1.3.9 candidate remains ProductionQualified=false.
