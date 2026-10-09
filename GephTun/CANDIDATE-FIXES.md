# GephTun 1.5.0 recovery fix candidate

This is a new, unqualified test candidate based on original candidate commit
`452180886b43f1faed849c57af18315052e1d755`. It is not the previously sealed
candidate and inherits none of that candidate's passing test claims.

The candidate fixes exact UTC process identity after JSON conversion, failed
session-start temporary permission ownership, bounded recovery, actual Windows
Geph bypass route selection, and scheduled-task action/principal ownership.
Revision recovery-fixes-2 also replaces the PowerShell 7-only ulong alias with
System.UInt64 in runtime permission opening and managed policy tests, preserving
the native unsigned LUID type. A regression checks the runtime cast against the
managed lease signature without calling native WFP.
The development branch is `fix/gephtun-1.5.0-recovery`.

Persistent WFP blocking has a separate lifetime. Failed connection setup,
cancellation, exhausted recovery retries, controller exit, and reboot do not
constitute consent to disable it. Recovery attempts run at most three times,
with one- and two-second backoff. Incomplete cleanup retains the journal and
recovery guard, reports the precise blocker, and closes temporary permissions.
The worker releases its mutex so an explicit Disconnect / Recover can retry.
If Windows will not close a permission lease, that uncertainty is reported;
process exit also ends dynamic WFP sessions. No background service or automatic
controller restart was added.

## Operator recovery

Read `RecoveryRequired` status and the named DNS, route, process, ownership,
boot-guard, or I/O blocker. Preserve `%ProgramData%\GephTun\session.json`, the
connection intent, and the protected state tree. Repair the named dependency
or obtain an administrator's ownership review, then choose **Disconnect /
Recover** again. A live or uncertain worker identity refuses takeover.
**Disable Protection** still requires explicit consent to allow direct internet,
completed session recovery, and no saved session journal. Failure retains
persistent blocking. Emergency unlock remains a separate, explicit mechanism;
it is not part of these tests or automatic recovery.

The task validator requires the root `GephTunBootReconcile` task, exactly one
absolute Windows PowerShell action targeting the protected state script, and
SYSTEM / ServiceAccount / Highest principal. A task registered by an older
candidate with the relative executable `powershell.exe`, unexpected arguments,
or missing metadata is conservatively retained. Recover with that original
candidate before replacing it, or obtain an administrator's explicit ownership
review. Do not automatically normalize, overwrite, or unregister an unverified
task merely to clear recovery.

## Qualification limits

The supported release tool regenerates manifest/source hashes and static-only
qualification metadata. Current isolated regression receipts are collected
separately; the package's static-only receipts do not claim to include them.
Historical evidence files are unchanged. See the repository-level updated
review for current commands, counts, and CI availability.

Windows-only native WFP installation, packet-leak, crash, reboot, physical
network acceptance, and Windows 11 kill-switch certification are **NOT TESTED**.
Default automated tests use OS command doubles and temporary files. They do not
invoke native smoke, enable/disable live protection, mutate live routes/DNS,
register/unregister real scheduled tasks, or invoke emergency unlock.

Real Windows route selection can change immediately after a successful query;
route repairs cannot rebind a socket already captured by the tunnel. Provider
calls have no new hard execution deadline: retries are bounded, but a hung
Windows provider can still delay a single attempt. Persistent blocking remains
installed through these failures. Foreign task replacement by another privileged
actor between validation and removal remains a Task Scheduler API race; the
state tree and controller mutex are not a lock against arbitrary administrators.
