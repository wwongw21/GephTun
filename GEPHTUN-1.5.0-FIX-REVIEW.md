# GephTun 1.5.0 recovery fix candidate review

This review describes implemented changes on `fix/gephtun-1.5.0-recovery`, based
on original candidate commit `452180886b43f1faed849c57af18315052e1d755`.
`GEPHTUN-1.5.0-REVIEW.md` remains the unchanged previous review. The remote
`candidate/gephtun-1.5.0-test` still resolves to the original commit. All 42 files
under `GephTun/docs/history/` were compared byte-for-byte with that commit and
remain unchanged. New candidate revision is `recovery-fixes-2`, version 1.5.0,
`ProductionQualified=false`. No final release or production publication occurred.

## Implemented findings

| Finding | Implemented fix | Regression coverage |
| --- | --- | --- |
| 1. Live worker classified dead after JSON | Standalone boot and Core parse strings with explicit ISO timezone using invariant DateTimeOffset; preserve typed DateTime/DateTimeOffset ticks without string coercion, convert to UTC, reject unspecified timezones. Core normalizes JSON's typed dates to roundtrip strings for other journal/status consumers. Metadata uncertainty remains UNKNOWN; only confirmed death or identity mismatch is DEAD. Stop-owned-process compares normalized ticks. Intent takeover and Disconnect / Recover refuse UNKNOWN and recheck identities under the session mutex. | Boot live JSON fixture now passes; fractional precision, positive offset, PowerShell 7 process name, malformed/no-zone/unknown dates and unreadable path. Core tests UTC, +05:45, -03:30 JSON equivalence, invalid offset/excess precision, unspecified DateTime, access denial, actual death and one-tick PID reuse. |
| 2. Failed direct start leaks permission lease | Actual exported Start-GephTunSession records only the lease it acquired, including partial acquisition that throws. Finally closes it on failure only while it remains that same owner. Success retains permissions. Early failure leaves a preexisting controller lease alone. Existing in-memory session start is refused. Context reset runs even if close throws. Two small DNS/probe wrappers expose isolated boundaries without changing runtime behavior. | Actual Start runs through successful initialization and preflight/cancellation/adapter/late-probe failures; tests verify the intended failure checkpoint, lease retention on success, closure on failure/partial acquisition, retained journal on rollback failure, preowned lease and existing session preservation. Repeated Dispose/close uncertainty is covered. |
| 3. Recovery never stops | Actual Wait-GephTunRecovery makes at most three attempts with 1s/2s backoff. Cancellation ends failed automatic recovery promptly. Retry exhaustion or recovery-control exceptions report RecoveryRequired with the exact blocker, preserve journal/guard, close temporary permissions, and throw so Worker finally releases intent/mutex. A later explicit Disconnect / Recover reacquires the mutex and retries. Disable Protection still requires AllowDirectInternet, successful recovery, and an absent session journal before the separate native removal boundary. | Actual wait loop tests repeated failure, successful third attempt/backoff, cancellation, retained journal, close errors, cancellation-read/backoff exceptions and explicit operator retry. Actual Disable gate is exercised with fake persistent removal for cleanup failure, retained journal and completed recovery. Persistent blocking is never removed by automatic cleanup. |
| 4. Matching route exists but is not selected | Confirm-GephTunBypass asks Windows Find-NetRoute for the route actually chosen for the destination; it requires exactly one chosen host route on the expected physical interface/gateway and a consistent source interface. Missing, competing, ambiguous or failed selection rejects the repair. Adapter GUID, hardware/up state, original physical gateway and owned route metric remain validated. No competing route is deleted or overwritten. Core cleanup retains ownership records when adapter ownership changed but a matching route remains, and confirms removal before retiring records. | Route doubles model competing equal prefixes with route plus interface costs. Tests cover lower/higher total cost, wrong gateway, ambiguity, missing result, failed query, metric/gateway/adapter changes, borrowed route preservation, reuse, retirement and failed retirement. Tests also execute actual Core add/remove helpers against OS doubles, including write-before-add journaling, add failure, uncertain removal, adapter/metric ownership and unrelated routes. |
| 5. Recovery task removed by name only | Both standalone boot and controller validate root path, name, exactly one absolute Windows PowerShell action with the exact protected-script arguments, empty working directory, SYSTEM identity, ServiceAccount logon and Highest run level before unregistering. Registration also refuses to overwrite an unverified existing root task. Missing/unreadable/ambiguous metadata retains task and script. Absence is handled idempotently; removal is verified. | Boot runs with a real task collection double: unregister actually removes matching records. Every fixture proves the same-named other-folder task survives. Foreign root executable/arguments/principal/logon/runlevel, missing action/principal, multiple actions and unreadable metadata must result in zero unregister calls and a retained root task/script. This replaces the ineffective ForeignTaskExists boolean assertion. |

No WFP architecture change, broad exception, service installer, watchdog, or
automatic controller restart was added. WFP C# and emergency-unlock source remain
unchanged. No safety assertion was removed to make the previous BootRecovery
failure pass. The release tool's source-function extractor now stops at
Export-ModuleMember so a last function's static check does not accidentally
include exported function names; seven new safety invariants were added, including a portable unsigned LUID type check.

## Windows CI compatibility correction

Initial Windows CI on commit `769d9739d1832433ae4aa7ec48a27f63cb694921`
ran on Windows Server 2022. PowerShell 7.6.6 passed 9/9 suites, 252 checks.
Windows PowerShell 5.1.20348.5622 passed eight suites (227 checks) but WfpPolicy
failed during initialization: `Unable to find type [ulong]`. It emitted no
receipt, so its 25 policy assertions were NOT RUN, not passing or individually
failed assertions. Both uploaded host receipts say `Administrator=false`.
The run is https://github.com/wwongw21/GephTun/actions/runs/37971913444;
its artifacts/logs are preserved separately in
`review-evidence/windows-ci-initial-769d973/`.

The same PowerShell 7-only alias existed in runtime Open-GephTunProtectionLease.
Replaced scalar/array casts with fully named System.UInt64, retaining the exact
native unsigned 64-bit signature. Added a policy regression that inspects the
runtime cast, rejects newer unsigned aliases, and checks reflection against
OpenLease's managed signature. It does not open a WFP lease. All existing
blocking assertions remain intact. This compatibility correction is additional
to the five implemented findings.

GitHub API access recovered after the user saved environment settings. GitHub
CLI artifact download initially returned Forbidden for redirected blob URLs;
a normal TLS-verified Python download of the same authorized artifact URLs
succeeded after the storage domain was allowed. No new task was necessary, and
no API token or signed download URL is included in committed evidence.

## Final current-host results

Fresh receipts and per-suite logs are committed outside the sealed package in
`review-evidence/gephtun-recovery-fixes-2-linux-pwsh-746/`. The final receipt's source
hashes were checked against the current package. These are new results, not old
candidate receipts copied into qualification. Bundled qualification metadata
remains static-only and honestly says PowerShell/C# execution NOT_RUN; the
separate current-host evidence below records actual Linux execution.

| Result | Check | Counts / scope |
| --- | --- | --- |
| PASS | Python integrity after supported build/reseal | 126 manifest entries, 127 files; exact manifest/source evidence coverage. |
| PASS | Python static | 250 passed, 0 failed. Lexical/source/AST/binary/DNS-input checks, not native acceptance. |
| PASS | Verify-GephTun.ps1 | Read-only integrity/static verification on Linux PowerShell 7.4.6. |
| PASS | Source | 40/40 PowerShell parser/current-host C#5 compiler checks; not Windows .NET Framework compilation. |
| PASS | WfpPolicy | 26/26 managed plan checks; no native WFP installation. |
| PASS | Bypasses | 35/35 actual registry/cache and core route functions with doubles. |
| PASS | Protection | 30/30 actual lease/start/disable-gate/identity functions with doubles. |
| PASS | Resilience | 34/34 isolated controller/recovery checks. |
| PASS | Controller | 18/18 isolated supervisor checks. |
| PASS | DnsMandatory | 20/20 in-memory DNS fixtures. |
| PASS | BootRecovery | 43/43 standalone boot fixtures with temporary files and command doubles. |
| PASS | Package | 7/7 isolated integrity/corruption/output-path cases. |
| PASS | Full default runner | 9/9 suites; 253 passed, 0 failed, 0 skipped; every suite process exited 0. |
| PASS | Candidate ZIP verification | Supported build and verify-zip both exited 0. 10,629,074 bytes; SHA-256 below. |
| PASS | Workflow lint | actionlint 1.7.7, ShellCheck disabled; exit 0. |
| PASS | CI helper parser | Zero PowerShell 7.4.6 Linux parser errors; Windows execution remains unrun. |

Candidate archive:
`/workspace/gephtun-artifacts/GephTun-1.5.0-recovery-fixes-2.zip`

SHA-256:
`f83287fd573b430ae2370b1a1c499a8368c4b9cb11e6dfe2c027184f1ee1828d`

### Development failures, resolved or expected

- First new Protection run: 20/21 passed, successful setup fixture failed with
  `An unexpected adapter name collision occurred.` The adapter double reported
  a tunnel before Start-Process. Corrected the fixture to expose it only after
  the fake process starts; added expected-checkpoint assertions to prevent
  unrelated failures from falsely satisfying negative tests. Final Protection
  is 30/30.
- First expanded static run: 248/249 passed. The extraction of the final recovery
  function also included Export-ModuleMember's Disable-GephTunProtection name.
  Corrected the static extractor's function boundary, preserving the assertion
  that recovery itself never invokes disable. Final static is 249/249.
- Pre-seal integrity check exited 2 with `Manifest mismatch:
  GephTun-BootReconcile.ps1`, as expected after authorized source changes. The
  supported seal/build regenerated fresh hashes and static-only evidence;
  subsequent integrity and ZIP checks pass.
- A preservation check initially looked for a nonexistent local candidate ref.
  The candidate had been fetched via FETCH_HEAD; checking the actual remote ref
  confirmed the unchanged original commit. Historical byte comparisons pass.

- Final observed-process timestamp review tightened the same timezone rule for
  actual StartTime values. A build initially refused the already existing ZIP
  path (`Use a new ZIP destination outside the package`); its subsequent
  unsealed regression run passed 251 cases and failed the Package intact-source
  case, correctly detecting stale hashes (8/9 suites). Built to a fresh `final/`
  destination using supported tooling and reran verification/all suites: final
  252/252, 9/9. Neither old ZIP nor passing receipts were silently reused.

### Could not run / deliberately excluded

Windows execution is unavailable on this Linux host. Actual Windows CI results
and initial failures are recorded separately in this document; Linux receipts
and workflow lint are never substituted for Windows CI. Final results for the
compatibility-corrected revision will be recorded after its new CI run completes.

Windows-only WFP installation, packet-leak, crash, reboot, physical-network
acceptance and Windows 11 kill-switch certification are **NOT TESTED**. Native
smoke, emergency unlock, live protection enable/disable, opt-in NRPT mutation,
real route/DNS/task changes were deliberately excluded. No skipped assertion is
counted as a pass. The automated suites' 0-skipped count does not imply those
separate acceptance categories ran.

## CI review

`.github/workflows/gephtun-tests.yml` has separate Linux integrity/static and
Windows Server 2022 matrix jobs. Windows uses powershell.exe and pwsh.exe in
separate entries, running the committed
`.github/scripts/Test-GephTunCandidate.ps1`. It launches only the read-only
verifier and nine explicit isolated suites as a disposable standard user; the
child refuses administrator rights and records actual engine/platform/token
status in host.json. Fixtures get a writable temporary directory. The elevated
parent only orchestrates a disposable account and ACL grants, not product
protection/networking operations. Exit codes and nonempty complete receipts are
required. Account removal happens in finally; errors remain failures.

Artifacts collect per-suite JSON/text logs, verifier output, host receipt,
launcher stdout/stderr, and setup/child/account-cleanup failure files even after
failures. Linux collects current JSON receipts. Both jobs check that committed
package bytes were not changed by testing. Token permissions are contents:read;
checkout credentials are not persisted; Windows matrix fail-fast is false.
There is no broad test-file discovery or invocation of dangerous opt-in scripts.
Initial Windows CI exercised the launcher/account/ACL logic successfully on both
engines, including the 5.1 suite failure path and artifact retention. New revision
results are reported separately below.

## Remaining risks and operator path

- Bounded retry count is not a hard timeout around a Windows provider call.
  A hung provider can still delay one cleanup attempt. The correct outcome is
  blocked connectivity and retained recovery state, not automatic internet unlock.
- Exiting after incomplete recovery can leave NRPT pointing to a terminated
  relay, retained tunnel routes/processes, and a stale guard. Persistent WFP
  blocking remains. This intentionally requires operator repair rather than
  unbounded permission retention; detailed status identifies the blocker.
- A permission Dispose failure is reported and retains the lease reference for
  retry. Worker finally also closes it; process exit ends native dynamic sessions.
  These are design expectations awaiting native Windows verification.
- On RecoveryRequired, preserve the protected journal/state, repair the precise
  dependency or obtain an administrator's ownership review, then choose explicit
  Disconnect / Recover. Live/unknown identities refuse takeover. Only successful
  recovery and explicit AllowDirectInternet consent permit Disable Protection.
  Emergency unlock is unchanged and never automatic or used in these tests.
- Older legitimate recovery tasks using a relative powershell.exe action are
  conservatively unverified by the new absolute-path validator. Recover with the
  original candidate before upgrading, or obtain explicit administrator review.
  Foreign/missing metadata is never normalized or overwritten to force success.
- Task Scheduler query/validation/removal is not an atomic operation against
  another privileged administrator replacing a task concurrently. The protected
  state directory and session mutex do not prevent arbitrary privileged mutation.
- Find-NetRoute confirms a selection snapshot; physical routing can change
  immediately afterward. Actual Windows route/source records and policy routing
  need acceptance validation. Equal-prefix competing routes are never deleted.
- Destination bypasses remain host-wide. Ordinary applications aimed at a Geph
  relay address may be blocked, while already captured Geph sockets may need
  Geph to reconnect. Adding a host route cannot rebind such a socket.
- Ordinary IPv6/UDP/QUIC tunneling remains unsupported; existing narrow local
  maintenance exceptions and Geph process authorization remain unchanged.
- Boot reconciliation cleans owned stale DNS/containment and verifies its task;
  it is not an automatic complete crash-recovery service. No service was added.
- Linux managed policy tests and compiler checks cannot prove persistent WFP
  filtering, leak prevention, boot/SYSTEM behavior or Windows 11 compatibility.

See `WINDOWS-SANDBOX-RECOVERY-CANDIDATE.md` for exact isolated Windows instructions
and `GephTun/CANDIDATE-FIXES.md` for packaged operator guidance. These acceptance
limitations remain blockers to production qualification, not unresolved versions
of the five implemented findings.

## Exact validation commands

Working directory: `/workspace/GephTun`. Portable PowerShell was installed from
the official 7.4.6 Linux x64 release and verified using its published
hashes.sha256. The setup script was rerun successfully, including checksum and
version checks. XDG paths are necessary because the home cache is read-only.

```bash
python3 GephTun/tools/release_tool.py check GephTun
python3 GephTun/tools/release_tool.py static GephTun
python3 GephTun/tools/release_tool.py seal GephTun > /tmp/gephtun-fix-seal.json
python3 GephTun/tools/release_tool.py build GephTun --output /workspace/gephtun-artifacts/GephTun-1.5.0-recovery-fixes-2.zip > /tmp/gephtun-revision2-build.json
python3 GephTun/tools/release_tool.py verify-zip /workspace/gephtun-artifacts/GephTun-1.5.0-recovery-fixes-2.zip > /tmp/gephtun-revision2-zip.json
python3 GephTun/tools/release_tool.py check GephTun > /tmp/gephtun-revision2-check.json
python3 GephTun/tools/release_tool.py static GephTun > /tmp/gephtun-revision2-static.json
XDG_CACHE_HOME=/tmp/gephtun-pwsh/cache XDG_CONFIG_HOME=/tmp/gephtun-pwsh/config XDG_DATA_HOME=/tmp/gephtun-pwsh/data /tmp/gephtun-pwsh/pwsh -NoLogo -NoProfile -NonInteractive -File GephTun/Verify-GephTun.ps1 -PackageDirectory GephTun > /tmp/gephtun-revision2-verify.txt 2>&1
XDG_CACHE_HOME=/tmp/gephtun-pwsh/cache XDG_CONFIG_HOME=/tmp/gephtun-pwsh/config XDG_DATA_HOME=/tmp/gephtun-pwsh/data /tmp/gephtun-pwsh/pwsh -NoLogo -NoProfile -NonInteractive -File GephTun/tests/Run-UpdateValidation.ps1 -PackageDirectory GephTun -OutputDirectory /tmp/gephtun-revision2-linux-pwsh-746 > /tmp/gephtun-revision2-validation.log 2>&1
/tmp/gephtun-actionlint/actionlint -shellcheck= .github/workflows/gephtun-tests.yml
XDG_CACHE_HOME=/tmp/gephtun-pwsh/cache XDG_CONFIG_HOME=/tmp/gephtun-pwsh/config XDG_DATA_HOME=/tmp/gephtun-pwsh/data /tmp/gephtun-pwsh/pwsh -NoLogo -NoProfile -NonInteractive -Command '$t=$null;$e=$null;[void][System.Management.Automation.Language.Parser]::ParseFile("/workspace/GephTun/.github/scripts/Test-GephTunCandidate.ps1",[ref]$t,[ref]$e);if($e.Count){$e|Format-List;exit 1};"CI helper parse: PASS"'
git diff --check
git ls-remote origin refs/heads/candidate/gephtun-1.5.0-test
gh api repos/wwongw21/GephTun/actions/runs --jq '.total_count'
curl --silent --show-error --head https://api.github.com
```

Targeted suites were also run while implementing the fixes. For each of
Protection, Bypasses, Resilience and BootRecovery, the command form was:

```bash
XDG_CACHE_HOME=/tmp/gephtun-pwsh/cache XDG_CONFIG_HOME=/tmp/gephtun-pwsh/config XDG_DATA_HOME=/tmp/gephtun-pwsh/data /tmp/gephtun-pwsh/pwsh -NoLogo -NoProfile -NonInteractive -File GephTun/tests/Protection.Tests.ps1 -ResultJson /tmp/gephtun-fixed-Protection-3.json > /tmp/gephtun-fixed-Protection-3.log 2>&1
```

The suite name was substituted literally in all three paths; final targeted
Bypasses used `-4` and passed 35/35. The full final run above supersedes these
intermediate receipts and verifies the supported built candidate.
