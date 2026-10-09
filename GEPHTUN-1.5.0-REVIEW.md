GephTun 1.5.0 Windows test candidate review

Reviewed candidate commit `452180886b43f1faed849c57af18315052e1d755` from `candidate/gephtun-1.5.0-test`, on local branch `review/gephtun-tests`. The initially selected `main` branch contains only a README. The application and its release evidence are under `GephTun/`.

Both requested Python commands passed. This Linux host initially had no PowerShell executable. A checksum-verified portable PowerShell 7.4.6 was installed only under `/tmp` for supplemental isolated checks. All nine default suites executed: eight suites passed; BootRecovery passed 26 of 27 cases and failed live-session preservation. Across the nine receipts, 181 checks passed and one failed. Windows execution, Windows/.NET Framework compilation, native WFP behavior, and the new Windows CI account setup remain unvalidated. None of the findings below is presented as a reproduced Windows leak. The candidate remains unqualified; this review does not certify Windows 11 kill-switch or leak-test behavior.

| Outcome | Check | Evidence |
| --- | --- | --- |
| PASS | `release_tool.py check GephTun` | Exit 0; version 1.5.0; 125 manifest entries, 126 files; manifest/source evidence PASS; `ProductionQualified=false`. |
| PASS | `release_tool.py static GephTun` | Exit 0; 243 checks passed, 0 failed. Python AST, lexical framing, source assertions, DNS INPUT framing, and pinned binary SHA/PE checks only. |
| PASS | Repeated Python checks after CI additions | Same results; current receipts are `/tmp/gephtun-review-check.json` and `/tmp/gephtun-review-static.json`. |
| PASS | Workflow YAML structure | Parsed with PyYAML; asserted triggers, read-only token permissions, separate jobs, and two Windows engines. |
| PASS | `actionlint` 1.7.7 | Exit 0; its downloaded archive passed the published SHA-256 check. ShellCheck was disabled; PowerShell scripts are not parsed by this check. |
| PASS | Package preservation | `git diff --exit-code -- GephTun` returned 0. No runtime, test, manifest, dependency, or qualification bytes changed. |
| PASS | New CI helper PowerShell parsing | PowerShell 7.4.6 Linux parser reported zero errors. Windows account/ACL/process orchestration was not executed. |
| PASS | `Verify-GephTun.ps1` on Linux PowerShell 7.4.6 | Read-only integrity verification passed; its reported scope remains static evidence only. |
| PASS | Supplemental Linux PowerShell suites | Source 40/40 (parser and current-host C# compile); WfpPolicy 25/25; Bypasses 13/13; Protection 7/7; Resilience 25/25; Controller 18/18; DnsMandatory 20/20; Package 7/7. These are not Windows outcomes. |
| PASS | Two isolated review reproductions | Actual boot identity function returns ALIVE before a JSON round trip and DEAD afterwards; actual exported session start retains an undisposed mocked lease after injected preflight failure. Counterexamples confirmed; no live networking. |
| FAILED | BootRecovery on Linux PowerShell 7.4.6 | 26/27 passed. `Boot keeps live-session policy and recovery while removing stale foreign-session policy` failed with `A live session lost its guard.` The default runner exited 1, with 8 passing suites and 1 failing suite. |
| FAILED, RESOLVED | Initial portable PowerShell startup | Attempted to create `/home/agent/.cache/powershell` on a read-only filesystem and exited 134. Supported XDG cache/config/data paths under `/tmp` resolved it; subsequent parser/verifier/suite/reproduction commands executed. This setup failure did not alter the package. |
| NOT RUN | Windows `Verify-GephTun.ps1`, `Run-UpdateValidation.ps1`, Windows PowerShell 5.1/PowerShell 7 regression suites | Windows is unavailable locally. The workflow is created locally and has not run on GitHub. Linux receipts are not substituted for these results. |
| NOT RUN, EXCLUDED | Native smoke, live protection enable/disable, emergency unlock, live NRPT conflict fixture, live tunnel/network/leak/crash/reboot tests | No such operation was executed or added to CI. |

The principal source-review findings are:

1. **Medium, reproduced with doubles: boot JSON timestamp conversion breaks live-worker identity on PowerShell 7.4.6.** `GephTun/GephTun-BootReconcile.ps1:61` uses `ConvertFrom-Json` with its default timestamp conversion. `Get-BootWorkerState` at line 27 then casts `StartUtc` to a string before parsing it: a DateTime value becomes a culture-formatted string without the original fractional seconds. Its exact-tick comparison labels the mocked live worker DEAD, and the actual boot-script fixture removes the live policy and recovery guard. A deterministic timestamp `2026-10-09T00:00:00.1234567Z` reproduced ALIVE before JSON conversion and DEAD afterwards. This explains the failed BootRecovery case. Real Windows scheduling, the shared mutex, and the primary Windows PowerShell 5.1 target have not been exercised. Proposed correction: preserve JSON timestamp strings where supported, or use an already-typed DateTime directly without converting it through a lossy string; add round-trip/offset/subsecond identity regressions. Core's JSON reader has a string-preservation branch only for 7.5+, so its 7.4 identity handling also needs review. No product correction was applied; the new PowerShell 7 CI entry must not waive this failure if reproduced there.

2. **Medium, reproduced with a mocked lease: an exported direct session start can retain bootstrap permissions after an early failure.** `GephTun/GephTun.Core.psm1:1406` opens a WFP lease before preflight. A preflight exception occurs before the inner recovery catch, and the outer `finally` at line 1600 does not close that lease. An isolated reproduction of the actual function returned `SessionExists=false`, `LeaseExists=true`, `LeaseClosed=false` after an injected preflight failure, then disposed the mocked lease. A direct caller of exported `Start-GephTunSession` can therefore catch the exception and leave approved Geph TCP physical permissions alive in its process. The ordinary Worker entry point closes the lease in its own `finally`, which mitigates the supported CLI/UI path. Persistent blocking for ordinary applications is still present; this is a permission-lifetime defect, not evidence of a general traffic leak. Proposed correction: track lease ownership and close a newly acquired lease on failed starts with no live session, while preserving leases deliberately owned by an existing session/controller. First add an isolated regression invoking the actual start function with mocked lease acquisition and failing preflight, and assert disposal. No correction was applied.

3. **Medium: bypass verification proves route existence, not that Windows selects it.** `GephTun/GephTun.Bypasses.ps1:94` accepts one route matching prefix, interface and next hop. It ignores competing routes for the same host prefix on other interfaces and their total metrics. A lower-cost competing route can win while the desired route is still reported as verified, stranding Geph traffic or choosing another permitted physical path. This requires Windows route-selection validation; no ordinary-application WFP escape is established. The test double at `GephTun/tests/Bypasses.Tests.ps1:33` treats any existing matching prefix as sufficient, whereas production `Add-GephTunOwnedRoute` at `GephTun/GephTun.Core.psm1:619` checks prefix, interface and next hop together. Its removal double similarly removes all matching prefixes, masking ownership distinctions. Proposed tests: competing same-prefix routes on different interfaces/gateways, interface metric changes, borrowed route changes, and Windows-selected route mismatch. Proposed correction, if reproduced: verify the effective route for each endpoint and refuse a conflicting selection without overwriting foreign routes.

4. **Medium: scheduled-task identity is not checked before boot cleanup; the foreign-task assertion is ineffective.** `GephTun/GephTun-BootReconcile.ps1:156` unregisters `\GephTunBootReconcile` by exact name/path without validating its action or principal. If another task replaces that root task, cleanup removes the replacement. A same-named task in another folder should be protected by the exact path, but the test does not actually model task folders/actions. `ForeignTaskExists` is initialized true at `GephTun/tests/BootRecovery.Tests.ps1:25`, never changed by either scheduled-task double, and asserted at line 142. `SameNameForeignTask` otherwise behaves like the normal fixture. Proposed correction: model real task identity and deletion in the fixture, test a distinct task folder and a replaced root task, and validate the intended state-script action/principal before deletion. No product or suite changes were applied.

5. **Recovery limitation: incomplete rollback can keep the worker and transport lease alive indefinitely.** `GephTun/GephTun.Core.psm1:1751` retries failed recovery without a terminal budget while holding session ownership. Route metric tampering/provider failures can preserve the journal and engine. The full temporary lease closes only after successful recovery or Worker finalization. Normal explicit disable first waits for recovery; native explicit unlock refuses while temporary filters remain (`GephTun/GephTun.Wfp.cs:400`). Thus an unrecoverable session can block both normal recovery and explicit unlock until its dependency is repaired or the controller exits. This is deliberately conservative blocking, but the operator path is incomplete and can leave the machine offline. Resilience tests substitute `Restore-GephTunSession` and do not exercise this actual retry loop or unlock interaction. Add isolated tests for repeated cleanup failure, retained lease behavior, cancellation, and the eventual safe operator path before changing policy. No unlock or protection operation was executed.

The five priority suites have useful isolated coverage. Their case counts below matched the current Linux PowerShell receipts; only BootRecovery had a failure. These are not Windows passes:

| Suite | Defined cases | Existing coverage | Important gaps |
| --- | ---: | --- | --- |
| `WfpPolicy.Tests.ps1` | 25 | Managed policy plans; x64 Marshal layouts; deny fallbacks; exact-image TCP/physical permissions; tunnel LUID conditions; loopback; DHCP/NDP scope; invalid inputs. | The custom evaluator sorts rules by weight within one modeled policy. It does not model actual WFP arbitration, native marshaling/API installation, existing flow reauthorization, BFE restart, boot/runtime transition, or dynamic-session rundown after a process crash. Only a small set of family/layer combinations has positive exception tests. |
| `Bypasses.Tests.ps1` | 13 | Route reuse, summary throttling, captured-socket warnings, grace retirement, empty snapshots, borrowed routes, owned metric changes, adapter identity, cache image/age/address/cap checks. | Real owned-route add/remove and journaling are mocked away; no persistence/removal failure, route-query failure, adapter-down case, competing route selection, multi-interface gateway, IPv6 scoped endpoint, 128-entry preload boundary, or 512-entry live-registry boundary test. |
| `Protection.Tests.ps1` | 7 | Temporary lease close/revoke/verify lifecycle and confirmation refusal before mutation. Native initialization is blocked by a double. | No `Dispose` failure; no failed initial preflight cleanup; no successful configuration/trust/hash validation path against isolated native doubles; no AddTunnel authorization failure/partial transaction coverage. Calling enable/disable without consent only tests refusal; it does not enable or disable policy. |
| `Resilience.Tests.ps1` | 25 | Typed failures, documented transient classes, cancellation, owner exit, cleanup-before-reconnect, budgets/circuit breaker, changed image path, network recheck, snapshot retries, firewall baseline refusal. | The actual session start/recovery and wait loop are replaced. Assert lease disposal on every hard failure, cancellation, and budget exhaustion; cover malformed/unreadable intents, process identity uncertainty, IP changes with unchanged gateway, and cleanup persistence failure. |
| `BootRecovery.Tests.ps1` | 27 | Temporary filesystem plus OS-command doubles; stale/live/unknown worker handling; provider/removal failures; retained task/script; mutex behavior; repeatable recovery. | Ineffective foreign-task check above; real SYSTEM/AtStartup behavior, task action ownership, journal reparse/access checks, file-deletion failure, schema/version mismatch, and firewall-provider transient retries are not exercised. Boot cleanup covers DNS/containment, not complete tunnel/journal recovery or persistent WFP unlock. |

The default runner also includes Source parser/C# checks, 18 Controller supervisor cases, 20 in-memory DNS fixtures, and 7 temporary package-corruption cases. It runs each of its nine suites in a fresh PowerShell process and checks both exit status and a nonempty, complete passing receipt. Diagnostics and auxiliary harnesses are outside that default runner. `Test-NrptConflict.ps1 -Run` is an opt-in live NRPT mutation fixture and is excluded from CI. No directory-wide test discovery was introduced.

Persistent blocking remaining enabled after Disconnect, Exit, a controller crash or reboot is documented behavior, not an unlock guarantee. The managed WFP plan intends ordinary direct traffic to remain blocked, but a passing static or mocked suite cannot establish that Windows applies it correctly. General UDP/QUIC and ordinary IPv6 application tunneling are intentionally unsupported. DHCP and local IPv6 neighbor maintenance are explicit exceptions. No independent packet-leak result is available.

Destination bypasses are host-wide routes, not per-process routes: an ordinary application connecting to a Geph relay address can be blocked instead of traveling through the tunnel. Previously unseen captured Geph sockets may need Geph to recreate them; adding a route cannot rebind an existing socket. The cache reduces this problem but does not eliminate it. Automatic controller crash recovery/restart is explicitly unimplemented in the existing release metadata. These remain unresolved compatibility/recovery limitations.

CI changes are outside the sealed package:

- `.github/workflows/gephtun-tests.yml` adds independent Linux static/integrity and Windows regression jobs. Windows Server 2022 runs both Windows PowerShell 5.1 and the installed PowerShell 7 engine. Each matrix entry is independent; failures retain receipts/logs and propagate a nonzero exit.
- `.github/scripts/Test-GephTunCandidate.ps1` creates a random temporary standard Windows user, grants source read/execute and temporary evidence write access, and starts a fresh noninteractive process with that account. The child refuses an administrator token before invoking the read-only verifier and the default isolated runner. The account is removed after execution. No product test executes with the runner's administrator token. The orchestration itself has not been exercised on Windows here; a user-logon or ACL failure must fail CI rather than bypass the account barrier.
- Receipts are written under `RUNNER_TEMP`, outside `GephTun/`; artifact upload and `git diff` checks do not reseal the package or update bundled historical/current qualification records. No workflow calls native smoke, launch/connect, protection commands, or emergency unlock.

Exact test and validation commands, from repository root `/workspace/GephTun` unless another directory is stated:

```bash
git fetch origin candidate/gephtun-1.5.0-test
git switch -c review/gephtun-tests FETCH_HEAD
python3 GephTun/tools/release_tool.py check GephTun
python3 GephTun/tools/release_tool.py static GephTun
python3 GephTun/tools/release_tool.py check GephTun > /tmp/gephtun-review-check.json
python3 GephTun/tools/release_tool.py static GephTun > /tmp/gephtun-review-static.json
git diff --check
git diff --exit-code -- GephTun
```

The new workflow's structural validation was:

```python
from pathlib import Path
import yaml
w = yaml.load(Path('.github/workflows/gephtun-tests.yml').read_text(), Loader=yaml.BaseLoader)
assert set(w['jobs']) == {'linux-static', 'windows-tests'}
assert set(w['on']) == {'workflow_dispatch', 'push', 'pull_request'}
assert w['permissions'] == {'contents': 'read'}
assert w['jobs']['windows-tests']['strategy']['matrix']['engine'] == ['powershell.exe', 'pwsh.exe']
assert all('GephTun/**' in w['on'][e]['paths'] for e in ['push', 'pull_request'])
```

Workflow linter installation/validation commands:

```bash
mkdir -p /tmp/gephtun-actionlint
curl --fail --location --silent --show-error https://github.com/rhysd/actionlint/releases/download/v1.7.7/actionlint_1.7.7_checksums.txt -o /tmp/gephtun-actionlint/checksums.txt
curl --fail --location --silent --show-error https://github.com/rhysd/actionlint/releases/download/v1.7.7/actionlint_1.7.7_linux_amd64.tar.gz -o /tmp/gephtun-actionlint/actionlint_1.7.7_linux_amd64.tar.gz
# Working directory: /tmp/gephtun-actionlint
sha256sum --check --ignore-missing checksums.txt
tar -xzf actionlint_1.7.7_linux_amd64.tar.gz actionlint
/tmp/gephtun-actionlint/actionlint -shellcheck= /workspace/GephTun/.github/workflows/gephtun-tests.yml
```

The child Windows CI process will execute these commands (not executed on this Linux host):

```powershell
& (Join-Path $package 'Verify-GephTun.ps1') -PackageDirectory $package
& (Join-Path $package 'tests/Run-UpdateValidation.ps1') -PackageDirectory $package -OutputDirectory (Join-Path $output 'suites')
```

Supplemental portable PowerShell installation used the official release assets with TLS and SHA-256 verification:

```bash
mkdir -p /tmp/gephtun-pwsh
curl --fail --location --silent --show-error https://github.com/PowerShell/PowerShell/releases/download/v7.4.6/hashes.sha256 -o /tmp/gephtun-pwsh/hashes.sha256
curl --fail --location --silent --show-error https://github.com/PowerShell/PowerShell/releases/download/v7.4.6/powershell-7.4.6-linux-x64.tar.gz -o /tmp/gephtun-pwsh/powershell-7.4.6-linux-x64.tar.gz
# Working directory: /tmp/gephtun-pwsh
sha256sum --check --ignore-missing hashes.sha256
tar -xzf powershell-7.4.6-linux-x64.tar.gz
chmod u+x pwsh
```

The initial parser launch without XDG overrides exited 134 before executing its command. These corrected commands ran from `/workspace/GephTun`:

```bash
XDG_CACHE_HOME=/tmp/gephtun-pwsh/cache XDG_CONFIG_HOME=/tmp/gephtun-pwsh/config XDG_DATA_HOME=/tmp/gephtun-pwsh/data /tmp/gephtun-pwsh/pwsh -NoLogo -NoProfile -NonInteractive -Command '$tokens=$null; $errors=$null; [void][System.Management.Automation.Language.Parser]::ParseFile("/workspace/GephTun/.github/scripts/Test-GephTunCandidate.ps1", [ref]$tokens, [ref]$errors); if ($errors.Count) { $errors | Format-List; exit 1 }; Write-Output "CI helper PowerShell parse: PASS"'
XDG_CACHE_HOME=/tmp/gephtun-pwsh/cache XDG_CONFIG_HOME=/tmp/gephtun-pwsh/config XDG_DATA_HOME=/tmp/gephtun-pwsh/data /tmp/gephtun-pwsh/pwsh -NoLogo -NoProfile -NonInteractive -File GephTun/Verify-GephTun.ps1 -PackageDirectory GephTun
XDG_CACHE_HOME=/tmp/gephtun-pwsh/cache XDG_CONFIG_HOME=/tmp/gephtun-pwsh/config XDG_DATA_HOME=/tmp/gephtun-pwsh/data /tmp/gephtun-pwsh/pwsh -NoLogo -NoProfile -NonInteractive -File GephTun/tests/Run-UpdateValidation.ps1 -PackageDirectory GephTun -OutputDirectory /tmp/gephtun-review-linux-pwsh-746
XDG_CACHE_HOME=/tmp/gephtun-pwsh/cache XDG_CONFIG_HOME=/tmp/gephtun-pwsh/config XDG_DATA_HOME=/tmp/gephtun-pwsh/data /tmp/gephtun-pwsh/pwsh -NoLogo -NoProfile -NonInteractive -File /tmp/gephtun-review-repros.ps1
```

The current run's receipts/logs and `summary.json` are under `/tmp/gephtun-review-linux-pwsh-746`. The safe reproducer at `/tmp/gephtun-review-repros.ps1` extracts only the actual boot identity function and imports Core with lease/preflight doubles; it does not invoke the whole boot recovery script against the host or any native WFP/network command. Its successful exit means the two defects were reproduced, not fixed. The runner's failed BootRecovery receipt remains a failure.

The workflow invokes the parent helper with an absolute `GephTun` package path, a fresh `RUNNER_TEMP/gephtun-validation` output path, and each of `powershell.exe` and `pwsh.exe`. GitHub execution, Windows CI orchestration, Windows regression receipts, and Windows 11 native qualification remain pending. The new helper was parsed successfully on Linux PowerShell 7.4.6. Do not interpret the new workflow or this report as successful execution of those checks.
