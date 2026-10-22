# GephTun engineering handoff

Review date: **22 October 2026**. All findings remain **OPEN**. This handoff contains proposed repairs and release checks; no source fixes or new runtime acceptance are claimed.

**Reviewed source:** [`main` at `98c01ed2a3af3e571a77abb115db1ef664700bd7`](https://github.com/wwongw21/GephTun/tree/98c01ed2a3af3e571a77abb115db1ef664700bd7).

The full structured handoff is in [report.json](report.json). Historical commands retain their original review-workspace paths; read the prerequisites before running them. Only repository-specific diagnostics listed below are attached.

## Audience and required outcome

### Audience

1. Windows networking maintainer

2. WFP/security reviewer

3. Release qualification engineer

4. Maintainer handing the candidate to a local VM operator

### Outcome

Preserve the exact candidate and distinguish existing static/isolated evidence from native Windows qualification. No new confirmed source defect was found in the reviewed recovery paths. The handoff defines the remaining evidence gates without claiming they ran or authorizing privileged execution.

## Scope and reviewed branches

Default branch contains only a 9-byte README and no runtime. To avoid missing actual work, inspected code-bearing recovery branch and its documented original candidate context.

### Branch

fix/gephtun-1.5.0-recovery

### Sha

9f8ecdfecab4d7cd7a6884c86bd2d56e99c286ed

### Coverage

Core storage/process identity and recovery, WFP policy/lease C#, worker lifecycle, transport approval, bypass routing, standalone boot cleanup, qualification and packaging checks reviewed; source exported read-only under /workspace/review/gephtun-recovery.

### Branch

candidate/gephtun-1.5.0-test

### Sha

452180886b43f1faed849c57af18315052e1d755

### Coverage

Fetched and used as documented original-candidate context; earlier findings addressed on recovery branch were not re-reported as current defects.

## Architecture

### Purpose

Wrap one separately installed Geph local SOCKS proxy with a Windows IPv4 TCP tunnel, constrained relay DNS, journaled network changes and a persistent WFP direct-egress block.

### Components

#### Item 1

##### Paths

1. GephTun/Launch-GephTun.cmd

2. GephTun/Launch-GephTun.ps1

3. GephTun/GephTun.UI.ps1

##### Responsibility

Launch and show the operator interface; expose connect, disconnect/recover and explicit protection controls.

#### Item 2

##### Paths

1. GephTun/GephTun.WorkerHost.ps1

2. GephTun/GephTun.Worker.ps1

3. GephTun/GephTun.Resilience.ps1

##### Responsibility

Run a dedicated connection controller, own the session mutex/intent, supervise failures, apply bounded reconnect/recovery, publish status and close temporary permissions on exit. No installed restart service is claimed.

#### Item 3

##### Paths

1. GephTun/GephTun.Core.psm1

##### Responsibility

Protect ProgramData state, validate process identity and paths, atomically write/read journals, apply and retire owned route/DNS changes, and coordinate recovery without deleting foreign state.

#### Item 4

##### Paths

1. GephTun/GephTun.Wfp.cs

2. GephTun/GephTun.Protection.ps1

##### Responsibility

Keep persistent/boot blocking independent of the controller process; manage temporary permissions in a dynamic WFP session. Transport permissions name exact reviewed Geph images and physical interfaces; approved files are held open against replacement during a lease.

#### Item 5

##### Paths

1. GephTun/GephTun.Bypasses.ps1

##### Responsibility

Observe, validate and journal physical routes to Geph peers, verify the route Windows actually selects, bound the registry/cache and retire only owned stale routes. Cached endpoints are an optimization, not routing authority.

#### Item 6

##### Paths

1. GephTun/GephTun.Network.cs

##### Responsibility

Implement bounded SOCKS/network probing and local relay DNS with input framing checks. The supported application tunnel is IPv4 TCP; this is not a claim of general IPv6/UDP forwarding.

#### Item 7

##### Paths

1. GephTun/GephTun-BootReconcile.ps1

##### Responsibility

Remove verified stale owned NRPT/firewall leftovers at boot and retire only a verified owned scheduled task. It retains uncertain ownership and does not deliberately remove persistent WFP protection.

#### Item 8

##### Paths

1. GephTun/Emergency-Unlock-GephTun.ps1

2. GephTun/Protection-GephTun.ps1

##### Responsibility

Provide explicit-consent normal unlock and a standalone local emergency WFP unlock; the emergency path does not repair all routes/DNS or erase a session journal.

#### Item 9

##### Paths

1. GephTun/bin

2. GephTun/third_party

3. GephTun/DEPENDENCIES.json

##### Responsibility

Supply pinned tun2socks/Wintun dependencies and provenance material. Hash pins establish the packaged identities, not a current comprehensive vulnerability screen or independent binary reproducibility.

#### Item 10

##### Paths

1. GephTun/tools/release_tool.py

2. GephTun/tests

3. .github/workflows/gephtun-tests.yml

4. .github/scripts/Test-GephTunCandidate.ps1

##### Responsibility

Bind package inventory/source evidence; perform static and isolated regression suites; run separate Windows PowerShell and PowerShell 7 CI without native WFP installation.

### Invariants to preserve

1. Disconnect, tray exit, worker death and reboot do not mean direct-internet unlock.

2. Dynamic permissions disappear with the owning session; the persistent blocker remains.

3. Unknown process, journal, task, route, adapter or filter ownership is not treated as safely absent.

4. Recovery is bounded, reports blockers and preserves uncertain state for an explicit operator retry.

5. A matching route's existence is insufficient: the selected route/interface/gateway must satisfy the session contract.

6. Only explicit reviewed Geph image identities receive physical transport permission; a general PowerShell/browser/DNS bypass is not an acceptable qualification workaround.

7. Manifest integrity is not a publisher signature, a successful API response is not packet-leak evidence, and a green UI is not traffic qualification.

## Prioritized sequence

### Item 1

#### Order

1

#### Status

OPEN

#### Work

Select the exact recovery SHA/archive as the candidate and preserve a receipt bundle. Keep main, original candidate and recovery refs distinct.

#### Depends on

None recorded.

### Item 2

#### Order

2

#### Status

OPEN

#### Work

Provision the documented disposable local-console Windows 11 x64 test target and run the non-mutating default verifier/suites there. Reuse existing unchanged-source static evidence; rerun it only when source/artifact changes warrant a new binding.

#### Depends on

1. 1

### Item 3

#### Order

3

#### Status

OPEN

#### Work

After separately authorized local VM setup and explicit operator consent, execute the standalone native WFP installation/readback/removal smoke gate. Preserve cleanup status.

#### Depends on

1. 2

### Item 4

#### Order

4

#### Status

OPEN

#### Work

Run packet-observed connected/disconnected, existing-flow, peer/network-change, crash, explicit-unlock and reboot/BFE qualification cases.

#### Depends on

1. 3

### Item 5

#### Order

5

#### Status

OPEN

#### Work

Run the documented endpoint-rotation soak and native update/rollback acceptance. Resolve any newly observed failure as a new reviewed candidate with fresh scoped evidence.

#### Depends on

1. 4

### Item 6

#### Order

6

#### Status

OPEN

#### Work

Review all required receipts against the supported compatibility statement, then make an explicit release-channel/qualification decision. No production promotion follows automatically from this handoff.

#### Depends on

1. 5

## Limits and mitigations

### Item 1

#### Limit

No PowerShell executable on the review host

#### Mitigation

Current local evidence is Python-only; separate Windows CI is identified by run/SHA/scope. Do not claim a local PowerShell/C# run.

### Item 2

#### Limit

Native Windows WFP/traffic/reboot acceptance absent

#### Mitigation

Keep ProductionQualified=false until explicit native gates have scoped evidence.

### Item 3

#### Limit

Actual Geph compatibility is not established by an archive name

#### Mitigation

Record and test exact Geph paths/hashes/version in local SOCKS mode; native VPN mode remains off.

### Item 4

#### Limit

No unattended automatic crash recovery

#### Mitigation

Document manual recovery expectations and test fail-closed worker loss; do not add a watchdog/service implicitly as part of qualification.

### Item 5

#### Limit

WSL/VM/vSwitch/raw-driver combinations are excluded by the acceptance document unless separately designed/tested

#### Mitigation

Keep support statements narrow; the disposable test VM is the host environment, not a claim to support all host virtualization traffic paths.

### Item 6

#### Limit

No exhaustive line-by-line proof or current comprehensive dependency-vulnerability scan

#### Mitigation

Preserve pins/provenance and request a separate scoped dependency/security assessment if needed for release.

## Findings and implementation handoff

No new confirmed defect was found within the reviewed paths. The remaining handoff is qualification work; passing static checks does not establish native production readiness.

## Reviewed refs

### Item 1

#### Branch

main

#### Sha

98c01ed2a3af3e571a77abb115db1ef664700bd7

#### Content

Only a 9-byte README; no runtime implementation on the default branch

#### Role

Default-branch inventory

#### Finding

Branch-content fact, not a confirmed source defect

### Item 2

#### Branch

fix/gephtun-1.5.0-recovery

#### Sha

9f8ecdfecab4d7cd7a6884c86bd2d56e99c286ed

#### Content

GephTun 1.5.0 recovery-fixes-2 package, tests, CI and review evidence

#### Role

Primary reviewed implementation

#### Local source snapshot

/workspace/review/gephtun-recovery

### Item 3

#### Branch

candidate/gephtun-1.5.0-test

#### Sha

452180886b43f1faed849c57af18315052e1d755

#### Content

Original candidate

#### Role

Historical context for recovery-branch fixes; earlier findings fixed in recovery were not re-reported as current defects

## Qualification state

### Package version

1.5.0

### Candidate revision

recovery-fixes-2

### Channel

Test candidate

### Production qualified

false

### Native windows acceptance

NOT_RUN

### Coverage complete

false

### Automatic crash recovery

NOT_IMPLEMENTED; no automatic controller restart is expected

### Authoritative files

1. GephTun/RELEASE.json

2. GephTun/QUALIFICATION.json

3. GephTun/VALIDATION.md

4. GephTun/START-HERE.md

5. GephTun/WINDOWS-ACCEPTANCE.md

### Interpretation

Bundled qualification metadata describes authoring/package evidence and remains static-only. Separately observed Windows CI success is isolated regression evidence, not permission to change that package metadata or claim native WFP/leak/reboot qualification.

## Confirmed findings

None recorded.

## Noted items

### Item 1

#### Id

GEPHTUN-NOTE-1

#### Status

OPEN

#### Category

Qualification gap, not a newly discovered code defect

#### Location

GephTun/QUALIFICATION.json:4-8

#### Evidence

ProductionQualified=false, NativeWindowsAcceptance=NOT_RUN, CoverageComplete=false

#### Impact

The candidate cannot yet support a production protection claim.

#### Next step

Complete the native evidence gates below for the exact candidate on the supported Windows target.

### Item 2

#### Id

GEPHTUN-NOTE-2

#### Status

OPEN

#### Category

Repository navigation/release decision

#### Location

main README.md versus recovery branch

#### Evidence

Default branch contains no runtime while the reviewed recovery code is on a nondefault branch.

#### Impact

A maintainer or integrator using only main will not obtain the candidate implementation.

#### Next step

Document the intended candidate ref and artifact explicitly. Consider default-branch or release-channel changes only after review/qualification; none were performed here.

## Already observed evidence

### Item 1

#### Check

Python release_tool check on exported recovery source

#### Command

```
python /workspace/review/gephtun-recovery/GephTun/tools/release_tool.py check /workspace/review/gephtun-recovery/GephTun
```

#### Result

PASS: 126 manifest entries, 127 files, exact manifest/source evidence; package remains unqualified

#### Scope

Inventory/source binding only; no PowerShell runtime, C# compilation or native WFP execution

### Item 2

#### Check

Current Python static checks

#### Command

```
python /workspace/review/gephtun-recovery/GephTun/tools/release_tool.py static /workspace/review/gephtun-recovery/GephTun
```

#### Result

250 passed, 0 failed

#### Receipt

/workspace/review/gephtun-static-current.json

#### Scope

Python AST, lexical/source assertions, DNS input fixtures and native dependency hash/PE checks; not actual PowerShell/C# parsing/compilation or traffic acceptance

### Item 3

#### Check

Separate Windows CI observation supplied by parent reviewer

#### Run url

<https://github.com/wwongw21/GephTun/actions/runs/37973491806>

#### Sha

9f8ecdfecab4d7cd7a6884c86bd2d56e99c286ed

#### Date

2026-10-09

#### Result

Successful connected GitHub Actions run

#### Scope

Workflow uses Windows Server 2022 matrix powershell.exe/pwsh.exe and standard-user isolated validation. Do not interpret run-level success as native Windows 11 WFP/leak/reboot certification or invent uninspected per-suite totals.

### Item 4

#### Check

Review checkout integrity

#### Result

No tracked source edits in GephTun checkout. Extra branches were fetched; recovery source was exported to the review directory.

## Evidence preservation

### Status

OPEN for subsequent qualification runs; current review receipts retained

### Required records

1. Exact repository SHA and branch, plus exact tested archive SHA-256

2. PACKAGE-MANIFEST.json and RELEASE/QUALIFICATION/source-binding records

3. Unique outside-package result directory for every run; do not overwrite a previous receipt

4. Windows build, PowerShell engine/version, administrator/token status and local/remote session context

5. Exact Geph executable paths, versions and SHA-256 values; Geph must be in local SOCKS mode with its native VPN mode off

6. Physical/tunnel interface identities, route selection/LUID generation and WFP state before/during/after each case

7. Timestamped controller/boot/helper logs and packet captures from an independent or externally located observation point

8. FAIL/BLOCKED/NOT_RUN cases and cleanup outcome, including any preserved session/intent journal

9. Foreign route/firewall/task baseline so noninterference can be checked

### Rules

1. Reuse evidence only for the exact unchanged source/artifact and stated host/test scope.

2. Preserve docs/history and original candidate evidence; do not relabel it as current acceptance.

3. Do not reseal or rewrite package qualification merely to make a failing integrity check pass; if source changes, regenerate through supported tooling and bind fresh evidence to the new candidate.

4. Keep emergency files locally available before native work; deleting the package or rebooting is not an unlock mechanism.

5. Retain journals and foreign-state snapshots through recovery and rollback; no blanket firewall reset or unrelated route deletion.

## Qualification gates

### Item 1

#### Gate

1. Target-host non-mutating validation

#### Status

OPEN on supported Windows 11 target

#### Prerequisites

1. Exact pinned GephTun package

2. Windows 11 x64 and 64-bit Windows PowerShell 5.1 for the supported target

3. Fresh processes and writable result space outside the package

4. No source modifications during validation

#### Proposed commands

1. ```
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Verify-GephTun.ps1
   ```

2. ```
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-UpdateValidation.ps1
   ```

#### Command directory

```
Extracted GephTun package directory
```

#### Acceptance

1. Integrity verifier accepts exact current bytes

2. Source parser/current-host C# compiler succeeds

3. Nine isolated suites Source, WfpPolicy, Bypasses, Protection, Resilience, Controller, DnsMandatory, BootRecovery and Package produce complete honest receipts

4. No native WFP filter installation or network mutation occurs in the default suite

5. A parser/compiler failure blocks later deployment rather than being treated as an acceptable skip

#### Limits

Passing default suites exercises managed plans, fixtures and doubles. It does not validate Windows packet filtering, physical routing, leak prevention or reboot behavior.

#### Rollback or abort

Keep failure receipts and unchanged package; stop progression to native gates until the failure is understood.

### Item 2

#### Gate

2. Native WFP smoke

#### Status

OPEN; NOT_RUN

#### Authorization boundary

Proposed operator test only. This handoff does not authorize execution, administrator elevation, persistent blocking, VM changes or host network changes.

#### Prerequisites

1. Disposable Windows 11 x64 VM snapshot

2. Local console and local administrator account; never remote-only/RDP control

3. Complete emergency unlock files retained locally

4. Fresh PowerShell process and no existing GephTun WFP policy

5. Unique external result path

6. Operator reviews WINDOWS-ACCEPTANCE.md and explicitly types TEST BLOCKING

#### Proposed command

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Wfp-NativeSmoke.ps1 -AllowNetworkDisruption -ResultJson "$env:TEMP\GephTun-150-native-smoke.json"
```

#### Change surface

The existing opt-in smoke script installs persistent/boot WFP blocking and attempts owned-policy cleanup in finally. No source repair is proposed here.

#### Invariants

1. Refuse pre-existing policy and an active session mutex owner

2. Install/read back/remove only candidate-owned policy

3. An interrupted process may leave persistent blocking; do not promise automatic unlock

4. A failed remote connection alone is not accepted as proof of packet blocking

#### Acceptance

1. Baseline transaction is readable and matches expected persistent policy with zero temporary permits

2. Direct literal-IP TCP does not succeed under the disconnected baseline

3. Explicit cleanup leaves no owned sublayer/filter and ordinary networking is restored

4. Partial precommit failure leaves no partial policy

5. Foreign policy/session state remains unchanged

#### Regression cases

1. Clean VM

2. Existing GephTun policy refusal

3. Active temporary owner refusal

4. API error before commit

5. Cleanup error with retained diagnostic

6. Interrupted process tested only in controlled follow-on failure qualification

#### Risk

Persistent network blocking can survive process loss or reboot. A smoke pass is not crash/reboot/leak qualification.

#### Rollback or abort

Use the reviewed explicit local unlock/recovery path or restore the disposable VM snapshot; preserve failure evidence and do not continue release promotion.

### Item 3

#### Gate

3. Packet-observed privacy and recovery matrix

#### Status

OPEN; NOT_RUN

#### Prerequisites

1. Gate 1 and native smoke pass for exact tested artifact

2. Separate local VM authorization and packet-capture setup

3. Exact reviewed Geph installation in local SOCKS mode

4. Baseline and foreign-state snapshots

5. Independent packet observation that distinguishes application traffic from allowed maintenance/Geph transport

#### Traffic

1. Ordinary IPv4 TCP

2. IPv6

3. UDP/QUIC

4. Port-53 DNS

5. HTTPS DNS

6. Long-lived flows established before protection and before route changes

7. Allowed narrow DHCP/NDP/Geph TCP traffic identified separately

#### Cases and acceptance

##### Item 1

###### Case

Enable protection with existing direct TCP/UDP flows

###### Acceptance

Existing ordinary direct flows cease, not just newly opened connections.

##### Item 2

###### Case

Protected but disconnected

###### Acceptance

No ordinary direct internet; local control and documented narrow maintenance exceptions remain usable.

##### Item 3

###### Case

Geph bootstrap and real connection

###### Acceptance

Exact approved Geph paths reconnect; a browser or PowerShell using the same relay destination does not inherit physical permission; no broad system DNS fallback.

##### Item 4

###### Case

Current tunnel traffic

###### Acceptance

IPv4 TCP and relay DNS work; IPv6/UDP/LAN behavior matches the stated policy rather than an implied full-IP tunnel.

##### Item 5

###### Case

DNS interruption and peer rotation

###### Acceptance

Retries stay bounded, failure is visible, protection remains, and diagnostics/registries stay bounded.

##### Item 6

###### Case

Wi-Fi/gateway change and Ethernet insertion

###### Acceptance

Old permissions retire; new route, source, adapter GUID and LUID generation are revalidated; no direct fallback.

##### Item 7

###### Case

Existing-flow route change and inbound-triggered reauthorization

###### Acceptance

An old tunnel source with a physical next hop is not permitted; reply authorization remains scoped to the correct interface.

##### Item 8

###### Case

Disconnect and tray Exit

###### Acceptance

Temporary permits disappear while persistent blocking remains; ordinary direct internet stays blocked.

##### Item 9

###### Case

Worker crash

###### Acceptance

Dynamic permits disappear through session rundown, persistent baseline remains, and manual Recover/Connect works. Automatic restart is not expected.

##### Item 10

###### Case

Tunnel or DNS helper death

###### Acceptance

Failure becomes visible without direct fallback or implicit unlock.

##### Item 11

###### Case

Reboot, BFE stop/start and security-software coexistence

###### Acceptance

Boot/runtime policy remains correct with no claimed-protected traffic gap; no auto-connect is expected.

##### Item 12

###### Case

Filter tampering, duplicate lease, interface replacement

###### Acceptance

Uncertainty is reported; temporary permission is closed; the controller does not silently unlock.

##### Item 13

###### Case

Changed Geph binary and stale cache

###### Acceptance

Trust is refused until explicit review; cache cannot grant routing authority.

##### Item 14

###### Case

Normal/emergency explicit unlock

###### Acceptance

User consent is required, only owned policy is removed, no active temporary owner is bypassed, and route recovery remains possible.

#### Failure policy

Any failed required privacy assertion blocks promotion. Do not obtain a pass by granting powershell.exe, all destinations or generic physical DNS egress.

#### Rollback or abort

Retain packet captures and state snapshots, complete owned recovery and explicit unlock when deliberately restoring direct internet, or restore the disposable VM snapshot. Do not erase journals or foreign policy to hide an incomplete cleanup.

### Item 4

#### Gate

4. Soak, update and rollback

#### Status

OPEN; NOT_RUN

#### Acceptance

1. At least 24 hours of endpoint rotation with bounded registry/cache and useful aggregate logs

2. Owned route retirement does not break still-live transport

3. Before an old-version launch, explicitly unlock and verify no orphan policy

4. Update/rollback preserves recovery journals and foreign routes/firewall/task state

5. Newly changed Geph executable hashes require explicit renewed trust

6. Every required supported case has PASS evidence or an explicit unresolved FAIL/BLOCKED that prevents promotion

#### Risk

A stale or mismatched artifact can make existing receipts inapplicable; changing executable hashes while a lease is active is intentionally refused.

#### Rollback or abort

Stop/recover, use explicit unlock with its stated consent, verify restoration, and retain both candidate and prior artifacts plus exact receipts. Emergency WFP unlock does not by itself repair orphan routes/DNS.

## Documented recovery commands for review only

### Item 1

#### Purpose

Normal explicit direct-internet unlock after recovery

#### Command

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Protection-GephTun.ps1 -Action Disable -AllowDirectInternet
```

#### Prerequisites

Local administrator context; deliberate operator choice; complete normal recovery and no retained active session journal

#### Status

NOT_RUN; no execution authorization implied

### Item 2

#### Purpose

Standalone emergency WFP unlock

#### Command

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Emergency-Unlock-GephTun.ps1 -AllowDirectInternet
```

#### Prerequisites

64-bit Windows administrator context; local GephTun.Wfp.cs; deliberate operator choice; no active temporary owner

#### Status

NOT_RUN; removes owned WFP protection only, does not repair all routes/DNS or erase journals

## Evidence files

1. /workspace/review/vpn.json

2. /workspace/review/gephtun-static-current.json

3. /workspace/review/gephtun-recovery/GephTun/WINDOWS-ACCEPTANCE.md

4. /workspace/review/gephtun-recovery/GephTun/QUALIFICATION.json

## Completion boundary

No source fixes are claimed because no new confirmed defect was found. All proposed qualification/release work is OPEN. No privileged tests, host configuration changes, branch changes, issue writes or production publication were performed.

## Delivery and diagnostic files

### Destination repository

wwongw21/GephTun

### Status

All findings remain OPEN; documentation transfer only.

### Portable evidence

This JSON retains the complete repository-specific handoff. Historical /workspace paths are evidence references and prerequisites, not portable hyperlinks. Applicable repository-specific diagnostics are included alongside the report.

### Diagnostics included

1. gephtun-static-current.json

### Not included

Original environments, model weights, user data and complete source snapshots are not included. Clone the pinned source and follow the recorded prerequisites. Bug-demonstration scripts intentionally assert pre-fix behavior; they are not a post-fix passing suite.

- [gephtun-static-current.json](diagnostics/gephtun-static-current.json)

## Remaining review limits

1. PowerShell executable unavailable in this environment; no PowerShell runtime or C# compile result claimed.

2. Windows-only WFP/leak/reboot/crash/NRPT/route/task/physical-network acceptance not run.

3. No new confirmed source defect found within reviewed recovery paths; this does not establish production qualification.

