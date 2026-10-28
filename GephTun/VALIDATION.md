# Application icon derivative

This copy is `application-icons-1`, based on `identity-safeguards-verifier-repair-3`. Icon and package checks are recorded separately beside this folder. The base candidate's preparation and qualification fields remain conservative; those fields do not claim that the full application has been run. The original records below are retained for context.

---

# Validation status: identity-safeguards-verifier-repair-3

This is a separate, unqualified source candidate. Its verifier and normal test runner were revised on 14 October 2026. The identity runtime behavior was not changed by this repair. In addition to nonempty case arrays and exact integer totals, each case must report PASS when Result is present and boolean Passed=true when Passed is present; if both appear, both must pass.

`ProductionQualified` is `false`. The machine-readable package records describe the preparation-time snapshot, when the verifier fixture suite had not run. The subsequent isolated verifier and receipt-fixture run passed all 21 checks; its executed results are recorded in the separate repair evidence report. The focused identity behavior suite, complete regression runner, and native Windows acceptance remain **NOT RUN**. Revision 1's exact-hash record shows that Windows PowerShell blocked the identity suite before any test code ran. That record is retained as history and is not used as current evidence for revision 3.

Two unchanged C# files have an exact-hash compile-only receipt. It reports no native API calls, network connections, or module imports. This does not establish product behavior.

`Verify-GephTun.ps1` now validates the current `GephTun.IdentityCandidate.LocalValidation.v1` record, the exact candidate source hashes, and the external compile-only receipt; stale blocked-test receipt claims are rejected. It rejects mismatched revision IDs, missing required fields or receipts, stale hashes, source changes, and claims that turn blocked or unrun tests into passes. Integrity verification does not certify behavioral or production qualification.

`tests/Run-UpdateValidation.ps1` now enumerates `IdentitySafeguards.Tests.ps1` and `Verify-IdentityCandidate.Tests.ps1`. It inherits the host execution policy and does not request an override. A policy denial therefore produces a failed or missing suite receipt; it cannot produce a pass. The receipt gate is a pure helper that checks both existing case-array shapes (`Tests` and `Results`) against integer aggregate counts and rejects empty, missing, truncated, failed, blocked, skipped, or malformed reports. A present Result=PASS cannot hide Passed=false or a nonboolean Passed value.

The verifier fixture suite uses synthetic receipt objects and disposable package copies. It covers valid legacy and boolean receipt shapes, matching dual fields, contradictory or nonboolean dual fields, missing/empty/truncated case arrays, missing, boolean, fractional, or negative counts, failed cases hidden by passing totals, intact-candidate acceptance, changed and missing source rejection, a missing current-evidence field, stale candidate identity, forged behavioral pass, and missing or changed external receipts. It extracts and calls only the pure receipt helper; it does not invoke the full runner or its child suites. It also checks the runner’s identity-suite entry and lack of an execution-policy override. The isolated suite ran under a user-approved temporary RemoteSigned process setting. It did not run the full regression runner or change permanent execution policy.

No live tunnel, networking, WFP, driver, service, administrator, VM, UI, reboot, download, or install workflow was run. The external receipt files are stored beside the `GephTun` source folder under `evidence/`; the integrity verifier expects that sidecar at `../evidence`.
