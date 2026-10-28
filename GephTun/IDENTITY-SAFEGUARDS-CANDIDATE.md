# GephTun 1.5.0-based identity safeguards candidate

Revision identity-safeguards-1, prepared 13 October 2026. This is a separate unqualified engineering candidate, not an update applied to the sealed optional-kill-switch-1 candidate or a live installation.

The intended change is startup prevention: bounded observation of a temporarily missing process executable path, refusal to record an incomplete or changed process identity, and verification of the launched engine's PID/start time/expected executable before journal commit. Preserve the 1.5.0 timestamp normalization, tri-state liveness, process-handle ownership, WFP protection leases, bounded recovery and persistent protection controls.

Do not copy the whole 1.3.10 recovery implementation. Legacy null-journal repair and replacing the orphan matcher are deferred; they need separate source-grounded review. The observed 1.3.9 incident motivates these safeguards but does not prove a native 1.5.0 reproduction or a successful correction in this candidate.

The original 1.5.0 archive and all qualification evidence stay unchanged. Previous metadata is copied under docs/history/optional-kill-switch-1-before-identity-safeguards. Historical local passes are not current candidate evidence. Fresh local receipts and exact source hashes will be recorded separately; tests use synthetic inputs and must not run a tunnel, touch host networking/security, open credentials or modify a live journal.

ProductionQualified=false. No existing VM-test consent applies to changed product bytes merely because the version label is still 1.5.0. New candidate acceptance and deployment require separate exact procedures, source-bound review and applicable authority. No live tests or installation are authorized by this candidate note.

This deliverable is an engineering/source candidate. The `identity-safeguards-verifier-repair-3` derivative extends revision 2's runner receipt gate: when a case includes both `Result` and `Passed`, each must independently report success. It includes synthetic fixtures for the legacy Result-only shape, the boolean Passed shape, matching fields, contradictory fields, and nonboolean Passed values. Identity behavior and verifier fixture tests remain not run. Revision 2 is preserved in full under the repair workspace baseline; revision 1's policy-block receipt remains historical and is not current evidence. No runtime or production qualification is claimed.
