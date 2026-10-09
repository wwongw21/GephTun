# GephTun 1.3.9 delivery record

Desktop is the local main repository. The repaired build is a production candidate pending live Windows qualification.

Run-IsolatedValidation.ps1 creates a source-bound snapshot, raw reports/logs with failures and explicit skips, strict integrity results, and optional engineering/runtime ZIPs checked after staging and extraction. Its SUMMARY.json records actual paths, hashes and results.

Outputs live outside the repository. VALIDATION.md records this implementation's validation location. The original folders/package remain in the archive indexed by docs/archive-index.json; cleanup is recorded in docs/RECONCILIATION-REPORT.md.

Candidate source/runtime packages remain ProductionQualified=false. They do not inherit the external historical 1.3.8 production claim.
