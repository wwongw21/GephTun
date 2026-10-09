# GephTun reconciliation completed

Desktop is the canonical local Git repository on **main**. The verified 1.3.8 baseline remains tagged **baseline-1.3.8**. All changes and cleanup are committed locally; no remote or push is used.

## Preserved and integrated

The recovery archive contains **15,745 original files and 1,112 directories**, including hidden files, packages, failed attempts, malformed receipts and diagnostic scripts. Every archived file was read back and checked by size/SHA-256 against the originals. The original inventory and archive checksums are indexed in archive-index.json.

RECONCILIATION.json assigns every original entry an outcome, destination and reason. The external source review compares 49 distinct application-source contents. Newer verified source was preserved rather than overwritten by old releases or experimental fixtures.

The **1.3.9 candidate** repairs uncertain/failed recovery, confirms task absence before deleting its state copy, and scopes task operations to their exact root location. Parameterized diagnostics and useful benchmarks were retained. Exact binary/source/patch/license pins remain unchanged.

## Validation

**696 named isolated checks: 685 passed, zero failed, 11 skipped.** The skipped cases are documented in VALIDATION.md. All receipts bind the final source. Engineering and runtime packages are verified after staging and extraction.

No real tunnel, native application UI, trust-store mutation, sleep or reboot test was performed. **ProductionQualified=false.**

## Cleanup

Immediately before removal, the archive identity and every deletion-input file were rechecked. The runtime gate confirmed no product processes, unreadable PowerShell commands, recovery journal, guard copy, boot task or owned session mutex. All **196 scheduled tasks** were read; none referenced removed folders/files.

The cleanup removed **795 obsolete Desktop files** and the old Documents project containing **14,885 files**. The complete originals remain in the verified archive. Exact paths/hashes and the deletion receipt are linked from RECONCILIATION.json.

The historical status file could not be read; that observation remains recorded separately. It is not an armed recovery dependency. The gate establishes folder-dependency safety, not Windows networking normalcy.

Windows networking state, installed Geph, Downloads and external recordings were not changed.
