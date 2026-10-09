# Changelog

## 1.5.0 — WFP and bypass test candidate

Added a native WFP management helper with a persistent private blocking baseline, separate boot-time deny filters, dynamic exact-Geph-image transport and current-tunnel permissions, transactional updates, full condition readback, explicit enable/unlock consent, normal and standalone emergency unlock tools, and policy status in the existing UI. No Windows service or callout driver was added.

Added a protected, image-bound 24-hour endpoint cache and pre-diversion route warmup; a capped, validated per-session bypass registry; five-minute owned-route retirement; periodic aggregate logs and rate-limited captured-socket escalation. New endpoints still use the wrapper fallback; Geph socket creation itself is unchanged.

Disconnect, Exit and reconnect retain WFP blocking. Status requests no longer publish an independent RecoveryRequired warning over live connection setup. New isolated policy-plan, protection-lifecycle and bypass suites; opt-in native smoke; updated evidence, docs and manifests.

Automatic crash recovery is explicitly deferred in docs/RECOMMENDATIONS.md. Existing network-resilience and session boot-cleanup logic are retained. No live Windows validation is claimed. Native dependencies are unchanged.

## Previous versions

The 1.4.0 source/evidence input is preserved by archive hash; selected original receipts/docs are under docs/history/1.4.0. Existing 1.3.9 history is retained. Historical pass counts are not current execution results.
