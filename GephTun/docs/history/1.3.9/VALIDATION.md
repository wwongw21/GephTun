# Validation — GephTun 1.3.9

**685 passed, zero failed, 11 skipped; 696 named checks.** ProductionQualified=false; live Windows acceptance is not run.

| Suite | Passed | Failed | Skipped |
| --- | ---: | ---: | ---: |
| Controller | 293 | 0 | 3 |
| Network | 70 | 0 | 3 |
| UI | 80 | 0 | 0 |
| Source | 35 | 0 | 0 |
| Package | 122 | 0 | 4 |
| Acceptance | 65 | 0 | 1 |
| Diagnostics | 20 | 0 | 0 |

The initial complete isolated run was followed by controller/parser reruns after scoping task operations to the exact root task location. All retained reports bind unchanged final source hashes. No old controller report was rebound onto changed boot code.

Controller checks include 26 direct boot recovery regressions and normal-disconnect failure cases. Diagnostics include 20 isolated checks. Native application UI, live tunnel, trust changes, sleep and reboot are excluded.

## Explicit skipped cases

- **Controller — Protected storage classifies redirected-file permissions before trusting state or messages**: BLOCKED_BY_HOST: Windows denied symbolic-link fixture creation because the required privilege is absent. Rerun this case from the approved elevated test host; its redirection protection is NOT_RUN here.
- **Controller — Protected storage classifies redirected-directory permissions before trusting state or messages**: BLOCKED_BY_HOST: Windows denied symbolic-link fixture creation because the required privilege is absent. Rerun this case from the approved elevated test host; its redirection protection is NOT_RUN here.
- **Controller — Protected storage classifies redirected-dangling-file permissions before trusting state or messages**: BLOCKED_BY_HOST: Windows denied symbolic-link fixture creation because the required privilege is absent. Rerun this case from the approved elevated test host; its redirection protection is NOT_RUN here.
- **Network — TLS trusted**: Windows validates TLS against its certificate stores and does not honor the test-process SSL_CERT_FILE/SSL_CERT_DIR mock CA; no machine trust store is changed.
- **Network — TLS untrusted**: Windows validates TLS against its certificate stores and does not honor the test-process SSL_CERT_FILE/SSL_CERT_DIR mock CA; no machine trust store is changed.
- **Network — TLS wrong_hostname**: Windows validates TLS against its certificate stores and does not honor the test-process SSL_CERT_FILE/SSL_CERT_DIR mock CA; no machine trust store is changed.
- **Package — Build rejects a redirected output ancestor into the source**: Administrator privilege required for this operation.
- **Package — Package verifier rejects redirected source ancestors**: Administrator privilege required for this operation.
- **Package — Verifier rejects redirected package entries**: Administrator privilege required for this operation.
- **Package — Source validator rejects redirected result ancestors**: Administrator privilege required for this operation.
- **Acceptance — A missing release and failed providers still produce a saved failure snapshot**: This specific negative fixture depends on Linux having no Windows providers; all other tests remain portable.

## Evidence and builds

Final validation summary: C:\Users\William\Documents\GephTun-Archives\2026-10-04-reconciliation-204758-706e06ad\final-validation-summary.json

Initial raw run/logs: C:\Users\William\Documents\GephTun-Archives\2026-10-04-reconciliation-204758-706e06ad\validation\isolated-20261004T211737926Z-e0798b8b

Final controller/parser reruns: C:\Users\William\Documents\GephTun-Archives\2026-10-04-reconciliation-204758-706e06ad\final-regressions

Final source snapshot: C:\Users\William\Documents\GephTun-Archives\2026-10-04-reconciliation-204758-706e06ad\candidate-final

Final engineering/runtime packages: C:\Users\William\Documents\GephTun-Archives\2026-10-04-reconciliation-204758-706e06ad\final-builds

Package builders verify staged and extracted archives. These integrity checks do not certify live Windows behavior. Receipts remain local; no push or upload is performed.
