# Delivery report — GephTun 1.5.0 test candidate

The supplied 1.4.0 package was used as the input. This delivery implements WFP policy management, explicit protection/unlock UI and CLI, temporary transport/tunnel authorization, revised connection/recovery integration, a bounded recent-endpoint cache and bypass registry, and current prepared regression suites. It retains the native dependency bytes and licenses.

No automatic crash-recovery service, controller restart watchdog, scheduled auto-connect, Geph engine source patch, custom callout driver or production certification was added. Future recommendations are in docs/RECOMMENDATIONS.md. Current source and manifest verification must not be confused with Windows execution.

The package is intentionally a TEST CANDIDATE. Persistent blocking can interrupt networking beyond app exit/reboot. It requires local-VM acceptance, explicit consent, retained emergency unlock files and a snapshot before use. Read README.md and WINDOWS-ACCEPTANCE.md. Correct policy readback is not proof that every networking path is blocked.
