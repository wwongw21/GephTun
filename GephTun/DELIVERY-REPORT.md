# Delivery report — GephTun 1.5.0 test candidate

Revision optional-kill-switch-1 is based on recovery-fixes-2. The kill switch is optional, with fixed per-connection mode selection across reconnects. Protected connections never downgrade after policy loss. Normal mode retains route, DNS, IPv6 containment and recovery checks; relay caching uses the running image hash. Proxy Check reports the mode and says Connect will recheck tunnel setup. Current isolated Windows PowerShell results are delivered separately; live network and native WFP acceptance remain pending. The retained RUNTIME-CHANGES.patch describes the original 1.5.0 base update; a separate optional-kill-switch.patch accompanies this revision.

The supplied 1.4.0 package was used as the input. This delivery implements WFP policy management, explicit protection/unlock UI and CLI, temporary transport/tunnel authorization, revised connection/recovery integration, a bounded recent-endpoint cache and bypass registry, and current prepared regression suites. It retains the native dependency bytes and licenses.

No automatic crash-recovery service, controller restart watchdog, scheduled auto-connect, Geph engine source patch, custom callout driver or production certification was added. Future recommendations are in docs/RECOMMENDATIONS.md. Current source and manifest verification must not be confused with Windows execution.

The package is intentionally a TEST CANDIDATE. Persistent blocking can interrupt networking beyond app exit/reboot. It requires local-VM acceptance, explicit consent, retained emergency unlock files and a snapshot before use. Read README.md and WINDOWS-ACCEPTANCE.md. Correct policy readback is not proof that every networking path is blocked.
