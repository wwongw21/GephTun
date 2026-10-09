# Recommendations for a later release — NOT implemented in 1.5.0

## Automatic crash recovery (explicitly deferred at the user's request)

A future independent Windows service could own the worker, provide authoritative generation-aware status, reconcile owned routes/DNS/adapter state after a verified crash, and reconnect after Windows and Geph are ready. It should distinguish a dead worker from an unreadable identity, preserve the kill switch during reconciliation, and respect explicit Disconnect. A service supervisor must not interpret an unknown state as permission to unlock.

This release installs **no Windows service**, no new restart-on-crash action, no scheduled auto-connect, and no independent watchdog. Existing in-process network retry and inherited session-scoped boot cleanup are retained. RecoveryRequired may still need manual Recover. WFP's independent filter lifetime is not automatic crash recovery.

Before implementing the recommendation: define authenticated service/UI IPC; protected durable intent and journal schema; a coherent status generation; repeated-safe recovery; service install/uninstall/upgrade; bounded restart behavior; crash during every network operation; cancellation races; reboot and pre-login Geph availability. Qualify these independently of the WFP policy implementation.

## Full pre-connect Geph socket protection

Obtain a complete compatible Geph engine checkout or a documented endpoint/socket hook. Choose the physical route/interface before each upstream socket is connected, update it on network generations, and remove reliance on global host routes where possible. Review TCP and IPv6 byte-order/socket-option details. This is separate from merely suppressing bypass logs.

## Additional qualification and possible callout

Test pre-existing connections, all claimed adapters, BFE transitions, sleep/resume, IPv6, DHCP and real Geph bootstrap under blocking. Host-forwarding filters do not qualify WSL/Hyper-V/vSwitch/guest traffic. Add a callout driver only if a measured policy/flow requirement cannot be handled safely by built-in WFP layers, with proper signing and Windows testing. Do not broaden exceptions to make an unexplained test failure disappear.
