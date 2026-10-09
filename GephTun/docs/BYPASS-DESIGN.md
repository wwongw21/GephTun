# Bypass changes: real scope and limits

The original wrapper reacts to Geph sockets it can observe. A socket that was already captured by a full-tunnel route cannot be rebound by simply adding a destination route. This release does not modify Geph socket creation or claim every first connection is protected in advance.

## Improvements in GephTun.Bypasses.ps1

- Protected `upstream-cache.json`, schema 1, exact approved Geph path/hash identity, canonical IPs, 24-hour TTL. Invalid, oversized, future, old or mismatched records are ignored as an optimization, never interpreted as routing authority. Gateways are never loaded from cache.
- Before split-route diversion, preload at most 128 remembered destinations using the new session's verified physical-network and route snapshot. Cancellation checks remain active. At most 512 cached/live registry entries.
- Registry key includes prefix, interface and gateway. Validate hardware/up adapter identity and actual ActiveStore route; refuse ambiguous routes, changed owned metrics or a different route generation. Cache reads within a pass avoid redundant adapter queries for every unchanged endpoint.
- Summarize additions/preloads/retirements/captured endpoints at 30-second checkpoints. A captured socket that persists for 15 seconds emits an actionable warning at most once per 60 seconds for that endpoint. Merely hiding duplicates was not the repair; 1.4.0 already deduplicated the old per-prefix message.
- An endpoint not observed for 300 seconds can have its **owned** route removed using the existing ownership-aware deletion routine and journal update. An empty/failed peer snapshot cannot trigger retirement. Borrowed routes are not deleted. The existing accepted TCP-state snapshot and Geph non-loopback UDP restriction remain relevant; long-lived, half-closed and unusual transport cases need Windows soak tests.
- Unknown endpoints retain the validated fallback repair. No route changes are made on a failed adapter identity check. A route conflict requests a clean-session reconnect rather than replacing the old gateway blindly.

Destination routes remain machine-wide. WFP separately prevents an ordinary application from inheriting a Geph transport authorization just because it uses the same remote IP. Such an application may be blocked, not automatically redirected back into the tunnel.

## Deferred work

An authenticated pre-connect endpoint API or Geph socket integration could eliminate the first-observation race. Neither exists in the provided engine source (the relevant source directories are absent from its packaging ZIP). Route/interface event subscriptions, per-flow handling and a custom WFP callout are not silently claimed. No service is installed for route management or crash recovery.
