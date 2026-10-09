# Geph compatibility

Use one separately installed Geph local SOCKS proxy; Geph's native VPN mode must be off. The wrapper discovers current TCP peer processes, refuses non-loopback Geph UDP, and requires explicit approval of exact executable paths/hashes for WFP transport. No claim of compatibility with a particular Geph build follows from a packaging ZIP name.

The supplied gephgui-pkg-5.9.1 archive lacks the main geph5/gephgui-wry source contents. This update does not change Geph socket creation. Recently validated IP routes are warmed before tunnel diversion; unknown endpoints still use the wrapper fallback. The actual Geph bootstrap/DNS/login behavior must be tested under WFP blocking. If bootstrap depends on ordinary system DNS or browser traffic, setup can fail while remaining blocked; use an explicit temporary unlock for login rather than a hidden global exception.

Approved Geph files are held open read-only without write/delete sharing during a worker lease. Stop/recover, explicitly unlock, and review new hashes after updating Geph. Do not approve unrelated executables renamed to look like Geph.
