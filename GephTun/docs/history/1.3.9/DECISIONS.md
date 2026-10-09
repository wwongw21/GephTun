# Current decisions — GephTun 1.3.9

| Area | Decision and reason |
| --- | --- |
| Main | Desktop is the local main repository. Remove old copies only after archive, validation and dependency gates. |
| History | Full verified archive outside the project; concise history and index inside it. |
| Ownership | Share the session mutex. Unknown ownership preserves recovery instead of guessing a live session is stale. |
| Worker identity | Require process name, exact start time and executable path; a recycled PID is not the original worker. |
| Recovery | Verify owned cleanup and task absence before deleting the protected guard copy. |
| Evidence | Bind boot code and tests directly into controller receipts; reject stale embedded hashes. |
| Packaging | Exclude only explicit root metadata in checkout mode; keep delivered packages strict. |
| Diagnostics | Parameters, bounded reads and explicit unknown results replace fixed PIDs/paths and suppressed errors. |
| Dependencies | Keep exact tun2socks .3, Wintun, source, patch and licenses. No upgrade or fresh advisory scan is implied. |
| Behavior | Preserve UI entry points, supervision intervals, bounded DNS workers and IPv4 TCP/DNS scope. Recovery restores direct internet. |
| Qualification | Isolated success produces a candidate; live acceptance is separately arranged. |
| Git | Local commits only. Preserve exact bytes and line endings for hashes; no remote or push. |

The complete inherited design and repair discussions remain in the recovery archive.
