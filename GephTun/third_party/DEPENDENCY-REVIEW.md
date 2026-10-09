# Current dependency audit — GephTun 1.3.4

The delivered engine is now **tun2socks 2.7.0-gephtun.3**, built from the freshly
verified source in the uploaded .2 package. The current artifact includes the
repairs, tests, complete source, cumulative patch, licenses, current receipts,
and explicitly labeled historical source and evidence. The final source archive
was extracted to a different directory, all 1,699 manifest entries were checked
before and after its clean-cache build, and the rebuilt Windows executable
matched the delivered bytes exactly.

## Confirmed repairs and current relevance

| Decision or repair | Current behavior and evidence |
| --- | --- |
| SOCKS command response validation (.3) | Reject versions other than 5 and nonzero reserved bytes. Four protocol cases and two socket cases failed before the patch; the final suite passes. Invalid localhost peers cannot be mistaken for a successful tunnel connection. |
| Authentication response validation (.3) | Reject methods the client did not offer, and require version 1 for username/password replies. Valid no-auth and user/password tests still pass. These generic-engine checks do not imply GephTun adds or requires user/password authentication. |
| UDP sender and datagram length (.1 retained) | Only the negotiated relay is accepted; decoding uses current bytes and returns actual payload length. Historical regressions reran 250 times on .3, and deterministic mutated datagrams verify current-buffer bounds. |
| Bounded/cancelable SOCKS handshake and constructor bounds (.2 retained) | Current .2 proxy implementation is byte unchanged. Cancellation, fragmented replies, post-success cancellation, failed UDP bindings, and server TCP-control closure passed fresh concurrent resource and race checks. |
| UDP payload accounting (.2 retained) | Writes return caller payload bytes excluding SOCKS framing; underlying errors/short writes retain coverage. This corrects statistics without changing emitted packets. |
| Previous module/toolchain security updates | Go 1.26.8, x/crypto v0.56.0, x/sys v0.47.0 and x/net v0.57.0 remain pinned. No module/vendor/toolchain upgrade was introduced by .3. |
| Source/history delivery | Complete .1 and .2 sources are retained under `history/`; only the verified duplicate top-level .1 archive was removed. `history/INDEX.json` maps the original names to current locations. |

SOCKS reply and method requirements follow
[RFC 1928](https://www.rfc-editor.org/rfc/rfc1928); the username/password reply
version follows [RFC 1929](https://www.rfc-editor.org/rfc/rfc1929). The inherited
test fixture that incorrectly returned version 5 for username/password auth now
returns version 1. An independent source review found no blocking defect in the
narrow .3 change; the earlier .2 socket-lifetime implementation is unchanged.

## Fresh current-source validation

| Test | Passing result |
| --- | --- |
| Complete native suite | 27 top-level tests / 60 entries including subtests / 5 packages |
| Complete suite with race detector, 5 repetitions | 135 top-level passes / 300 entries; no reported races |
| Concurrent lifecycle/resource stress, 20 repetitions | 100 top-level passes / 140 entries |
| Historical UDP/cancellation/accounting regression stress, 250 repetitions | 1,500 top-level passes / 6,000 entries |
| Static Go vet | Passed |
| Uploaded .2 fresh rebuild | Exact match to the uploaded .2 executable |
| Final .3 archive rebuild with fresh cache | All 1,699 source entries verified; native tests and byte-identical Windows cross-build passed |

Twenty lifecycle rounds exercised 2,560 canceled TCP handshakes, 1,280 successful
TCP sessions, 1,280 successful UDP associations with 10,240 datagram round trips,
2,560 rejected UDP bindings, and 40 malformed-reply socket cases. Failed-binding
tests settled at 8 descriptors and 3 goroutines after every round on this Linux
host. Successful TCP tests receive fragmented replies and remain usable after
dial-context cancellation. UDP tests divide closure between the caller and the
server's TCP control connection. A seeded mutation test checks 100,000 datagrams
per complete-suite run. Counts include repetitions and subtests; they are not
distinct Windows user journeys or a production throughput benchmark.

Current receipt paths and exact log hashes are in `tun2socks-validation-1.3.4.json`.
Raw current logs are in the source archive at `verification/gephtun.3/`. Fresh
failed-before cases and the uploaded-source rebuild are retained at
`verification/history/gephtun.2-retested/`; older failures and successes remain
historical and are not added to fresh counts.

## Current dependency provenance and security checks

Official tun2socks source archive SHA-256 remains
`a26310f661eef4b6d58cef0d52b7e479c2adc8c834cd8e99a629068dc7f58924` at commit
`8dda19e8e4613e014f0b12f3e624fdff5e5f23b3`. All 119 upstream files are present;
the five modified upstream files are module locks, the existing proxy repair,
the transport repair, and its corrected test fixture. The cumulative patch
replays from that fresh official source and exactly matches the current changed
files and added regression tests. The official latest-release endpoint still
reports [v2.7.0](https://github.com/xjasonlyu/tun2socks/releases/tag/v2.7.0), and its
public advisory endpoint returned no entries. An empty advisory list does not
override the defects demonstrated locally.

The official [Go 1.26.8 archive metadata](https://go.dev/dl/?mode=json&include=all)
matches the runtime archive, and all 15,036 runtime files were checked against
that archive. Module and toolchain downloads are disabled during builds/tests;
source stress uses localhost peers. Go telemetry was in its local-only mode.
All 23 built nonstdlib modules have their bundled notices included; the MIT and
Go licenses remain present.

The fresh [Go vulnerability database](https://vuln.go.dev/index/modules.json)
screen checked 11 candidate advisory bodies against current versions and all
318 Windows build packages. It found zero affected built-package alerts. The
module-level [OpenPGP warning GO-2026-5932](https://vuln.go.dev/ID/GO-2026-5932.json)
applies to seven packages absent from this build. This is a range/package screen,
not full symbol call-graph analysis, malware scanning, or proof of complete
security.

The current official [Wintun 0.14.1 distribution](https://www.wintun.net/) archive
and its DLL/license match the delivered files. Wintun SHA-256 remains
`e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce`.
No new signed distribution was established by this check. The exact official
[Geph v5.9.0 tag lookup](https://api.github.com/repos/geph-official/gephgui-pkg/releases/tags/v5.9.0)
returned HTTP 404 on 2026-09-17, so the user's installed binary-to-engine mapping
is not established by an assumed release label.

## Final artifact identity and remaining qualification

The final engine SHA-256 is
`6435bf99650b47551b46ca1a7b5ac44ff64fdbdf1b13d3ccb0b8c329a5734e8e`
(12,002,816 bytes). Source archive SHA-256 is
`d7dfb2c51dec52b9aa918551a5b1d8ddd38a9d235745156807d0d380dce5d24c`
(4,328,734 bytes). Cumulative patch SHA-256 is
`798562d415edb41238861e90bcabf50c22bc4552285a6eae6fda39c91cf7a0a2`.
The recipe, complete manifest, current machine-readable validation, and final
source rebuild receipt accompany these files.

No Windows EXE or DLL was executed. The new executable is unsigned. Windows
signature trust/revocation, Wintun loading, elevation, actual routing/DNS/firewall
behavior, installed Geph compatibility, and sustained Windows traffic remain
final production qualification tasks. Localhost UDP source tests do not qualify
general live Geph UDP or a kill switch. The dependency work is ready for that
Windows testing; it is not a claim that Windows production qualification has
already passed.
