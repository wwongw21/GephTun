# GephTun dependency build: tun2socks 2.7.0-gephtun.3

This local build is based on official tun2socks v2.7.0, commit
`8dda19e8e4613e014f0b12f3e624fdff5e5f23b3`. The MIT license is retained in
`LICENSE`. It is distributed with GephTun 1.3.4 and is not an official upstream
release binary.

The .3 repair validates SOCKS command response version 5 and the zero reserved
byte, requires the server to select the authentication method actually offered,
and validates version 1 of the username/password authentication response.
Invalid peers are rejected and their sockets close. These requirements follow
[RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) and
[RFC 1929](https://www.rfc-editor.org/rfc/rfc1929). Four new protocol regression
cases and two real-socket cases failed against the uploaded .2 source before
the repair. The method and username/password checks harden the reusable engine;
they do not add an authentication feature to GephTun's normal loopback flow.

Earlier repairs remain in the current source. The UDP receiver discards packets
from endpoints other than the negotiated relay and decodes only the current
datagram, returning its actual payload length. SOCKS TCP and UDP negotiation
uses the existing five-second budget and responds to context cancellation.
Successful negotiation removes its deadline and cancellation callback, leaving
the established connection usable. Short proxy endpoints return an error
instead of panicking. UDP write counts exclude SOCKS framing, preserve underlying
errors, and report short writes. The .2 proxy implementation is byte unchanged
by this .3 repair, and its regression tests were rerun on this source.

Go 1.26.8, x/crypto v0.56.0, x/sys v0.47.0 and x/net v0.57.0 retain the earlier
security updates. All module versions and vendor source are unchanged from .2.
Required dependency source is in `vendor/`; complete license notices, including
the Go license, are in `THIRD-PARTY-LICENSES.txt`. All 23 built nonstdlib modules
have their bundled notices represented.

## Rebuild

Use Python 3.8 or later and official Go 1.26.8 for your build host. Verify the
toolchain archive against [Go download metadata](https://go.dev/dl/?mode=json&include=all).
The independently checked Linux/AMD64 archive SHA-256 is
`d0f743b33e8d8945e6b1f432edd15785c70507121d6e2a723b21285eddf8b57b`.
Extract the source archive, enter its root directory, and run:

```sh
python build-gephtun.py --go /absolute/path/to/go --test --output ./build/tun2socks-windows-amd64.exe
```

On Windows, pass the local Go executable path, for example `C:\Go\bin\go.exe`.
The builder requires Go 1.26.8, disables module/toolchain downloads, uses vendor
source, and normalizes Go experiment, FIPS, and extra build-flag settings.
`--test` runs the full native Go suite before compiling for Windows AMD64 v1
with cgo disabled. It does not load Wintun or change system routes. Build flags
are `-mod=vendor -trimpath -buildvcs=false` with `-s -w -buildid=` and explicit
version/commit linker strings. The exact flags are in `build-gephtun.py`.

Expected executable SHA-256:

```text
6435bf99650b47551b46ca1a7b5ac44ff64fdbdf1b13d3ccb0b8c329a5734e8e
```

`SOURCE-MANIFEST.json` records every included file except itself. The enclosing
GephTun dependency manifest pins this complete archive and the cumulative
upstream-to-.3 patch. The archive includes source, vendor, tests, notices, the
builder, current validation, and explicit historical records. The final archive
rebuild receipt is stored outside the archive to avoid circular hash claims.

## Current verification

Current raw logs and receipts are under `verification/gephtun.3/`. Baseline
failures and the fresh uploaded-.2 reproduction are under
`verification/history/gephtun.2-retested/`; older evidence retains its history
labels. Absolute paths in receipts identify the actual audit execution context.

| Check on this .3 source | Result |
| --- | --- |
| Full native suite | 27 top-level tests, 60 entries including subtests, 5 packages; pass |
| Complete suite with race detector, 5 repetitions | 135 top-level passes, 300 entries; pass, no reported races |
| Concurrent lifecycle/resource stress, 20 repetitions | 100 top-level passes, 140 entries; pass |
| Historical UDP/cancellation/accounting regressions, 250 repetitions | 1,500 top-level passes, 6,000 entries; pass |
| go vet | pass |
| Native tests plus Windows cross-compile | pass |

The 20-round lifecycle stress performed 2,560 canceled TCP handshakes, 1,280
successful TCP sessions, 1,280 UDP associations with 10,240 datagram round trips,
2,560 failed UDP bindings, and 40 malformed-reply socket cases. Failed-association
resource checks returned to 8 descriptors and 3 goroutines after every round on
the Linux audit host. A deterministic mutation test checks 100,000 datagrams per
full-suite run. These counts include repetitions and are not counts of distinct
product scenarios. Tests use local mock peers, including fragmented replies,
post-handshake cancellation, and TCP-control closure.

Fresh official source and Wintun archive identity checks passed. The public Go
database module/package range screen found no affected Windows build packages
among 318 compiled packages after checking 11 candidate advisory bodies. One
module-level OpenPGP warning affects seven packages absent from this build.
This screen is not full call-graph analysis or proof of absence of vulnerabilities.

The executable is unsigned and was cross-compiled on Linux. No Windows EXE or
DLL was executed. Windows trust/revocation, Wintun loading, actual installed Geph
compatibility, real routing/DNS/firewall behavior, and sustained Windows traffic
remain final Windows qualification tasks. The official exact Geph v5.9.0 tag
lookup returned HTTP 404, so its engine mapping is not established by these
checks. Loopback UDP tests do not qualify arbitrary live Geph UDP support.
