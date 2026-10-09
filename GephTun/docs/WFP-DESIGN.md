# WFP implementation and security boundary

## Implementation, not a Windows certification

`GephTun.Wfp.cs` contains real x64 P/Invoke calls to fwpuclnt.dll, iphlpapi.dll and standard Windows security APIs. It is compiled by Add-Type when protection is used. No dummy no-op or firewall-command substitute stands in for WFP. It has not been compiled or executed in the Linux authoring environment. Do not treat source assertions as proof that Windows accepts each layer/condition combination or that every traffic path is covered.

## Ownership and lifetime

Private sublayer: `0c195e67-f506-4f48-b06a-fb056243caaf`; deterministic filter GUIDs derived from SHA-256 of `GephTun.WFP.v1/<rule name>`; schema marker in provider data. The persistent sublayer and filters are providerless. A named provider/service was deliberately not fabricated: FWPM_FILTER0 documents disabled filters when an associated provider lacks a suitable auto-start service, while Object Management phrases some no-service cases differently. Providerless policy avoids relying on that discrepancy. Reboot/BFE acceptance is still mandatory.

Objects are created with SYSTEM/Administrators access. Baseline rules are persistent (flag 1); boot rules use flag 2 separately. All temporary allowances are created on one dynamic engine session (session flag 1). RPC session rundown closes allowances after worker death; no watchdog runs. The blocker lives independently.

The normal controller verifies the full expected private rule set, flags, conditions, types and values. Enumeration includes boot and disabled filters, visits each used layer explicitly and enforces an upper bound. An unexpected namespace, disabled filter, mismatched policy, or unverified object fails closed in the controller: permissions are closed, not silently repaired or unlocked. Readback does not assert the absence of all external filter overrides or verify real packets.

## Layer plan

Runtime: ALE_AUTH_CONNECT_V4/V6 and ALE_AUTH_RECV_ACCEPT_V4/V6 deny fallbacks. IPFORWARD_V4/V6 denies host-forwarded traffic; this does not qualify all VM/vSwitch paths. Loopback permits use the loopback condition flag. Maintenance permits are scoped to svchost DHCP v4 UDP 68/67, DHCPv6 546/547 on local destinations, and ICMPv6 types 133–136/code 0 within link-local/multicast neighbor scopes. These exceptions intentionally permit maintenance traffic. No blanket local subnet, svchost DNS, generic PowerShell, browser, updater or global IPv6 application exception is installed.

Boot: inbound and outbound IPPACKET v4/v6 deny non-loopback traffic until persistent runtime policy takes over. Persistent and boot flags are not combined. Boot-time and runtime transition must be observed on the target OS before an always-on claim.

Live transport: exact approved Geph app IDs plus TCP protocol plus current physical next-hop interface LUID. A separate inbound-triggered reauthorization alternative requires the IS_REAUTHORIZE flag and approved arrival interface because next-hop metadata can be empty for that direction. Geph non-loopback UDP is still refused by the inherited transport contract.

Live tunnel: IPv4 TCP on the current tunnel's local-interface and next-hop LUID. The reauthorization alternative requires its local-interface, reauthorization flag and arrival LUID. No IPv6 tunnel permit, direct DNS or general UDP permit.

Weight ranges: deny 1; tunnel 8; maintenance 10; loopback/Geph 12. These are legal FWP_UINT8 range indexes (0–15), not arbitrary byte priorities. The private sublayer weight is 0x7000. Permits do not set CLEAR_ACTION_RIGHT; security products and system policy can still deny traffic. This candidate does not claim resistance to a privileged hard-permit override, administrator, kernel component or compromised trusted Geph process.

## Image approval and route privacy

Only explicitly reviewed Geph paths are recorded by the UI/CLI, with SHA-256. The controller holds those files open without write/delete sharing and rehashes before creating temporary policy. This is not code signing or a secure-loader guarantee. Protect the installation hierarchy; do not approve untrusted binaries or expose a user-writable trusted path to other users.

Application exceptions are not destination-only. An unrelated app targeting a Geph relay IP remains subject to the deny fallback on a physical path. It may consequently be blocked due to a machine-wide host route, rather than tunneled. Preventing that interference completely requires per-socket/interface integration with Geph, deferred separately.

## Transactions and failure ordering

Enable writes protected user intent, then installs the complete owned baseline inside a WFP transaction and verifies it. Existing incompatible policy is not overwritten. Connect requires baseline verification before opening a dynamic transport lease. The tunnel allowance is added before split-route diversion and verified again before Connected. Policy is checked periodically even in peer grace and after long DNS probes.

Recovery revokes the tunnel permit before removing tunnel routes. A revoke error closes the entire temporary lease; the persistent baseline is not deliberately removed. Successful session cleanup closes the remaining Geph lease. Reconnect establishes a new lease against the new interface snapshot. A failure may interrupt connectivity; it is not permission to unlock.

WFP transactions do not include file, DNS or route operations. Persistent blocking bridges those separately journaled steps. API success and readback are necessary but not sufficient; pre-existing flows, routing transitions, security software, BFE restart and reboot require actual traffic tests.

Normal explicit unlock first completes session recovery and refuses active temporary filters. Standalone emergency unlock bypasses controller state but retains the same explicit-consent and private-namespace rules. It does not sweep other products' policy or force-kill a live controller. Reboot or uninstall without explicit unlock can leave blocking installed; README.md gives the removal path.

## Why there is no automatic crash recovery

The worker still depends on the existing application lifecycle. A dead worker does not restart itself; a reboot does not create a tunnel. Only Windows WFP policy lifetime is independent. A future service must be separately designed and qualified. See RECOMMENDATIONS.md.

## Primary implementation references (retrieved during this update)

- Microsoft, FWPM_FILTER0: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
- Microsoft, WFP Object Management: https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
- Microsoft, WFP Operation: https://learn.microsoft.com/en-us/windows/win32/fwp/basic-operation
- Microsoft, Filter Arbitration: https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration
- Microsoft, ALE reauthorization: https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- Microsoft, available layer conditions: https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer
- Microsoft, filtering condition identifiers: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/filtering-condition-identifiers
- Microsoft, filter enumeration template: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_enum_template0
- Microsoft, transaction commit: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmtransactioncommit0
- Microsoft SDK fwpmu.h, Win32 metadata: https://raw.githubusercontent.com/microsoft/win32metadata/main/generation/WinSDK/RecompiledIdlHeaders/um/fwpmu.h

The native layout assertions and isolated managed policy tests are executable on Windows but were not run during authoring. Their outputs must be retained separately from the bundled static evidence.
