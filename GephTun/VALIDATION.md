# GephTun 1.5.0 validation status

**ProductionQualified: false. NativeWindowsAcceptance: NOT_RUN. PowerShellExecution: NOT_RUN. CSharpCompilation: NOT_RUN.**

The authoring environment is Linux without a usable PowerShell/.NET toolchain or Windows network stack. No current native filter, tunnel, DNS helper, GUI, service, reboot, crash or leak test was executed here. No automatic crash-recovery service was implemented. This update is a complete source/binary-dependency package, not a validated production VPN.

## Executed evidence

`tests/static-results.json` contains actual Python checks of source assertions, lexical framing (not PowerShell/C# parsing), Python AST, DNS INPUT packet structure (not the C# filter), fixed native dependency hashes/PE headers, and the release identity. `tests/current-validation.json` and QUALIFICATION.json bind the exact current sources and evidence. PACKAGE-MANIFEST.json covers every non-manifest file. The external delivery verification also reopens the ZIP, verifies the complete inventory and performs controlled in-memory corruption rejection.

## Prepared, not executed during authoring

The default Windows runner includes actual source parsing/C# compilation; managed WFP policy/Marshal-layout tests (no native filter installation); bypass and protection lifecycle functions with isolated doubles; existing updated controller and resilience doubles; DNS filter in-memory fixtures; boot script doubles; package corruption tests. They do not count as current passes until run. Their external receipts must not be substituted for live WFP/traffic qualification.

Native WFP smoke is separately consent-gated and destructive. WINDOWS-ACCEPTANCE.md describes the required local-VM install/uninstall, traffic, old-flow, network-change, worker-death, BFE/reboot and long-soak tests. A host that cannot exercise a relevant assertion must report it as NOT_RUN/BLOCKED, not PASS.

Historical 1.4.0/1.3.9 evidence lives under docs/history and does not validate changed sources. A manifest is internal integrity evidence, not a publisher signature. The unchanged tun2socks and Wintun binary pins do not establish binary reproducibility or a current comprehensive vulnerability scan.
