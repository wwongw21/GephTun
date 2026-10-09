#!/usr/bin/env python3
"""GephTun 1.5.0 read-only checks, candidate sealing, ZIP build and verification.
Python 3.10+, standard library. Does not execute PowerShell/C#, binaries or networking.
Static checks are not parser/compiler/runtime tests. Build never grants qualification.
"""
from __future__ import annotations
import argparse
import ast
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import sys
import zipfile

VERSION = '1.5.0'
INPUT_SHA256 = '625f5465acc0f1b061f12d46c51c5e231d0626bb4845fe0af1095aae2412ebb1'
BINARY_PINS = {
    'tun2socks-windows-amd64.exe': '6435bf99650b47551b46ca1a7b5ac44ff64fdbdf1b13d3ccb0b8c329a5734e8e',
    'wintun.dll': 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce',
}
CODE_SUFFIXES = {'.ps1', '.psm1', '.cs', '.py', '.cmd'}

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def valid_path(name: str) -> None:
    if not name or '\\' in name or name.startswith('/') or re.search(r'[<>:"|?*\x00-\x1f\x7f]', name):
        raise ValueError(f'Unsafe relative path: {name!r}')
    for part in name.split('/'):
        if part in ('', '.', '..') or part[-1:] in (' ', '.') or re.match(r'(?i)^(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)', part):
            raise ValueError(f'Unsafe Windows path segment: {part!r}')

def inventory(root: Path) -> dict[str, bytes]:
    if not root.is_dir():
        raise ValueError('Package root is not a directory.')
    for ancestor in (root, *root.parents):
        if ancestor.is_symlink():
            raise ValueError('Redirected package root is not supported.')
    files: dict[str, bytes] = {}
    seen = set()
    for path in sorted(root.rglob('*')):
        name = path.relative_to(root).as_posix()
        valid_path(name)
        if path.is_symlink():
            raise ValueError(f'Redirected member: {name}')
        if name.casefold() in seen:
            raise ValueError(f'Case-colliding member: {name}')
        seen.add(name.casefold())
        if path.is_file():
            files[name] = path.read_bytes()
    return files

def is_source(name: str) -> bool:
    return PurePosixPath(name).suffix.lower() in CODE_SUFFIXES or name in ('RELEASE.json', 'DEPENDENCIES.json')

def sources(files: dict[str, bytes]) -> list[dict]:
    return [{'Path': n, 'Sha256': digest(b)} for n, b in sorted(files.items()) if is_source(n)]

def decode_json(data: bytes):
    return json.loads(data.decode('utf-8-sig'))

def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + '\n', encoding='utf-8')

def function(text: str, name: str) -> str:
    match = re.search(r'(?m)^function ' + re.escape(name) + r'\b', text)
    if not match:
        raise ValueError(f'Function not found: {name}')
    tail = text[match.end():]
    following = re.search(r'(?m)^function ', tail)
    return text[match.start(): match.end() + following.start()] if following else text[match.start():]

def lexical_check(text: str, csharp: bool = False) -> None:
    """Basic quote/comment/delimiter framing ONLY; not a language parser.
    PowerShell quoted interpolation is treated as opaque quoted text.
    """
    i = 0
    stack = []
    pairs = {')': '(', ']': '[', '}': '{'}
    length = len(text)
    while i < length:
        if (csharp and text.startswith('//', i)) or (not csharp and text[i] == '#'):
            end = text.find('\n', i)
            i = length if end < 0 else end + 1
            continue
        opening, closing = ('/*', '*/') if csharp else ('<#', '#>')
        if text.startswith(opening, i):
            end = text.find(closing, i+2)
            if end < 0:
                raise ValueError(f'Unterminated block comment at offset {i}')
            i = end+2
            continue
        # PowerShell here strings terminate at the start of a new line.
        if not csharp and text[i:i+2] in ('@"', "@'") and text[i+2:i+3] in ('\r', '\n'):
            quote = text[i+1]
            match = re.search(r'(?m)^' + re.escape(quote+'@'), text[i+2:])
            if not match:
                raise ValueError(f'Unterminated here string at offset {i}')
            i = i+2+match.end()
            continue
        verbatim = csharp and text.startswith('@"', i)
        if verbatim or text[i] in ('"', "'"):
            if verbatim:
                i += 1
            quote = text[i]
            begin = i
            i += 1
            while i < length:
                if text[i] == quote:
                    if (verbatim or (not csharp and quote == "'")) and text[i:i+2] == quote*2:
                        i += 2
                        continue
                    i += 1
                    break
                escape = '\\' if csharp and not verbatim else '`' if not csharp and quote == '"' else None
                if escape and text[i] == escape:
                    i += 2
                else:
                    i += 1
            else:
                raise ValueError(f'Unterminated quoted literal at offset {begin}')
            continue
        if not csharp and text[i] == '`':
            i += 2
            continue
        char = text[i]
        if char in '([{':
            stack.append((char, i))
        elif char in ')]}':
            if not stack or stack[-1][0] != pairs[char]:
                raise ValueError(f'Unbalanced delimiter {char!r} at offset {i}')
            stack.pop()
        i += 1
    if stack:
        raise ValueError(f'Unclosed delimiter at offset {stack[-1][1]}')

def inspect_dns_input(case: dict) -> None:
    """Validate wire framing only; intentionally invalid SvcParams remain fixtures."""
    data = base64.b64decode(case['WireBase64'], validate=True)
    if len(data) < 12:
        raise ValueError('Short DNS header')
    _, _, qd, an, ns, ar = struct.unpack_from('!6H', data)
    if qd != 1 or ns != 0 or ar != 0 or an < 1:
        raise ValueError('Unexpected fixture record counts')
    def skip_name(offset: int) -> int:
        while offset < len(data):
            size = data[offset]
            if size == 0:
                return offset+1
            if size & 0xc0 == 0xc0:
                if offset+2 > len(data):
                    raise ValueError('Truncated name pointer')
                target = ((size & 0x3f) << 8) | data[offset+1]
                if target >= offset:
                    raise ValueError('Non-backward compression pointer')
                return offset+2
            if size > 63 or offset+1+size > len(data):
                raise ValueError('Invalid label framing')
            offset += 1+size
        raise ValueError('Unterminated name')
    offset = skip_name(12)+4
    for _ in range(an):
        header = skip_name(offset)
        if header+10 > len(data):
            raise ValueError('Truncated RR header')
        typ, _, _, rdlen = struct.unpack_from('!HHIH', data, header)
        end = header+10+rdlen
        if end > len(data):
            raise ValueError('Truncated RDATA')
        if typ in (64, 65):
            current = skip_name(header+12)
            while current < end:
                if current+4 > end:
                    raise ValueError('Truncated SvcParam header')
                _, size = struct.unpack_from('!HH', data, current)
                current += 4+size
                if current > end:
                    raise ValueError('Truncated SvcParam framing')
        elif typ == 1 and rdlen != 4:
            raise ValueError('Invalid A record length')
        offset = end
    if offset != len(data):
        raise ValueError('Trailing or missing fixture bytes')

def static_checks(root: Path) -> dict:
    files = inventory(root)
    tests = []
    def check(name: str, action) -> None:
        try:
            result = action()
            if result is False:
                raise AssertionError('Source invariant not satisfied')
            tests.append({'Name': name, 'Result': 'PASS', 'Detail': ''})
        except Exception as exc:
            tests.append({'Name': name, 'Result': 'FAIL', 'Detail': str(exc)})
    def text(name: str) -> str:
        return files[name].decode('utf-8-sig')
    check('Release identity is this unqualified 1.5.0 candidate', lambda:
          decode_json(files['RELEASE.json'])['Version'] == VERSION and
          decode_json(files['RELEASE.json'])['ProductionQualified'] is False and
          decode_json(files['RELEASE.json'])['InputArchiveSha256'] == INPUT_SHA256)
    for name, data in files.items():
        suffix = PurePosixPath(name).suffix.lower()
        if suffix in ('.ps1', '.psm1', '.cs'):
            check('Lexical framing only: '+name, lambda n=name, c=suffix == '.cs': lexical_check(text(n), c))
            if suffix in ('.ps1', '.psm1'):
                check('Windows PowerShell 5.1-safe text encoding: '+name,
                      lambda b=data: b.startswith(b'\xef\xbb\xbf') or all(v < 128 for v in b))
        elif suffix == '.py':
            check('Python AST parse: '+name, lambda n=name: ast.parse(text(n), filename=n))
        elif suffix == '.json':
            check('JSON parse: '+name, lambda b=data: decode_json(b))
    core, helper, worker, ui, dns, boot = (text(n) for n in (
        'GephTun.Core.psm1','GephTun.Resilience.ps1','GephTun.Worker.ps1','GephTun.UI.ps1','GephTun.Network.cs','GephTun-BootReconcile.ps1'))
    monitor = function(core, 'Watch-GephTunCurrentSession')
    reconnect = function(helper, 'Invoke-GephTunReconnect')
    peer = function(core, 'Get-GephTunPeerRouteSnapshot')
    setup = function(core, 'Start-GephTunSession')
    containment = function(core, 'Install-GephTunContainment')
    names = re.findall(r'(?m)^function ([\w-]+)', core+'\n'+helper)
    checks = {
        'Controller functions have unique names': len(names) == len(set(n.casefold() for n in names)),
        'Controller loads the new resilience helper': ". (Join-Path $PSScriptRoot 'GephTun.Resilience.ps1')" in core,
        'Worker establishes intent before first setup': worker.index('Initialize-GephTunConnectionIntent') < worker.index('$result = Start-GephTunSession'),
        'Worker cleans its intent in finalization': 'Clear-GephTunConnectionIntent' in worker and 'Release-GephTunLock' in worker,
        'Disconnect latches a worker-lifetime token': "'disconnect-intent.json') @{ Token = $intent.Token }" in core,
        'Stop reader does not consume the cancellation marker': 'Remove-Item' not in function(helper,'Test-GephTunIntentStopRequested') and '::Delete' not in function(helper,'Test-GephTunIntentStopRequested'),
        'Active intent preserves operation-cancellation marker': '$null -eq $script:ConnectionIntent -and $cancelPath' in setup,
        'Clean recovery precedes fresh setup': reconnect.index('Restore-GephTunSession') < reconnect.index('Start-GephTunSession -Port'),
        'Residual journal blocks automatic reconnect': 'old session is not fully recovered' in reconnect and "'session.json'" in reconnect,
        'Cancellation is rechecked after old cleanup': reconnect.index('if (Test-GephTunIntentStopRequested) { return $false }', reconnect.index('Restore-GephTunSession')) < reconnect.index('Start-GephTunSession -Port'),
        'Reconnect uses a monotonic 180-second checkpoint budget': '[Diagnostics.Stopwatch]::StartNew()' in reconnect and 'TotalSeconds -lt 180' in reconnect,
        'Reconnect limits three attempts and three cycles per ten minutes': '$attempts -lt 3' in reconnect and 'ReconnectHistory.Count -ge 3' in reconnect and 'TotalSeconds -gt 600' in reconnect,
        'Geph installation path is pinned through reconnect': 'ConnectionIntent.ProxyPath' in reconnect and 'OrdinalIgnoreCase' in reconnect and 'ConnectionIntent.ProxyPath' in setup,
        'Physical network is observed again after blocking Geph probe': reconnect.index('$afterProbe =') > reconnect.index('$proxy = Get-GephTunProxy'),
        'Stable physical network includes address and identity': all(n in function(helper,'Get-GephTunNetworkFingerprint') for n in ('IPAddress','InterfaceIndex','InterfaceGuid','Gateway')),
        'Peer failures retry complete observations at most three times': '$attempt -le 3' in function(helper,'Get-GephTunPeerRoutes') and 'Get-GephTunPeerRouteSnapshot' in function(helper,'Get-GephTunPeerRoutes'),
        'Peer diagnostics log socket and failure context': all(n in function(helper,'Write-GephTunPeerDiagnostic') for n in ('LocalAddress','RemoteAddress','OwningProcess','Detail')),
        'Peer address/adapter reads are not silently ignored': 'Get-NetIPAddress' in peer and '-IncludeHidden -ErrorAction Stop' in peer and 'PEER_SNAPSHOT' in peer,
        'Missing saved physical route requests a fresh session': 'NETWORK_CHANGED' in peer,
        'Grace checks firewall/route/DNS invariants before continuing': all(monitor.index(n) < monitor.index('if ($null -ne $peerFailure)') for n in ('Test-GephTunContainment','Test-GephTunInstalledRoutes','Test-GephTunDnsPolicy')),
        'Peer and DNS grace are both bounded': monitor.count('$outage.Elapsed.TotalSeconds -ge 45') == 2,
        'Grace only declares Connected after a successful probe': monitor.index("Set-GephTunStatus 'Connected'") > monitor.index('if (-not $probeVerified)'),
        'DNS heartbeat logs relay pressure and error timestamp': all(n in monitor for n in ('RejectedRequests','HighWaterRequests','LastErrorUtc','UpstreamFailures')),
        'Fresh sessions do not enable global firewall profiles': 'Set-NetFirewallProfile' not in containment and 'Test-GephTunFirewallBaseline' in containment,
        'Preflight rejects disabled global firewall profiles': 'Test-GephTunFirewallBaseline' in function(core,'Test-GephTunPreflight') and "@('True','NotConfigured')" in helper,
        'Legacy global-profile recovery remains available': 'Set-NetFirewallProfile' in function(core,'Remove-GephTunContainment'),
        'Legacy boot profile residue prevents task deletion': boot.index('A legacy session changed global firewall profiles') < boot.index('try { Unregister-ScheduledTask'),
        'Boot cleanup verifies remaining owned rules before disarming': 'remainingNrpt.Count -ne 0' in boot and 'remainingFirewall.Count -ne 0' in boot and 'tasks.Count -ne 0' in boot,
        'UI gates configuration and exit on live intent': ui.count('[IO.File]::Exists($script:IntentPath)') >= 5 and "'Reconnecting'" in ui,
        'UI displays candidate status and persistent-blocking warning': '(test candidate)' in ui and 'Disconnect and Exit KEEP blocking' in ui,
        'DNS incompatible mandatory IPv6 hints are discarded': 'if (required == Ipv6HintSvcParamKey) return false;' in dns,
        'DNS mandatory references and ordering are validated': all(n in dns for n in ('!keys.Contains(required)','required <= previousMandatory','key <= previousKey','valueLength == 0 || (valueLength & 1) != 0')),
        'DNS relay maximum concurrency is not increased': 'private const int MaximumWorkers = 16;' in dns,
        'Runtime documents unqualified WFP and no automatic crash recovery': 'NOT production-qualified' in text('README.md') and 'Automatic crash recovery is explicitly a future recommendation' in text('README.md'),
        'Current test runner uses fresh processes and external results': '-NoProfile' in text('tests/Run-UpdateValidation.ps1') and 'Assert-GephPackageOutput' in text('tests/Run-UpdateValidation.ps1'),
    }
    wfp, protection, bypass = (text(n) for n in ('GephTun.Wfp.cs','GephTun.Protection.ps1','GephTun.Bypasses.ps1'))
    recovery=function(core,'Restore-GephTunSession')
    native_unlock=wfp[wfp.index('public static void Disable(bool'):wfp.index('public static WfpLease OpenLease')]
    permission_close=function(protection,'Close-GephTunProtectionLease')
    registered_names=re.findall(r'(?m)^function ([\w-]+)',core+'\n'+helper+'\n'+protection+'\n'+bypass)
    checks.update({
        'All four controller source units have unique function names':len(registered_names)==len(set(x.lower() for x in registered_names)),
        'Core loads protection and bypass modules':all(". (Join-Path $PSScriptRoot '"+n+"')" in core for n in ('GephTun.Protection.ps1','GephTun.Bypasses.ps1')),
        'Real native WFP filter API is implemented':all(n in wfp for n in ('FwpmEngineOpen0','FwpmFilterAdd0','FwpmFilterDeleteByKey0','FwpmFilterEnum0','FwpmSubLayerAdd0')),
        'Transactions abort on incomplete commit':'if(!committed) Native.FwpmTransactionAbort0' in wfp,
        'Persistent and boot filter flags are mutually exclusive':'rule.Temporary?0U:rule.Boot?2U:1U' in wfp,
        'Temporary permission session is dynamic':'Flags=dynamic?1U:0U' in wfp and 'engine=new Engine(true)' in wfp,
        'Persistent baseline is installed using a nondynamic engine':'public static void Enable()' in wfp and 'using(var e=new Engine(false))using(var security' in wfp,
        'Providerless private namespace avoids a fabricated startup service':'Provider=IntPtr.Zero' in wfp and 'FwpmProviderAdd0' not in wfp,
        'Private namespace is stable':'0c195e67-f506-4f48-b06a-fb056243caaf' in wfp and 'GephTun.WFP.v1' in wfp,
        'Private policy has explicit administrator ACL':'D:P(A;;GA;;;SY)(A;;GA;;;BA)' in wfp,
        'Readback enumerates boot AND disabled filters':'Flags=0x18' in wfp,
        'Enumeration is bounded and checks schema ownership':'page<128' in wfp and 'Unexpected object in GephTun WFP namespace' in wfp,
        'Policy readback compares condition values':'actual.Signature!=Signature(f)' in wfp and 'terms.Sort(StringComparer.Ordinal)' in wfp,
        'Readback rejects missing indirect condition values':'Missing indirect WFP condition value' in wfp,
        'Filter ABI is guarded before native use':'Marshal.SizeOf(p.Key)!=p.Value' in wfp and 'Native filter field offset mismatch' in wfp,
        'FWP UINT64 union is stored indirectly':'case 4:v.Pointer=a.Struct(p.Number)' in wfp,
        'WFP enum template and dynamic session have explicit SDK layouts':'typeof(EnumTemplate),72' in wfp and 'typeof(SessionData),72' in wfp,
        'WFP provider pointers are not compared after native free':'Signature=Signature(f)' in wfp and 'f.Provider!=IntPtr.Zero' in wfp,
        'Connection layers are covered in both address families':all(x in wfp for x in ('Connect4,Accept4,Connect6,Accept6','base/forward4','base/forward6')),
        'Separate boot packet layers deny rather than permit':'Guid[] boot={OutPacket4,OutPacket6,InPacket4,InPacket6}' in wfp and 'boot[i],false,1,true,false' in wfp,
        'Geph permits are app-and-interface scoped':'Image(images[p]),Num(Protocol,1,6,0),Num(NextHop,4,luid,0)' in wfp,
        'No generic UDP transport permission is created':'public static PolicyRule[] Transport' in wfp and 'Num(Protocol,1,17,0)' not in wfp.split('public static PolicyRule[] Transport',1)[1].split('public static PolicyRule[] Tunnel',1)[0],
        'Tunnel permits require local AND next-hop LUID':'Num(LocalInterface,4,luid,0),Num(NextHop,4,luid,0)' in wfp,
        'Inbound reauthorization alternatives are explicitly gated':'Num(Flags,3,4,6),Num(Arrival,4,luid,0)' in wfp,
        'Runtime IPv6 application tunnel allowance is absent':'Connect6' not in wfp.split('public static PolicyRule[] Tunnel',1)[1].split('// All native structures',1)[0],
        'Narrow maintenance uses both client/server ports':'Num(LocalPort,2,local,0),Num(RemotePort,2,remote,0)' in wfp,
        'No persistent hard-permit override flag':'rule.Temporary?0U:rule.Boot?2U:1U' in wfp and '0x1002U:0x1001U' in wfp,
        'Exact trusted executable files are pinned for permission lifetime':'FileShare.Read' in wfp and 'sha.ComputeHash(stream)' in wfp,
        'Changed executable identities are refused':'Approved Geph executable changed' in wfp,
        'Normal unlock requires explicit consent':'if(!explicitConsent)' in native_unlock,
        'Normal native unlock refuses active temporary permissions':'filters.Any(f=>(f.Filter.Flags&3)==0)' in native_unlock,
        'Only owned filters and private sublayer are removed':'e.CheckObjects(true)' in native_unlock and 'e.Enumerate()' in native_unlock and 'WfpPolicy.Sublayer' in native_unlock,
        'Controller cleanup never disables persistent protection':'WfpController]::Disable' not in recovery and 'Disable-GephTunProtection' not in recovery,
        'Tunnel permission revoked before DNS/route cleanup':recovery.index('Remove-GephTunTunnelPermission')<recovery.index('Remove-GephTunDnsPolicy'),
        'Successful cleanup closes transport lease':'Close-GephTunProtectionLease' in recovery,
        'Permission close never calls persistent unlock':'Dispose()' in permission_close and 'Disable' not in permission_close,
        'Failed tunnel-permit revocation closes all temporary permissions':'Close-GephTunProtectionLease' in function(protection,'Remove-GephTunTunnelPermission'),
        'WFP ownership check runs before peer-grace continuation':monitor.index('Assert-GephTunProtection')<monitor.index('if ($null -ne $peerFailure)'),
        'WFP ownership check runs again after blocking DNS':monitor.count('Assert-GephTunProtection')>=2,
        'Fresh setup opens protection before proxy preflight':setup.index('Open-GephTunProtectionLease')<setup.index('Test-GephTunPreflight'),
        'Remembered bypasses are installed before tunnel authorization':setup.index('Install-GephTunRememberedBypasses')<setup.index('Add-GephTunTunnelPermission'),
        'Reconnect reopens a fresh physical permission lease':'Open-GephTunProtectionLease' in reconnect and 'Close-GephTunProtectionLease' in reconnect,
        'Network changes after a proxy probe retire the old physical lease': 'if ($afterProbe -cne $fingerprint) { Close-GephTunProtectionLease;' in reconnect,
        'An unsuccessful reconnect closes its temporary lease in finally': 'if ($null -eq $script:Session) { Close-GephTunProtectionLease }' in reconnect,
        'Enable is explicitly consent-gated before mutation':function(protection,'Enable-GephTunProtection').index('if (-not $AllowBlocking)')<function(protection,'Enable-GephTunProtection').index('Get-GephTunLock'),
        'Disable is explicitly consent-gated before disconnect':function(protection,'Disable-GephTunProtection').index('if (-not $AllowDirectInternet)')<function(protection,'Disable-GephTunProtection').index('Request-GephTunDisconnect'),
        'Emergency unlock does not depend on ProgramData or Core':'GephTun.Core.psm1' not in text('Emergency-Unlock-GephTun.ps1') and 'WfpController]::Disable' in text('Emergency-Unlock-GephTun.ps1'),
        'Read-only Status worker cannot publish a competing warning':"Set-GephTunStatus" not in worker.split("'Status' {",1)[1].split("'Check' {",1)[0],
        'UI exposes an explicit protection dialog':'Protection...' in ui and 'Open-ProtectionWindow' in ui,
        'Old direct-network reconnect text removed from runtime':'direct internet may be active between sessions' not in (ui+helper).lower(),
        'Cache is bound to approved exact executable identity':'Sha256.ToLowerInvariant()' in bypass and 'Get-GephTunBypassCacheIdentity' in bypass,
        'Cache does not accept future or older-than-24-hour entries':'$age -lt 0 -or $age -gt 24' in bypass,
        'Cache preloading is capped to 128 endpoints':'Select-Object -First 128' in bypass,
        'Cache and live registry are capped to 512':'Select-Object -First 512' in bypass and 'BypassRegistry.Count -ge 512' in bypass,
        'Warmup obtains gateways only from current session snapshot':'Session.OriginalRoutes' in function(bypass,'Install-GephTunRememberedBypasses') and 'Session.OriginalNetwork.InterfaceIndex' in function(bypass,'Install-GephTunRememberedBypasses'),
        'Adapter identity checked before adding bypass':function(bypass,'Confirm-GephTunBypass').index('$expected.Count -eq 0')<function(bypass,'Confirm-GephTunBypass').index('Add-GephTunOwnedRoute'),
        'Changed owned bypass metrics are refused':'An owned Geph bypass was changed' in bypass,
        'No retirement occurs on an empty peer snapshot':function(bypass,'Invoke-GephTunBypassRefresh').index('$peers.Count -eq 0')<function(bypass,'Invoke-GephTunBypassRefresh').index('Remove-GephTunOwnedRoute'),
        'Retirement has a five-minute grace period':'$now-$record.LastSeen -lt 300' in bypass,
        'Borrowed routes are not deleted':'if ($owned.Count -eq 1)' in bypass and 'Never delete a borrowed route' in bypass,
        'Normal bypass logs are aggregated':'$now-$script:BypassLogAt -ge 30' in bypass and 'Geph bypass update:' in bypass,
        'Captured-socket diagnostics are rate-limited':'$now-$record.CapturedAt -ge 15' in bypass and '$now-$record.LastWarning -ge 60' in bypass,
        'Wrapper limitation is explicit in docs':'does not guarantee their complete elimination' in text('README.md'),
        'No new service installation is present':not re.search(r'(?i)New-Service|ServiceBase\s*[:(]|sc\.exe\s+create',core+helper+protection+ui+wfp),
        'Automatic crash recovery explicitly deferred':'NOT implemented in 1.5.0' in text('docs/RECOMMENDATIONS.md') and 'Automatic crash recovery (explicitly deferred' in text('docs/RECOMMENDATIONS.md'),
        'Default runner includes three new isolated suites':all(n in text('tests/Run-UpdateValidation.ps1') for n in ('WfpPolicy.Tests.ps1','Bypasses.Tests.ps1','Protection.Tests.ps1')),
        'Default runner never calls native smoke':'Wfp-NativeSmoke.ps1' not in text('tests/Run-UpdateValidation.ps1'),
        'Native smoke is opt-in and locally confirmed':'AllowNetworkDisruption' in text('tests/Wfp-NativeSmoke.ps1') and 'TEST BLOCKING' in text('tests/Wfp-NativeSmoke.ps1'),
        'Windows/native qualification is explicitly pending':'NativeWindowsAcceptance: NOT_RUN' in text('VALIDATION.md'),
    })
    expected = {'NETWORK_UNAVAILABLE','NETWORK_CHANGED','PEER_SNAPSHOT','PEER_MISSING','PROXY_UNAVAILABLE','DNS_UNAVAILABLE'}
    values = set(re.findall(r"'([A-Z_]+)'", function(helper,'Test-GephTunRetryableFailure')))
    checks['Automatic reconnect uses only the six documented transient codes'] = values == expected
    for name, passed in checks.items():
        check('Source invariant: '+name, lambda value=passed: value)
    fixtures = decode_json(files['tests/dns-mandatory-fixtures.json'])['Tests']
    check('Twenty distinct DNS INPUT fixtures are present', lambda: len(fixtures) == 20 and len({f['Name'] for f in fixtures}) == 20)
    for case in fixtures:
        check('DNS INPUT framing only: '+case['Name'], lambda value=case: inspect_dns_input(value))
    deps = decode_json(files['DEPENDENCIES.json'])
    check('Dependency manifest names exactly the retained two binaries', lambda: {b['File'] for b in deps['Binaries']} == set(BINARY_PINS) and len(deps['Binaries']) == 2 and deps['Version'] == VERSION)
    for name, sha in BINARY_PINS.items():
        data = files['bin/'+name]
        check('Retained dependency bytes: '+name, lambda b=data, h=sha: digest(b) == h)
        def pe_check(b=data):
            offset = struct.unpack_from('<I', b, 0x3c)[0]
            return b[:2] == b'MZ' and b[offset:offset+4] == b'PE\0\0' and struct.unpack_from('<H', b, offset+4)[0] == 0x8664
        check('AMD64 PE header only: '+name, pe_check)
    failed = sum(t['Result'] != 'PASS' for t in tests)
    return {'Kind':'StaticSourceChecks','Version':VERSION,'CapturedUtc':dt.datetime.now(dt.timezone.utc).isoformat(),
            'Scope':'Python AST, lexical framing (NOT PowerShell/C# parse or compile), source assertions, DNS INPUT framing, native SHA/PE checks only.',
            'PowerShellExecution':'NOT_RUN','CSharpCompilation':'NOT_RUN','NativeWindowsAcceptance':'NOT_RUN',
            'Total':len(tests),'Passed':len(tests)-failed,'Failed':failed,'Sources':sources(files),'Tests':tests}

def seal(root: Path) -> dict:
    report = static_checks(root)
    if report['Failed']:
        raise ValueError(json.dumps([t for t in report['Tests'] if t['Result'] != 'PASS'], indent=2))
    write_json(root/'tests/static-results.json', report)
    current = sources(inventory(root))
    static_ref = {'Path':'tests/static-results.json','Sha256':digest((root/'tests/static-results.json').read_bytes())}
    validation = {'Schema':3,'Version':VERSION,'Mode':'STATIC_SOURCE_REVIEW','CapturedUtc':report['CapturedUtc'],
                  'PowerShellExecution':'NOT_RUN','CSharpCompilation':'NOT_RUN','NativeWindowsAcceptance':'NOT_RUN',
                  'ProductionQualified':False,'Sources':current,'Evidence':[static_ref],
                  'StaticChecks':{'Total':report['Total'],'Passed':report['Passed'],'Failed':0},
                  'PreparedSuitesNotExecuted':['Source','WfpPolicy','Bypasses','Protection','Resilience','Controller','DnsMandatory','BootRecovery','Package']}
    write_json(root/'tests/current-validation.json', validation)
    qualification = {'Schema':3,'Version':VERSION,'ProductionQualified':False,'NativeWindowsAcceptance':'NOT_RUN',
                     'PowerShellExecution':'NOT_RUN','CSharpCompilation':'NOT_RUN','CoverageComplete':False,
                     'Reason':'Static-checked test candidate. Execute Windows parser/compiler, isolated regressions and live acceptance before production approval.',
                     'Sources':current,'Evidence':[static_ref,{'Path':'tests/current-validation.json','Sha256':digest((root/'tests/current-validation.json').read_bytes())}]}
    write_json(root/'QUALIFICATION.json', qualification)
    files = inventory(root)
    release = decode_json(files['RELEASE.json'])
    manifest = {k:release[k] for k in ('Package','Version','Status','Date','InputArchiveSha256')}
    manifest['Files'] = [{'Path':n,'Bytes':len(b),'Sha256':digest(b)} for n,b in sorted(files.items()) if n != 'PACKAGE-MANIFEST.json']
    write_json(root/'PACKAGE-MANIFEST.json', manifest)
    return verify_files(inventory(root))

def verify_files(files: dict[str, bytes]) -> dict:
    manifest = decode_json(files['PACKAGE-MANIFEST.json'])
    listed = {}
    for item in manifest['Files']:
        name = item['Path']
        valid_path(name)
        if name == 'PACKAGE-MANIFEST.json' or name.casefold() in listed:
            raise ValueError('Duplicate or invalid manifest member')
        listed[name.casefold()] = name
        if name not in files or len(files[name]) != item['Bytes'] or digest(files[name]) != item['Sha256'].lower():
            raise ValueError(f'Manifest mismatch: {name}')
    if set(listed.values()) | {'PACKAGE-MANIFEST.json'} != set(files):
        raise ValueError('Manifest coverage is not exact')
    release = decode_json(files['RELEASE.json'])
    for key in ('Package','Version','Status','Date','InputArchiveSha256'):
        if manifest[key] != release[key]:
            raise ValueError('Manifest/release metadata differ')
    if release['Version'] != VERSION or release['ProductionQualified'] is not False or release['InputArchiveSha256'] != INPUT_SHA256:
        raise ValueError('Unexpected candidate identity/qualification')
    current = sources(files)
    for name in ('tests/current-validation.json','QUALIFICATION.json'):
        record = decode_json(files[name])
        if record['Version'] != VERSION or record['NativeWindowsAcceptance'] != 'NOT_RUN' or record['ProductionQualified'] is not False:
            raise ValueError('Misrepresented candidate qualification')
        if record['PowerShellExecution'] != 'NOT_RUN' or record['CSharpCompilation'] != 'NOT_RUN':
            raise ValueError('Unperformed execution cannot be claimed')
        if sorted(record['Sources'],key=lambda x:x['Path']) != current:
            raise ValueError(f'Source binding mismatch: {name}')
        for item in record['Evidence']:
            if digest(files[item['Path']]) != item['Sha256']:
                raise ValueError('Evidence hash mismatch')
    static = decode_json(files['tests/static-results.json'])
    if static['Kind'] != 'StaticSourceChecks' or static['Failed'] != 0 or static['Passed'] != static['Total'] or len(static['Tests']) != static['Total'] or static['Total'] < 1 or any(t['Result'] != 'PASS' for t in static['Tests']):
        raise ValueError('Invalid static evidence totals')
    if static['Sources'] != current:
        raise ValueError('Static source evidence has drifted')
    for name, sha in BINARY_PINS.items():
        if digest(files['bin/'+name]) != sha:
            raise ValueError('Retained dependency changed')
    return {'Version':VERSION,'ManifestEntries':len(listed),'TotalFiles':len(files),'StaticChecks':static['Total'],
            'ManifestAndSourceEvidence':'PASS','PowerShellExecution':'NOT_RUN','CSharpCompilation':'NOT_RUN',
            'NativeWindowsAcceptance':'NOT_RUN','ProductionQualified':False}

def read_zip(path: Path) -> dict[str, bytes]:
    files = {}
    seen = set()
    total = 0
    with zipfile.ZipFile(path) as archive:
        for item in archive.infolist():
            if item.is_dir():
                continue
            valid_path(item.filename)
            if not item.filename.startswith('GephTun/') or item.filename.casefold() in seen or stat.S_ISLNK(item.external_attr >> 16):
                raise ValueError('Unsafe/duplicate archive member or unexpected root')
            seen.add(item.filename.casefold())
            total += item.file_size
            if total > 1024**3 or item.file_size > 100*1024**2:
                raise ValueError('Archive exceeds the checker size limits')
            files[item.filename[len('GephTun/'):]] = archive.read(item)
    return files

def build(root: Path, output: Path) -> dict:
    root = root.absolute()
    output = output.absolute()
    if output.exists() or output.is_relative_to(root):
        raise ValueError('Use a new ZIP destination outside the package')
    result = seal(root)
    files = inventory(root)
    stamp = dt.date.fromisoformat(decode_json(files['RELEASE.json'])['Date'])
    output.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(output,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
        for name,data in sorted(files.items()):
            member = zipfile.ZipInfo('GephTun/'+name,(stamp.year,stamp.month,stamp.day,0,0,0))
            member.create_system=3
            member.external_attr=0o100644 << 16
            archive.writestr(member,data,compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
    loaded=read_zip(output)
    if files != loaded:
        raise ValueError('ZIP bytes differ from the source tree')
    result.update(verify_files(loaded))
    result.update({'Archive':output.name,'Bytes':output.stat().st_size,'Sha256':digest(output.read_bytes())})
    return result

def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('static','check','seal','build','verify','verify-zip'))
    parser.add_argument('path',type=Path)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    try:
        if args.action == 'static':
            result=static_checks(args.path)
        elif args.action == 'seal':
            result=seal(args.path)
        elif args.action == 'build':
            if args.output is None:
                raise ValueError('--output is required for build')
            result=build(args.path,args.output)
        else:
            result=verify_files(read_zip(args.path) if args.path.is_file() else inventory(args.path))
        print(json.dumps(result,indent=2))
        return 1 if result.get('Failed',0) else 0
    except (OSError,ValueError,KeyError,TypeError,zipfile.BadZipFile,struct.error) as exc:
        print(f'Check/build failed: {exc}',file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
