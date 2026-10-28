param([Parameter(Mandatory = $true)][string]$Source)
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ge 6) { Add-Type -Path $Source -CompilerOptions '/langversion:5' -ErrorAction Stop }
else { Add-Type -Path $Source -ErrorAction Stop }
$protocol = [GephTun.ProxyProbe].Assembly.GetType('GephTun.DnsProtocol')
$staticFlags = [System.Reflection.BindingFlags]'Static,NonPublic'
$queryMethod = $protocol.GetMethod('ValidateQuery', $staticFlags)
$responseMethod = $protocol.GetMethod('ValidateResponse', $staticFlags)
$filterMethod = $protocol.GetMethod('RemoveIpv6Records', $staticFlags)
$relay = $null
function Get-RelayTestState {
    param($Value)
    if ($null -eq $Value) { return @{ healthy = $false; workers = 0; sockets = 0; queued = 0; workerThreadsAlive = 0; listenerThreadsAlive = 0 } }
    $flags = [System.Reflection.BindingFlags]'Instance,NonPublic'
    $workerField = $Value.GetType().GetField('activeWorkers', $flags)
    $socketField = $Value.GetType().GetField('activeSockets', $flags)
    $queueField = $Value.GetType().GetField('pendingWork', $flags)
    $threadField = $Value.GetType().GetField('workerThreads', $flags)
    $listenersAlive = 0
    foreach ($name in @('udpThread', 'tcpThread')) {
        $listenerThread = $Value.GetType().GetField($name, $flags).GetValue($Value)
        if ($null -ne $listenerThread -and $listenerThread.IsAlive) { $listenersAlive++ }
    }
    $alive = $null; $queued = $null
    if ($null -ne $threadField) {
        $alive = 0
        foreach ($workerThread in $threadField.GetValue($Value)) {
            if ($null -ne $workerThread -and $workerThread.IsAlive) { $alive++ }
        }
    }
    if ($null -ne $queueField) { $queued = $queueField.GetValue($Value).Count }
    return @{ healthy = $Value.Healthy; error = $Value.LastError; workers = $workerField.GetValue($Value);
        sockets = $socketField.GetValue($Value).Count; queued = $queued; workerThreadsAlive = $alive; listenerThreadsAlive = $listenersAlive }
}
function Test-RelayDispatchLifecycle {
    if (-not ('RelayDispatchFixture' -as [type])) {
        $fixtureSource = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Threading;
public static class RelayDispatchFixture {
    private static Type T;
    private static BindingFlags F = BindingFlags.Instance | BindingFlags.NonPublic;
    private static object Start() { return T.GetMethod("Start").Invoke(null, new object[] { 65534 }); }
    private static object Get(object relay, string name) { return T.GetField(name, F).GetValue(relay); }
    private static object Call(object relay, string name, params object[] args) { return T.GetMethod(name, F).Invoke(relay, args); }
    private static void Check(bool value, string message) { if (!value) throw new Exception(message); }
    private static void Dispose(object relay) { ((IDisposable)relay).Dispose(); }
    private static int Alive(object relay) { int count=0; foreach (Thread thread in (Thread[])Get(relay, "workerThreads")) if (thread != null && thread.IsAlive) ++count; return count; }
    private static int QueueCount(object relay) { object q = Get(relay, "pendingWork"); return (int)q.GetType().GetProperty("Count").GetValue(q, null); }
    private static void Enqueue(object relay, WaitCallback callback, object state) {
        Check((bool)Call(relay, "TryBeginWork"), "Expected an available work reservation.");
        Check((bool)Call(relay, "QueueWork", callback, state), "Expected queued callback.");
    }
    private static void Stopped(object relay) {
        Check(Alive(relay)==0, "Successful disposal left an owned thread alive.");
        foreach(string name in new string[] { "udpThread", "tcpThread" }) {
            Thread listener=(Thread)Get(relay,name);
            Check(listener==null || !listener.IsAlive, "Successful disposal left a listener alive.");
        }
        Check((int)Get(relay, "activeWorkers")==0, "Successful disposal left a reservation.");
        Check(QueueCount(relay)==0, "Successful disposal left queued callbacks.");
        Check(!(bool)T.GetProperty("Healthy").GetValue(relay, null), "Disposed relay remained healthy.");
    }
    public static Dictionary<string,object>[] Run(Type relayType) {
        T=relayType;
        var results = new List<Dictionary<string,object>>();
        object relay=Start();
        var entered=new ManualResetEvent(false);
        var release=new ManualResetEvent(false);
        int queuedRan=0;
        try {
            Check(Alive(relay)==16, "Startup did not own exactly sixteen workers.");
            Enqueue(relay, delegate(object ignored) { entered.Set(); release.WaitOne(); }, null);
            Check(entered.WaitOne(2000), "Active fixture callback did not start.");
            object gate=Get(relay,"gate");
            lock(gate) {
                // Hold the queue gate to arrange an otherwise transient state;
                // this is explicit internal scheduling injection, not wire traffic.
                for(int i=0;i<15;++i) Enqueue(relay, delegate(object ignored) { Interlocked.Increment(ref queuedRan); }, null);
                Check(QueueCount(relay)==15, "Expected fifteen pending callbacks.");
                Check((int)Get(relay,"activeWorkers")==16, "Pending plus active exceeded or missed the slot cap.");
                Call(relay,"CloseAllSockets"); // The stop primitive called by public Dispose.
                Check(QueueCount(relay)==0, "Stop did not cancel pending callbacks.");
                Check((int)Get(relay,"activeWorkers")==1, "Stop did not return pending reservations exactly once.");
            }
            release.Set();
            Stopwatch elapsed=Stopwatch.StartNew(); Dispose(relay); Dispose(relay); Stopped(relay);
            Check(queuedRan==0, "A canceled pending callback executed.");
            results.Add(new Dictionary<string,object> { {"name","queued stop cancels fifteen callbacks while one callback is active"}, {"result","PASS"},
                {"internalSchedulingFixture",true}, {"queuedBeforeStop",15}, {"activeBeforeStop",1}, {"canceledCallbacksExecuted",queuedRan},
                {"shutdownSeconds",elapsed.Elapsed.TotalSeconds}, {"workerThreadsAfterDispose",Alive(relay)} });
        } finally { release.Set(); Dispose(relay); entered.Dispose(); release.Dispose(); }
        object rebound=Start(); Dispose(rebound); Stopped(rebound);

        relay=Start();
        var allEntered=new CountdownEvent(16);
        var releases=new ManualResetEvent[16];
        for(int i=0;i<16;++i) releases[i]=new ManualResetEvent(false);
        Thread releaser=null;
        try {
            Thread[] workers=(Thread[])Get(relay,"workerThreads");
            for(int i=0;i<16;++i) Enqueue(relay, delegate(object ignored) {
                int index=Array.IndexOf(workers,Thread.CurrentThread);
                allEntered.Signal(); releases[index].WaitOne();
            },null);
            Check(allEntered.Wait(2000), "Not all sixteen fixture callbacks started.");
            releaser=new Thread(delegate() { Thread.Sleep(4000); releases[0].Set(); });
            releaser.IsBackground=true; releaser.Start();
            Stopwatch elapsed=Stopwatch.StartNew();
            bool timeout=false;
            try { Dispose(relay); } catch(TimeoutException) { timeout=true; }
            double seconds=elapsed.Elapsed.TotalSeconds;
            Check(timeout, "Incomplete shutdown was silently treated as successful.");
            Check(seconds>=4.5 && seconds<6.5, "Listener and worker joins did not share a five-second deadline.");
            int aliveAtTimeout=Alive(relay);
            Check(aliveAtTimeout>=15, "The controlled uncooperative callbacks were unexpectedly killed.");
            for(int i=0;i<16;++i) releases[i].Set();
            elapsed.Restart(); Dispose(relay); Dispose(relay); Stopped(relay);
            results.Add(new Dictionary<string,object> { {"name","shutdown shares one deadline and retries after explicit incomplete termination"}, {"result","PASS"},
                {"internalSchedulingFixture",true}, {"uncooperativeCallbacks",16}, {"firstWorkerReleasedAfterSeconds",4},
                {"timeoutSeconds",seconds}, {"exceptionType","System.TimeoutException"}, {"workerThreadsAliveAtExplicitTimeout",aliveAtTimeout},
                {"retryDisposalSeconds",elapsed.Elapsed.TotalSeconds}, {"workerThreadsAfterRetry",Alive(relay)} });
        } finally {
            for(int i=0;i<16;++i) releases[i].Set();
            if(releaser!=null) releaser.Join(2000);
            Dispose(relay); allEntered.Dispose(); foreach(var ev in releases) ev.Dispose();
        }
        rebound=Start(); Dispose(rebound); Stopped(rebound);
        results.Add(new Dictionary<string,object> { {"name","both controlled shutdown scenarios release listeners for immediate rebind"}, {"result","PASS"}, {"immediateRebinds",2}, {"workerThreadsAfterDispose",0} });
        return results.ToArray();
    }
}
'@
        if ($PSVersionTable.PSVersion.Major -ge 6) { Add-Type -TypeDefinition $fixtureSource -CompilerOptions '/langversion:5' }
        else { Add-Type -TypeDefinition $fixtureSource }
    }
    return [RelayDispatchFixture]::Run([GephTun.SocksDnsRelay])
}
[Console]::Out.WriteLine((@{ ready = $true; languageVersion = 5;
    powershellVersion = $PSVersionTable.PSVersion.ToString();
    telemetryOptOutRequested = ([Environment]::GetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT') -eq '1' -and
        [Environment]::GetEnvironmentVariable('DOTNET_CLI_TELEMETRY_OPTOUT') -eq '1');
    updateChecksDisabledRequested = ([Environment]::GetEnvironmentVariable('POWERSHELL_UPDATECHECK') -eq 'Off');
    dotnetVersion = [Environment]::Version.ToString() } | ConvertTo-Json -Compress))
try {
    while ($null -ne ($line = [Console]::In.ReadLine())) {
        $quit = $false
        try {
            $request = $line | ConvertFrom-Json
            $result = $null
            switch ($request.operation) {
                'probe' { $result = [GephTun.ProxyProbe]::Test([int]$request.port) }
                'dns' { $result = [GephTun.ProxyProbe]::TestDns([int]$request.port) }
                'start' {
                    if ($null -ne $relay) { throw 'A relay is already active.' }
                    $relay = [GephTun.SocksDnsRelay]::Start([int]$request.port)
                    $result = @{ healthy = $relay.Healthy; error = $relay.LastError }
                }
                'status' {
                    if ($null -eq $relay) { throw 'No active relay.' }
                    $result = Get-RelayTestState $relay
                }
                'dispose' {
                    if ($null -ne $relay) { $relay.Dispose(); $relay.Dispose() }
                    $result = Get-RelayTestState $relay
                    $relay = $null
                }
                'dispatch_lifecycle' {
                    if ($null -ne $relay) { throw 'Stop the relay before the controlled lifecycle fixture.' }
                    $result = Test-RelayDispatchLifecycle
                }
                'wire_batch' {
                    $results = New-Object 'System.Collections.Generic.List[object]'
                    foreach ($item in $request.items) {
                        try {
                            [byte[]]$query = [Convert]::FromBase64String([string]$item.query)
                            [object[]]$arguments = @($query, 0)
                            if (-not $queryMethod.Invoke($null, $arguments)) {
                                $results.Add(@{ valid = $false })
                                continue
                            }
                            if ($null -ne $item.response) {
                                [byte[]]$response = [Convert]::FromBase64String([string]$item.response)
                                $responseMethod.Invoke($null, @($response, $query))
                                [byte[]]$filtered = $filterMethod.Invoke($null, (, $response))
                                $results.Add(@{ valid = $true; filtered = [Convert]::ToBase64String($filtered) })
                            } else {
                                $results.Add(@{ valid = $true; questionEnd = $arguments[1] })
                            }
                        } catch {
                            $failure = $_.Exception
                            while ($null -ne $failure.InnerException) { $failure = $failure.InnerException }
                            $results.Add(@{ valid = $false; errorType = $failure.GetType().FullName;
                                error = $failure.Message })
                        }
                    }
                    $result = $results.ToArray()
                }
                'quit' { $quit = $true }
                default { throw 'Unknown test operation.' }
            }
            [Console]::Out.WriteLine((@{ ok = $true; result = $result } | ConvertTo-Json -Compress -Depth 5))
        } catch {
            [Console]::Out.WriteLine((@{ ok = $false; error = $_.Exception.ToString() } | ConvertTo-Json -Compress -Depth 5))
        }
        if ($quit) { break }
    }
} finally {
    if ($null -ne $relay) { $relay.Dispose() }
}
