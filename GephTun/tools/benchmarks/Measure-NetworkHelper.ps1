param([Parameter(Mandatory=$true)][string]$Source,
      [Parameter(Mandatory=$true)][string]$Fixtures,
      [Parameter(Mandatory=$true)][string]$Output,
      [int]$RelayPort = 18537)
$ErrorActionPreference = 'Stop'
$original = [IO.File]::ReadAllText($Source)
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('gephtun-measure-' + [Guid]::NewGuid().ToString('N') + '.cs')
try {
    # Only the privileged listener port is changed for the portable measurement.
    [IO.File]::WriteAllText($temporary, $original.Replace('IPAddress.Loopback, 53)', ('IPAddress.Loopback, ' + $RelayPort + ')')))
    Add-Type -Path $temporary -CompilerOptions '/langversion:5'
    $fixtureSource = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Threading;
public static class NetworkResourceFixture {
    public static Dictionary<string,object> Measure(Type protocol, byte[] query, byte[] response, int iterations) {
        BindingFlags flags = BindingFlags.NonPublic | BindingFlags.Static;
        var validate = (Action<byte[],byte[]>)Delegate.CreateDelegate(typeof(Action<byte[],byte[]>), protocol.GetMethod("ValidateResponse", flags));
        var filter = (Func<byte[],byte[]>)Delegate.CreateDelegate(typeof(Func<byte[],byte[]>), protocol.GetMethod("RemoveIpv6Records", flags));
        var allocationMethod = typeof(GC).GetMethod("GetAllocatedBytesForCurrentThread", BindingFlags.Public | BindingFlags.Static);
        if (allocationMethod == null) throw new NotSupportedException("This measurement needs a runtime allocation counter.");
        var allocated = (Func<long>)Delegate.CreateDelegate(typeof(Func<long>), allocationMethod);
        byte[] last = null;
        for (int i=0; i<256; ++i) { validate(response,query); last=filter(response); }
        GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
        Stopwatch watch = Stopwatch.StartNew();
        long before = allocated();
        for (int i=0; i<iterations; ++i) { validate(response,query); last=filter(response); }
        long bytes = allocated()-before;
        watch.Stop();
        GC.KeepAlive(last);
        return new Dictionary<string,object> { {"iterations",iterations}, {"allocatedBytes",bytes},
            {"allocatedBytesPerResponse",(double)bytes/iterations}, {"elapsedMilliseconds",watch.Elapsed.TotalMilliseconds},
            {"inputBytes",response.Length}, {"outputBytes",last.Length} };
    }
    public static Dictionary<string,object> Idle(Type relayType) {
        int timeouts = 0;
        EventHandler<FirstChanceExceptionEventArgs> count = delegate(object sender, FirstChanceExceptionEventArgs e) {
            SocketException socket = e.Exception as SocketException;
            if(socket != null && socket.SocketErrorCode == SocketError.TimedOut) Interlocked.Increment(ref timeouts);
        };
        object relay = relayType.GetMethod("Start").Invoke(null,new object[] { 65534 });
        try {
            Thread.Sleep(250);
            var process = Process.GetCurrentProcess();
            TimeSpan cpu = process.TotalProcessorTime;
            Stopwatch elapsed = Stopwatch.StartNew();
            AppDomain.CurrentDomain.FirstChanceException += count;
            try { Thread.Sleep(5000); }
            finally { AppDomain.CurrentDomain.FirstChanceException -= count; }
            elapsed.Stop();
            double cpuMs = (Process.GetCurrentProcess().TotalProcessorTime-cpu).TotalMilliseconds;
            Stopwatch stop = Stopwatch.StartNew();
            ((IDisposable)relay).Dispose();
            stop.Stop();
            return new Dictionary<string,object> { {"observedSeconds",elapsed.Elapsed.TotalSeconds},
                {"socketTimeoutExceptions",timeouts}, {"processCpuMilliseconds",cpuMs}, {"disposeMilliseconds",stop.Elapsed.TotalMilliseconds},
                {"healthyAfterDispose",relayType.GetProperty("Healthy").GetValue(relay,null)} };
        } finally { ((IDisposable)relay).Dispose(); }
    }
}
'@
    Add-Type -TypeDefinition $fixtureSource -CompilerOptions '/langversion:5'
    $protocol = [GephTun.ProxyProbe].Assembly.GetType('GephTun.DnsProtocol')
    $results = @()
    foreach ($fixture in ([IO.File]::ReadAllText($Fixtures) | ConvertFrom-Json)) {
        foreach ($sample in 1..3) {
            $measurement = [NetworkResourceFixture]::Measure($protocol, [Convert]::FromBase64String($fixture.query),
                [Convert]::FromBase64String($fixture.response), [int]$fixture.iterations)
            $measurement['fixture'] = $fixture.name
            $measurement['sample'] = $sample
            $results += $measurement
        }
    }
    $result = @{
        status = 'PASS'; source = $Source; sourceSha256 = (Get-FileHash $Source -Algorithm SHA256).Hash.ToLowerInvariant();
        fixtureSha256 = (Get-FileHash $Fixtures -Algorithm SHA256).Hash.ToLowerInvariant();
        host = [Environment]::OSVersion.ToString(); powershell = $PSVersionTable.PSVersion.ToString();
        dotnet = [Environment]::Version.ToString(); listenerPortSubstitution = $RelayPort;
        scope = 'In-process validate/filter allocation microbenchmark and five-second idle loopback observation; not Windows end-to-end performance.';
        measurementScriptSha256 = (Get-FileHash $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant();
        samples = $results; idle = [NetworkResourceFixture]::Idle([GephTun.SocksDnsRelay])
    }
    [IO.File]::WriteAllText($Output, ($result | ConvertTo-Json -Depth 8))
    $result | ConvertTo-Json -Depth 8
} finally { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
