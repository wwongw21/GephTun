// GephTun 1.5.0. Windows x64 / .NET Framework 4.x. No service or callout driver.
// Persistent deny policy is independent of this process. Temporary permissions
// use a DYNAMIC WFP session: process death removes permissions, NOT protection.
// SDK references and threat/scope limits: docs/WFP-DESIGN.md.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace GephTun.Security
{
    public sealed class WfpStatus
    {
        public string State { get; set; }
        public int PersistentFilters { get; set; }
        public int TemporaryFilters { get; set; }
        public string Detail { get; set; }
    }
    public sealed class TrustedImage
    {
        public string Path { get; set; }
        public string Sha256 { get; set; }
    }
    public sealed class PolicyCondition
    {
        public Guid Field;
        public uint Match; // FWP_MATCH_EQUAL=0; FLAGS_ALL_SET=6; FLAGS_NONE_SET=8.
        public uint Type;
        public ulong Number;
        public byte[] Bytes;
        public string Image;
        internal PolicyCondition Copy() { return (PolicyCondition)MemberwiseClone(); }
    }
    public sealed class PolicyRule
    {
        public string Name;
        public Guid Key, Layer;
        public bool Permit;
        public bool Boot;
        public bool Temporary;
        public byte Weight;
        public PolicyCondition[] Conditions;
    }
    public static class WfpPolicy
    {
        // Private, stable namespace. Used only for GephTun-owned objects.
        // Providerless filters avoid the documented disabled-on-boot behavior of a
        // named provider with no auto-start Windows service. Ownership is a private
        // persistent sublayer + deterministic keys + schema marker; no service is installed.
        public static readonly Guid Sublayer = new Guid("0c195e67-f506-4f48-b06a-fb056243caaf");
        public const string Schema = "GephTun.WFP.v1";
        public static readonly Guid Connect4 = new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82");
        public static readonly Guid Connect6 = new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
        public static readonly Guid Accept4 = new Guid("e1cd9fe7-f4b5-4273-96c0-592e487b8650");
        public static readonly Guid Accept6 = new Guid("a3b42c97-9f04-4672-b87e-cee9c483257f");
        public static readonly Guid Forward4 = new Guid("a82acc24-4ee1-4ee1-b465-fd1d25cb10a4");
        public static readonly Guid Forward6 = new Guid("7b964818-19c7-493a-b71f-832c3684d28c");
        public static readonly Guid OutPacket4 = new Guid("1e5c9fae-8a84-4135-a331-950b54229ecd");
        public static readonly Guid OutPacket6 = new Guid("a3b3ab6b-3564-488c-9117-f34e82142763");
        public static readonly Guid InPacket4 = new Guid("c86fd1bf-21cd-497e-a0bb-17425c885c58");
        public static readonly Guid InPacket6 = new Guid("f52032cb-991c-46e7-971d-2601459a91ca");
        public static readonly Guid App = new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");
        public static readonly Guid Flags = new Guid("632ce23b-5167-435c-86d7-e903684aa80c");
        public static readonly Guid Protocol = new Guid("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");
        public static readonly Guid LocalPort = new Guid("0c1ba1af-5765-453f-af22-a8f791ac775b");
        public static readonly Guid RemotePort = new Guid("c35a604d-d22b-4e1a-91b4-68f674ee674b");
        public static readonly Guid RemoteAddress = new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
        public static readonly Guid LocalInterface = new Guid("4cd62a49-59c3-4969-b7f3-bda5d32890a4");
        public static readonly Guid NextHop = new Guid("93ae8f5b-7f6f-4719-98c8-14e97429ef04");
        public static readonly Guid Arrival = new Guid("618a9b6d-386b-4136-ad6e-b51587cfb1cd");
        public static PolicyCondition Num(Guid field, uint type, ulong number, uint match)
        { return new PolicyCondition { Field=field, Type=type, Number=number, Match=match }; }
        public static PolicyCondition Image(string path)
        { return new PolicyCondition { Field=App, Type=12, Image=path }; }
        public static PolicyCondition V6Prefix(string ip, byte prefix)
        {
            byte[] address=IPAddress.Parse(ip).GetAddressBytes();
            if(address.Length!=16 || prefix>128) throw new ArgumentException("Invalid IPv6 prefix.");
            byte[] bytes=new byte[17]; Buffer.BlockCopy(address,0,bytes,0,16); bytes[16]=prefix;
            return new PolicyCondition { Field=RemoteAddress, Type=257, Bytes=bytes };
        }
        internal static Guid Key(string name)
        {
            using(SHA256 sha=SHA256.Create()) {
                byte[] all=sha.ComputeHash(Encoding.UTF8.GetBytes(Schema+"/"+name));
                byte[] b=new byte[16]; Buffer.BlockCopy(all,0,b,0,16); return new Guid(b);
            }
        }
        private static PolicyRule Rule(string name, Guid layer, bool permit, byte weight, bool boot, bool temporary, params PolicyCondition[] conditions)
        { return new PolicyRule {Name=name,Key=Key(name),Layer=layer,Permit=permit,Weight=weight,Boot=boot,Temporary=temporary,Conditions=conditions}; }
        public static PolicyRule[] Baseline(string systemHost)
        {
            if(String.IsNullOrWhiteSpace(systemHost)) throw new ArgumentException("System host path is required.");
            var rules=new List<PolicyRule>();
            Guid[] layers={Connect4,Accept4,Connect6,Accept6};
            for(int i=0;i<layers.Length;i++) {
                string n="base/"+i;
                rules.Add(Rule(n+"/deny",layers[i],false,1,false,false));
                rules.Add(Rule(n+"/loopback",layers[i],true,12,false,false,Num(Flags,3,1,6)));
                // DHCP is a narrowly scoped maintenance exception, not general svchost internet.
                ushort local=(ushort)(i<2?68:546), remote=(ushort)(i<2?67:547);
                var dhcp=new List<PolicyCondition> {Image(systemHost),Num(Protocol,1,17,0),Num(LocalPort,2,local,0),Num(RemotePort,2,remote,0)};
                if(i<2) rules.Add(Rule(n+"/dhcp4",layers[i],true,10,false,false,dhcp.ToArray()));
                else {
                    foreach(string destination in new[]{"fe80::/10","ff02::1:2/128"}) {
                        string[] parts=destination.Split('/'); var c=new List<PolicyCondition>(dhcp);
                        c.Add(V6Prefix(parts[0],Byte.Parse(parts[1])));
                        rules.Add(Rule(n+"/dhcp6/"+destination,layers[i],true,10,false,false,c.ToArray()));
                    }
                    // Only link-local neighbor/router discovery. No global ICMPv6 permit.
                    for(ushort type=133;type<=136;type++) foreach(string destination in new[]{"fe80::/10","ff02::/16"}) {
                        string[] parts=destination.Split('/');
                        rules.Add(Rule(n+"/ndp/"+type+"/"+destination,layers[i],true,10,false,false,
                            Num(Protocol,1,58,0),Num(LocalPort,2,type,0),Num(RemotePort,2,0,0),V6Prefix(parts[0],Byte.Parse(parts[1]))));
                    }
                }
            }
            rules.Add(Rule("base/forward4",Forward4,false,1,false,false));
            rules.Add(Rule("base/forward6",Forward6,false,1,false,false));
            // Boot policy is intentionally stricter: non-loopback IP is blocked until BFE
            // atomically loads persistent runtime policy. No boot-time transport exceptions.
            Guid[] boot={OutPacket4,OutPacket6,InPacket4,InPacket6};
            for(int i=0;i<boot.Length;i++) rules.Add(Rule("boot/"+i,boot[i],false,1,true,false,Num(Flags,3,1,8)));
            return rules.ToArray();
        }
        public static PolicyRule[] Transport(string[] images, ulong[] physicalLuids)
        {
            if(images==null || images.Length<1 || images.Length>8 || physicalLuids==null || physicalLuids.Length<1 || physicalLuids.Length>32)
                throw new ArgumentException("A bounded explicit transport allow-list and physical interface list are required.");
            var rules=new List<PolicyRule>();
            for(int p=0;p<images.Length;p++) foreach(ulong luid in physicalLuids.Distinct()) {
                if(luid==0) throw new ArgumentException("Zero physical interface LUID.");
                for(int family=0;family<2;family++) {
                    Guid layer=family==0?Connect4:Connect6; string n="lease/geph/"+p+"/"+luid+"/"+family;
                    // The supported wrapper already refuses Geph's non-loopback UDP sockets.
                    // No generic PowerShell, browser, UDP or destination-only internet permits.
                    rules.Add(Rule(n+"/out",layer,true,12,false,true,Image(images[p]),Num(Protocol,1,6,0),Num(NextHop,4,luid,0)));
                    // Next-hop is empty on inbound-triggered ALE reauthorization; restrict the
                    // alternate to reauthorization AND the actual physical arrival interface.
                    rules.Add(Rule(n+"/reply",layer,true,12,false,true,Image(images[p]),Num(Protocol,1,6,0),Num(Flags,3,4,6),Num(Arrival,4,luid,0)));
                }
            }
            return rules.ToArray();
        }
        public static PolicyRule[] Tunnel(ulong luid)
        {
            if(luid==0) throw new ArgumentException("Zero tunnel LUID.");
            return new[] {
                Rule("lease/tunnel/out",Connect4,true,8,false,true,Num(Protocol,1,6,0),Num(LocalInterface,4,luid,0),Num(NextHop,4,luid,0)),
                Rule("lease/tunnel/reply",Connect4,true,8,false,true,Num(Protocol,1,6,0),Num(LocalInterface,4,luid,0),Num(Flags,3,4,6),Num(Arrival,4,luid,0))
            };
        }
    }

    // All native structures are x64 SDK layouts. Guarded by AssertLayout before API use.
    [StructLayout(LayoutKind.Sequential)] internal struct Display { public IntPtr Name,Description; }
    [StructLayout(LayoutKind.Sequential)] internal struct Blob { public uint Size; public IntPtr Data; }
    [StructLayout(LayoutKind.Explicit,Size=16)] internal struct Value {
        [FieldOffset(0)] public uint Type;
        [FieldOffset(8)] public byte U8;
        [FieldOffset(8)] public ushort U16;
        [FieldOffset(8)] public uint U32;
        [FieldOffset(8)] public IntPtr Pointer;
    }
    [StructLayout(LayoutKind.Sequential)] internal struct Condition { public Guid Field; public uint Match; public Value Value; }
    [StructLayout(LayoutKind.Sequential)] internal struct ActionData { public uint Type; public Guid FilterType; }
    [StructLayout(LayoutKind.Explicit,Size=16)] internal struct Context { [FieldOffset(0)] public ulong Raw; [FieldOffset(0)] public Guid Key; }
    [StructLayout(LayoutKind.Sequential)] internal struct Filter {
        public Guid Key; public Display Display; public uint Flags; public IntPtr Provider; public Blob Data;
        public Guid Layer,Sublayer; public Value Weight; public uint Count; public IntPtr Conditions;
        public ActionData Action; public Context Context; public IntPtr Reserved; public ulong Id; public Value EffectiveWeight;
    }
    [StructLayout(LayoutKind.Sequential)] internal struct SublayerData { public Guid Key; public Display Display; public uint Flags; public IntPtr Provider; public Blob Data; public ushort Weight; }
    [StructLayout(LayoutKind.Sequential)] internal struct SessionData { public Guid Key; public Display Display; public uint Flags,Timeout,ProcessId; public IntPtr Sid,UserName; public int KernelMode; }
    [StructLayout(LayoutKind.Sequential)] internal struct EnumTemplate { public IntPtr Provider; public Guid Layer; public uint EnumType,Flags; public IntPtr Context; public uint Count; public IntPtr Conditions; public uint ActionMask; public IntPtr Callout; }
    internal sealed class Arena : IDisposable {
        private readonly List<IntPtr> blocks=new List<IntPtr>();
        public IntPtr Alloc(int size) { IntPtr p=Marshal.AllocHGlobal(size); blocks.Add(p); for(int i=0;i<size;i++) Marshal.WriteByte(p,i,0); return p; }
        public IntPtr Bytes(byte[] value) { IntPtr p=Alloc(Math.Max(1,value.Length)); Marshal.Copy(value,0,p,value.Length); return p; }
        public IntPtr Text(string value) { if(value==null)return IntPtr.Zero; return Bytes(Encoding.Unicode.GetBytes(value+"\0")); }
        public IntPtr Struct<T>(T value) where T:struct { IntPtr p=Alloc(Marshal.SizeOf(typeof(T))); Marshal.StructureToPtr(value,p,false); return p; }
        public void Dispose() { for(int i=blocks.Count-1;i>=0;i--) Marshal.FreeHGlobal(blocks[i]); blocks.Clear(); }
    }
    internal static class Native {
        [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode)] internal static extern uint FwpmEngineOpen0(string server,uint auth,IntPtr identity,IntPtr session,out IntPtr engine);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmEngineClose0(IntPtr engine);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmTransactionBegin0(IntPtr engine,uint flags);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmTransactionCommit0(IntPtr engine);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmTransactionAbort0(IntPtr engine);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmSubLayerAdd0(IntPtr engine,ref SublayerData layer,IntPtr sd);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmSubLayerGetByKey0(IntPtr engine,ref Guid key,out IntPtr layer);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmSubLayerDeleteByKey0(IntPtr engine,ref Guid key);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmFilterAdd0(IntPtr engine,ref Filter filter,IntPtr sd,out ulong id);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmFilterDeleteByKey0(IntPtr engine,ref Guid key);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmFilterCreateEnumHandle0(IntPtr engine,IntPtr template,out IntPtr handle);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmFilterEnum0(IntPtr engine,IntPtr handle,uint requested,out IntPtr entries,out uint count);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engine,IntPtr handle);
        [DllImport("fwpuclnt.dll")] internal static extern void FwpmFreeMemory0(ref IntPtr memory);
        [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode)] internal static extern uint FwpmGetAppIdFromFileName0(string file,out IntPtr blob);
        [DllImport("iphlpapi.dll")] internal static extern uint ConvertInterfaceGuidToLuid(ref Guid guid,out ulong luid);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string value,uint revision,out IntPtr sd,out uint size);
        [DllImport("kernel32.dll")] internal static extern IntPtr LocalFree(IntPtr memory);
    }
    internal sealed class Observed {
        internal Filter Filter;
        internal string Name,Signature;
    }
    internal sealed class Engine : IDisposable {
        internal IntPtr Handle;
        internal Engine(bool dynamic) {
            WfpController.AssertLayout();
            if(Environment.OSVersion.Platform!=PlatformID.Win32NT) throw new PlatformNotSupportedException("WFP requires Windows x64.");
            using(var a=new Arena()) {
                SessionData s=new SessionData { Key=Guid.NewGuid(),Display=new Display {Name=a.Text("GephTun WFP "+(dynamic?"temporary permissions":"policy management"))},Flags=dynamic?1U:0U,Timeout=5000 };
                Check(Native.FwpmEngineOpen0(null,10,IntPtr.Zero,a.Struct(s),out Handle),"open WFP");
            }
        }
        internal static void Check(uint code,string operation) { if(code!=0)throw new InvalidOperationException(operation+" failed: 0x"+code.ToString("X8")+". Protection was not deliberately disabled."); }
        internal void Transaction(System.Action action) {
            Check(Native.FwpmTransactionBegin0(Handle,0),"begin WFP transaction"); bool committed=false;
            try { action(); Check(Native.FwpmTransactionCommit0(Handle),"commit WFP transaction"); committed=true; }
            finally { if(!committed) Native.FwpmTransactionAbort0(Handle); }
        }
        internal void ReadTransaction(System.Action action) {
            Check(Native.FwpmTransactionBegin0(Handle,1),"begin WFP read transaction");
            try { action(); } finally { Native.FwpmTransactionAbort0(Handle); }
        }
        public void Dispose() { if(Handle!=IntPtr.Zero) { Check(Native.FwpmEngineClose0(Handle),"close WFP session"); Handle=IntPtr.Zero; } }
        internal static byte[] AppId(string path) {
            IntPtr p=IntPtr.Zero;
            Check(Native.FwpmGetAppIdFromFileName0(path,out p),"resolve WFP application identity");
            try { Blob b=(Blob)Marshal.PtrToStructure(p,typeof(Blob)); return ReadBytes(b); }
            finally { if(p!=IntPtr.Zero)Native.FwpmFreeMemory0(ref p); }
        }
        internal static byte[] ReadBytes(Blob b) {
            if(b.Size>65536 || (b.Size>0 && b.Data==IntPtr.Zero))throw new InvalidOperationException("Invalid WFP blob.");
            byte[] bytes=new byte[b.Size]; if(bytes.Length>0)Marshal.Copy(b.Data,bytes,0,bytes.Length); return bytes;
        }
        internal static string Signature(Filter f) {
            var head=new StringBuilder();
            head.Append(f.Layer).Append('|').Append(f.Sublayer).Append('|').Append(f.Action.Type).Append('|').Append(f.Flags).Append('|').Append(f.Weight.Type).Append(':').Append(f.Weight.U8);
            if(f.Count>64 || (f.Count>0 && f.Conditions==IntPtr.Zero))throw new InvalidOperationException("Unexpected WFP condition array.");
            var terms=new List<string>();
            for(int i=0;i<f.Count;i++) {
                Condition c=(Condition)Marshal.PtrToStructure(IntPtr.Add(f.Conditions,i*Marshal.SizeOf(typeof(Condition))),typeof(Condition));
                var s=new StringBuilder();
                s.Append(c.Field).Append(':').Append(c.Match).Append(':').Append(c.Value.Type).Append(':');
                if((c.Value.Type==4 || c.Value.Type==12 || c.Value.Type==257) && c.Value.Pointer==IntPtr.Zero)
                    throw new InvalidOperationException("Missing indirect WFP condition value.");
                switch(c.Value.Type) {
                    case 1:s.Append(c.Value.U8);break; case 2:s.Append(c.Value.U16);break; case 3:s.Append(c.Value.U32);break;
                    case 4:s.Append(unchecked((ulong)Marshal.ReadInt64(c.Value.Pointer)));break;
                    case 12:s.Append(Convert.ToBase64String(ReadBytes((Blob)Marshal.PtrToStructure(c.Value.Pointer,typeof(Blob)))));break;
                    case 257:byte[] prefix=new byte[17];Marshal.Copy(c.Value.Pointer,prefix,0,17);s.Append(Convert.ToBase64String(prefix));break;
                    default:throw new InvalidOperationException("Unknown condition type in owned WFP policy.");
                }
                terms.Add(s.ToString());
            }
            // The conjunction is order-independent on the supported Windows versions.
            // Readback may normalize order; retain every term (including duplicates).
            terms.Sort(StringComparer.Ordinal);
            foreach(string term in terms)head.Append('|').Append(term);
            return head.ToString();
        }
        internal static Filter Compile(PolicyRule rule,Arena a) {
            var conditions=new List<Condition>();
            foreach(PolicyCondition p in rule.Conditions) {
                Value v=new Value {Type=p.Type};
                switch(p.Type) {
                    case 1:v.U8=checked((byte)p.Number);break;
                    case 2:v.U16=checked((ushort)p.Number);break;
                    case 3:v.U32=checked((uint)p.Number);break;
                    case 4:v.Pointer=a.Struct(p.Number);break; // UINT64 is indirect in FWP_VALUE0.
                    case 12:byte[] app=AppId(p.Image);v.Pointer=a.Struct(new Blob {Size=(uint)app.Length,Data=a.Bytes(app)});break;
                    case 257:v.Pointer=a.Bytes(p.Bytes);break;
                    default:throw new ArgumentException("Unsupported native condition type.");
                }
                conditions.Add(new Condition {Field=p.Field,Match=p.Match,Value=v});
            }
            IntPtr array=IntPtr.Zero; int stride=Marshal.SizeOf(typeof(Condition));
            if(conditions.Count>0) { array=a.Alloc(stride*conditions.Count); for(int i=0;i<conditions.Count;i++)Marshal.StructureToPtr(conditions[i],IntPtr.Add(array,i*stride),false); }
            byte[] marker=Encoding.ASCII.GetBytes(WfpPolicy.Schema);
            return new Filter {Key=rule.Key,Display=new Display {Name=a.Text("GephTun/"+rule.Name),Description=a.Text("GephTun 1.5.0. Explicit Disable protection removes this owned policy.")},
                Flags=rule.Temporary?0U:rule.Boot?2U:1U,Provider=IntPtr.Zero,Data=new Blob {Size=(uint)marker.Length,Data=a.Bytes(marker)},
                Layer=rule.Layer,Sublayer=WfpPolicy.Sublayer,Weight=new Value {Type=1,U8=rule.Weight},Count=(uint)conditions.Count,Conditions=array,
                Action=new ActionData {Type=rule.Permit?0x1002U:0x1001U}};
        }
        internal void Add(PolicyRule rule,IntPtr sd) { using(var a=new Arena()) {Filter f=Compile(rule,a); ulong id;Check(Native.FwpmFilterAdd0(Handle,ref f,sd,out id),"install "+rule.Name);} }
        internal List<Observed> Enumerate() {
            var result=new List<Observed>();
            // Layer keys are explicit; boot and disabled filters MUST be included.
            Guid[] layers={WfpPolicy.Connect4,WfpPolicy.Connect6,WfpPolicy.Accept4,WfpPolicy.Accept6,
                WfpPolicy.Forward4,WfpPolicy.Forward6,WfpPolicy.OutPacket4,WfpPolicy.OutPacket6,WfpPolicy.InPacket4,WfpPolicy.InPacket6};
            foreach(Guid layer in layers)using(var a=new Arena()) {
                IntPtr handle=IntPtr.Zero;
                EnumTemplate t=new EnumTemplate {Provider=IntPtr.Zero,Layer=layer,EnumType=1,Flags=0x18,ActionMask=0xffffffff};
                Check(Native.FwpmFilterCreateEnumHandle0(Handle,a.Struct(t),out handle),"enumerate owned WFP policy");
                try {
                    bool complete=false;
                    for(int page=0;page<128;page++) {
                        IntPtr entries=IntPtr.Zero;uint count=0;
                        try {
                            Check(Native.FwpmFilterEnum0(Handle,handle,128,out entries,out count),"read owned WFP policy");
                            for(int i=0;i<count;i++) {
                                Filter f=(Filter)Marshal.PtrToStructure(Marshal.ReadIntPtr(entries,i*IntPtr.Size),typeof(Filter));
                                if(f.Sublayer!=WfpPolicy.Sublayer)continue;
                                if(f.Provider!=IntPtr.Zero || Encoding.ASCII.GetString(ReadBytes(f.Data))!=WfpPolicy.Schema)throw new InvalidOperationException("Unexpected object in GephTun WFP namespace; not modified.");
                                result.Add(new Observed {Filter=f,Name=Marshal.PtrToStringUni(f.Display.Name),Signature=Signature(f)});
                            }
                            if(count==0){complete=true;break;}
                        } finally {if(entries!=IntPtr.Zero)Native.FwpmFreeMemory0(ref entries);}
                    }
                    if(!complete)throw new InvalidOperationException("Owned WFP policy exceeds enumeration limit.");
                } finally {if(handle!=IntPtr.Zero)Native.FwpmFilterDestroyEnumHandle0(Handle,handle);}
            }
            return result;
        }
        internal bool CheckObjects(bool allowAbsent) {
            Guid key=WfpPolicy.Sublayer;IntPtr pointer=IntPtr.Zero;
            uint code=Native.FwpmSubLayerGetByKey0(Handle,ref key,out pointer);
            try {
                if(code==0x80320007 && allowAbsent)return false;
                Check(code,"read GephTun WFP sublayer");
                SublayerData s=(SublayerData)Marshal.PtrToStructure(pointer,typeof(SublayerData));
                if(s.Flags!=1 || s.Weight!=0x7000 || s.Provider!=IntPtr.Zero || Encoding.ASCII.GetString(ReadBytes(s.Data))!=WfpPolicy.Schema)
                    throw new InvalidOperationException("GephTun WFP sublayer has unexpected identity or settings.");
                return true;
            } finally {if(pointer!=IntPtr.Zero)Native.FwpmFreeMemory0(ref pointer);}
        }
        internal void CreateObjects(IntPtr sd) {
            using(var a=new Arena()) {
                byte[] marker=Encoding.ASCII.GetBytes(WfpPolicy.Schema);Blob b=new Blob {Size=(uint)marker.Length,Data=a.Bytes(marker)};
                SublayerData s=new SublayerData {Key=WfpPolicy.Sublayer,Display=new Display {Name=a.Text("GephTun kill switch v1")},Flags=1,Provider=IntPtr.Zero,Data=b,Weight=0x7000};
                Check(Native.FwpmSubLayerAdd0(Handle,ref s,sd),"create persistent WFP sublayer");
            }
        }
        internal void VerifyRules(PolicyRule[] expected,bool persistentOnly) {
            CheckObjects(false); var found=Enumerate();
            if(persistentOnly)found=found.Where(x=>(x.Filter.Flags&3)!=0).ToList();
            var expectedKeys=new HashSet<Guid>(expected.Select(r=>r.Key));
            if(found.Count!=expected.Length || found.Any(x=>!expectedKeys.Contains(x.Filter.Key)))throw new InvalidOperationException("Owned WFP policy count/keys do not match. Protection cannot be verified.");
            foreach(PolicyRule r in expected)using(var a=new Arena()) {
                var actual=found.Single(x=>x.Filter.Key==r.Key); var f=Compile(r,a);
                if(actual.Signature!=Signature(f))throw new InvalidOperationException("Owned WFP policy differs: "+r.Name);
            }
        }
    }
    internal sealed class AdminSecurity : IDisposable {
        internal IntPtr Pointer;
        internal AdminSecurity() {
            uint length;
            if(!Native.ConvertStringSecurityDescriptorToSecurityDescriptorW("D:P(A;;GA;;;SY)(A;;GA;;;BA)",1,out Pointer,out length))throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        public void Dispose() { if(Pointer!=IntPtr.Zero){Native.LocalFree(Pointer);Pointer=IntPtr.Zero;} }
    }
    public static class WfpController
    {
        private static string SystemHost { get {return System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"svchost.exe");} }
        public static void AssertLayout() {
            if(IntPtr.Size!=8)throw new PlatformNotSupportedException("Only x64 WFP layout is supported.");
            var checks=new Dictionary<Type,int>{{typeof(Value),16},{typeof(Condition),40},{typeof(Filter),200},{typeof(SessionData),72},{typeof(SublayerData),72},{typeof(EnumTemplate),72}};
            foreach(var p in checks)if(Marshal.SizeOf(p.Key)!=p.Value)throw new InvalidOperationException("Native ABI layout mismatch: "+p.Key.Name);
            if(Marshal.OffsetOf(typeof(Filter),"Conditions").ToInt32()!=120 || Marshal.OffsetOf(typeof(Filter),"Context").ToInt32()!=152 || Marshal.OffsetOf(typeof(Filter),"Id").ToInt32()!=176)throw new InvalidOperationException("Native filter field offset mismatch.");
        }
        public static ulong InterfaceLuid(string guid) {
            Guid g=new Guid(guid);ulong luid;Engine.Check(Native.ConvertInterfaceGuidToLuid(ref g,out luid),"resolve interface LUID");
            if(luid==0)throw new InvalidOperationException("Invalid zero interface LUID.");return luid;
        }
        public static WfpStatus Inspect() {
            using(var e=new Engine(false)) {
                WfpStatus status=null;
                e.ReadTransaction(delegate {
                    if(!e.CheckObjects(true)){status=new WfpStatus {State="Disabled",Detail="No GephTun WFP policy is installed."};return;}
                    e.VerifyRules(WfpPolicy.Baseline(SystemHost),true);var filters=e.Enumerate();
                    status=new WfpStatus {State="Enabled",PersistentFilters=filters.Count(x=>(x.Filter.Flags&3)!=0),TemporaryFilters=filters.Count(x=>(x.Filter.Flags&3)==0),Detail="Persistent baseline verified. Temporary transport permissions are possible while a controller is running. This is policy verification, not a packet-leak test."};
                });return status;
            }
        }
        public static void Enable() {
            using(var e=new Engine(false))using(var security=new AdminSecurity()) {
                e.Transaction(delegate {
                    if(e.CheckObjects(true)) {e.VerifyRules(WfpPolicy.Baseline(SystemHost),true);return;}
                    e.CreateObjects(security.Pointer);
                    foreach(var r in WfpPolicy.Baseline(SystemHost))e.Add(r,security.Pointer);
                    e.VerifyRules(WfpPolicy.Baseline(SystemHost),true);
                });
            }
        }
        public static void Disable(bool explicitConsent) {
            if(!explicitConsent)throw new InvalidOperationException("Explicit consent to allow direct internet is required.");
            using(var e=new Engine(false)) {
                e.Transaction(delegate {
                    if(!e.CheckObjects(true))return;
                    var filters=e.Enumerate();
                    if(filters.Any(f=>(f.Filter.Flags&3)==0))throw new InvalidOperationException("Temporary controller permissions remain. Disconnect / Recover, then disable protection. No filters were removed.");
                    foreach(var f in filters) {Guid k=f.Filter.Key;Engine.Check(Native.FwpmFilterDeleteByKey0(e.Handle,ref k),"remove owned persistent filter");}
                    Guid sk=WfpPolicy.Sublayer;
                    Engine.Check(Native.FwpmSubLayerDeleteByKey0(e.Handle,ref sk),"remove owned sublayer");
                });
                if(Inspect().State!="Disabled")throw new InvalidOperationException("Unlock could not be verified.");
            }
        }
        public static WfpLease OpenLease(TrustedImage[] images,ulong[] interfaces) {return new WfpLease(images,interfaces);}
    }
    public sealed class WfpLease : IDisposable
    {
        private Engine engine;
        private readonly List<FileStream> heldImages=new List<FileStream>();
        private readonly List<PolicyRule> rules=new List<PolicyRule>();
        private bool tunnel;
        internal WfpLease(TrustedImage[] images,ulong[] interfaces) {
            if(images==null || images.Length<1 || images.Length>8)throw new ArgumentException("Explicit trusted Geph paths required.");
            try {
                if(WfpController.Inspect().State!="Enabled")throw new InvalidOperationException("Enable the kill switch before opening a connection.");
                var paths=new List<string>();
                foreach(var image in images) {
                    string path=Path.GetFullPath(image.Path);
                    if(!String.Equals(Path.GetExtension(path),".exe",StringComparison.OrdinalIgnoreCase) || image.Sha256==null || image.Sha256.Length!=64)throw new ArgumentException("Invalid trusted image record.");
                    // Keep the exact image open without write/delete sharing for the lease.
                    var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);heldImages.Add(stream);
                    string hash;using(var sha=SHA256.Create())hash=BitConverter.ToString(sha.ComputeHash(stream)).Replace("-","");
                    if(!String.Equals(hash,image.Sha256,StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("Approved Geph executable changed. Disable/re-enable protection after reviewing the new installation: "+path);
                    paths.Add(path);
                }
                engine=new Engine(true);rules.AddRange(WfpPolicy.Transport(paths.ToArray(),interfaces));
                using(var sd=new AdminSecurity())engine.Transaction(delegate {foreach(var r in rules)engine.Add(r,sd.Pointer);});
                Verify();
            } catch {Dispose();throw;}
        }
        public void AuthorizeTunnel(ulong luid) {
            if(engine==null)throw new ObjectDisposedException("WfpLease");
            if(tunnel)throw new InvalidOperationException("Tunnel permission is already installed.");
            var add=WfpPolicy.Tunnel(luid);
            using(var sd=new AdminSecurity())engine.Transaction(delegate {foreach(var r in add)engine.Add(r,sd.Pointer);});
            rules.AddRange(add);tunnel=true;Verify();
        }
        public void RevokeTunnel() {
            if(engine==null || !tunnel)return;
            var remove=rules.Where(r=>r.Name.StartsWith("lease/tunnel/",StringComparison.Ordinal)).ToArray();
            engine.Transaction(delegate {foreach(var r in remove){Guid k=r.Key;Engine.Check(Native.FwpmFilterDeleteByKey0(engine.Handle,ref k),"revoke tunnel permission");}});
            rules.RemoveAll(r=>r.Name.StartsWith("lease/tunnel/",StringComparison.Ordinal));tunnel=false;
        }
        public void Verify() {
            if(engine==null)throw new ObjectDisposedException("WfpLease");
            using(var reader=new Engine(false))reader.ReadTransaction(delegate {
                reader.VerifyRules(WfpPolicy.Baseline(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"svchost.exe")),true);
                // Validate EVERY owned temporary filter, including condition values and flags.
                var all=reader.Enumerate();var observed=all.Where(x=>(x.Filter.Flags&3)==0).ToList();
                if(observed.Count!=rules.Count)throw new InvalidOperationException("Unexpected temporary WFP policy.");
                foreach(var r in rules)using(var a=new Arena()) {
                    var f=observed.SingleOrDefault(x=>x.Filter.Key==r.Key);
                    if(f==null || f.Signature!=Engine.Signature(Engine.Compile(r,a)))throw new InvalidOperationException("Temporary WFP permission changed: "+r.Name);
                }
            });
        }
        public void Dispose() {
            if(engine!=null){engine.Dispose();engine=null;}
            foreach(var stream in heldImages)stream.Dispose();heldImages.Clear();rules.Clear();tunnel=false;
        }
    }
}
