// Compatible with the C# 5 compiler used by Windows PowerShell 5.1 Add-Type.
// No DNS lookup or all-interface listener is used by this helper.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Threading;

namespace GephTun
{
    internal sealed class NetworkDeadline
    {
        private readonly Stopwatch watch = Stopwatch.StartNew();
        private readonly int timeoutMilliseconds;

        internal NetworkDeadline(int milliseconds)
        {
            timeoutMilliseconds = milliseconds;
        }

        internal int Remaining(string operation)
        {
            long remaining = timeoutMilliseconds - watch.ElapsedMilliseconds;
            if (remaining <= 0)
                throw new TimeoutException(operation + " exceeded its time limit.");
            return (int)remaining;
        }
    }

    internal static class NetworkIo
    {
        internal const int TimeoutMilliseconds = 8000;

        internal static void ValidatePort(int port)
        {
            if (port < 1 || port > 65535)
                throw new ArgumentOutOfRangeException("port", "The SOCKS port must be between 1 and 65535.");
        }

        internal static Socket NewTcpSocket()
        {
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.NoDelay = true;
            socket.ReceiveTimeout = TimeoutMilliseconds;
            socket.SendTimeout = TimeoutMilliseconds;
            return socket;
        }

        internal static void Connect(Socket socket, IPEndPoint endpoint, NetworkDeadline deadline)
        {
            IAsyncResult pending = socket.BeginConnect(endpoint, null, null);
            // An already-completed APM result can wrap a shared completed Task
            // on modern runtimes. Disposing its wait handle breaks later socket
            // operations. Only create/own a handle when a wait is necessary.
            WaitHandle completed = null;
            try
            {
                if (!pending.IsCompleted)
                {
                    completed = pending.AsyncWaitHandle;
                    if (!completed.WaitOne(deadline.Remaining("TCP connect")))
                    {
                        Close(socket);
                        throw new TimeoutException("TCP connect to " + endpoint + " timed out.");
                    }
                }
                socket.EndConnect(pending);
            }
            finally { if (completed != null) completed.Dispose(); }
        }

        internal static byte[] ReadExact(Stream stream, int count, NetworkDeadline deadline, string operation)
        {
            byte[] bytes = new byte[count];
            int offset = 0;
            while (offset < count)
            {
                stream.ReadTimeout = deadline.Remaining(operation);
                int received;
                try
                {
                    received = stream.Read(bytes, offset, count - offset);
                }
                catch (IOException ex)
                {
                    throw new IOException(operation + " failed: " + ex.Message, ex);
                }
                if (received == 0)
                    throw new EndOfStreamException(operation + " ended before the complete reply arrived.");
                offset += received;
            }
            return bytes;
        }

        internal static void Write(Stream stream, byte[] bytes, NetworkDeadline deadline, string operation)
        {
            stream.WriteTimeout = deadline.Remaining(operation);
            try
            {
                stream.Write(bytes, 0, bytes.Length);
            }
            catch (IOException ex)
            {
                throw new IOException(operation + " failed: " + ex.Message, ex);
            }
        }

        internal static NetworkStream OpenSocksTunnel(Socket socket, int socksPort, int destinationPort,
            NetworkDeadline deadline)
        {
            Connect(socket, new IPEndPoint(IPAddress.Loopback, socksPort), deadline);
            NetworkStream stream = new NetworkStream(socket, false);
            try
            {
                Write(stream, new byte[] { 5, 1, 0 }, deadline, "SOCKS5 greeting");
                byte[] greeting = ReadExact(stream, 2, deadline, "SOCKS5 method selection");
                if (greeting[0] != 5)
                    throw new IOException("The proxy returned an invalid SOCKS5 method-selection version.");
                if (greeting[1] == 255)
                    throw new IOException("The SOCKS5 proxy rejected no-authentication access.");
                if (greeting[1] != 0)
                    throw new IOException("The SOCKS5 proxy selected an unsupported authentication method.");

                // Literal IPv4 destination: the proxy carries DNS and TLS traffic.
                byte[] connect = new byte[] { 5, 1, 0, 1, 1, 1, 1, 1,
                    (byte)(destinationPort >> 8), (byte)destinationPort };
                Write(stream, connect, deadline, "SOCKS5 CONNECT request");
                byte[] reply = ReadExact(stream, 4, deadline, "SOCKS5 CONNECT reply");
                if (reply[0] != 5)
                    throw new IOException("The proxy returned an invalid SOCKS5 CONNECT version.");
                if (reply[2] != 0)
                    throw new IOException("The proxy returned a nonzero SOCKS5 reserved byte.");
                int addressLength;
                if (reply[3] == 1)
                    addressLength = 4;
                else if (reply[3] == 4)
                    addressLength = 16;
                else if (reply[3] == 3)
                {
                    addressLength = ReadExact(stream, 1, deadline, "SOCKS5 bound-address length")[0];
                    if (addressLength == 0)
                        throw new IOException("The proxy returned an empty SOCKS5 bound address.");
                }
                else
                    throw new IOException("The proxy returned an invalid SOCKS5 address type.");

                // Consume the complete BND.ADDR and BND.PORT before returning the tunnel.
                ReadExact(stream, addressLength + 2, deadline, "SOCKS5 bound address and port");
                if (reply[1] != 0)
                    throw new IOException("SOCKS5 CONNECT failed: " + ReplyName(reply[1]) + ".");
                return stream;
            }
            catch
            {
                stream.Dispose();
                throw;
            }
        }

        private static string ReplyName(byte reply)
        {
            switch (reply)
            {
                case 1: return "general proxy failure (REP 1)";
                case 2: return "connection forbidden by proxy rules (REP 2)";
                case 3: return "network unreachable (REP 3)";
                case 4: return "host unreachable (REP 4)";
                case 5: return "connection refused (REP 5)";
                case 6: return "TTL expired (REP 6)";
                case 7: return "command unsupported (REP 7)";
                case 8: return "address type unsupported (REP 8)";
                default: return "invalid reply code " + reply;
            }
        }

        internal static void Close(Socket socket)
        {
            if (socket == null) return;
            try { socket.Close(); }
            catch (ObjectDisposedException) { }
            catch (SocketException) { }
        }
    }

    internal static class DnsProtocol
    {
        internal const int MaximumMessage = 65535;
        internal const int MaximumUdpMessage = 65507;
        // AAAA records publish IPv6 addresses that Geph SOCKS implementations cannot dial.
        internal const int Ipv6AddressRecordType = 28;
        private const int Ipv6HintSvcParamKey = 6;

        internal static int ReadUInt16(byte[] bytes, int offset)
        {
            return (bytes[offset] << 8) | bytes[offset + 1];
        }

        private static void WriteUInt16(byte[] bytes, int offset, int value)
        {
            bytes[offset] = (byte)(value >> 8);
            bytes[offset + 1] = (byte)value;
        }

        private static bool SkipName(byte[] bytes, ref int offset)
        {
            return WalkName(bytes, ref offset, null);
        }

        private static bool WalkName(byte[] bytes, ref int offset, List<byte> canonical)
        {
            return WalkName(bytes, ref offset, canonical, true);
        }

        private static bool WalkName(byte[] bytes, ref int offset, List<byte> canonical, bool foldCase)
        {
            int cursor = offset;
            int next = -1;
            int expandedLength = 1;
            int pointerHops = 0;
            // A legal 255-octet name can contain 127 one-octet labels. Count
            // compression hops separately so a pointer to that name remains
            // valid. Expanded length and bounded backward hops limit work and
            // reject cycles without confusing labels with compression depth.
            while (cursor < bytes.Length)
            {
                int length = bytes[cursor++];
                if (length == 0)
                {
                    if (canonical != null) canonical.Add(0);
                    offset = next >= 0 ? next : cursor;
                    return true;
                }
                if ((length & 192) == 192)
                {
                    if (cursor >= bytes.Length || ++pointerHops > 128) return false;
                    int pointer = ((length & 63) << 8) | bytes[cursor++];
                    if (pointer < 12 || pointer >= cursor - 2) return false;
                    if (next < 0) next = cursor;
                    cursor = pointer;
                }
                else
                {
                    if ((length & 192) != 0 || length > 63 || cursor + length > bytes.Length)
                        return false;
                    expandedLength += length + 1;
                    if (expandedLength > 255) return false;
                    if (canonical != null)
                    {
                        canonical.Add((byte)length);
                        for (int i = 0; i < length; ++i)
                        {
                            byte value = bytes[cursor + i];
                            if (foldCase && value >= 65 && value <= 90) value = (byte)(value + 32);
                            canonical.Add(value);
                        }
                    }
                    cursor += length;
                }
            }
            return false;
        }

        private static bool ValidateSections(byte[] bytes, out int questionEnd)
        {
            questionEnd = 12;
            if (bytes == null || bytes.Length < 12 || bytes.Length > MaximumMessage)
                return false;
            int offset = 12;
            int questions = ReadUInt16(bytes, 4);
            for (int i = 0; i < questions; ++i)
            {
                if (!SkipName(bytes, ref offset) || offset + 4 > bytes.Length) return false;
                offset += 4;
            }
            questionEnd = offset;
            int records = ReadUInt16(bytes, 6) + ReadUInt16(bytes, 8) + ReadUInt16(bytes, 10);
            for (int i = 0; i < records; ++i)
            {
                if (!SkipName(bytes, ref offset) || offset + 10 > bytes.Length) return false;
                int length = ReadUInt16(bytes, offset + 8);
                offset += 10;
                if (length > bytes.Length - offset) return false;
                offset += length;
            }
            return offset == bytes.Length;
        }

        internal static bool ValidateQuery(byte[] query, out int questionEnd)
        {
            questionEnd = 12;
            if (query == null || query.Length < 12 || query.Length > MaximumMessage) return false;
            // This local resolver supports ordinary, single-question DNS queries.
            // Only RD, AD, and CD are meaningful for these ordinary queries.
            if ((query[2] & 254) != 0 || (query[3] & 207) != 0 || ReadUInt16(query, 4) != 1)
                return false;
            if (ReadUInt16(query, 6) != 0 || ReadUInt16(query, 8) != 0) return false;
            if (!ValidateSections(query, out questionEnd)) return false;
            int offset = questionEnd;
            bool optSeen = false;
            int records = ReadUInt16(query, 10);
            for (int i = 0; i < records; ++i)
            {
                int nameStart = offset;
                if (!SkipName(query, ref offset)) return false;
                if (ReadUInt16(query, offset) == 41)
                {
                    // OPT must have the root owner name, and only one OPT is allowed.
                    if (optSeen || query[nameStart] != 0) return false;
                    optSeen = true;
                    if (query[offset + 4] != 0) return false; // No extended response code in a query.
                    int option = offset + 10;
                    int optionEnd = option + ReadUInt16(query, offset + 8);
                    while (option < optionEnd)
                    {
                        if (option + 4 > optionEnd) return false;
                        int optionLength = ReadUInt16(query, option + 2);
                        option += 4;
                        if (optionLength > optionEnd - option) return false;
                        option += optionLength;
                    }
                }
                offset += 10 + ReadUInt16(query, offset + 8);
            }
            return true;
        }

        private static int FindOpt(byte[] query, int questionEnd)
        {
            int offset = questionEnd;
            int records = ReadUInt16(query, 10);
            for (int i = 0; i < records; ++i)
            {
                SkipName(query, ref offset);
                if (ReadUInt16(query, offset) == 41)
                    return offset;
                offset += 10 + ReadUInt16(query, offset + 8);
            }
            return -1;
        }

        internal static int UdpPayloadLimit(byte[] query, int questionEnd)
        {
            int opt = FindOpt(query, questionEnd);
            return opt < 0 ? 512 : Math.Min(MaximumUdpMessage, Math.Max(512, ReadUInt16(query, opt + 2)));
        }

        internal static bool UnsupportedEdnsVersion(byte[] query, int questionEnd)
        {
            int opt = FindOpt(query, questionEnd);
            return opt >= 0 && query[opt + 5] != 0;
        }

        internal static void ValidateResponse(byte[] response, byte[] query)
        {
            int questionEnd;
            if (response == null || response.Length < 12 || response.Length > MaximumMessage)
                throw new IOException("The DNS upstream returned an invalid message length.");
            if (response[0] != query[0] || response[1] != query[1])
                throw new IOException("The DNS upstream returned a mismatched transaction ID.");
            if ((response[2] & 128) == 0 || (response[2] & 120) != 0 || (response[3] & 64) != 0)
                throw new IOException("The DNS upstream returned an invalid response header.");
            if (ReadUInt16(response, 4) != 1 || !ValidateSections(response, out questionEnd))
                throw new IOException("The DNS upstream returned a malformed response.");
            List<byte> queryName = new List<byte>(256);
            List<byte> responseName = new List<byte>(256);
            int queryOffset = 12;
            int responseOffset = 12;
            if (!WalkName(query, ref queryOffset, queryName) ||
                !WalkName(response, ref responseOffset, responseName) ||
                queryName.Count != responseName.Count)
                throw new IOException("The DNS upstream returned a mismatched question.");
            for (int i = 0; i < queryName.Count; ++i)
                if (queryName[i] != responseName[i])
                    throw new IOException("The DNS upstream returned a mismatched question.");
            for (int i = 0; i < 4; ++i)
                if (query[queryOffset + i] != response[responseOffset + i])
                    throw new IOException("The DNS upstream returned a mismatched question type or class.");
            // Validate known resource data even when no AAAA record needs to be
            // removed. Otherwise malformed A/name/OPT data could pass unchanged
            // and even satisfy the connection-health DNS probe.
            int answers = ReadUInt16(response, 6);
            int authorities = ReadUInt16(response, 8);
            int records = answers + authorities + ReadUInt16(response, 10);
            int offset = questionEnd;
            bool optSeen = false;
            for (int i = 0; i < records; ++i)
            {
                int owner = offset;
                SkipName(response, ref offset);
                int type = ReadUInt16(response, offset);
                int end = offset + 10 + ReadUInt16(response, offset + 8);
                if (type == 41)
                {
                    if (optSeen || i < answers + authorities || response[owner] != 0)
                        throw new IOException("The DNS upstream returned an invalid OPT record.");
                    optSeen = true;
                    if (response[offset + 5] != 0)
                        throw new IOException("The DNS upstream returned an unsupported EDNS version.");
                }
                ReadRdata(response, offset, end, null);
                offset = end;
            }
        }

        internal static int ResponseCode(byte[] response)
        {
            int questionEnd;
            if (!ValidateSections(response, out questionEnd))
                throw new IOException("The DNS upstream returned a malformed response.");
            int offset = questionEnd;
            int records = ReadUInt16(response, 6) + ReadUInt16(response, 8) + ReadUInt16(response, 10);
            for (int i = 0; i < records; ++i)
            {
                SkipName(response, ref offset);
                if (ReadUInt16(response, offset) == 41)
                    return (response[offset + 4] << 4) | (response[3] & 15);
                offset += 10 + ReadUInt16(response, offset + 8);
            }
            return response[3] & 15;
        }

        internal static bool HasIpv4Answer(byte[] response)
        {
            int offset = 12;
            List<byte> name = new List<byte>(256);
            if (!WalkName(response, ref offset, name)) return false;
            string question = Convert.ToBase64String(name.ToArray());
            offset += 4;
            int answers = ReadUInt16(response, 6);
            HashSet<string> addresses = new HashSet<string>(StringComparer.Ordinal);
            Dictionary<string, List<string>> aliases = new Dictionary<string, List<string>>(StringComparer.Ordinal);
            for (int i = 0; i < answers; ++i)
            {
                name.Clear();
                if (!WalkName(response, ref offset, name)) return false;
                string owner = Convert.ToBase64String(name.ToArray());
                int type = ReadUInt16(response, offset);
                int recordClass = ReadUInt16(response, offset + 2);
                int length = ReadUInt16(response, offset + 8);
                if (type == 1 && recordClass == 1 && length == 4) addresses.Add(owner);
                if (type == 5 && recordClass == 1)
                {
                    int targetOffset = offset + 10;
                    name.Clear();
                    if (!WalkName(response, ref targetOffset, name)) return false;
                    List<string> targets;
                    if (!aliases.TryGetValue(owner, out targets))
                    {
                        targets = new List<string>();
                        aliases.Add(owner, targets);
                    }
                    targets.Add(Convert.ToBase64String(name.ToArray()));
                }
                offset += 10 + length;
            }
            // Follow only the queried name and its CNAME chain. An unrelated A
            // record or a CNAME-only answer does not prove IPv4 name resolution.
            HashSet<string> visited = new HashSet<string>(StringComparer.Ordinal);
            Queue<string> pending = new Queue<string>();
            pending.Enqueue(question);
            while (pending.Count > 0)
            {
                string current = pending.Dequeue();
                if (!visited.Add(current)) continue;
                if (addresses.Contains(current)) return true;
                List<string> targets;
                if (aliases.TryGetValue(current, out targets))
                    foreach (string target in targets) pending.Enqueue(target);
            }
            return false;
        }

        internal static byte[] Exchange(Stream stream, byte[] query, NetworkDeadline deadline)
        {
            byte[] framed = new byte[query.Length + 2];
            WriteUInt16(framed, 0, query.Length);
            Buffer.BlockCopy(query, 0, framed, 2, query.Length);
            NetworkIo.Write(stream, framed, deadline, "DNS-over-TCP query");
            byte[] prefix = NetworkIo.ReadExact(stream, 2, deadline, "DNS-over-TCP response length");
            int length = ReadUInt16(prefix, 0);
            if (length < 12 || length > MaximumMessage)
                throw new IOException("The DNS upstream returned an invalid frame length.");
            byte[] response = NetworkIo.ReadExact(stream, length, deadline, "DNS-over-TCP response");
            ValidateResponse(response, query);
            return response;
        }

        internal static byte[] ErrorResponse(byte[] query, int questionEnd, bool truncated)
        {
            return LocalResponse(query, questionEnd, truncated ? 0 : 2, truncated);
        }

        private static byte[] LocalResponse(byte[] query, int questionEnd, int resultCode, bool truncated)
        {
            int opt = FindOpt(query, questionEnd);
            byte[] response = new byte[questionEnd + (opt < 0 ? 0 : 11)];
            Buffer.BlockCopy(query, 0, response, 0, questionEnd);
            response[2] = (byte)(128 | (query[2] & 1) | (truncated ? 2 : 0));
            // Local policy answers are neither authoritative nor DNSSEC validated.
            response[3] = (byte)(128 | (query[3] & 16) | (resultCode & 15));
            WriteUInt16(response, 4, 1);
            WriteUInt16(response, 6, 0);
            WriteUInt16(response, 8, 0);
            WriteUInt16(response, 10, opt < 0 ? 0 : 1);
            if (opt >= 0)
            {
                // RFC 6891 requires OPT even for synthesized/truncated responses.
                // Advertise EDNS(0); do not blindly echo client option payloads.
                WriteUInt16(response, questionEnd + 1, 41);
                WriteUInt16(response, questionEnd + 3, MaximumUdpMessage);
                response[questionEnd + 5] = (byte)(resultCode >> 4);
                response[questionEnd + 7] = (byte)(query[opt + 6] & 128);
            }
            return response;
        }

        internal static int QueryType(byte[] query, int questionEnd)
        {
            return ReadUInt16(query, questionEnd - 4);
        }

        // A local policy empty answer for an AAAA question: applications keep
        // connecting over IPv4 instead of waiting for a proxy dial that ends in EOF.
        internal static byte[] NoDataResponse(byte[] query, int questionEnd)
        {
            return LocalResponse(query, questionEnd, 0, false);
        }

        internal static byte[] BadVersionResponse(byte[] query, int questionEnd)
        {
            return LocalResponse(query, questionEnd, 16, false);
        }

        private static void CopyRdataBytes(byte[] source, ref int offset, int end, int count,
            List<byte> destination)
        {
            if (count < 0 || count > end - offset)
                throw new IOException("The DNS upstream returned malformed resource data.");
            if (destination == null) offset += count;
            else for (int i = 0; i < count; ++i) destination.Add(source[offset++]);
        }

        private static void CopyRdataName(byte[] source, ref int offset, int end, List<byte> destination)
        {
            if (offset >= end || !WalkName(source, ref offset, destination, false) || offset > end)
                throw new IOException("The DNS upstream returned a malformed resource-data name.");
        }

        private static void ReadRdata(byte[] source, int header, int end, List<byte> expanded)
        {
            int offset = header + 10;
            int type = ReadUInt16(source, header);
            // A null destination validates in place without allocating copies of
            // payloads. Only an IPv6-filtered reply needs expanded record bytes.
            // RFC 3597: decompress the original well-known RDATA types and
            // legacy types that permitted compression. Unknown RDATA is opaque;
            // pointer-looking bytes in addresses, signatures or TXT are not names.
            switch (type)
            {
                case 2: case 3: case 4: case 5: case 7: case 8: case 9: case 12: case 39:
                    CopyRdataName(source, ref offset, end, expanded);
                    break;
                case 6: // SOA: two names, then five 32-bit numbers.
                    CopyRdataName(source, ref offset, end, expanded);
                    CopyRdataName(source, ref offset, end, expanded);
                    CopyRdataBytes(source, ref offset, end, 20, expanded);
                    break;
                case 14: case 17: // MINFO, RP
                    CopyRdataName(source, ref offset, end, expanded);
                    CopyRdataName(source, ref offset, end, expanded);
                    break;
                case 15: case 18: case 21: case 36: // MX, AFSDB, RT, KX
                    CopyRdataBytes(source, ref offset, end, 2, expanded);
                    CopyRdataName(source, ref offset, end, expanded);
                    break;
                case 24: case 46: // SIG, RRSIG
                    CopyRdataBytes(source, ref offset, end, 18, expanded);
                    CopyRdataName(source, ref offset, end, expanded);
                    CopyRdataBytes(source, ref offset, end, end - offset, expanded);
                    break;
                case 26: // PX
                    CopyRdataBytes(source, ref offset, end, 2, expanded);
                    CopyRdataName(source, ref offset, end, expanded);
                    CopyRdataName(source, ref offset, end, expanded);
                    break;
                case 30: // NXT
                    CopyRdataName(source, ref offset, end, expanded);
                    CopyRdataBytes(source, ref offset, end, end - offset, expanded);
                    break;
                case 33: // SRV
                    CopyRdataBytes(source, ref offset, end, 6, expanded);
                    CopyRdataName(source, ref offset, end, expanded);
                    break;
                case 35: // NAPTR: order/preference, three character strings, replacement.
                    CopyRdataBytes(source, ref offset, end, 4, expanded);
                    for (int i = 0; i < 3; ++i)
                    {
                        if (offset >= end)
                            throw new IOException("The DNS upstream returned malformed NAPTR resource data.");
                        CopyRdataBytes(source, ref offset, end, source[offset] + 1, expanded);
                    }
                    CopyRdataName(source, ref offset, end, expanded);
                    break;
                case 41: // EDNS options are a sequence of code/length/value tuples.
                    while (offset < end)
                    {
                        if (end - offset < 4)
                            throw new IOException("The DNS upstream returned malformed EDNS option data.");
                        int optionLength = ReadUInt16(source, offset + 2);
                        CopyRdataBytes(source, ref offset, end, 4 + optionLength, expanded);
                    }
                    break;
                default:
                    if (type == 1 && ReadUInt16(source, header + 2) == 1 && end - offset != 4)
                        throw new IOException("The DNS upstream returned a malformed IPv4 address record.");
                    if (type == Ipv6AddressRecordType && ReadUInt16(source, header + 2) == 1 && end - offset != 16)
                        throw new IOException("The DNS upstream returned a malformed IPv6 address record.");
                    CopyRdataBytes(source, ref offset, end, end - offset, expanded);
                    break;
            }
            if (offset != end)
                throw new IOException("The DNS upstream returned trailing resource data.");
        }

        // Rebuild filtered messages using expanded names from the original wire
        // image. A kept record can refer to a name inside a removed AAAA record;
        // merely deleting bytes would corrupt that reference or leak IPv6 data.
        internal static byte[] RemoveIpv6Records(byte[] response)
        {
            int questionEnd;
            if (!ValidateSections(response, out questionEnd))
                throw new IOException("The DNS upstream returned a malformed response.");

            int answers = ReadUInt16(response, 6);
            int authorities = ReadUInt16(response, 8);
            int additionals = ReadUInt16(response, 10);
            int total = answers + authorities + additionals;
            int[] starts = new int[total];
            int[] headers = new int[total];
            int[] ends = new int[total];
            bool[] remove = new bool[total];
            bool[] svcParams = new bool[total];
            bool anySvcParams = false;
            int removed = 0;
            int offset = questionEnd;
            for (int i = 0; i < total; ++i)
            {
                starts[i] = offset;
                SkipName(response, ref offset);
                headers[i] = offset;
                int type = ReadUInt16(response, offset);
                int dataLength = ReadUInt16(response, offset + 8);
                remove[i] = type == Ipv6AddressRecordType ||
                    ((type == 24 || type == 46) && dataLength >= 2 &&
                    ReadUInt16(response, offset + 10) == Ipv6AddressRecordType);
                // HTTPS/SVCB records carry literal IPv6 targets in the ipv6hint
                // SvcParam; they survive only through parameter filtering.
                svcParams[i] = type == 64 || type == 65;
                if (svcParams[i]) anySvcParams = true;
                offset += 10 + dataLength;
                ends[i] = offset;
                if (remove[i]) ++removed;
            }
            if (removed == 0 && !anySvcParams) return response;

            List<byte> filtered = new List<byte>(response.Length);
            for (int i = 0; i < questionEnd; ++i) filtered.Add(response[i]);
            int[] kept = new int[3];
            for (int i = 0; i < total; ++i)
            {
                if (remove[i]) continue;
                offset = starts[i];
                List<byte> rdata = new List<byte>(ends[i] - headers[i] - 10);
                if (svcParams[i])
                {
                    if (!TryCopySvcRdataWithoutIpv6Hint(response, headers[i], ends[i], rdata))
                        continue; // Unparseable SVCB/HTTPS data is dropped, not passed through.
                }
                else
                {
                    ReadRdata(response, headers[i], ends[i], rdata);
                }
                if (!WalkName(response, ref offset, filtered, false))
                    throw new IOException("The DNS upstream returned a malformed owner name.");
                if (rdata.Count > MaximumMessage)
                    throw new IOException("DNS resource data is too large after IPv6 filtering.");
                for (int j = 0; j < 8; ++j) filtered.Add(response[headers[i] + j]);
                filtered.Add((byte)(rdata.Count >> 8));
                filtered.Add((byte)rdata.Count);
                filtered.AddRange(rdata);
                if (filtered.Count > MaximumMessage)
                    throw new IOException("The DNS response is too large after IPv6 filtering.");
                ++kept[i < answers ? 0 : (i < answers + authorities ? 1 : 2)];
            }
            byte[] result = filtered.ToArray();
            WriteUInt16(result, 6, kept[0]);
            WriteUInt16(result, 8, kept[1]);
            WriteUInt16(result, 10, kept[2]);
            // A modified answer cannot inherit upstream authority or DNSSEC assertions.
            result[2] = (byte)(result[2] & ~4);
            result[3] = (byte)(result[3] & ~32);
            return result;
        }

        // RFC 9460 SVCB/HTTPS RDATA is a 2-byte SvcPriority, an uncompressed
        // TargetName, then SvcParam entries (2-byte key, 2-byte length, value).
        // Compression pointers are not permitted inside SVCB RDATA, so a pointer
        // byte marks the record invalid. The ipv6hint parameter (key 6) carries
        // literal IPv6 addresses that the tunnel cannot dial, so it is removed;
        // other parameters are preserved only when their mandatory-key contract
        // remains valid. Invalid/incompatible records are dropped, not weakened.
        private static bool TryCopySvcRdataWithoutIpv6Hint(byte[] source, int header, int end, List<byte> destination)
        {
            int offset = header + 10;
            if (offset < 0 || end > source.Length || end - offset < 3) return false;
            destination.Add(source[offset]);
            destination.Add(source[offset + 1]);
            offset += 2;
            int nameBytes = 0;
            for (;;)
            {
                if (offset >= end) return false;
                int labelLength = source[offset];
                if (labelLength > 63 || offset + labelLength >= end) return false;
                nameBytes += labelLength + 1;
                if (nameBytes > 255) return false;
                for (int i = 0; i <= labelLength; ++i) destination.Add(source[offset + i]);
                offset += labelLength + 1;
                if (labelLength == 0) break;
            }
            HashSet<int> keys = new HashSet<int>();
            List<int> mandatory = new List<int>();
            int previousKey = -1;
            while (offset < end)
            {
                if (end - offset < 4) return false;
                int key = ReadUInt16(source, offset);
                int valueLength = ReadUInt16(source, offset + 2);
                if (key <= previousKey || key == 65535 || end - offset - 4 < valueLength) return false;
                previousKey = key;
                keys.Add(key);
                int valueStart = offset + 4;
                if (key == 0)
                {
                    // RFC 9460 section 8: nonempty, sorted unique 16-bit keys;
                    // mandatory cannot require itself and each key must exist.
                    if (valueLength == 0 || (valueLength & 1) != 0) return false;
                    int previousMandatory = -1;
                    for (int i = 0; i < valueLength; i += 2)
                    {
                        int required = ReadUInt16(source, valueStart + i);
                        if (required == 0 || required == 65535 || required <= previousMandatory) return false;
                        // Removing a required IPv6 hint makes this record incompatible.
                        // Drop the RR; do not silently weaken its mandatory contract.
                        if (required == Ipv6HintSvcParamKey) return false;
                        mandatory.Add(required);
                        previousMandatory = required;
                    }
                }
                if (key == Ipv6HintSvcParamKey)
                {
                    if (valueLength == 0 || valueLength % 16 != 0) return false;
                }
                else
                {
                    for (int i = 0; i < 4 + valueLength; ++i) destination.Add(source[offset + i]);
                }
                offset += 4 + valueLength;
            }
            foreach (int required in mandatory) if (!keys.Contains(required)) return false;
            return true;
        }

        internal static byte[] ProbeQuery()
        {
            byte[] query = new byte[] { 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
                7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1 };
            byte[] id = new byte[2];
            using (RandomNumberGenerator random = RandomNumberGenerator.Create()) random.GetBytes(id);
            query[0] = id[0];
            query[1] = id[1];
            return query;
        }
    }

    public static class ProxyProbe
    {
        public static string Test(int port)
        {
            NetworkIo.ValidatePort(port);
            return TestTls(port, true);
        }

        public static string TestDirect()
        {
            return TestTls(0, false);
        }

        private static string TestTls(int port, bool throughSocks)
        {
            Stopwatch watch = Stopwatch.StartNew();
            try
            {
                using (Socket socket = NetworkIo.NewTcpSocket())
                {
                    NetworkDeadline deadline = new NetworkDeadline(NetworkIo.TimeoutMilliseconds);
                    NetworkStream transport;
                    if (throughSocks)
                        transport = NetworkIo.OpenSocksTunnel(socket, port, 443, deadline);
                    else
                    {
                        NetworkIo.Connect(socket, new IPEndPoint(IPAddress.Parse("1.1.1.1"), 443), deadline);
                        transport = new NetworkStream(socket, false);
                    }
                    using (transport)
                    using (SslStream tls = new SslStream(transport, false))
                    {
                        tls.ReadTimeout = NetworkIo.TimeoutMilliseconds;
                        tls.WriteTimeout = NetworkIo.TimeoutMilliseconds;
                        // No validation callback: use the operating system trust store and hostname checks.
                        // false is the standard AuthenticateAsClient default for online revocation checks.
                        IAsyncResult pending = tls.BeginAuthenticateAsClient("one.one.one.one", null,
                            SslProtocols.Tls12, false, null, null);
                        WaitHandle completed = null;
                        try
                        {
                            if (!pending.IsCompleted)
                            {
                                completed = pending.AsyncWaitHandle;
                                if (!completed.WaitOne(deadline.Remaining("TLS authentication")))
                                {
                                    NetworkIo.Close(socket);
                                    throw new TimeoutException("TLS authentication for one.one.one.one timed out.");
                                }
                            }
                            tls.EndAuthenticateAsClient(pending);
                        }
                        finally { if (completed != null) completed.Dispose(); }
                        if (!tls.IsAuthenticated || !tls.IsEncrypted)
                            throw new AuthenticationException("The TLS session is not authenticated and encrypted.");
                        return (throughSocks ? "SOCKS5 CONNECT" : "Direct routed TCP") +
                            " to 1.1.1.1:443 and verified TLS for one.one.one.one succeeded (" +
                            tls.SslProtocol + "; " + watch.ElapsedMilliseconds + " ms).";
                    }
                }
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException((throughSocks ? "SOCKS proxy probe" : "Routed TLS probe") +
                    " failed: " + ex.Message, ex);
            }
        }

        public static string TestDns(int port)
        {
            NetworkIo.ValidatePort(port);
            Stopwatch watch = Stopwatch.StartNew();
            try
            {
                using (Socket socket = NetworkIo.NewTcpSocket())
                {
                    NetworkDeadline deadline = new NetworkDeadline(NetworkIo.TimeoutMilliseconds);
                    using (NetworkStream stream = NetworkIo.OpenSocksTunnel(socket, port, 53, deadline))
                    {
                        byte[] response = DnsProtocol.Exchange(stream, DnsProtocol.ProbeQuery(), deadline);
                        int resultCode = DnsProtocol.ResponseCode(response);
                        if (resultCode != 0)
                            throw new IOException("The DNS probe received response code " + resultCode + ".");
                        if ((response[2] & 2) != 0)
                            throw new IOException("The DNS probe received a truncated TCP response.");
                        if (!DnsProtocol.HasIpv4Answer(response))
                            throw new IOException("The DNS probe received no IPv4 answer records.");
                        return "SOCKS5 CONNECT and DNS-over-TCP to 1.1.1.1:53 succeeded (" +
                            watch.ElapsedMilliseconds + " ms).";
                    }
                }
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("SOCKS DNS probe failed: " + ex.Message, ex);
            }
        }
    }

    public sealed class SocksDnsRelay : IDisposable
    {
        private const int MaximumWorkers = 16;
        private const int MaximumTcpQueries = 64;
        private readonly object gate = new object();
        private readonly HashSet<Socket> activeSockets = new HashSet<Socket>();
        private readonly Queue<RelayWork> pendingWork = new Queue<RelayWork>();
        private readonly Thread[] workerThreads = new Thread[MaximumWorkers];
        private readonly int socksPort;
        private Socket udpSocket;
        private Socket tcpListener;
        private Thread udpThread;
        private Thread tcpThread;
        private volatile bool stopping;
        private volatile bool listenerFault;
        private volatile string lastError = "";
        private int activeWorkers;
        private int highWaterWorkers;
        private long rejectedRequests;
        private long upstreamFailures;
        private volatile string lastErrorUtc = "";

        private sealed class RelayWork
        {
            internal WaitCallback Callback;
            internal object State;
        }

        private sealed class UdpWork
        {
            internal byte[] Query;
            internal int QuestionEnd;
            internal int UdpLimit;
            internal IPEndPoint Client;
        }

        private SocksDnsRelay(int port)
        {
            socksPort = port;
        }

        public static SocksDnsRelay Start(int socksPort)
        {
            NetworkIo.ValidatePort(socksPort);
            SocksDnsRelay relay = new SocksDnsRelay(socksPort);
            try
            {
                relay.udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                relay.udpSocket.ExclusiveAddressUse = true;
                // CloseAllSockets interrupts the blocking receive during stop.
                // No polling timeout is needed while the listener is idle.
                relay.udpSocket.SendTimeout = 1000;
                relay.udpSocket.ReceiveBufferSize = 65536;
                relay.udpSocket.Bind(new IPEndPoint(IPAddress.Loopback, 53));

                relay.tcpListener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                relay.tcpListener.ExclusiveAddressUse = true;
                relay.tcpListener.Bind(new IPEndPoint(IPAddress.Loopback, 53));
                relay.tcpListener.Listen(MaximumWorkers);

                // Blocking client/proxy I/O must not occupy the shared .NET
                // ThreadPool: socket completion work also needs that pool.
                // Fixed relay-owned workers keep both progress and resources
                // bounded when slow clients coexist with fresh DNS requests.
                for (int i = 0; i < MaximumWorkers; ++i)
                {
                    relay.workerThreads[i] = new Thread(relay.WorkLoop);
                    relay.workerThreads[i].IsBackground = true;
                    relay.workerThreads[i].Name = "GephTun DNS worker " + (i + 1);
                    relay.workerThreads[i].Start();
                }
                relay.udpThread = new Thread(relay.UdpLoop);
                relay.udpThread.IsBackground = true;
                relay.udpThread.Name = "GephTun DNS UDP";
                relay.tcpThread = new Thread(relay.TcpLoop);
                relay.tcpThread.IsBackground = true;
                relay.tcpThread.Name = "GephTun DNS TCP";
                relay.udpThread.Start();
                relay.tcpThread.Start();
                return relay;
            }
            catch (Exception ex)
            {
                relay.Dispose();
                throw new InvalidOperationException("Could not start the DNS relay on IPv4 127.0.0.1:53: " +
                    ex.Message, ex);
            }
        }

        // Transient upstream errors are reported separately; malformed client packets do not alter health.
        public bool Healthy
        {
            get
            {
                if (stopping || listenerFault || udpThread == null || tcpThread == null ||
                    !udpThread.IsAlive || !tcpThread.IsAlive) return false;
                foreach (Thread thread in workerThreads)
                    if (thread == null || !thread.IsAlive) return false;
                return true;
            }
        }

        public string LastError { get { return lastError; } }
        public string LastErrorUtc { get { return lastErrorUtc; } }
        public int ActiveRequests { get { lock (gate) return activeWorkers; } }
        public int HighWaterRequests { get { lock (gate) return highWaterWorkers; } }
        public long RejectedRequests { get { return Interlocked.Read(ref rejectedRequests); } }
        public long UpstreamFailures { get { return Interlocked.Read(ref upstreamFailures); } }

        private bool TryBeginWork()
        {
            lock (gate)
            {
                if (stopping) return false;
                if (activeWorkers >= MaximumWorkers)
                {
                    Interlocked.Increment(ref rejectedRequests);
                    return false;
                }
                ++activeWorkers;
                if (activeWorkers > highWaterWorkers) highWaterWorkers = activeWorkers;
                return true;
            }
        }

        private void EndWork()
        {
            lock (gate)
            {
                --activeWorkers;
                Monitor.PulseAll(gate);
            }
        }

        private bool QueueWork(WaitCallback callback, object state)
        {
            lock (gate)
            {
                if (stopping) return false;
                // A slot is reserved before this call, so queued plus active
                // work can never exceed MaximumWorkers.
                pendingWork.Enqueue(new RelayWork { Callback = callback, State = state });
                Monitor.Pulse(gate);
                return true;
            }
        }

        private void WorkLoop()
        {
            while (true)
            {
                RelayWork work;
                lock (gate)
                {
                    while (!stopping && pendingWork.Count == 0) Monitor.Wait(gate);
                    if (stopping) return;
                    work = pendingWork.Dequeue();
                }
                try { work.Callback(work.State); }
                catch (Exception ex) { ListenerFailed("DNS worker failed", ex); }
                finally { EndWork(); }
            }
        }

        private bool Track(Socket socket)
        {
            lock (gate)
            {
                if (stopping) return false;
                activeSockets.Add(socket);
                return true;
            }
        }

        private void Untrack(Socket socket)
        {
            lock (gate) activeSockets.Remove(socket);
            NetworkIo.Close(socket);
        }

        private void RecordError(string stage, Exception error)
        {
            if (stopping) return;
            string message = stage + ": " + error.Message;
            lastError = message.Length <= 512 ? message : message.Substring(0, 512);
            lastErrorUtc = DateTime.UtcNow.ToString("o");
            if (stage == "DNS upstream request failed") Interlocked.Increment(ref upstreamFailures);
        }

        private void ListenerFailed(string stage, Exception error)
        {
            if (stopping) return;
            RecordError(stage, error);
            listenerFault = true;
            CloseAllSockets();
        }

        private void UdpLoop()
        {
            byte[] buffer = new byte[DnsProtocol.MaximumMessage];
            try
            {
                while (!stopping)
                {
                    EndPoint endpoint = new IPEndPoint(IPAddress.Any, 0);
                    int length;
                    try { length = udpSocket.ReceiveFrom(buffer, ref endpoint); }
                    catch (SocketException ex)
                    {
                        if (stopping) break;
                        if (ex.SocketErrorCode == SocketError.TimedOut ||
                            ex.SocketErrorCode == SocketError.ConnectionReset ||
                            ex.SocketErrorCode == SocketError.MessageSize) continue;
                        throw;
                    }
                    if (stopping) break;
                    IPEndPoint client = endpoint as IPEndPoint;
                    if (client == null || !IPAddress.IsLoopback(client.Address) || length < 12 ||
                        length > DnsProtocol.MaximumUdpMessage) continue;
                    byte[] query = new byte[length];
                    Buffer.BlockCopy(buffer, 0, query, 0, length);
                    int questionEnd;
                    if (!DnsProtocol.ValidateQuery(query, out questionEnd)) continue;
                    if (!TryBeginWork())
                    {
                        SendUdp(DnsProtocol.ErrorResponse(query, questionEnd, false), client);
                        continue;
                    }
                    UdpWork work = new UdpWork { Query = query, QuestionEnd = questionEnd,
                        UdpLimit = DnsProtocol.UdpPayloadLimit(query, questionEnd), Client = client };
                    bool queued = false;
                    try { queued = QueueWork(UdpWorker, work); }
                    finally { if (!queued) EndWork(); }
                }
            }
            catch (Exception ex) { ListenerFailed("DNS UDP listener failed", ex); }
        }

        private void SendUdp(byte[] response, IPEndPoint client)
        {
            if (stopping) return;
            try { udpSocket.SendTo(response, client); }
            catch (SocketException) { }
            catch (ObjectDisposedException) { }
        }

        private void UdpWorker(object state)
        {
            UdpWork work = (UdpWork)state;
            if (stopping) return;
            byte[] response;
            try
            {
                response = Resolve(work.Query, work.QuestionEnd);
                if (response.Length > work.UdpLimit)
                    response = DnsProtocol.ErrorResponse(work.Query, work.QuestionEnd, true);
            }
            catch (Exception ex)
            {
                RecordError("DNS upstream request failed", ex);
                response = DnsProtocol.ErrorResponse(work.Query, work.QuestionEnd, false);
            }
            SendUdp(response, work.Client);
        }

        private void TcpLoop()
        {
            try
            {
                while (!stopping)
                {
                    Socket client = tcpListener.Accept();
                    if (!TryBeginWork())
                    {
                        NetworkIo.Close(client);
                        continue;
                    }
                    if (!Track(client))
                    {
                        NetworkIo.Close(client);
                        EndWork();
                        continue;
                    }
                    bool queued = false;
                    try { queued = QueueWork(TcpWorker, client); }
                    finally
                    {
                        if (!queued)
                        {
                            Untrack(client);
                            EndWork();
                        }
                    }
                }
            }
            catch (Exception ex) { ListenerFailed("DNS TCP listener failed", ex); }
        }

        private void TcpWorker(object state)
        {
            Socket client = (Socket)state;
            try
            {
                if (stopping) return;
                using (NetworkStream stream = new NetworkStream(client, false))
                {
                    // DNS clients may reuse connections and pipeline frames.
                    // Process them in order with bounded memory: no per-client
                    // query queue, an eight-second idle/frame deadline, and a
                    // finite request count before the client must reconnect.
                    for (int request = 0; request < MaximumTcpQueries && !stopping; ++request)
                    {
                        NetworkDeadline readDeadline = new NetworkDeadline(NetworkIo.TimeoutMilliseconds);
                        byte[] prefix = NetworkIo.ReadExact(stream, 2, readDeadline, "Local DNS TCP frame length");
                        int length = DnsProtocol.ReadUInt16(prefix, 0);
                        if (length < 12 || length > DnsProtocol.MaximumMessage) return;
                        byte[] query = NetworkIo.ReadExact(stream, length, readDeadline, "Local DNS TCP query");
                        int questionEnd;
                        if (!DnsProtocol.ValidateQuery(query, out questionEnd)) return;
                        byte[] response;
                        try { response = Resolve(query, questionEnd); }
                        catch (Exception ex)
                        {
                            RecordError("DNS upstream request failed", ex);
                            response = DnsProtocol.ErrorResponse(query, questionEnd, false);
                        }
                        if (stopping) return;
                        byte[] framed = new byte[response.Length + 2];
                        framed[0] = (byte)(response.Length >> 8);
                        framed[1] = (byte)response.Length;
                        Buffer.BlockCopy(response, 0, framed, 2, response.Length);
                        NetworkIo.Write(stream, framed, new NetworkDeadline(NetworkIo.TimeoutMilliseconds),
                            "Local DNS TCP response");
                    }
                }
            }
            catch (IOException) { }
            catch (SocketException) { }
            catch (ObjectDisposedException) { }
            catch (TimeoutException) { }
            catch (Exception ex) { RecordError("DNS TCP client failed", ex); }
            finally
            {
                Untrack(client);
            }
        }

        // AAAA questions are answered locally and never reach the proxy: Geph
        // rejects IPv6 destinations, so applications must connect over IPv4.
        // Forwarded answers also lose any AAAA record, covering exotic queries
        // whose responses could still carry IPv6 addresses.
        private byte[] Resolve(byte[] query, int questionEnd)
        {
            if (DnsProtocol.UnsupportedEdnsVersion(query, questionEnd))
                return DnsProtocol.BadVersionResponse(query, questionEnd);
            if (DnsProtocol.QueryType(query, questionEnd) == DnsProtocol.Ipv6AddressRecordType)
                return DnsProtocol.NoDataResponse(query, questionEnd);
            return DnsProtocol.RemoveIpv6Records(Forward(query));
        }

        private byte[] Forward(byte[] query)
        {
            Socket socket = NetworkIo.NewTcpSocket();
            if (!Track(socket))
            {
                NetworkIo.Close(socket);
                throw new ObjectDisposedException("SocksDnsRelay");
            }
            try
            {
                NetworkDeadline deadline = new NetworkDeadline(NetworkIo.TimeoutMilliseconds);
                using (NetworkStream stream = NetworkIo.OpenSocksTunnel(socket, socksPort, 53, deadline))
                    return DnsProtocol.Exchange(stream, query, deadline);
            }
            finally { Untrack(socket); }
        }

        private void CloseAllSockets()
        {
            Socket[] sockets;
            lock (gate)
            {
                stopping = true;
                // Cancel reservations that have not been dispatched. Their TCP
                // sockets are part of the tracked snapshot closed below.
                activeWorkers -= pendingWork.Count;
                pendingWork.Clear();
                sockets = new Socket[activeSockets.Count];
                activeSockets.CopyTo(sockets);
                activeSockets.Clear();
                Monitor.PulseAll(gate);
            }
            NetworkIo.Close(udpSocket);
            NetworkIo.Close(tcpListener);
            foreach (Socket socket in sockets) NetworkIo.Close(socket);
        }

        public void Dispose()
        {
            CloseAllSockets();
            // Preserve the previous aggregate five-second shutdown budget, but
            // do not report successful disposal with live worker threads.
            NetworkDeadline shutdown = new NetworkDeadline(5000);
            JoinStoppedThread(udpThread, shutdown);
            JoinStoppedThread(tcpThread, shutdown);
            foreach (Thread thread in workerThreads) JoinStoppedThread(thread, shutdown);
            lock (gate)
            {
                if (activeWorkers != 0 || pendingWork.Count != 0)
                    throw new InvalidOperationException("DNS relay shutdown left unfinished work.");
            }
        }

        private static void JoinStoppedThread(Thread thread, NetworkDeadline shutdown)
        {
            if (thread == null || !thread.IsAlive) return;
            if (thread == Thread.CurrentThread || !thread.Join(shutdown.Remaining("DNS relay shutdown")))
                throw new TimeoutException("DNS relay shutdown could not stop a worker or listener.");
        }
    }
}
