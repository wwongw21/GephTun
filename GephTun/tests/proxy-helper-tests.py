#!/usr/bin/env python3
"""Offline security/behavior tests for the C# 5 GephTun network helper.

Only local sockets are used. The test PowerShell process receives a temporary
SSL_CERT_FILE containing a mock CA, allowing both positive certificate checks
and negative trust/hostname checks without altering the machine trust store.
No adapter, route, firewall, NRPT, DNS setting, or system certificate is changed.
"""
import argparse
import base64
import contextlib
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import queue
import random
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

RELAY_PORT = 53

# .NET on Windows ignores SSL_CERT_FILE and validates through the Windows
# certificate stores; the mock-CA trust cases run only where the environment
# variable is honored, because importing a test CA would mutate trust state.
TLS_ENVIRONMENT_SUPPORTED = sys.platform != 'win32'
TLS_CASE_NAMES = ('TLS trusted', 'TLS untrusted', 'TLS wrong_hostname', 'bounded timeout hang_tls')
TLS_TRUST_SKIP_REASON = ('Windows validates TLS against its certificate stores and does not honor the '
                         'test-process SSL_CERT_FILE/SSL_CERT_DIR mock CA; no machine trust store is changed.')


def exact(connection, length):
    data = bytearray()
    while len(data) < length:
        chunk = connection.recv(length - len(data))
        if not chunk:
            raise EOFError('socket closed')
        data.extend(chunk)
    return bytes(data)


def query(identifier=0x1234, edns=None, qtype=1, flags=0x0100, edns_ttl=0, options=b'',
          wire_name=b'\x07example\x03com\x00'):
    data = struct.pack('!HHHHHH', identifier, flags, 1, 0, 0, edns is not None)
    data += wire_name + struct.pack('!HH', qtype, 1)
    if edns is not None:
        data += b'\x00' + struct.pack('!HHIH', 41, edns, edns_ttl, len(options)) + options
    return data


def name_at(packet, offset):
    labels, next_offset, visited = [], None, set()
    while True:
        assert offset not in visited, 'compression cycle'
        visited.add(offset)
        length = packet[offset]
        if length & 0xc0 == 0xc0:
            pointer = ((length & 63) << 8) | packet[offset + 1]
            assert 12 <= pointer < offset, 'invalid compression pointer'
            next_offset = offset + 2 if next_offset is None else next_offset
            offset = pointer
        elif length == 0:
            return b'.'.join(labels), offset + 1 if next_offset is None else next_offset
        else:
            assert length < 64 and offset + length + 1 <= len(packet), 'invalid name label'
            labels.append(packet[offset + 1:offset + length + 1])
            offset += length + 1


def records_in(packet):
    _, offset = name_at(packet, 12)
    offset += 4
    records = []
    for section, count in enumerate(struct.unpack('!HHH', packet[6:12])):
        for _ in range(count):
            owner, offset = name_at(packet, offset)
            rtype, rclass, ttl, length = struct.unpack('!HHIH', packet[offset:offset + 10])
            offset += 10
            assert offset + length <= len(packet), 'resource data exceeds response'
            records.append(dict(section=section, owner=owner, type=rtype, rclass=rclass, ttl=ttl,
                                data=packet[offset:offset + length], data_offset=offset))
            offset += length
    assert offset == len(packet), 'trailing bytes in response'
    return records


def record(rtype, data, owner=b'\xc0\x0c', rclass=1, ttl=60):
    return owner + struct.pack('!HHIH', rtype, rclass, ttl, len(data)) + data


def legacy_rdata(name):
    single = {rtype: name for rtype in (2, 3, 4, 5, 7, 8, 9, 12, 39)}
    single.update({6: name + name + struct.pack('!IIIII', 1, 2, 3, 4, 5),
                   14: name + name, 17: name + name,
                   24: struct.pack('!HBBIIIH', 1, 8, 2, 60, 300, 1, 123) + name + b'\xc0\x1dSIGN',
                   26: b'\x00\x0a' + name + name,
                   30: name + b'\x40',
                   33: struct.pack('!HHH', 1, 2, 443) + name,
                   35: struct.pack('!HH', 1, 2) + b'\x01S\x00\x00' + name,
                   46: struct.pack('!HBBIIIH', 1, 8, 2, 60, 300, 1, 123) + name + b'\xc0\x1dSIGN'})
    single.update({rtype: b'\x00\x0a' + name for rtype in (15, 18, 21, 36)})
    return single


def response(request, mode):
    _, question_end = name_at(request, 12)
    question = request[12:question_end + 4]
    identifier = request[:2]
    if mode == 'wrong_id':
        identifier = bytes([identifier[0] ^ 1, identifier[1]])
    if mode == 'wrong_name':
        question = question[:1] + b'z' + question[2:]
    if mode == 'wrong_type':
        question = question[:-4] + b'\x00\x1c' + question[-2:]
    if mode == 'wrong_class':
        question = question[:-2] + b'\x00\x03'
    if mode == 'case_name':
        question = question[:1] + b'EXAMPLE' + question[8:]
    flags = 0x0100 if mode == 'wrong_qr' else 0x8180
    if mode == 'rcode':
        flags |= 2
    if mode == 'tcp_truncated':
        flags |= 0x0200
    malformed_rdata = {'bad_a': (1, b'\x01\x02\x03'),
        'bad_aaaa': (28, b'\x20' * 15), 'bad_cname': (5, b'\xc0'),
        'bad_soa': (6, b'\xc0\x0c\xc0\x0c' + b'\x00' * 19)}
    if mode in malformed_rdata:
        rtype, rdata = malformed_rdata[mode]
        return identifier + struct.pack('!HHHHH', flags, 1, 1, 0, 0) + question + record(rtype, rdata)
    if mode.startswith('opt_'):
        a = record(1, b'\x01\x02\x03\x04')
        options = b'\x00\x01\x00\x04X' if mode == 'opt_bad_length' else b''
        owner = b'\xc0\x0c' if mode == 'opt_nonroot' else b'\x00'
        ttl = {'opt_bad_version': 0x10000, 'opt_extended_error': 0x1000000}.get(mode, 0)
        opt = record(41, options, owner=owner, rclass=1232, ttl=ttl)
        if mode == 'opt_in_answer':
            return identifier + struct.pack('!HHHHH', flags, 1, 2, 0, 0) + question + a + opt
        opts = opt * (2 if mode == 'opt_duplicate' else 1)
        return identifier + struct.pack('!HHHHH', flags, 1, 1, 0, 2 if mode == 'opt_duplicate' else 1) + question + a + opts
    if mode in ('cname_only', 'cname_valid', 'cname_cycle', 'unrelated_a'):
        alias = b'\x05alias\x07example\x03com\x00'
        a = record(1, b'\x01\x02\x03\x04', owner=alias)
        cname = record(5, alias)
        if mode == 'cname_only':
            records, count = cname, 1
        elif mode == 'cname_valid':
            records, count = a + cname, 2  # Follow the chain regardless of record order.
        elif mode == 'unrelated_a':
            records, count = a, 1
        else:
            unrelated = record(1, b'\x01\x02\x03\x04', owner=b'\x05other\x00')
            records, count = cname + record(5, b'\xc0\x0c', owner=alias) + unrelated, 3
        return identifier + struct.pack('!HHHHH', flags, 1, count, 0, 0) + question + records
    if mode.startswith('aaaa_'):
        a = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + b'\x01\x02\x03\x04'
        aaaa = b'\xc0\x0c' + struct.pack('!HHIH', 28, 1, 60, 16) + b'\x20' + b'\x10' * 15
        count = 2
        if mode == 'aaaa_after':
            records = a + aaaa
        elif mode == 'aaaa_first':
            records = aaaa + a
        elif mode == 'aaaa_unsafe':
            # A literal owner name inside the first AAAA record that the later A
            # record compresses to: removing the AAAA would orphan that pointer.
            literal = b'\x05alias\x07example\x03com\x00'
            aaaa = literal + struct.pack('!HHIH', 28, 1, 60, 16) + b'\x20' + b'\x10' * 15
            records = aaaa + bytes((0xc0, 29)) + struct.pack('!HHIH', 1, 1, 60, 4) + b'\x01\x02\x03\x04'
        elif mode == 'aaaa_opaque':
            records = aaaa + record(16, b'\x06\xc0\x1dTEST') + record(65280, b'\xc0\x1dOPAQUE')
            count = 3
        elif mode == 'aaaa_signed':
            signature = struct.pack('!HBBIIIH', 28, 8, 2, 60, 300, 1, 123) + b'\x00SIGN'
            records = aaaa + a + record(46, signature) + record(46, b'\x00\x01' + signature[2:])
            count = 4
            flags |= 0x420
        elif mode == 'aaaa_legacy':
            literal = b'\x05Alias\x07Example\x03COM\x00'
            aaaa = record(28, b'\x20' + b'\x10' * 15, owner=literal)
            fixtures = legacy_rdata(b'\xc0\x1d')
            records = aaaa + b''.join(record(rtype, data) for rtype, data in fixtures.items())
            count = 1 + len(fixtures)
        elif mode == 'aaaa_malformed_rdata':
            records = aaaa + record(5, b'\xc0') + a
            count = 3
        elif mode == 'aaaa_overflow':
            records = aaaa + a * 3000
            count = 3001
        else:
            raise AssertionError('unknown IPv6 fixture ' + mode)
        return identifier + struct.pack('!HHHHH', flags, 1, count, 0, 0) + question + records
    answer_record = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + b'\x01\x02\x03\x04'
    records = 80 if mode == 'large' else 1
    data = identifier + struct.pack('!HHHHH', flags, 1, records, 0, 0) + question + answer_record * records
    if mode == 'max_frame':
        data = identifier + struct.pack('!HHHHH', flags, 1, 1, 0, 0) + question
        length = 65535 - len(data) - 12
        data += b'\xc0\x0c' + struct.pack('!HHIH', 65280, 1, 60, length) + b'\x00' * length
    return data


class MockSocks:
    def __init__(self, mode='ok', bind_type=1, tls_context=None, fragment=False, dns_delay=0):
        self.mode = mode
        self.bind_type = bind_type
        self.tls_context = tls_context
        self.fragment = fragment
        self.dns_delay = dns_delay
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(32)
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.sockets = set()
        self.total = 0
        self.active = 0
        self.peak = 0
        self.errors = []
        self.threads = []
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def send(self, connection, data):
        if self.fragment:
            for value in data:
                connection.sendall(bytes([value]))
                time.sleep(0.001)
        else:
            connection.sendall(data)

    def accept(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self.lock:
                self.sockets.add(connection)
                self.total += 1
                self.active += 1
                self.peak = max(self.peak, self.active)
            worker = threading.Thread(target=self.handle, args=(connection,), daemon=True)
            self.threads.append(worker)
            worker.start()

    def handle(self, connection):
        original = connection
        try:
            connection.settimeout(12)
            assert exact(connection, 3) == b'\x05\x01\x00', 'non-noauth greeting'
            if self.mode == 'hang_greeting':
                while connection.recv(1):
                    pass
                return
            greeting = {'greeting_version': b'\x04\x00', 'auth': b'\x05\x02',
                        'reject_auth': b'\x05\xff', 'truncated_greeting': b'\x05'}.get(self.mode, b'\x05\x00')
            self.send(connection, greeting)
            if self.mode in ('greeting_version', 'auth', 'reject_auth', 'truncated_greeting'):
                return
            connect = exact(connection, 10)
            assert connect[:8] == b'\x05\x01\x00\x01\x01\x01\x01\x01', 'wrong CONNECT target'
            destination_port = int.from_bytes(connect[8:], 'big')
            assert destination_port in (53, 443), 'unexpected target port'
            address = {1: b'\x7f\x00\x00\x01', 3: b'\x09localhost', 4: b'\x00' * 15 + b'\x01'}[self.bind_type]
            reply = b'\x05\x00\x00' + bytes([self.bind_type]) + address + b'\x12\x34'
            if self.mode == 'connect_version':
                reply = b'\x04' + reply[1:]
            elif self.mode == 'reserved':
                reply = reply[:2] + b'\x01' + reply[3:]
            elif self.mode == 'address_type':
                reply = reply[:3] + b'\x02' + reply[4:]
            elif self.mode == 'rep':
                reply = reply[:1] + b'\x05' + reply[2:]
            elif self.mode == 'unknown_rep':
                reply = reply[:1] + b'\x63' + reply[2:]
            elif self.mode == 'empty_domain':
                reply = b'\x05\x00\x00\x03\x00\x00\x00'
            elif self.mode == 'truncated_reply':
                reply = reply[:-1]
            self.send(connection, reply)
            if self.mode in ('connect_version', 'reserved', 'address_type', 'rep', 'unknown_rep',
                             'empty_domain', 'truncated_reply'):
                return
            if destination_port == 443:
                if self.mode == 'hang_tls':
                    while connection.recv(4096):
                        pass
                    return
                assert self.tls_context is not None, 'TLS context required'
                connection = self.tls_context.wrap_socket(connection, server_side=True)
                try:
                    connection.recv(1)
                except OSError:
                    pass
                return
            length = int.from_bytes(exact(connection, 2), 'big')
            request = exact(connection, length)
            if self.mode == 'stall':
                while connection.recv(1):
                    pass
                return
            if self.mode == 'short_frame':
                self.send(connection, b'\x00\x0b')
                return
            if self.mode == 'truncated_frame':
                self.send(connection, b'\x00\x64' + b'\x00' * 12)
                return
            if self.dns_delay and self.stop.wait(self.dns_delay):
                return
            answer = response(request, self.mode)
            if self.mode == 'drip_dns':
                for value in struct.pack('!H', len(answer)) + answer:
                    connection.sendall(bytes([value]))
                    if self.stop.wait(0.3):
                        return
                return
            self.send(connection, struct.pack('!H', len(answer)) + answer)
        except (EOFError, OSError, ssl.SSLError):
            pass
        except Exception as error:
            self.errors.append(str(error))
        finally:
            connection.close()
            with self.lock:
                self.sockets.discard(original)
                self.active -= 1

    def close(self):
        self.stop.set()
        self.listener.close()
        with self.lock:
            active = list(self.sockets)
        for connection in active:
            with contextlib.suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)
            connection.close()
        self.thread.join(1)
        for worker in self.threads:
            worker.join(0.5)

    def __enter__(self):
        return self

    def __exit__(self, exception_type, *_):
        self.close()
        if exception_type is None:
            assert not self.errors, self.errors


class Driver:
    def __init__(self, pwsh, source, ca_file, empty_ca_directory):
        # These flags must exist before pwsh starts. Its own startup/session
        # telemetry and update checks are unrelated to the offline mock peers.
        environment = dict(os.environ, SSL_CERT_FILE=str(ca_file), SSL_CERT_DIR=str(empty_ca_directory),
                           POWERSHELL_TELEMETRY_OPTOUT='1', DOTNET_CLI_TELEMETRY_OPTOUT='1',
                           POWERSHELL_UPDATECHECK='Off')
        policy_flags = ['-ExecutionPolicy', 'Bypass'] if sys.platform == 'win32' else []
        self.process = subprocess.Popen([pwsh, '-NoLogo', '-NoProfile', '-NonInteractive', *policy_flags, '-File',
            str(Path(__file__).with_name('proxy-helper-driver.ps1')), '-Source', str(source)],
            text=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
        self.lines = queue.Queue()

        def read_lines():
            for line in self.process.stdout:
                self.lines.put(line)
            self.lines.put(None)

        threading.Thread(target=read_lines, daemon=True).start()
        line = self.next_line()
        self.metadata = json.loads(line)
        assert self.metadata['ready']
        assert self.metadata['telemetryOptOutRequested'] and self.metadata['updateChecksDisabledRequested'], self.metadata

    def next_line(self):
        try:
            line = self.lines.get(timeout=30)
        except queue.Empty:
            self.process.kill()
            self.process.wait(timeout=5)
            raise RuntimeError('Network test driver exceeded its 30-second response deadline')
        if line is None:
            self.process.wait(timeout=5)
            raise RuntimeError(self.process.stderr.read() or 'Network test driver exited without a response')
        return line

    def call(self, operation, port=None, **arguments):
        self.process.stdin.write(json.dumps(dict(operation=operation, port=port, **arguments)) + '\n')
        self.process.stdin.flush()
        return json.loads(self.next_line())

    def close(self):
        if self.process.poll() is None:
            self.call('quit')
            self.process.wait(timeout=8)
        stderr = self.process.stderr.read()
        if stderr.strip():
            raise RuntimeError(stderr)


def certificates(directory):
    def run(*arguments):
        subprocess.run(['openssl', *arguments], check=True, capture_output=True, cwd=directory)
    run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=GephTun Test CA',
        '-addext', 'basicConstraints=critical,CA:TRUE', '-keyout', 'ca.key', '-out', 'ca.pem')
    contexts = {}
    for label, hostname in [('trusted', 'one.one.one.one'), ('wrong_hostname', 'wrong.invalid')]:
        run('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=' + hostname,
            '-keyout', label + '.key', '-out', label + '.csr')
        (directory / (label + '.ext')).write_text('basicConstraints=critical,CA:FALSE\n'
            'keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n'
            'subjectAltName=DNS:' + hostname + '\n')
        run('x509', '-req', '-in', label + '.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial',
            '-days', '1', '-out', label + '.pem', '-extfile', label + '.ext')
    run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=one.one.one.one',
        '-addext', 'subjectAltName=DNS:one.one.one.one', '-keyout', 'untrusted.key', '-out', 'untrusted.pem')
    for label in ('trusted', 'wrong_hostname', 'untrusted'):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(directory / (label + '.pem'), directory / (label + '.key'))
        contexts[label] = context
    return contexts


def udp_exchange(packet, timeout=3):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.settimeout(timeout)
        connection.sendto(packet, ('127.0.0.1', RELAY_PORT))
        return connection.recv(65535)


def tcp_exchange(packet, fragment=False):
    with socket.create_connection(('127.0.0.1', RELAY_PORT), timeout=3) as connection:
        data = struct.pack('!H', len(packet)) + packet
        if fragment:
            for value in data:
                connection.sendall(bytes([value]))
                time.sleep(0.001)
        else:
            connection.sendall(data)
        length = int.from_bytes(exact(connection, 2), 'big')
        result = exact(connection, length)
        return result


def wire_item(packet, answer=None):
    return dict(query=base64.b64encode(packet).decode('ascii'),
                response=None if answer is None else base64.b64encode(answer).decode('ascii'))


def wire_batch(driver, items):
    value = assert_ok(driver.call('wire_batch', items=items))
    return value if isinstance(value, list) else [value]


def assert_ok(result):
    assert result['ok'], result.get('error')
    return result['result']


def assert_fails(result, phrase):
    assert not result['ok'], 'operation unexpectedly succeeded'
    assert phrase.lower() in result['error'].lower(), result['error']


def prepare_tcp_bind(connection):
    # Linux retains closed TCP pairs in TIME_WAIT; allow a fresh listener to
    # reuse that port. On Windows, SO_REUSEADDR would weaken exclusive binding.
    if sys.platform != 'win32':
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


def main():
    global RELAY_PORT
    parser = argparse.ArgumentParser()
    parser.add_argument('--pwsh', required=True)
    parser.add_argument('--source', type=Path, default=Path(__file__).parents[1] / 'GephTun.Network.cs')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--relay-port', type=int, default=53,
                        help='For a sandbox denying port53, change only the two bind literals in a temporary test copy.')
    args = parser.parse_args()
    RELAY_PORT = args.relay_port
    # A stalled TLS peer never presents a certificate. Its timeout fixture
    # needs neither a mock CA nor OpenSSL and therefore runs on every host.
    tls_trust_skip_reason = None
    if not TLS_ENVIRONMENT_SUPPORTED:
        tls_trust_skip_reason = TLS_TRUST_SKIP_REASON
    elif shutil.which('openssl') is None:
        tls_trust_skip_reason = ('OpenSSL is unavailable for temporary mock-certificate generation; '
                                 'the three certificate trust/hostname fixtures are skipped. '
                                 'No machine trust store is changed.')
    tls_trust_supported = tls_trust_skip_reason is None
    verification = dict(sourceFile=args.source.name,
        sourceSha256=hashlib.sha256(args.source.read_bytes()).hexdigest(),
        testScriptFile=Path(__file__).name,
        testScriptSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        driverSha256=hashlib.sha256(Path(__file__).with_name('proxy-helper-driver.ps1').read_bytes()).hexdigest())
    verification['declaredTlsCases'] = list(TLS_CASE_NAMES)
    verification['tlsTrustSkipReason'] = tls_trust_skip_reason
    verification['tlsTrustCases'] = tls_trust_supported
    verification['Sources'] = [dict(Path='GephTun.Network.cs', Sha256=verification['sourceSha256']),
        dict(Path='tests/proxy-helper-tests.py', Sha256=verification['testScriptSha256']),
        dict(Path='tests/proxy-helper-driver.ps1', Sha256=verification['driverSha256'])]
    if args.output:
        args.output.write_text(json.dumps(dict(verification, complete=False, total=0, passed=0, failed=0,
                                              skipped=0, coverageComplete=False, tests=[]), indent=2) + '\n')
    results = []

    def counts(complete=False):
        passed = sum(result['result'] == 'PASS' for result in results)
        failed = sum(result['result'] == 'FAIL' for result in results)
        skipped = sum(result['result'] == 'SKIP' for result in results)
        return dict(total=len(results), passed=passed, failed=failed, skipped=skipped,
                    coverageComplete=complete and skipped == 0)

    def case(name, action, skip_reason=None):
        if skip_reason is not None:
            result = dict(name=name, result='SKIP', passed=False, reason=skip_reason, elapsedSeconds=0)
            results.append(result)
            print(json.dumps(result), flush=True)
            return
        started = time.monotonic()
        try:
            metrics = action()
        except Exception as error:
            results.append(dict(name=name, result='FAIL', passed=False, error=str(error),
                                elapsedSeconds=round(time.monotonic() - started, 3)))
            if args.output:
                args.output.write_text(json.dumps(dict(verification, complete=False, tests=results,
                                                      **counts()), indent=2) + '\n')
            raise
        result = dict(name=name, result='PASS', passed=True, elapsedSeconds=round(time.monotonic() - started, 3))
        if isinstance(metrics, dict):
            result['metrics'] = metrics
        results.append(result)
        print(json.dumps(result), flush=True)

    with tempfile.TemporaryDirectory(prefix='proxy-helper-') as temporary:
        directory = Path(temporary)
        contexts = certificates(directory) if tls_trust_supported else {}
        empty = directory / 'empty-ca-directory'
        empty.mkdir()
        original_driver = Driver(args.pwsh, args.source, directory / 'ca.pem', empty)
        original_driver.close()
        test_source = args.source
        if RELAY_PORT != 53:
            original_text = args.source.read_text()
            literal = 'new IPEndPoint(IPAddress.Loopback, 53)'
            assert original_text.count(literal) == 2
            test_source = directory / 'proxy-helper-unprivileged.cs'
            test_source.write_text(original_text.replace(literal,
                'new IPEndPoint(IPAddress.Loopback, ' + str(RELAY_PORT) + ')'))
        driver = Driver(args.pwsh, test_source, directory / 'ca.pem', empty)
        try:
            cases = [('greeting_version', 'version'), ('auth', 'authentication'), ('reject_auth', 'no-authentication'),
                     ('truncated_greeting', 'complete'), ('connect_version', 'version'), ('reserved', 'reserved'),
                     ('address_type', 'address type'), ('rep', 'refused'), ('unknown_rep', 'reply code'),
                     ('empty_domain', 'empty'), ('truncated_reply', 'complete')]
            for mode, phrase in cases:
                def run(mode=mode, phrase=phrase):
                    with MockSocks(mode) as server:
                        assert_fails(driver.call('probe', server.port), phrase)
                        assert not server.errors, server.errors
                case('SOCKS rejects ' + mode, run)

            for address_type in (1, 3, 4):
                def run(address_type=address_type):
                    with MockSocks(bind_type=address_type, fragment=True) as server:
                        assert_ok(driver.call('dns', server.port))
                        assert not server.errors, server.errors
                case('partial reads and complete bind reply ATYP ' + str(address_type), run)

            for label in ('trusted', 'untrusted', 'wrong_hostname'):
                def run(label=label):
                    with MockSocks(tls_context=contexts[label], fragment=True) as server:
                        result = driver.call('probe', server.port)
                        if label == 'trusted':
                            assert 'verified TLS' in assert_ok(result)
                        else:
                            assert_fails(result, 'certificate')
                        assert not server.errors, server.errors
                case('TLS ' + label, run, tls_trust_skip_reason)

            for mode in ('hang_greeting', 'hang_tls'):
                def run(mode=mode):
                    with MockSocks(mode) as server:
                        started = time.monotonic()
                        result = driver.call('probe', server.port)
                        assert not result['ok']
                        assert 6.5 < time.monotonic() - started < 11, result
                case('bounded timeout ' + mode, run)

            for mode, phrase in [('wrong_id', 'transaction ID'), ('wrong_name', 'question'),
                                 ('wrong_type', 'question type'), ('wrong_class', 'question type'),
                                 ('wrong_qr', 'header'), ('rcode', 'response code'),
                                 ('short_frame', 'frame length'), ('truncated_frame', 'complete')]:
                def run(mode=mode, phrase=phrase):
                    with MockSocks(mode) as server:
                        assert_fails(driver.call('dns', server.port), phrase)
                case('DNS rejects ' + mode, run)

            def casefold():
                with MockSocks('case_name') as server:
                    assert_ok(driver.call('dns', server.port))
            case('DNS response names allow ASCII case folding', casefold)

            def maximum_legal_name():
                packet = query(wire_name=b'\x01a' * 127 + b'\x00')
                answer = response(packet, 'ok')
                result = wire_batch(driver, [wire_item(packet, answer)])[0]
                assert result['valid'], result
                assert base64.b64decode(result['filtered']) == answer
                with MockSocks() as server:
                    assert_ok(driver.call('start', server.port))
                    try:
                        for actual in (udp_exchange(packet), tcp_exchange(packet, fragment=True)):
                            assert records_in(actual)[0]['owner'] == b'.'.join([b'a'] * 127)
                    finally:
                        driver.call('dispose')
            case('255-octet DNS name remains valid when compressed in an answer', maximum_legal_name)

            invalid_upstream = [('bad_a', 'IPv4'), ('bad_aaaa', 'IPv6'),
                ('bad_cname', 'resource-data name'), ('bad_soa', 'resource data'),
                ('opt_bad_length', 'resource data'), ('opt_duplicate', 'OPT'),
                ('opt_in_answer', 'OPT'), ('opt_nonroot', 'OPT'), ('opt_bad_version', 'EDNS version')]
            for mode, phrase in invalid_upstream:
                def run(mode=mode, phrase=phrase):
                    with MockSocks(mode) as server:
                        assert_fails(driver.call('dns', server.port), phrase)
                        assert_ok(driver.call('start', server.port))
                        try:
                            for answer in (udp_exchange(query()), tcp_exchange(query())):
                                assert answer[3] & 15 == 2, (mode, answer.hex())
                                assert int.from_bytes(answer[6:8], 'big') == 0
                            assert assert_ok(driver.call('status'))['healthy']
                        finally:
                            driver.call('dispose')
                case('upstream ' + mode + ' is rejected before forwarding or healthy-probe success', run)

            for mode, phrase in [('opt_extended_error', 'response code 16'),
                                 ('tcp_truncated', 'truncated'), ('cname_only', 'no IPv4'),
                                 ('unrelated_a', 'no IPv4'), ('cname_cycle', 'no IPv4')]:
                def run(mode=mode, phrase=phrase):
                    with MockSocks(mode) as server:
                        assert_fails(driver.call('dns', server.port), phrase)
                case('DNS health probe rejects ' + mode, run)

            def cname_probe():
                with MockSocks('cname_valid') as server:
                    assert_ok(driver.call('dns', server.port))
            case('DNS health probe follows CNAME to IPv4 independent of record order', cname_probe)

            def adversarial_wire():
                rng = random.Random(0x47657068)
                corpus = []
                seeds = [query(), query(edns=1232), query(qtype=28),
                         query(wire_name=b'\x01a' * 127 + b'\x00')]
                for index in range(2048):
                    packet = bytearray(seeds[index % len(seeds)])
                    for _ in range(rng.randint(1, 6)):
                        packet[rng.randrange(len(packet))] = rng.randrange(256)
                    if index % 3 == 0:
                        packet = packet[:rng.randrange(len(packet))]
                    elif index % 7 == 0:
                        packet.extend(rng.randbytes(rng.randrange(33)))
                    corpus.append(wire_item(bytes(packet)))
                answer_seeds = [response(query(), mode) for mode in
                    ('ok', 'aaaa_signed', 'aaaa_legacy', 'aaaa_opaque', 'opt_duplicate', 'cname_valid')]
                for index in range(2048):
                    answer = bytearray(answer_seeds[index % len(answer_seeds)])
                    for _ in range(rng.randint(1, 6)):
                        answer[rng.randrange(len(answer))] = rng.randrange(256)
                    if index % 3 == 0:
                        answer = answer[:rng.randrange(len(answer))]
                    corpus.append(wire_item(query(), bytes(answer)))
                accepted_queries, accepted_answers, rejected = 0, 0, 0
                for start in range(0, len(corpus), 128):
                    batch = corpus[start:start + 128]
                    output = wire_batch(driver, batch)
                    assert len(output) == len(batch)
                    for sent, result in zip(batch, output):
                        assert result.get('errorType', 'System.IO.IOException') == 'System.IO.IOException', result
                        if result['valid'] and sent['response'] is not None:
                            answer = base64.b64decode(result['filtered'])
                            assert len(answer) <= 65535
                            assert all(entry['type'] != 28 for entry in records_in(answer))
                            accepted_answers += 1
                        elif result['valid']:
                            accepted_queries += 1
                        else:
                            rejected += 1
                assert accepted_answers > 0 and accepted_queries > 0 and rejected > 3000
                return dict(seed='0x47657068', mutatedQueries=2048, mutatedResponses=2048,
                            acceptedQueries=accepted_queries, acceptedResponses=accepted_answers, rejected=rejected)
            case('4096 deterministic adversarial wire mutations stay bounded and reject safely', adversarial_wire)

            def dns_drip_deadline():
                with MockSocks('drip_dns') as server:
                    started = time.monotonic()
                    result = driver.call('dns', server.port)
                    elapsed = time.monotonic() - started
                    assert not result['ok'], result
                    assert 6.5 < elapsed < 11, elapsed
                    return dict(elapsedSeconds=round(elapsed, 3), totalDeadlineSeconds=8)
            case('trickled DNS framing consumes one overall deadline instead of resetting on every byte', dns_drip_deadline)

            def aaaa_intercepted():
                with MockSocks() as server:
                    assert_ok(driver.call('start', server.port))
                    try:
                        packet = query(qtype=28)
                        for reply in (udp_exchange(packet), tcp_exchange(packet)):
                            assert reply[:2] == packet[:2]
                            assert reply[2] & 0x80 and reply[3] & 15 == 0
                            assert int.from_bytes(reply[6:8], 'big') == 0
                            assert reply[12:] == packet[12:] and len(reply) == 29
                        assert server.total == 0
                        assert assert_ok(driver.call('status'))['healthy']
                    finally:
                        driver.call('dispose')
            case('AAAA queries get an empty local answer without any proxy connection', aaaa_intercepted)

            def aaaa_filtered():
                aaaa = b'\xc0\x0c' + struct.pack('!HHIH', 28, 1, 60, 16) + b'\x20' + b'\x10' * 15
                for mode in ('aaaa_after', 'aaaa_first'):
                    with MockSocks(mode) as server:
                        assert_ok(driver.call('start', server.port))
                        try:
                            for reply in (udp_exchange(query()), tcp_exchange(query())):
                                assert int.from_bytes(reply[6:8], 'big') == 1
                                assert int.from_bytes(reply[8:10], 'big') == 0
                                assert aaaa not in reply and b'\x01\x02\x03\x04' in reply
                                records = records_in(reply)
                                assert len(records) == 1 and records[0]['type'] == 1
                                assert records[0]['owner'] == b'example.com'
                        finally:
                            driver.call('dispose')
                        assert not server.errors, server.errors
            case('relayed responses keep A records and drop upstream AAAA records', aaaa_filtered)

            def aaaa_unsafe():
                with MockSocks('aaaa_unsafe') as server:
                    assert_ok(driver.call('start', server.port))
                    try:
                        reply = tcp_exchange(query())
                        records = records_in(reply)
                        assert len(records) == 1 and records[0]['type'] == 1
                        assert records[0]['owner'] == b'alias.example.com'
                        assert records[0]['data'] == b'\x01\x02\x03\x04'
                    finally:
                        driver.call('dispose')
            case('AAAA removal preserves an owner name compressed into the removed record', aaaa_unsafe)

            def opaque_data():
                with MockSocks('aaaa_opaque') as server:
                    assert_ok(driver.call('start', server.port))
                    try:
                        for reply in (udp_exchange(query()), tcp_exchange(query())):
                            records = records_in(reply)
                            assert [entry['type'] for entry in records] == [16, 65280]
                            assert records[0]['data'] == b'\x06\xc0\x1dTEST'
                            assert records[1]['data'] == b'\xc0\x1dOPAQUE'
                    finally:
                        driver.call('dispose')
            case('pointer-like TXT and unknown RDATA bytes do not bypass AAAA filtering', opaque_data)

            def compressed_rdata():
                with MockSocks('aaaa_legacy') as server:
                    assert_ok(driver.call('start', server.port))
                    try:
                        reply = tcp_exchange(query())
                        records = records_in(reply)
                        expected = legacy_rdata(b'\x05Alias\x07Example\x03COM\x00')
                        assert len(records) == len(expected)
                        for entry in records:
                            assert entry['owner'] == b'example.com'
                            assert entry['data'] == expected[entry['type']], entry
                        assert not server.errors, server.errors
                    finally:
                        driver.call('dispose')
            case('AAAA filtering expands legacy compressed RDATA names and preserves name case', compressed_rdata)

            def signed_answer():
                with MockSocks('aaaa_signed') as server:
                    assert_ok(driver.call('start', server.port))
                    try:
                        for reply in (udp_exchange(query()), tcp_exchange(query())):
                            records = records_in(reply)
                            assert not reply[2] & 4, 'modified answer claimed upstream authority'
                            assert not reply[3] & 0x20, 'modified answer claimed DNSSEC authentication'
                            assert [entry['type'] for entry in records] == [1, 46]
                            assert records[1]['data'][:2] == b'\x00\x01'
                    finally:
                        driver.call('dispose')
            case('modified replies clear AD and remove signatures that cover removed AAAA records', signed_answer)

            for mode in ('aaaa_malformed_rdata', 'aaaa_overflow'):
                def run(mode=mode):
                    with MockSocks(mode) as server:
                        assert_ok(driver.call('start', server.port))
                        try:
                            reply = tcp_exchange(query())
                            assert reply[3] & 15 == 2 and records_in(reply) == []
                            assert assert_ok(driver.call('status'))['healthy']
                        finally:
                            driver.call('dispose')
                case('AAAA filtering returns SERVFAIL on ' + mode, run)

            def local_edns():
                with MockSocks() as server:
                    assert_ok(driver.call('start', server.port))
                    try:
                        packet = query(qtype=28, flags=0x0130, edns=1232, edns_ttl=0x8000,
                                       options=b'\xfd\xe8\x00\x03ABC')
                        for reply in (udp_exchange(packet), tcp_exchange(packet)):
                            assert reply[2] & 4 == 0 and reply[3] & 32 == 0
                            assert reply[3] & 16 and reply[3] & 15 == 0
                            records = records_in(reply)
                            assert len(records) == 1 and records[0]['type'] == 41
                            assert records[0]['section'] == 2 and records[0]['owner'] == b''
                            assert records[0]['ttl'] == 0x8000 and records[0]['data'] == b''
                        for qtype in (1, 28):
                            packet = query(qtype=qtype, edns=1232, edns_ttl=0x18000)
                            for reply in (udp_exchange(packet), tcp_exchange(packet)):
                                records = records_in(reply)
                                assert reply[3] & 15 == 0
                                assert len(records) == 1 and records[0]['type'] == 41
                                assert records[0]['ttl'] == 0x01008000, 'expected EDNS(0) BADVERS with DO'
                        assert server.total == 0
                    finally:
                        driver.call('dispose')
            case('synthetic EDNS replies preserve DO/CD and negotiate unsupported versions with BADVERS', local_edns)

            def listener_release():
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, socket.socket() as tcp:
                    udp.bind(('127.0.0.1', RELAY_PORT))
                    prepare_tcp_bind(tcp)
                    tcp.bind(('127.0.0.1', RELAY_PORT))
                    tcp.listen(1)
            case('disposed relay releases both listeners for exclusive restart', listener_release)

            def partial_bind_cleanup():
                with socket.socket() as blocker, MockSocks() as server:
                    prepare_tcp_bind(blocker)
                    blocker.bind(('127.0.0.1', RELAY_PORT))
                    blocker.listen(1)
                    assert_fails(driver.call('start', server.port), '127.0.0.1:53')
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as verify:
                        verify.bind(('127.0.0.1', RELAY_PORT))
            case('failed TCP bind releases earlier UDP bind', partial_bind_cleanup)

            def relay_roundtrip():
                with MockSocks(fragment=True) as server:
                    assert assert_ok(driver.call('start', server.port))['healthy']
                    try:
                        packet = query()
                        for reply in (udp_exchange(packet), tcp_exchange(packet, fragment=True)):
                            assert reply[:2] == packet[:2]
                            assert reply[3] & 15 == 0
                            assert int.from_bytes(reply[6:8], 'big') == 1
                        assert server.total == 2
                    finally:
                        assert not assert_ok(driver.call('dispose'))['healthy']
            case('loopback UDP and fragmented TCP roundtrip preserve transaction IDs', relay_roundtrip)

            def malformed_clients():
                with MockSocks() as server:
                    assert_ok(driver.call('start', server.port))
                    try:
                        packets = [b'\x00', b'\x00' * 12, query()[:2] + b'\x81' + query()[3:],
                                   query()[:12] + b'\xc0\x0c\x00\x01\x00\x01', query() + b'\x00',
                                   *(query(flags=flags) for flags in (0x0500, 0x0300, 0x0180, 0x0140, 0x0102)),
                                   query(edns=1232, options=b'\x00'),
                                   query(edns=1232, options=b'\x00\x01\x00\x04X'),
                                   query(edns=1232, edns_ttl=0x01000000)]
                        for packet in packets:
                            try:
                                udp_exchange(packet, timeout=0.1)
                                raise AssertionError('malformed UDP query received a response')
                            except socket.timeout:
                                pass
                            with socket.create_connection(('127.0.0.1', RELAY_PORT), timeout=2) as connection:
                                connection.sendall(struct.pack('!H', len(packet)) + packet)
                                try:
                                    assert connection.recv(1) == b''
                                except ConnectionResetError:
                                    pass
                        for prefix in (b'\x00\x00', b'\x00\x0b'):
                            with socket.create_connection(('127.0.0.1', RELAY_PORT), timeout=2) as connection:
                                connection.sendall(prefix)
                                assert connection.recv(1) == b''
                        assert server.total == 0
                        assert assert_ok(driver.call('status'))['healthy']
                    finally:
                        driver.call('dispose')
            case('malformed UDP/TCP names, header flags, EDNS options and short frames are dropped', malformed_clients)

            def truncated_answers():
                with MockSocks('large') as server:
                    assert_ok(driver.call('start', server.port))
                    try:
                        ordinary = udp_exchange(query())
                        small_edns = udp_exchange(query(edns=1232))
                        large_edns = udp_exchange(query(edns=4096))
                        tcp = tcp_exchange(query())
                        assert len(ordinary) <= 512 and ordinary[2] & 2
                        assert len(small_edns) <= 1232 and small_edns[2] & 2
                        assert len(records_in(small_edns)) == 1 and records_in(small_edns)[0]['type'] == 41
                        assert len(large_edns) > 1232 and not large_edns[2] & 2
                        assert len(tcp) == len(large_edns)
                    finally:
                        driver.call('dispose')
            case('UDP honors default512 and EDNS size with TCP retry', truncated_answers)

            def maximum_frame():
                with MockSocks('max_frame') as server:
                    assert_ok(driver.call('start', server.port))
                    try:
                        assert len(tcp_exchange(query())) == 65535
                        answer = udp_exchange(query(edns=65535))
                        assert len(answer) <= 65507 and answer[2] & 2
                    finally:
                        driver.call('dispose')
            case('65535-byte DNS frame is bounded; UDP truncates transport overflow', maximum_frame)

            def servfail():
                with MockSocks('wrong_id') as server:
                    assert_ok(driver.call('start', server.port))
                    try:
                        packet = query()
                        result = udp_exchange(packet)
                        assert result[:2] == packet[:2] and result[3] & 15 == 2
                        status = assert_ok(driver.call('status'))
                        assert status['healthy'] and 'transaction ID' in status['error']
                        assert 'example' not in status['error'].lower()
                        for result in (udp_exchange(query(edns=1232)), tcp_exchange(query(edns=1232))):
                            assert result[3] & 15 == 2
                            records = records_in(result)
                            assert len(records) == 1 and records[0]['type'] == 41
                    finally:
                        driver.call('dispose')
            case('upstream error yields SERVFAIL without changing listener health or logging query', servfail)

            def pipeline_reuse():
                with MockSocks(fragment=True) as server:
                    assert_ok(driver.call('start', server.port))
                    try:
                        with socket.create_connection(('127.0.0.1', RELAY_PORT), timeout=5) as client:
                            packets = [query(0x5000 + index, edns=1232, qtype=28 if index % 3 == 0 else 1)
                                       for index in range(64)]
                            framed = b''.join(struct.pack('!H', len(packet)) + packet for packet in packets)
                            # Vary segment sizes across both two-byte lengths and DNS bodies.
                            sizes, offset = (1, 7, 2, 127, 3, 64), 0
                            while offset < len(framed):
                                size = sizes[offset % len(sizes)]
                                client.sendall(framed[offset:offset + size])
                                offset += size
                            for packet in packets:
                                answer = exact(client, int.from_bytes(exact(client, 2), 'big'))
                                assert answer[:2] == packet[:2]
                                expected = 0 if packet[25:27] == b'\x00\x1c' else 1
                                assert int.from_bytes(answer[6:8], 'big') == expected
                            assert client.recv(1) == b'', 'connection exceeded its 64-request bound'
                        assert tcp_exchange(query(0x6000))[:2] == b'\x60\x00'
                        assert server.total == 43  # 42 forwarded in the pipeline, plus reconnect.
                    finally:
                        driver.call('dispose')
                return dict(pipelinedRequests=64, upstreamRequests=43, connectionRequestLimit=64)
            case('64 segmented pipelined UDP-sized DNS queries preserve order; client reconnect works', pipeline_reuse)

            def tcp_reuse_after_error():
                with MockSocks('wrong_id') as server:
                    assert_ok(driver.call('start', server.port))
                    try:
                        with socket.create_connection(('127.0.0.1', RELAY_PORT), timeout=3) as client:
                            first, second = query(91), query(92, qtype=28)
                            client.sendall(struct.pack('!H', len(first)) + first)
                            result = exact(client, int.from_bytes(exact(client, 2), 'big'))
                            assert result[3] & 15 == 2
                            client.sendall(struct.pack('!H', len(second)) + second)
                            result = exact(client, int.from_bytes(exact(client, 2), 'big'))
                            assert result[:2] == second[:2] and result[3] & 15 == 0
                            client.sendall(b'\x00\x00')
                            assert client.recv(1) == b'', 'invalid later frame must close only its client'
                        assert assert_ok(driver.call('status'))['healthy']
                    finally:
                        driver.call('dispose')
            case('reused TCP recovers from upstream SERVFAIL and rejects a later malformed frame', tcp_reuse_after_error)

            def idle_tcp_timeout():
                with MockSocks() as server:
                    assert_ok(driver.call('start', server.port))
                    try:
                        with socket.create_connection(('127.0.0.1', RELAY_PORT), timeout=11) as client:
                            packet = query(qtype=28)
                            client.sendall(struct.pack('!H', len(packet)) + packet)
                            exact(client, int.from_bytes(exact(client, 2), 'big'))
                            started = time.monotonic()
                            assert client.recv(1) == b''
                            elapsed = time.monotonic() - started
                            assert 6.5 < elapsed < 11, elapsed
                        status = assert_ok(driver.call('status'))
                        assert status['healthy'] and status['workers'] == 0, status
                    finally:
                        driver.call('dispose')
                return dict(idleTimeoutSeconds=round(elapsed, 3), workersAfterTimeout=0)
            case('idle reusable TCP client is reclaimed within the eight-second deadline', idle_tcp_timeout)

            def sustained_mixed_load():
                latencies = []
                failures = []
                with MockSocks() as server:
                    assert_ok(driver.call('start', server.port))
                    try:
                        def exchange(index):
                            packet = query(0x7000 + index, qtype=28 if index % 4 == 0 else 1,
                                           edns=1232 if index % 3 == 0 else None)
                            started = time.monotonic()
                            answer = tcp_exchange(packet) if index % 2 else udp_exchange(packet)
                            latencies.append(time.monotonic() - started)
                            if answer[:2] != packet[:2] or answer[3] & 15 != 0:
                                failures.append(dict(index=index, responseCode=answer[3] & 15,
                                                     actualId=answer[:2].hex(), expectedId=packet[:2].hex()))
                                return
                            expected = 0 if index % 4 == 0 else 1
                            assert int.from_bytes(answer[6:8], 'big') == expected
                            assert all(entry['type'] != 28 for entry in records_in(answer))
                        started = time.monotonic()
                        with ThreadPoolExecutor(max_workers=8) as pool:
                            list(pool.map(exchange, range(512)))
                        elapsed = time.monotonic() - started
                        deadline = time.monotonic() + 2
                        status = assert_ok(driver.call('status'))
                        while status['workers'] and time.monotonic() < deadline:
                            time.sleep(0.02)
                            status = assert_ok(driver.call('status'))
                        assert status['healthy'] and status['workers'] == 0 and status['sockets'] == 0, status
                        assert not failures, (failures, status, server.peak)
                        assert server.total == 384 and server.peak <= 16, (server.total, server.peak)
                    finally:
                        driver.call('dispose')
                ordered = sorted(latencies)
                return dict(requests=512, concurrentClients=8, upstreamRequests=384,
                    peakUpstreamConnections=server.peak, elapsedSeconds=round(elapsed, 3),
                    medianLatencyMs=round(ordered[len(ordered) // 2] * 1000, 3),
                    p95LatencyMs=round(ordered[int(len(ordered) * .95)] * 1000, 3),
                    maximumLatencyMs=round(ordered[-1] * 1000, 3), workersAfterLoad=0, socketsAfterLoad=0)
            case('512 mixed TCP/UDP, A/AAAA and EDNS requests finish correctly with bounded workers', sustained_mixed_load)

            def cold_dispatch(slow_tcp_clients, request_count, upstream_delay):
                # A fresh process prevents earlier tests from warming the shared
                # CLR ThreadPool and hiding blocking-I/O scheduling starvation.
                cold = Driver(args.pwsh, test_source, directory / 'ca.pem', empty)
                clients, replies = [], []
                try:
                    with MockSocks(dns_delay=upstream_delay) as server, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                        startup_started = time.monotonic()
                        assert_ok(cold.call('start', server.port))
                        startup_elapsed = time.monotonic() - startup_started
                        startup = assert_ok(cold.call('status'))
                        assert startup['workerThreadsAlive'] == 16 and startup['listenerThreadsAlive'] == 2, startup
                        for _ in range(slow_tcp_clients):
                            client = socket.create_connection(('127.0.0.1', RELAY_PORT), timeout=2)
                            client.sendall(b'\x00')
                            clients.append(client)
                        started = time.monotonic()
                        for identifier in range(request_count):
                            udp.sendto(query(identifier), ('127.0.0.1', RELAY_PORT))
                        while len(replies) < request_count:
                            remaining = 3 - (time.monotonic() - started)
                            assert remaining > 0, 'admitted loopback requests stalled behind shared-pool work'
                            udp.settimeout(remaining)
                            packet = udp.recv(65535)
                            replies.append((int.from_bytes(packet[:2], 'big'), packet[3] & 15))
                        elapsed = time.monotonic() - started
                        assert len({entry[0] for entry in replies}) == request_count
                        successful = sum(code == 0 for _, code in replies)
                        rejected = sum(code == 2 for _, code in replies)
                        assert successful + rejected == request_count
                        assert successful == server.total, 'a request admitted to the healthy proxy failed'
                        if slow_tcp_clients:
                            assert successful == request_count and rejected == 0
                        else:
                            assert successful >= 16 and server.peak <= 16, (successful, server.peak)
                        for client in clients:
                            client.close()
                        stopped = assert_ok(cold.call('dispose'))
                        assert not stopped['healthy'] and stopped['workers'] == 0 and stopped['sockets'] == 0
                        assert stopped['queued'] == 0 and stopped['workerThreadsAlive'] == 0 and stopped['listenerThreadsAlive'] == 0, stopped
                        assert assert_ok(cold.call('start', server.port))['healthy']
                        stopped = assert_ok(cold.call('dispose'))
                        assert stopped['workerThreadsAlive'] == 0
                    return dict(freshProcess=True, slowTcpClients=slow_tcp_clients, udpRequests=request_count,
                                mockUpstreamDelaySeconds=upstream_delay, successful=successful, overloadServfail=rejected,
                                upstreamConnections=server.total, peakUpstreamConnections=server.peak,
                                maximumBatchSeconds=round(elapsed, 3), startupSeconds=round(startup_elapsed, 3),
                                workerThreadsWhileRunning=16, listenerThreadsWhileRunning=2,
                                workerThreadsAfterDispose=0, listenerThreadsAfterDispose=0,
                                queuedAfterDispose=0, listenersRebound=True)
                finally:
                    for client in clients:
                        client.close()
                    cold.close()

            case('fresh relay serves eight DNS clients promptly alongside eight slow TCP clients',
                 lambda: cold_dispatch(8, 8, 0))
            case('fresh 32-query burst completes every admitted request despite a 200ms upstream delay',
                 lambda: cold_dispatch(0, 32, .2))

            def controlled_dispatch_lifecycle():
                # Internal synchronization injection makes pending cancellation
                # and an uncooperative callback reproducible. Real socket
                # overload/disposal is exercised separately below.
                checks = assert_ok(driver.call('dispatch_lifecycle'))
                assert len(checks) == 3 and all(check['result'] == 'PASS' for check in checks), checks
                return dict(internalSchedulingFixture=True, checks=checks)
            case('queued callbacks cancel; one shutdown deadline reports unfinished workers and retry joins them',
                 controlled_dispatch_lifecycle)

            def mixed_saturation():
                clients = []
                with MockSocks('stall') as server, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    assert_ok(driver.call('start', server.port))
                    try:
                        for _ in range(8):
                            client = socket.create_connection(('127.0.0.1', RELAY_PORT), timeout=2)
                            client.sendall(b'\x00')
                            clients.append(client)
                        for identifier in range(8):
                            udp.sendto(query(identifier), ('127.0.0.1', RELAY_PORT))
                        deadline = time.monotonic() + 4
                        status = assert_ok(driver.call('status'))
                        while (status['workers'] < 16 or server.active == 0) and time.monotonic() < deadline:
                            time.sleep(0.02)
                            status = assert_ok(driver.call('status'))
                        # Measure the admission cap here even if dispatch is in
                        # progress. Separate cold-process regressions above
                        # enforce prompt completion of admitted healthy traffic.
                        upstreams_at_saturation = server.active
                        assert status['workers'] == 16 and 1 <= upstreams_at_saturation <= 8, (status, server.active)
                        overload = udp_exchange(query(0x7777))
                        assert overload[:2] == b'\x77\x77' and overload[3] & 15 == 2
                        with socket.create_connection(('127.0.0.1', RELAY_PORT), timeout=2) as overflow:
                            assert overflow.recv(1) == b''
                        for client in clients:
                            client.close()
                        deadline = time.monotonic() + 2
                        status = assert_ok(driver.call('status'))
                        while (status['workers'] != 8 or server.active != 8) and time.monotonic() < deadline:
                            time.sleep(0.02)
                            status = assert_ok(driver.call('status'))
                        assert status['workers'] == 8 and server.active == 8, (status, server.active)
                        assert udp_exchange(query(qtype=28))[3] & 15 == 0
                    finally:
                        for client in clients:
                            client.close()
                        assert_ok(driver.call('dispose'))
                return dict(stalledTcpClients=8, queuedOrStalledUdpRequests=8, workerCeiling=16,
                            upstreamsStartedAtSaturation=upstreams_at_saturation,
                            activeUpstreamsAfterClientsClose=8, overloadServfail=True,
                            recoveredAfterClientsClose=True)
            case('mixed TCP slow clients and stalled UDP share16 slots; overload is bounded and recovers', mixed_saturation)

            def repeated_lifecycle():
                with MockSocks() as server:
                    for cycle in range(40):
                        assert assert_ok(driver.call('start', server.port))['healthy']
                        assert udp_exchange(query(cycle, qtype=28))[:2] == cycle.to_bytes(2, 'big')
                        assert tcp_exchange(query(cycle))[:2] == cycle.to_bytes(2, 'big')
                        stopped = assert_ok(driver.call('dispose'))
                        assert stopped['workerThreadsAlive'] == 0 and stopped['listenerThreadsAlive'] == 0 and stopped['workers'] == 0 and stopped['queued'] == 0, stopped
                    assert server.total == 40
                    deadline = time.monotonic() + 2
                    while server.active and time.monotonic() < deadline:
                        time.sleep(.02)
                    assert server.active == 0
                return dict(startStopCycles=40, requests=80, upstreamsAfterDisposal=0,
                            workerThreadsAfterEveryDispose=0, listenerThreadsAfterEveryDispose=0, queuedAfterEveryDispose=0)
            case('40 successive start/query/stop cycles release sockets and preserve listener restart', repeated_lifecycle)

            def concurrency_dispose():
                with MockSocks('stall') as server, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    assert_ok(driver.call('start', server.port))
                    for identifier in range(64):
                        client.sendto(query(identifier), ('127.0.0.1', RELAY_PORT))
                    deadline = time.monotonic() + 5
                    while server.active < 16 and time.monotonic() < deadline:
                        time.sleep(0.05)
                    status = assert_ok(driver.call('status'))
                    assert status['workers'] == 16, status
                    assert server.peak <= 16, server.peak
                    started = time.monotonic()
                    stopped = assert_ok(driver.call('dispose'))
                    assert stopped['workerThreadsAlive'] == 0 and stopped['listenerThreadsAlive'] == 0 and stopped['workers'] == 0 and stopped['queued'] == 0, stopped
                    assert time.monotonic() - started < 4
                    deadline = time.monotonic() + 2
                    while server.active and time.monotonic() < deadline:
                        time.sleep(0.02)
                    assert server.active == 0
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                        udp.bind(('127.0.0.1', RELAY_PORT))
                    with socket.socket() as tcp:
                        tcp.settimeout(1)
                        assert tcp.connect_ex(('127.0.0.1', RELAY_PORT)) != 0
                    # A raw Linux bind can be blocked by normal TCP TIME_WAIT;
                    # verify actual relay restart using its own socket options.
                    assert assert_ok(driver.call('start', server.port))['healthy']
                    assert_ok(driver.call('dispose'))
            case('64 UDP requests share16 workers; dispose closes stalled upstreams and listeners', concurrency_dispose)

            def local_tcp_dispose():
                with MockSocks() as server:
                    assert_ok(driver.call('start', server.port))
                    with socket.create_connection(('127.0.0.1', RELAY_PORT), timeout=3) as client:
                        client.sendall(b'\x00')
                        time.sleep(0.05)
                        assert_ok(driver.call('dispose'))
                        try:
                            assert client.recv(1) == b''
                        except ConnectionResetError:
                            pass  # Closing a socket with unread input may send TCP RST.
            case('dispose interrupts a partial local TCP frame', local_tcp_dispose)
        finally:
            driver.close()

    report = dict(verification, complete=True, runtime=driver.metadata, platform=sys.platform,
                  scope='offline mocks; no Windows adapters, routing, Geph service, or live internet tested',
                  relayListenerPort=RELAY_PORT,
                  productionSourceCompiledUnmodified=True,
                  relaySourcePortSubstitution=(RELAY_PORT != 53),
                  tlsTimeoutCaseExecuted=True,
                  tests=results, **counts(complete=True))
    if args.output:
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(counts(complete=True)), flush=True)


if __name__ == '__main__':
    main()
