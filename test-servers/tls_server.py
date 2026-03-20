#!/usr/bin/env python3
"""Evil TLS server for openssl s_client fuzzing.

Good mode: proper TLS server using Python ssl module.
Evil mode: raw TCP with malformed TLS records.
Both mode: alternates between good and evil via MalformationRotator.
"""

import argparse
import os
import socket
import socketserver
import ssl
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(__file__))
from tls_wrapper import add_tls_args, generate_cert, create_tls_context
from malformation_rotator import MalformationRotator


# ============================================================================
# TLS record helpers
# ============================================================================

# Content types
CT_CCS = 20
CT_ALERT = 21
CT_HANDSHAKE = 22
CT_APP_DATA = 23

# Handshake types
HT_SERVER_HELLO = 2

# TLS versions
VER_SSL30 = b'\x03\x00'
VER_TLS10 = b'\x03\x01'
VER_TLS12 = b'\x03\x03'


def _tls_record(content_type, version, payload):
    """Build a TLS record: type(1) + version(2) + length(2) + payload."""
    return struct.pack('!B', content_type) + version + struct.pack('!H', len(payload)) + payload


def _read_client_hello(conn):
    """Read and discard the ClientHello TLS record from the client."""
    try:
        conn.settimeout(5)
        # Read TLS record header: type(1) + version(2) + length(2) = 5 bytes
        header = b""
        while len(header) < 5:
            chunk = conn.recv(5 - len(header))
            if not chunk:
                return False
            header += chunk
        length = struct.unpack('!H', header[3:5])[0]
        # Read the payload
        payload = b""
        while len(payload) < length:
            chunk = conn.recv(length - len(payload))
            if not chunk:
                return False
            payload += chunk
        return True
    except Exception:
        return False


def _make_server_hello(cipher=b'\x00\x2f', version=VER_TLS12):
    """Build a minimal ServerHello handshake message.
    Default cipher: TLS_RSA_WITH_AES_128_CBC_SHA (0x002f).
    """
    server_random = os.urandom(32)
    session_id = b''
    compression = b'\x00'  # null compression

    body = version + server_random
    body += struct.pack('!B', len(session_id)) + session_id
    body += cipher
    body += compression

    # Handshake header: type(1) + length(3)
    handshake = struct.pack('!B', HT_SERVER_HELLO)
    handshake += struct.pack('!I', len(body))[1:]  # 3-byte length
    handshake += body

    return _tls_record(CT_HANDSHAKE, VER_TLS12, handshake)


# ============================================================================
# Evil malformation functions (12 total)
# ============================================================================

def evil_garbage_bytes(conn, state):
    """Send random non-TLS garbage bytes."""
    _read_client_hello(conn)
    conn.sendall(os.urandom(256))


def evil_truncated_server_hello(conn, state):
    """Send partial ServerHello, cut mid-record."""
    _read_client_hello(conn)
    hello = _make_server_hello()
    # Send only first 10 bytes of the record
    conn.sendall(hello[:10])


def evil_wrong_tls_version(conn, state):
    """ServerHello with SSLv2-era version (0x0200)."""
    _read_client_hello(conn)
    hello = _make_server_hello(version=b'\x02\x00')
    conn.sendall(hello)


def evil_oversized_record(conn, state):
    """TLS record with payload >16KB (protocol max)."""
    _read_client_hello(conn)
    # 20KB of random data as a handshake record
    payload = os.urandom(20000)
    record = _tls_record(CT_HANDSHAKE, VER_TLS12, payload)
    conn.sendall(record)


def evil_fatal_alert(conn, state):
    """Send fatal Alert (internal_error) instead of ServerHello."""
    _read_client_hello(conn)
    # Alert: level=fatal(2), description=internal_error(80)
    alert = _tls_record(CT_ALERT, VER_TLS12, b'\x02\x50')
    conn.sendall(alert)


def evil_early_ccs(conn, state):
    """Send ChangeCipherSpec before ServerHello."""
    _read_client_hello(conn)
    ccs = _tls_record(CT_CCS, VER_TLS12, b'\x01')
    conn.sendall(ccs)
    time.sleep(0.1)
    # Then send ServerHello
    conn.sendall(_make_server_hello())


def evil_immediate_close(conn, state):
    """Read ClientHello then close immediately."""
    _read_client_hello(conn)
    # Close without sending anything


def evil_null_cipher_hello(conn, state):
    """ServerHello advertising NULL cipher (0x0000)."""
    _read_client_hello(conn)
    hello = _make_server_hello(cipher=b'\x00\x00')
    conn.sendall(hello)


def evil_duplicate_server_hello(conn, state):
    """Send two ServerHellos back-to-back."""
    _read_client_hello(conn)
    hello = _make_server_hello()
    conn.sendall(hello + hello)


def evil_slow_drip(conn, state):
    """Send ServerHello 1 byte at a time, 200ms apart."""
    _read_client_hello(conn)
    hello = _make_server_hello()
    for byte in hello:
        try:
            conn.sendall(bytes([byte]))
            time.sleep(0.2)
        except Exception:
            break


def evil_wrong_content_type(conn, state):
    """TLS record with invalid content type (99)."""
    _read_client_hello(conn)
    hello_payload = _make_server_hello()
    # Replace content type with 99
    record = struct.pack('!B', 99) + hello_payload[1:]
    conn.sendall(record)


def evil_zero_length_record(conn, state):
    """Send a zero-length TLS record."""
    _read_client_hello(conn)
    record = _tls_record(CT_HANDSHAKE, VER_TLS12, b'')
    conn.sendall(record)


TLS_MALFORMATIONS = [
    (evil_garbage_bytes, "garbage_bytes"),
    (evil_truncated_server_hello, "truncated_server_hello"),
    (evil_wrong_tls_version, "wrong_tls_version"),
    (evil_oversized_record, "oversized_record"),
    (evil_fatal_alert, "fatal_alert"),
    (evil_early_ccs, "early_ccs"),
    (evil_immediate_close, "immediate_close"),
    (evil_null_cipher_hello, "null_cipher_hello"),
    (evil_duplicate_server_hello, "duplicate_server_hello"),
    (evil_slow_drip, "slow_drip"),
    (evil_wrong_content_type, "wrong_content_type"),
    (evil_zero_length_record, "zero_length_record"),
]


# ============================================================================
# Good mode: proper TLS server
# ============================================================================

class GoodTLSHandler(socketserver.BaseRequestHandler):
    """Handler that performs a proper TLS handshake and echoes."""

    def handle(self):
        try:
            ssl_sock = self.server.tls_context.wrap_socket(
                self.request, server_side=True
            )
            # Read whatever s_client sends (usually "Q\n")
            try:
                ssl_sock.settimeout(5)
                data = ssl_sock.recv(4096)
            except Exception:
                pass
            ssl_sock.close()
        except ssl.SSLError:
            pass
        except Exception:
            pass


# ============================================================================
# Evil handler
# ============================================================================

class EvilTLSHandler(socketserver.BaseRequestHandler):
    """Handler that serves evil TLS malformations or normal TLS responses."""

    def handle(self):
        rotator = self.server.rotator
        is_evil, fn, n = rotator.next_action()

        if is_evil:
            name = "unknown"
            for mfn, mname in TLS_MALFORMATIONS:
                if mfn is fn:
                    name = mname
                    break
            rotator.log_action("TLS", n, True, name)
            try:
                fn(self.request, {})
            except Exception:
                pass
        else:
            rotator.log_action("TLS", n, False)
            # Do a proper TLS handshake for "good" responses in both mode
            try:
                ssl_sock = self.server.tls_context.wrap_socket(
                    self.request, server_side=True
                )
                try:
                    ssl_sock.settimeout(5)
                    ssl_sock.recv(4096)
                except Exception:
                    pass
                ssl_sock.close()
                return  # Don't close raw socket, ssl_sock handles it
            except Exception:
                pass

        try:
            self.request.close()
        except Exception:
            pass


# ============================================================================
# Main entry point
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description='Evil TLS test server for openssl s_client fuzzing')
    parser.add_argument('--port', type=int, default=8443)
    parser.add_argument('--mode', choices=['good', 'evil', 'both'], default='good')
    parser.add_argument('--state-dir', default=None,
                        help='Directory for malformation state files')
    parser.add_argument('--certfile', type=str, default=None)
    parser.add_argument('--keyfile', type=str, default=None)

    args = parser.parse_args()

    # Generate certs if not provided
    if not args.certfile or not args.keyfile:
        cert_dir = '/tmp/curl-fuzz-certs'
        args.certfile, args.keyfile = generate_cert(cert_dir)

    tls_context = create_tls_context(args.certfile, args.keyfile)

    if args.mode == 'good':
        socketserver.TCPServer.allow_reuse_address = True
        server = socketserver.ThreadingTCPServer(('0.0.0.0', args.port), GoodTLSHandler)
        server.tls_context = tls_context
        print(f"TLS server running on port {args.port} (mode=good)", file=sys.stderr)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()
    else:
        state_file = None
        if args.state_dir:
            os.makedirs(args.state_dir, exist_ok=True)
            state_file = os.path.join(args.state_dir, "tls.state")
        rotator = MalformationRotator(
            [fn for fn, _ in TLS_MALFORMATIONS], mode=args.mode, state_file=state_file
        )
        socketserver.ThreadingTCPServer.allow_reuse_address = True
        server = socketserver.ThreadingTCPServer(('0.0.0.0', args.port), EvilTLSHandler)
        server.rotator = rotator
        server.tls_context = tls_context

        print(f"TLS server running on port {args.port} (mode={args.mode})", file=sys.stderr)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()


if __name__ == '__main__':
    main()
