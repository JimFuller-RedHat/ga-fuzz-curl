#!/usr/bin/env python3
"""FTP/FTPS test server using pyftpdlib."""

import argparse
import os
import random
import socket
import socketserver
import sys
import tempfile
import threading
import time
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

sys.path.insert(0, os.path.dirname(__file__))
from tls_wrapper import add_tls_args
from malformation_rotator import MalformationRotator


# ===== Helper functions for evil mode =====

def _recv_line(conn):
    """Read one line from socket."""
    data = b""
    try:
        conn.settimeout(5)
        while not data.endswith(b"\n"):
            chunk = conn.recv(1)
            if not chunk:
                break
            data += chunk
    except Exception:
        pass
    return data


def _drain(conn):
    """Read and discard remaining data."""
    try:
        conn.settimeout(1)
        while conn.recv(4096):
            pass
    except Exception:
        pass


def _do_login(conn):
    """Complete normal FTP login sequence."""
    conn.sendall(b"220 Welcome\r\n")
    _recv_line(conn)  # USER
    conn.sendall(b"331 Password required\r\n")
    _recv_line(conn)  # PASS
    conn.sendall(b"230 Login successful\r\n")


def _setup_pasv(conn):
    """Set up PASV data connection, return listener socket."""
    data = _recv_line(conn)  # TYPE/PASV/EPSV/etc
    if data.upper().startswith(b"TYPE"):
        conn.sendall(b"200 Type set\r\n")
        data = _recv_line(conn)

    pasv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    pasv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    pasv_sock.bind(("127.0.0.1", 0))
    pasv_sock.listen(1)
    pasv_sock.settimeout(5)
    _, port = pasv_sock.getsockname()
    p1, p2 = port >> 8, port & 0xFF

    if b"EPSV" in data.upper():
        conn.sendall(f"229 Entering Extended Passive Mode (|||{port}|)\r\n".encode())
    else:
        conn.sendall(f"227 Entering Passive Mode (127,0,0,1,{p1},{p2})\r\n".encode())

    return pasv_sock


# ===== 12 Malformation functions =====

def evil_invalid_reply_code(conn, state):
    """Send invalid 999 reply code."""
    conn.sendall(b"999 Unknown reply\r\n")
    _drain(conn)


def evil_missing_reply_code(conn, state):
    """Send banner without numeric reply code."""
    conn.sendall(b"Welcome to the server\r\n")
    _drain(conn)


def evil_oversized_banner(conn, state):
    """Send oversized banner with 65536 X characters."""
    conn.sendall(b"220-" + b"X" * 65536 + b"\r\n")
    conn.sendall(b"220 Welcome\r\n")
    _drain(conn)


def evil_multiline_never_ends(conn, state):
    """Send 1000 continuation lines without final reply."""
    for i in range(1000):
        conn.sendall(f"220-Line {i}\r\n".encode())
    # Never send final 220


def evil_nul_in_reply(conn, state):
    """Send reply with NUL byte embedded."""
    conn.sendall(b"220 Welcome\x00to server\r\n")
    _drain(conn)


def evil_wrong_reply(conn, state):
    """Reply with wrong code for command context."""
    conn.sendall(b"220 Welcome\r\n")
    _recv_line(conn)  # USER
    conn.sendall(b"150 Data connection opening\r\n")  # Wrong for USER
    _drain(conn)


def evil_pasv_no_data(conn, state):
    """PASV reply points to non-listening port."""
    _do_login(conn)
    _recv_line(conn)  # PASV/EPSV
    # Send PASV reply with port 65535 (nobody listening)
    conn.sendall(b"227 Entering Passive Mode (127,0,0,1,255,255)\r\n")
    _drain(conn)


def evil_truncated_file(conn, state):
    """Send truncated file on RETR."""
    _do_login(conn)
    pasv_sock = _setup_pasv(conn)
    _recv_line(conn)  # RETR
    conn.sendall(b"150 Opening data connection\r\n")
    try:
        data_conn, _ = pasv_sock.accept()
        data_conn.sendall(b"Short")  # Truncated
        data_conn.close()
    except Exception:
        pass
    pasv_sock.close()
    conn.sendall(b"226 Transfer complete\r\n")
    _drain(conn)


def evil_data_immediate_close(conn, state):
    """Accept data connection then immediately close."""
    _do_login(conn)
    pasv_sock = _setup_pasv(conn)
    _recv_line(conn)  # RETR
    conn.sendall(b"150 Opening data connection\r\n")
    try:
        data_conn, _ = pasv_sock.accept()
        data_conn.close()  # Immediate close
    except Exception:
        pass
    pasv_sock.close()
    conn.sendall(b"226 Transfer complete\r\n")
    _drain(conn)


def evil_infinite_data(conn, state):
    """Send infinite random data on RETR."""
    _do_login(conn)
    pasv_sock = _setup_pasv(conn)
    _recv_line(conn)  # RETR
    conn.sendall(b"150 Opening data connection\r\n")
    try:
        data_conn, _ = pasv_sock.accept()
        data_conn.settimeout(1)
        end_time = time.time() + 30
        while time.time() < end_time:
            try:
                data_conn.sendall(bytes([random.randint(0, 255) for _ in range(1024)]))
            except Exception:
                break
        data_conn.close()
    except Exception:
        pass
    pasv_sock.close()
    try:
        conn.sendall(b"226 Transfer complete\r\n")
    except Exception:
        pass


def evil_accept_then_reject(conn, state):
    """Accept login then reject with 530."""
    conn.sendall(b"220 Welcome\r\n")
    _recv_line(conn)  # USER
    conn.sendall(b"331 Password required\r\n")
    _recv_line(conn)  # PASS
    conn.sendall(b"530 Login incorrect\r\n")
    _drain(conn)


def evil_delayed_response(conn, state):
    """Delay 10 seconds before login success."""
    conn.sendall(b"220 Welcome\r\n")
    _recv_line(conn)  # USER
    conn.sendall(b"331 Password required\r\n")
    _recv_line(conn)  # PASS
    time.sleep(10)
    conn.sendall(b"230 Login successful\r\n")
    _drain(conn)


FTP_MALFORMATIONS = [
    (evil_invalid_reply_code, "invalid_reply_code"),
    (evil_missing_reply_code, "missing_reply_code"),
    (evil_oversized_banner, "oversized_banner"),
    (evil_multiline_never_ends, "multiline_never_ends"),
    (evil_nul_in_reply, "nul_in_reply"),
    (evil_wrong_reply, "wrong_reply"),
    (evil_pasv_no_data, "pasv_no_data"),
    (evil_truncated_file, "truncated_file"),
    (evil_data_immediate_close, "data_immediate_close"),
    (evil_infinite_data, "infinite_data"),
    (evil_accept_then_reject, "accept_then_reject"),
    (evil_delayed_response, "delayed_response"),
]


# ===== Normal FTP implementation for 'both' mode =====

def _do_normal_ftp(conn):
    """Minimal FTP state machine for good responses in both mode."""
    try:
        conn.sendall(b"220 FTP server ready\r\n")

        while True:
            line = _recv_line(conn)
            if not line:
                break

            cmd = line.decode('utf-8', errors='ignore').strip().upper()

            if cmd.startswith("USER"):
                conn.sendall(b"331 Password required\r\n")
            elif cmd.startswith("PASS"):
                conn.sendall(b"230 Login successful\r\n")
            elif cmd.startswith("SYST"):
                conn.sendall(b"215 UNIX Type: L8\r\n")
            elif cmd.startswith("PWD"):
                conn.sendall(b"257 \"/\" is current directory\r\n")
            elif cmd.startswith("TYPE"):
                conn.sendall(b"200 Type set\r\n")
            elif cmd.startswith("SIZE"):
                conn.sendall(b"213 18\r\n")
            elif cmd.startswith("PASV"):
                # Set up passive mode
                pasv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                pasv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                pasv_sock.bind(("127.0.0.1", 0))
                pasv_sock.listen(1)
                pasv_sock.settimeout(10)
                _, port = pasv_sock.getsockname()
                p1, p2 = port >> 8, port & 0xFF
                conn.sendall(f"227 Entering Passive Mode (127,0,0,1,{p1},{p2})\r\n".encode())

                # Wait for RETR/LIST
                retr_line = _recv_line(conn)
                conn.sendall(b"150 Opening data connection\r\n")

                try:
                    data_conn, _ = pasv_sock.accept()
                    data_conn.sendall(b"test file content\r\n")
                    data_conn.close()
                except Exception:
                    pass
                pasv_sock.close()
                conn.sendall(b"226 Transfer complete\r\n")
            elif cmd.startswith("EPSV"):
                # Set up extended passive mode
                pasv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                pasv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                pasv_sock.bind(("127.0.0.1", 0))
                pasv_sock.listen(1)
                pasv_sock.settimeout(10)
                _, port = pasv_sock.getsockname()
                conn.sendall(f"229 Entering Extended Passive Mode (|||{port}|)\r\n".encode())

                # Wait for RETR/LIST
                retr_line = _recv_line(conn)
                conn.sendall(b"150 Opening data connection\r\n")

                try:
                    data_conn, _ = pasv_sock.accept()
                    data_conn.sendall(b"test file content\r\n")
                    data_conn.close()
                except Exception:
                    pass
                pasv_sock.close()
                conn.sendall(b"226 Transfer complete\r\n")
            elif cmd.startswith("QUIT"):
                conn.sendall(b"221 Goodbye\r\n")
                break
            else:
                conn.sendall(b"502 Command not implemented\r\n")
    except Exception:
        pass


# ===== Evil handler =====

class EvilFTPHandler(socketserver.BaseRequestHandler):
    """Handler that rotates between evil malformations and good responses."""

    def handle(self):
        rotator = self.server.rotator
        is_evil, fn, n = rotator.next_action()

        if is_evil:
            name = "unknown"
            for mfn, mname in FTP_MALFORMATIONS:
                if mfn is fn:
                    name = mname
                    break
            rotator.log_action("FTP", n, True, name)
            try:
                fn(self.request, {})
            except Exception:
                pass
        else:
            rotator.log_action("FTP", n, False)
            _do_normal_ftp(self.request)

        try:
            self.request.close()
        except Exception:
            pass


# ===== pyftpdlib wrapper (good mode) =====

def _run_pyftpdlib(args):
    """Run the original pyftpdlib server (good mode)."""
    ftp_root = tempfile.mkdtemp(prefix='curl-fuzz-ftp-')

    test_file = os.path.join(ftp_root, 'test.txt')
    with open(test_file, 'w') as f:
        f.write('This is a test file for FTP fuzzing.\n')

    authorizer = DummyAuthorizer()
    authorizer.add_user('foo', 'pass', ftp_root, perm='elradfmwMT')
    authorizer.add_anonymous(ftp_root, perm='elr')

    if args.tls:
        from pyftpdlib.handlers import TLS_FTPHandler
        handler = TLS_FTPHandler
        handler.certfile = args.certfile
        handler.keyfile = args.keyfile
        handler.tls_control_required = False
        handler.tls_data_required = False
        proto = 'FTPS'
    else:
        handler = FTPHandler
        proto = 'FTP'

    handler.authorizer = authorizer
    handler.passive_ports = range(60000, 60101)

    server = FTPServer(('0.0.0.0', args.port), handler)
    print(f'{proto} server running on port {args.port}', file=sys.stderr)
    server.serve_forever()


# ===== Main entry point =====

def main():
    parser = argparse.ArgumentParser(description='FTP/FTPS test server')
    parser.add_argument('--port', type=int, default=2121, help='FTP port')
    parser.add_argument('--mode', choices=['good', 'evil', 'both'], default='good')
    parser.add_argument('--state-dir', default=None,
                        help='Directory for malformation state files')
    add_tls_args(parser)
    args = parser.parse_args()

    if args.mode == 'good':
        _run_pyftpdlib(args)
    else:
        state_file = None
        if args.state_dir:
            os.makedirs(args.state_dir, exist_ok=True)
            state_file = os.path.join(args.state_dir, "ftp.state")
        rotator = MalformationRotator(
            [fn for fn, _ in FTP_MALFORMATIONS], mode=args.mode, state_file=state_file
        )
        socketserver.ThreadingTCPServer.allow_reuse_address = True
        server = socketserver.ThreadingTCPServer(('0.0.0.0', args.port), EvilFTPHandler)
        server.rotator = rotator

        if args.tls:
            from tls_wrapper import create_tls_context
            ctx = create_tls_context(args.certfile, args.keyfile)
            server.socket = ctx.wrap_socket(server.socket, server_side=True)

        print(f"FTP server running on port {args.port} (mode={args.mode})", file=sys.stderr)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()


if __name__ == '__main__':
    main()
