#!/usr/bin/env python3
"""SMTP test server using aiosmtpd."""

import argparse
import asyncio
import os
import socket
import socketserver
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(__file__))
from tls_wrapper import add_tls_args, create_tls_context
from malformation_rotator import MalformationRotator

from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Sink


# ============================================================================
# Helper functions for evil mode
# ============================================================================

def _recv_line_smtp(conn):
    """Receive a single line from SMTP client."""
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


def _drain_smtp(conn):
    """Drain any remaining data from the client."""
    try:
        conn.settimeout(1)
        while conn.recv(4096):
            pass
    except Exception:
        pass


def _do_smtp_to_data(conn):
    """Run normal SMTP up to DATA command."""
    conn.sendall(b"220 Welcome\r\n")
    _recv_line_smtp(conn)  # EHLO
    conn.sendall(b"250 OK\r\n")
    _recv_line_smtp(conn)  # MAIL FROM
    conn.sendall(b"250 OK\r\n")
    _recv_line_smtp(conn)  # RCPT TO
    conn.sendall(b"250 OK\r\n")
    _recv_line_smtp(conn)  # DATA


def _read_smtp_data(conn):
    """Read SMTP DATA payload until \\r\\n.\\r\\n."""
    data = b""
    try:
        conn.settimeout(5)
        while b"\r\n.\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
    except Exception:
        pass
    return data


# ============================================================================
# Evil malformation functions (12 total)
# ============================================================================

def evil_no_greeting(conn, state):
    """Accept connection, send nothing, sleep(2)."""
    time.sleep(2)


def evil_oversized_greeting(conn, state):
    """Send oversized greeting with 65KB of X's."""
    conn.sendall(b"220-" + b"X" * 65536 + b"\r\n")
    conn.sendall(b"220 Welcome\r\n")
    _drain_smtp(conn)


def evil_negative_greeting(conn, state):
    """Send negative greeting."""
    conn.sendall(b"554 Service unavailable\r\n")


def evil_slow_greeting(conn, state):
    """Send greeting 1 byte at a time every 500ms."""
    greeting = b"220 Welcome\r\n"
    for byte in greeting:
        conn.sendall(bytes([byte]))
        time.sleep(0.5)
    _drain_smtp(conn)


def evil_wrong_reply_code(conn, state):
    """Send 220, receive EHLO, reply with 550."""
    conn.sendall(b"220 Welcome\r\n")
    _recv_line_smtp(conn)  # EHLO
    conn.sendall(b"550 Access denied\r\n")
    _drain_smtp(conn)


def evil_invalid_reply_code(conn, state):
    """Send 220, receive EHLO, reply with 999."""
    conn.sendall(b"220 Welcome\r\n")
    _recv_line_smtp(conn)  # EHLO
    conn.sendall(b"999 Whatever\r\n")
    _drain_smtp(conn)


def evil_nul_in_response(conn, state):
    """Send 220, receive EHLO, reply with NUL byte in response."""
    conn.sendall(b"220 Welcome\r\n")
    _recv_line_smtp(conn)  # EHLO
    conn.sendall(b"250 OK\x00hidden\r\n")
    _drain_smtp(conn)


def evil_multiline_never_ends(conn, state):
    """Send 220, receive EHLO, send 1000 multiline extensions, never final."""
    conn.sendall(b"220 Welcome\r\n")
    _recv_line_smtp(conn)  # EHLO
    for i in range(1000):
        conn.sendall(f"250-Extension-{i}\r\n".encode())
    # Never send final 250 OK


def evil_ehlo_overflow(conn, state):
    """Send 220, receive EHLO, send 100 fake extensions then OK."""
    conn.sendall(b"220 Welcome\r\n")
    _recv_line_smtp(conn)  # EHLO
    for i in range(100):
        conn.sendall(f"250-X-FAKE-EXT-{i}\r\n".encode())
    conn.sendall(b"250 OK\r\n")
    _drain_smtp(conn)


def evil_data_then_drop(conn, state):
    """Run SMTP to DATA, send 354, read data, close without 250."""
    _do_smtp_to_data(conn)
    conn.sendall(b"354 Go ahead\r\n")
    _read_smtp_data(conn)
    # Drop connection without sending 250


def evil_truncated_mid_data(conn, state):
    """Run SMTP to DATA, send 354, read data, send truncated '25' then close."""
    _do_smtp_to_data(conn)
    conn.sendall(b"354 Go ahead\r\n")
    _read_smtp_data(conn)
    conn.sendall(b"25")
    # Close mid-response


def evil_reject_after_data(conn, state):
    """Run SMTP to DATA, send 354, read data, then 550."""
    _do_smtp_to_data(conn)
    conn.sendall(b"354 Go ahead\r\n")
    _read_smtp_data(conn)
    conn.sendall(b"550 Message rejected\r\n")
    _drain_smtp(conn)


SMTP_MALFORMATIONS = [
    (evil_no_greeting, "no_greeting"),
    (evil_oversized_greeting, "oversized_greeting"),
    (evil_negative_greeting, "negative_greeting"),
    (evil_slow_greeting, "slow_greeting"),
    (evil_wrong_reply_code, "wrong_reply_code"),
    (evil_invalid_reply_code, "invalid_reply_code"),
    (evil_nul_in_response, "nul_in_response"),
    (evil_multiline_never_ends, "multiline_never_ends"),
    (evil_ehlo_overflow, "ehlo_overflow"),
    (evil_data_then_drop, "data_then_drop"),
    (evil_truncated_mid_data, "truncated_mid_data"),
    (evil_reject_after_data, "reject_after_data"),
]


# ============================================================================
# Normal SMTP handler for 'both' mode
# ============================================================================

def _do_normal_smtp(conn):
    """Minimal SMTP state machine for good responses."""
    try:
        conn.sendall(b"220 SMTP server ready\r\n")

        while True:
            line = _recv_line_smtp(conn)
            if not line:
                break

            cmd = line.strip().upper()

            if cmd.startswith(b"EHLO") or cmd.startswith(b"HELO"):
                conn.sendall(b"250-localhost\r\n250 OK\r\n")
            elif cmd.startswith(b"MAIL"):
                conn.sendall(b"250 OK\r\n")
            elif cmd.startswith(b"RCPT"):
                conn.sendall(b"250 OK\r\n")
            elif cmd.startswith(b"DATA"):
                conn.sendall(b"354 Go ahead\r\n")
                _read_smtp_data(conn)
                conn.sendall(b"250 OK\r\n")
            elif cmd.startswith(b"QUIT"):
                conn.sendall(b"221 Bye\r\n")
                break
            elif cmd.startswith(b"RSET"):
                conn.sendall(b"250 OK\r\n")
            else:
                conn.sendall(b"502 Command not implemented\r\n")
    except Exception:
        pass


# ============================================================================
# Evil handler for socketserver
# ============================================================================

class EvilSMTPHandler(socketserver.BaseRequestHandler):
    """Handler that serves evil SMTP malformations or normal responses."""

    def handle(self):
        rotator = self.server.rotator
        is_evil, fn, n = rotator.next_action()

        if is_evil:
            name = "unknown"
            for mfn, mname in SMTP_MALFORMATIONS:
                if mfn is fn:
                    name = mname
                    break
            rotator.log_action("SMTP", n, True, name)
            try:
                fn(self.request, {})
            except Exception:
                pass
        else:
            rotator.log_action("SMTP", n, False)
            _do_normal_smtp(self.request)

        try:
            self.request.close()
        except Exception:
            pass


# ============================================================================
# Good mode using aiosmtpd
# ============================================================================

def _run_aiosmtpd(args):
    """Run good SMTP server using aiosmtpd."""
    controller_kwargs = dict(hostname='0.0.0.0', port=args.port)
    if args.tls:
        controller_kwargs['tls_context'] = create_tls_context(args.certfile, args.keyfile)

    controller = Controller(Sink(), **controller_kwargs)

    proto = 'SMTPS' if args.tls else 'SMTP'
    print(f'{proto} server running on port {args.port}', file=sys.stderr)
    print('Press Ctrl+C to stop', file=sys.stderr)

    controller.start()

    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        print('\nShutting down...', file=sys.stderr)
        controller.stop()


# ============================================================================
# Main entry point
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description='SMTP/SMTPS test server')
    parser.add_argument('--port', type=int, default=2525)
    parser.add_argument('--mode', choices=['good', 'evil', 'both'], default='good')
    parser.add_argument('--state-dir', default=None,
                        help='Directory for malformation state files')
    add_tls_args(parser)
    args = parser.parse_args()

    if args.mode == 'good':
        _run_aiosmtpd(args)
    else:
        state_file = None
        if args.state_dir:
            os.makedirs(args.state_dir, exist_ok=True)
            state_file = os.path.join(args.state_dir, "smtp.state")
        rotator = MalformationRotator(
            [fn for fn, _ in SMTP_MALFORMATIONS], mode=args.mode, state_file=state_file
        )
        socketserver.ThreadingTCPServer.allow_reuse_address = True
        server = socketserver.ThreadingTCPServer(('0.0.0.0', args.port), EvilSMTPHandler)
        server.rotator = rotator

        if args.tls:
            ctx = create_tls_context(args.certfile, args.keyfile)
            server.socket = ctx.wrap_socket(server.socket, server_side=True)

        print(f"SMTP server running on port {args.port} (mode={args.mode})", file=sys.stderr)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()


if __name__ == '__main__':
    main()
