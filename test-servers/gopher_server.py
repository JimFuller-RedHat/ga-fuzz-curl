#!/usr/bin/env python3
"""Minimal Gopher test server (RFC 1436) with normal and malformed modes."""

import argparse
import os
import random
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(__file__))
from tls_wrapper import add_tls_args, wrap_socket

# Gopher item types
TYPE_TEXT = '0'
TYPE_DIR = '1'
TYPE_ERROR = '3'

# Default host/port used in directory listings (overridden at runtime)
_host = 'localhost'
_port = 7070

# Canned text document
TEXT_DOC = (
    "Welcome to the Gopher test server.\r\n"
    "This is a sample text document.\r\n"
    "It contains three lines of text.\r\n"
)


def _random_bytes(n=16):
    return bytes(random.randint(0, 255) for _ in range(n))


def _gopher_item(itype, display, selector, host, port):
    """Format a Gopher menu item line."""
    return f'{itype}{display}\t{selector}\t{host}\t{port}\r\n'


def build_root_menu():
    """Build the root directory listing."""
    lines = []
    lines.append(_gopher_item(TYPE_TEXT, 'About this server', '/1', _host, _port))
    lines.append(_gopher_item(TYPE_DIR, 'A subdirectory', '/sub', _host, _port))
    lines.append(_gopher_item(TYPE_TEXT, 'Another document', '/2', _host, _port))
    lines.append('.\r\n')
    return ''.join(lines)


def build_subdir_menu():
    """Build a subdirectory listing."""
    lines = []
    lines.append(_gopher_item(TYPE_TEXT, 'Nested document', '/sub/doc', _host, _port))
    lines.append('.\r\n')
    return ''.join(lines)


def handle_client(conn, addr, mode):
    """Handle a single Gopher client connection."""
    try:
        rfile = conn.makefile('rb')
        wfile = conn.makefile('wb')

        # Read the selector line
        line = rfile.readline()
        if not line:
            return
        selector = line.decode('utf-8', errors='ignore').strip()

        # Determine response
        if selector == '' or selector == '/':
            response = build_root_menu()
        elif selector == '/1':
            response = TEXT_DOC + '.\r\n'
        elif selector == '/2':
            response = 'This is another sample document.\r\n.\r\n'
        elif selector == '/sub':
            response = build_subdir_menu()
        elif selector == '/sub/doc':
            response = 'A nested document in a subdirectory.\r\n.\r\n'
        else:
            response = _gopher_item(TYPE_ERROR, f'Item not found: {selector}', '', _host, _port)
            response += '.\r\n'

        # In malformed mode, corrupt the response
        if mode != 'good':
            corrupted_lines = []
            for rline in response.split('\r\n'):
                if not rline:
                    continue
                if random.random() < 0.3:
                    choice = random.randint(0, 2)
                    if choice == 0:
                        # Invalid item type character
                        if len(rline) > 0 and rline[0] in '013i':
                            rline = chr(random.randint(65, 90)) + rline[1:]
                    elif choice == 1:
                        # Unterminated line (no \r\n added later, skip)
                        corrupted_lines.append(rline)
                        continue
                    else:
                        # Random bytes instead
                        wfile.write(_random_bytes(random.randint(4, 32)))
                        wfile.flush()
                        continue
                corrupted_lines.append(rline + '\r\n')
            data = ''.join(corrupted_lines).encode()
        else:
            data = response.encode()

        wfile.write(data)
        wfile.flush()
        wfile.close()
        rfile.close()
    except Exception as e:
        print(f'Error handling {addr}: {e}', file=sys.stderr)
    finally:
        conn.close()


def main():
    global _host, _port

    parser = argparse.ArgumentParser(description='Gopher test server')
    parser.add_argument('--port', type=int, default=7070, help='Gopher port (default: 7070)')
    parser.add_argument('--mode', choices=['good', 'evil', 'both'], default='good',
                        help='Server response mode (only good supported for this protocol)')
    parser.add_argument('--state-dir', default=None, help='Directory for malformation state files')
    add_tls_args(parser)
    args = parser.parse_args()

    _port = args.port

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', args.port))
    sock.listen(5)

    proto = 'Gopher+TLS' if args.tls else 'Gopher'
    print(f'{proto} server running on port {args.port} (mode: {args.mode})', file=sys.stderr)

    try:
        while True:
            client_sock, addr = sock.accept()
            if args.tls:
                try:
                    client_sock = wrap_socket(client_sock, args.certfile, args.keyfile)
                except Exception as e:
                    print(f'TLS handshake failed for {addr}: {e}', file=sys.stderr)
                    client_sock.close()
                    continue
            t = threading.Thread(target=handle_client, args=(client_sock, addr, args.mode),
                                 daemon=True)
            t.start()
    except KeyboardInterrupt:
        print('\nShutting down...', file=sys.stderr)
    finally:
        sock.close()


if __name__ == '__main__':
    main()
