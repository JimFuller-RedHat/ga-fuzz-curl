#!/usr/bin/env python3
"""Minimal POP3 test server (RFC 1939) with normal and malformed modes."""

import argparse
import os
import random
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(__file__))
from tls_wrapper import add_tls_args, wrap_socket

# Canned email messages
MESSAGES = [
    (
        "From: sender@example.com\r\n"
        "To: user@example.com\r\n"
        "Subject: Test message 1\r\n"
        "\r\n"
        "This is the first test message.\r\n"
    ),
    (
        "From: noreply@example.com\r\n"
        "To: user@example.com\r\n"
        "Subject: Test message 2\r\n"
        "\r\n"
        "This is the second test message.\r\n"
        "It has two lines of body.\r\n"
    ),
    (
        "From: admin@example.com\r\n"
        "To: user@example.com\r\n"
        "Subject: Test message 3\r\n"
        "\r\n"
        "Third test message body.\r\n"
    ),
]

MSG_SIZES = [len(m.encode()) for m in MESSAGES]
TOTAL_SIZE = sum(MSG_SIZES)


def _random_bytes(n=16):
    return bytes(random.randint(0, 255) for _ in range(n))


def handle_client(conn, addr, mode):
    """Handle a single POP3 client connection."""
    try:
        rfile = conn.makefile('rb')
        wfile = conn.makefile('wb')

        def send(line):
            """Send a line, potentially corrupting it in malformed mode."""
            data = line.encode() if isinstance(line, str) else line
            if mode != 'good' and random.random() < 0.3:
                choice = random.randint(0, 2)
                if choice == 0:
                    # Truncated response
                    data = data[:max(1, len(data) // 3)]
                elif choice == 1:
                    # Missing +OK/-ERR prefix
                    if data.startswith(b'+OK'):
                        data = data[4:]
                    elif data.startswith(b'-ERR'):
                        data = data[5:]
                else:
                    # Random bytes
                    data = _random_bytes(random.randint(4, 32)) + b'\r\n'
            wfile.write(data)
            wfile.flush()

        send('+OK POP3 server ready\r\n')

        deleted = set()

        while True:
            line = rfile.readline()
            if not line:
                break
            line = line.decode('utf-8', errors='ignore').strip()
            if not line:
                continue

            parts = line.split(None, 1)
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ''

            if cmd == 'USER':
                send('+OK user accepted\r\n')

            elif cmd == 'PASS':
                send('+OK pass accepted\r\n')

            elif cmd == 'STAT':
                active = len(MESSAGES) - len(deleted)
                active_size = sum(s for i, s in enumerate(MSG_SIZES) if i not in deleted)
                send(f'+OK {active} {active_size}\r\n')

            elif cmd == 'LIST':
                if arg:
                    # LIST <msg>
                    try:
                        idx = int(arg) - 1
                        if idx < 0 or idx >= len(MESSAGES) or idx in deleted:
                            send('-ERR no such message\r\n')
                        else:
                            send(f'+OK {idx + 1} {MSG_SIZES[idx]}\r\n')
                    except ValueError:
                        send('-ERR invalid argument\r\n')
                else:
                    active = len(MESSAGES) - len(deleted)
                    active_size = sum(s for i, s in enumerate(MSG_SIZES) if i not in deleted)
                    send(f'+OK {active} messages ({active_size} octets)\r\n')
                    for i, size in enumerate(MSG_SIZES):
                        if i not in deleted:
                            send(f'{i + 1} {size}\r\n')
                    send('.\r\n')

            elif cmd == 'RETR':
                try:
                    idx = int(arg) - 1
                    if idx < 0 or idx >= len(MESSAGES) or idx in deleted:
                        send('-ERR no such message\r\n')
                    else:
                        send(f'+OK {MSG_SIZES[idx]} octets\r\n')
                        # Byte-stuff lines starting with '.'
                        for msgline in MESSAGES[idx].splitlines(True):
                            if msgline.startswith('.'):
                                send('..' + msgline)
                            else:
                                send(msgline)
                        send('.\r\n')
                except ValueError:
                    send('-ERR invalid argument\r\n')

            elif cmd == 'DELE':
                try:
                    idx = int(arg) - 1
                    if idx < 0 or idx >= len(MESSAGES) or idx in deleted:
                        send('-ERR no such message\r\n')
                    else:
                        deleted.add(idx)
                        send(f'+OK message {idx + 1} deleted\r\n')
                except ValueError:
                    send('-ERR invalid argument\r\n')

            elif cmd == 'NOOP':
                send('+OK\r\n')

            elif cmd == 'RSET':
                deleted.clear()
                send('+OK\r\n')

            elif cmd == 'QUIT':
                send('+OK bye\r\n')
                break

            else:
                send(f'-ERR unknown command {cmd}\r\n')

        wfile.close()
        rfile.close()
    except Exception as e:
        print(f'Error handling {addr}: {e}', file=sys.stderr)
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description='POP3 test server')
    parser.add_argument('--port', type=int, default=1110, help='POP3 port (default: 1110)')
    parser.add_argument('--mode', choices=['good', 'evil', 'both'], default='good',
                        help='Server response mode (only good supported for this protocol)')
    parser.add_argument('--state-dir', default=None, help='Directory for malformation state files')
    add_tls_args(parser)
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', args.port))
    sock.listen(5)

    proto = 'POP3S' if args.tls else 'POP3'
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
