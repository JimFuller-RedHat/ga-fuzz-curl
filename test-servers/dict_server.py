#!/usr/bin/env python3
"""Minimal DICT test server (RFC 2229) with normal and malformed modes."""

import argparse
import os
import random
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(__file__))
from tls_wrapper import add_tls_args, wrap_socket

# Hardcoded dictionary
DICTIONARY = {
    'curl': 'A command-line tool for transferring data with URLs.',
    'fuzzing': 'An automated software testing technique involving random or semi-random inputs.',
    'protocol': 'A set of rules governing the exchange of data between devices.',
    'server': 'A computer program that provides services to other programs or devices.',
    'network': 'A group of interconnected computers that can exchange data.',
}

DICT_NAME = 'test'
DICT_DESC = 'Test Dictionary'


def _random_bytes(n=16):
    return bytes(random.randint(0, 255) for _ in range(n))


def handle_client(conn, addr, mode):
    """Handle a single DICT client connection."""
    try:
        rfile = conn.makefile('rb')
        wfile = conn.makefile('wb')

        def send(line):
            """Send a line, potentially corrupting it in malformed mode."""
            data = line.encode() if isinstance(line, str) else line
            if mode != 'good' and random.random() < 0.3:
                choice = random.randint(0, 2)
                if choice == 0:
                    # Wrong response code
                    if len(data) >= 3 and data[:3].isdigit():
                        code = random.choice([b'199', b'399', b'499', b'599'])
                        data = code + data[3:]
                elif choice == 1:
                    # Broken text
                    data = data[:max(1, len(data) // 2)]
                else:
                    # Random bytes
                    data = _random_bytes(random.randint(4, 32)) + b'\r\n'
            wfile.write(data)
            wfile.flush()

        # Banner
        send('220 dict server ready\r\n')

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

            if cmd == 'CLIENT':
                send('250 ok\r\n')

            elif cmd == 'DEFINE':
                # Parse: DEFINE <dict> <word>
                def_parts = arg.split(None, 1)
                if len(def_parts) < 2:
                    send('501 syntax error\r\n')
                    continue
                _dict_name = def_parts[0]
                word = def_parts[1].strip('"').lower()

                if word in DICTIONARY:
                    send('150 1 definitions found\r\n')
                    send(f'151 "{word}" "{DICT_NAME}" "{DICT_DESC}"\r\n')
                    send(f'{DICTIONARY[word]}\r\n')
                    send('.\r\n')
                    send('250 ok\r\n')
                else:
                    send(f'552 no match for "{word}"\r\n')

            elif cmd == 'MATCH':
                # Parse: MATCH <dict> <strategy> <word>
                match_parts = arg.split(None, 2)
                if len(match_parts) < 3:
                    send('501 syntax error\r\n')
                    continue
                _dict_name = match_parts[0]
                _strategy = match_parts[1]
                pattern = match_parts[2].strip('"').lower()

                matches = [w for w in DICTIONARY if pattern in w]
                if matches:
                    send(f'152 {len(matches)} matches found\r\n')
                    for m in matches:
                        send(f'{DICT_NAME} "{m}"\r\n')
                    send('.\r\n')
                    send('250 ok\r\n')
                else:
                    send(f'552 no match for "{pattern}"\r\n')

            elif cmd == 'SHOW':
                # SHOW DATABASES or SHOW STRATEGIES
                sub = arg.upper()
                if sub.startswith('DB') or sub.startswith('DATABASES'):
                    send('110 1 databases present\r\n')
                    send(f'{DICT_NAME} "{DICT_DESC}"\r\n')
                    send('.\r\n')
                    send('250 ok\r\n')
                elif sub.startswith('STRAT'):
                    send('111 1 strategies present\r\n')
                    send('exact "Match exact word"\r\n')
                    send('.\r\n')
                    send('250 ok\r\n')
                else:
                    send('501 syntax error\r\n')

            elif cmd == 'QUIT':
                send('221 bye\r\n')
                break

            else:
                send(f'500 unknown command "{cmd}"\r\n')

        wfile.close()
        rfile.close()
    except Exception as e:
        print(f'Error handling {addr}: {e}', file=sys.stderr)
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description='DICT test server')
    parser.add_argument('--port', type=int, default=2628, help='DICT port (default: 2628)')
    parser.add_argument('--mode', choices=['good', 'evil', 'both'], default='good',
                        help='Server response mode (only good supported for this protocol)')
    parser.add_argument('--state-dir', default=None, help='Directory for malformation state files')
    add_tls_args(parser)
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', args.port))
    sock.listen(5)

    proto = 'DICT+TLS' if args.tls else 'DICT'
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
