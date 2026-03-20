#!/usr/bin/env python3
"""Minimal Telnet echo server with RFC 854 option negotiation."""

import argparse
import os
import random
import socketserver
import sys

sys.path.insert(0, os.path.dirname(__file__))
from tls_wrapper import add_tls_args, wrap_socket

# Telnet constants
IAC = 255   # Interpret As Command
WILL = 251
WONT = 252
DO = 253
DONT = 254
SB = 250    # Sub-negotiation Begin
SE = 240    # Sub-negotiation End

# Common options
OPT_ECHO = 1
OPT_SUPPRESS_GO_AHEAD = 3


class TelnetHandler(socketserver.BaseRequestHandler):
    """Minimal Telnet protocol handler with echo."""

    def handle(self):
        """Handle Telnet client connection."""
        malformed = getattr(self.server, 'malformed', False)

        # Send initial option negotiations
        if malformed:
            # Send invalid IAC sequences and random bytes
            self.request.sendall(bytes([IAC, 0x00, OPT_ECHO]))  # invalid command
            self.request.sendall(os.urandom(random.randint(3, 10)))
            self.request.sendall(bytes([IAC, WILL, OPT_ECHO]))
        else:
            # IAC WILL ECHO
            self.request.sendall(bytes([IAC, WILL, OPT_ECHO]))
            # IAC WILL SUPPRESS-GO-AHEAD
            self.request.sendall(bytes([IAC, WILL, OPT_SUPPRESS_GO_AHEAD]))

        buf = b''

        while True:
            try:
                chunk = self.request.recv(4096)
                if not chunk:
                    break

                buf += chunk
                out = b''
                i = 0

                while i < len(buf):
                    if buf[i] == IAC:
                        # Need at least 3 bytes for IAC command option
                        if i + 2 >= len(buf):
                            # Incomplete IAC sequence, keep in buffer
                            break

                        command = buf[i + 1]

                        if command == IAC:
                            # Escaped IAC (literal 0xFF)
                            out += bytes([IAC])
                            i += 2

                        elif command == DO:
                            option = buf[i + 2]
                            # Respond with WILL
                            if malformed:
                                self.request.sendall(os.urandom(random.randint(1, 5)))
                            self.request.sendall(bytes([IAC, WILL, option]))
                            i += 3

                        elif command == DONT:
                            option = buf[i + 2]
                            # Respond with WONT
                            self.request.sendall(bytes([IAC, WONT, option]))
                            i += 3

                        elif command == WILL:
                            # Client offers, we accept with DO
                            option = buf[i + 2]
                            self.request.sendall(bytes([IAC, DO, option]))
                            i += 3

                        elif command == WONT:
                            # Client refuses, acknowledge with DONT
                            option = buf[i + 2]
                            self.request.sendall(bytes([IAC, DONT, option]))
                            i += 3

                        elif command == SB:
                            # Sub-negotiation: find SE
                            se_pos = buf.find(bytes([IAC, SE]), i + 2)
                            if se_pos == -1:
                                break  # Incomplete, wait for more data
                            i = se_pos + 2

                        else:
                            # Unknown IAC command, skip
                            i += 2

                    else:
                        out += bytes([buf[i]])
                        i += 1

                # Keep unprocessed bytes
                buf = buf[i:]

                # Echo back non-IAC data
                if out:
                    if malformed and random.random() < 0.3:
                        # Mix in random bytes
                        garbage = os.urandom(random.randint(1, 5))
                        self.request.sendall(garbage + out)
                    else:
                        self.request.sendall(out)

            except (ConnectionResetError, BrokenPipeError, OSError):
                break


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """TCP server with threading support."""
    allow_reuse_address = True


def main():
    parser = argparse.ArgumentParser(description='Telnet test server')
    parser.add_argument('--port', type=int, default=2323, help='Telnet port (default: 2323)')
    parser.add_argument('--mode', choices=['good', 'evil', 'both'], default='good',
                        help='Server response mode (only good supported for this protocol)')
    parser.add_argument('--state-dir', default=None, help='Directory for malformation state files')
    add_tls_args(parser)
    args = parser.parse_args()

    server = ThreadedTCPServer(('0.0.0.0', args.port), TelnetHandler)
    server.malformed = (args.mode != 'good')

    if args.tls:
        server.socket = wrap_socket(server.socket, args.certfile, args.keyfile)

    proto = 'TelnetS' if args.tls else 'Telnet'
    mode_str = f' (mode: {args.mode})'
    print(f'{proto} server running on port {args.port}{mode_str}')
    print('Press Ctrl+C to stop')

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nShutting down...')
        server.shutdown()


if __name__ == '__main__':
    main()
