#!/usr/bin/env python3
"""Minimal IMAP4 test server using socketserver."""

import argparse
import os
import socketserver
import sys
import threading

sys.path.insert(0, os.path.dirname(__file__))
from tls_wrapper import add_tls_args, wrap_socket

class IMAPHandler(socketserver.StreamRequestHandler):
    """Minimal IMAP4 protocol handler."""

    def handle(self):
        """Handle IMAP client connection."""
        # Send greeting
        self.wfile.write(b'* OK IMAP4rev1 Test Server Ready\r\n')
        self.wfile.flush()

        # Process commands
        while True:
            try:
                line = self.rfile.readline()
                if not line:
                    break

                line = line.decode('utf-8', errors='ignore').strip()
                if not line:
                    continue

                # Parse tag and command
                parts = line.split(None, 1)
                if len(parts) < 1:
                    continue

                tag = parts[0]
                command = parts[1].upper() if len(parts) > 1 else ''

                # Handle commands
                if command.startswith('CAPABILITY'):
                    self.wfile.write(b'* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n')
                    self.wfile.write(f'{tag} OK CAPABILITY completed\r\n'.encode())

                elif command.startswith('LOGIN'):
                    # Accept any credentials
                    self.wfile.write(f'{tag} OK LOGIN completed\r\n'.encode())

                elif command.startswith('LOGOUT'):
                    self.wfile.write(b'* BYE IMAP4rev1 Server logging out\r\n')
                    self.wfile.write(f'{tag} OK LOGOUT completed\r\n'.encode())
                    break

                elif command.startswith('NOOP'):
                    self.wfile.write(f'{tag} OK NOOP completed\r\n'.encode())

                elif command.startswith('SELECT') or command.startswith('EXAMINE'):
                    # Return empty mailbox
                    self.wfile.write(b'* 0 EXISTS\r\n')
                    self.wfile.write(b'* 0 RECENT\r\n')
                    self.wfile.write(b'* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n')
                    cmd_name = 'SELECT' if command.startswith('SELECT') else 'EXAMINE'
                    self.wfile.write(f'{tag} OK {cmd_name} completed\r\n'.encode())

                else:
                    # Unknown command
                    self.wfile.write(f'{tag} BAD Command not recognized\r\n'.encode())

                self.wfile.flush()

            except Exception as e:
                print(f'Error handling request: {e}')
                break

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """TCP server with threading support."""
    allow_reuse_address = True

def main():
    parser = argparse.ArgumentParser(description='IMAP4 test server')
    parser.add_argument('--port', type=int, default=1143, help='IMAP port (default: 1143)')
    parser.add_argument('--mode', choices=['good', 'evil', 'both'], default='good',
                        help='Server response mode (only good supported for this protocol)')
    parser.add_argument('--state-dir', default=None, help='Directory for malformation state files')
    add_tls_args(parser)
    args = parser.parse_args()

    server = ThreadedTCPServer(('0.0.0.0', args.port), IMAPHandler)

    if args.tls:
        server.socket = wrap_socket(server.socket, args.certfile, args.keyfile)

    proto = 'IMAPS' if args.tls else 'IMAP'
    print(f'{proto} server running on port {args.port}')
    print('Press Ctrl+C to stop')

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nShutting down...')
        server.shutdown()

if __name__ == '__main__':
    main()
