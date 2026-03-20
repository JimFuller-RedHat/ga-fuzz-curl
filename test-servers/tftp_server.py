#!/usr/bin/env python3
"""Minimal TFTP server (RFC 1350) using raw UDP sockets."""

import argparse
import os
import random
import socket
import struct
import sys
import tempfile


# TFTP opcodes
OP_RRQ = 1
OP_WRQ = 2
OP_DATA = 3
OP_ACK = 4
OP_ERROR = 5

BLOCK_SIZE = 512


def create_test_files(directory):
    """Create test files in the serving directory."""
    test_file = os.path.join(directory, 'test.txt')
    with open(test_file, 'w') as f:
        f.write('This is a TFTP test file.\n' * 40)

    # Create a small binary file too
    bin_file = os.path.join(directory, 'binary.bin')
    with open(bin_file, 'wb') as f:
        f.write(os.urandom(1024))


def parse_request(data):
    """Parse RRQ/WRQ packet. Returns (opcode, filename, mode)."""
    if len(data) < 4:
        return None, None, None
    opcode = struct.unpack('!H', data[:2])[0]
    # Filename and mode are null-terminated strings
    rest = data[2:]
    parts = rest.split(b'\x00')
    if len(parts) < 2:
        return opcode, None, None
    filename = parts[0].decode('ascii', errors='ignore')
    mode = parts[1].decode('ascii', errors='ignore').lower()
    return opcode, filename, mode


def make_data_packet(block_num, data):
    """Create a DATA packet."""
    return struct.pack('!HH', OP_DATA, block_num) + data


def make_error_packet(error_code, msg):
    """Create an ERROR packet."""
    return struct.pack('!HH', OP_ERROR, error_code) + msg.encode('ascii') + b'\x00'


def make_ack_packet(block_num):
    """Create an ACK packet."""
    return struct.pack('!HH', OP_ACK, block_num)


def handle_rrq(sock, client_addr, filename, serve_dir, malformed):
    """Handle a read request by sending the file in 512-byte blocks."""
    filepath = os.path.join(serve_dir, os.path.basename(filename))

    if not os.path.isfile(filepath):
        sock.sendto(make_error_packet(1, 'File not found'), client_addr)
        return

    with open(filepath, 'rb') as f:
        file_data = f.read()

    block_num = 1
    offset = 0

    while True:
        chunk = file_data[offset:offset + BLOCK_SIZE]

        if malformed and random.random() < 0.3:
            # Send wrong opcode or truncated block
            if random.random() < 0.5:
                bad_packet = struct.pack('!HH', OP_ERROR, block_num) + chunk
                sock.sendto(bad_packet, client_addr)
            else:
                truncated = chunk[:max(1, len(chunk) // 2)]
                sock.sendto(make_data_packet(block_num, truncated), client_addr)
        else:
            sock.sendto(make_data_packet(block_num, chunk), client_addr)

        # Wait for ACK with timeout
        sock.settimeout(3.0)
        try:
            ack_data, ack_addr = sock.recvfrom(516)
            if len(ack_data) >= 4:
                ack_opcode, ack_block = struct.unpack('!HH', ack_data[:4])
                if ack_opcode == OP_ACK and ack_block == block_num:
                    pass  # ACK received
        except socket.timeout:
            return  # Give up on timeout

        offset += BLOCK_SIZE
        block_num += 1

        if len(chunk) < BLOCK_SIZE:
            break  # Last block sent


def handle_wrq(sock, client_addr, filename, malformed):
    """Handle a write request by accepting data silently."""
    # Send ACK for block 0 to accept the write
    sock.sendto(make_ack_packet(0), client_addr)

    block_num = 1
    while True:
        sock.settimeout(3.0)
        try:
            data, addr = sock.recvfrom(516 + 4)
            if len(data) < 4:
                break
            opcode, recv_block = struct.unpack('!HH', data[:4])
            if opcode == OP_DATA and recv_block == block_num:
                sock.sendto(make_ack_packet(block_num), client_addr)
                payload = data[4:]
                block_num += 1
                if len(payload) < BLOCK_SIZE:
                    break  # Last block
        except socket.timeout:
            break


def main():
    parser = argparse.ArgumentParser(description='TFTP test server')
    parser.add_argument('--port', type=int, default=6969, help='TFTP port (default: 6969)')
    parser.add_argument('--mode', choices=['good', 'evil', 'both'], default='good',
                        help='Server response mode (only good supported for this protocol)')
    parser.add_argument('--state-dir', default=None, help='Directory for malformation state files')
    args = parser.parse_args()

    malformed = (args.mode != 'good')

    # Create temp directory with test files
    serve_dir = tempfile.mkdtemp(prefix='tftp_')
    create_test_files(serve_dir)
    print(f'Serving files from: {serve_dir}')

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', args.port))

    mode_str = f' (mode: {args.mode})'
    print(f'TFTP server running on port {args.port}{mode_str}')
    print('Press Ctrl+C to stop')

    try:
        while True:
            sock.settimeout(None)
            data, client_addr = sock.recvfrom(516)

            if len(data) < 4:
                continue

            opcode = struct.unpack('!H', data[:2])[0]

            if opcode == OP_RRQ:
                _, filename, mode = parse_request(data)
                if filename:
                    # Use a new socket for the transfer (per RFC 1350)
                    transfer_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    transfer_sock.bind(('0.0.0.0', 0))
                    handle_rrq(transfer_sock, client_addr, filename, serve_dir, malformed)
                    transfer_sock.close()

            elif opcode == OP_WRQ:
                _, filename, mode = parse_request(data)
                if filename:
                    transfer_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    transfer_sock.bind(('0.0.0.0', 0))
                    handle_wrq(transfer_sock, client_addr, filename, malformed)
                    transfer_sock.close()

            else:
                sock.sendto(make_error_packet(4, 'Illegal TFTP operation'), client_addr)

    except KeyboardInterrupt:
        print('\nShutting down...')
    finally:
        sock.close()


if __name__ == '__main__':
    main()
