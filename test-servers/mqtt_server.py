#!/usr/bin/env python3
"""Minimal MQTT broker using raw sockets."""

import argparse
import os
import random
import socketserver
import struct
import sys

sys.path.insert(0, os.path.dirname(__file__))
from tls_wrapper import add_tls_args, wrap_socket


def _decode_remaining_length(data, offset):
    """Decode MQTT variable-length encoding. Returns (value, bytes_consumed)."""
    multiplier = 1
    value = 0
    idx = offset
    while idx < len(data):
        encoded_byte = data[idx]
        value += (encoded_byte & 0x7F) * multiplier
        multiplier *= 128
        idx += 1
        if (encoded_byte & 0x80) == 0:
            break
    return value, idx - offset


class MQTTHandler(socketserver.BaseRequestHandler):
    """Minimal MQTT 3.1.1 protocol handler."""

    def handle(self):
        """Handle MQTT client connection."""
        malformed = getattr(self.server, 'malformed', False)
        buf = b''

        while True:
            try:
                chunk = self.request.recv(4096)
                if not chunk:
                    break
                buf += chunk

                while len(buf) >= 2:
                    packet_type = (buf[0] & 0xF0)
                    remaining_len, len_bytes = _decode_remaining_length(buf, 1)
                    total_len = 1 + len_bytes + remaining_len

                    if len(buf) < total_len:
                        break  # wait for more data

                    packet = buf[:total_len]
                    buf = buf[total_len:]

                    self._handle_packet(packet_type, packet, malformed)

            except (ConnectionResetError, BrokenPipeError, OSError):
                break

    def _handle_packet(self, packet_type, packet, malformed):
        """Dispatch a single MQTT packet."""
        if packet_type == 0x10:
            # CONNECT -> CONNACK
            if malformed:
                # Send invalid CONNACK with bad return code
                self.request.sendall(bytes([0x20, 0x02, 0x00, 0x05]))
                # Also send some random garbage
                self.request.sendall(os.urandom(random.randint(1, 20)))
            else:
                self.request.sendall(bytes([0x20, 0x02, 0x00, 0x00]))

        elif packet_type == 0x30:
            # PUBLISH
            if malformed:
                self.request.sendall(os.urandom(random.randint(1, 10)))
                return
            # Check QoS from fixed header flags
            qos = (packet[0] & 0x06) >> 1
            if qos >= 1:
                # Extract packet identifier (after topic)
                remaining_len, len_bytes = _decode_remaining_length(packet, 1)
                offset = 1 + len_bytes
                if offset + 2 <= len(packet):
                    topic_len = struct.unpack('!H', packet[offset:offset + 2])[0]
                    offset += 2 + topic_len
                    if offset + 2 <= len(packet):
                        packet_id = packet[offset:offset + 2]
                        if qos == 1:
                            # PUBACK
                            self.request.sendall(bytes([0x40, 0x02]) + packet_id)
                        elif qos == 2:
                            # PUBREC
                            self.request.sendall(bytes([0x50, 0x02]) + packet_id)

        elif packet_type == 0x80:
            # SUBSCRIBE
            if malformed:
                self.request.sendall(os.urandom(random.randint(2, 15)))
                return
            remaining_len, len_bytes = _decode_remaining_length(packet, 1)
            offset = 1 + len_bytes
            if offset + 2 <= len(packet):
                packet_id = packet[offset:offset + 2]
                # Count topic filters to build return codes
                pos = offset + 2
                granted_qos = []
                while pos < len(packet):
                    if pos + 2 > len(packet):
                        break
                    topic_len = struct.unpack('!H', packet[pos:pos + 2])[0]
                    pos += 2 + topic_len
                    if pos < len(packet):
                        requested_qos = packet[pos]
                        granted_qos.append(min(requested_qos, 2))
                        pos += 1
                if not granted_qos:
                    granted_qos = [0x00]
                payload = bytes(granted_qos)
                suback_remaining = 2 + len(payload)
                self.request.sendall(bytes([0x90, suback_remaining]) + packet_id + payload)

        elif packet_type == 0xC0:
            # PINGREQ -> PINGRESP
            if malformed:
                self.request.sendall(os.urandom(random.randint(1, 5)))
            else:
                self.request.sendall(bytes([0xD0, 0x00]))

        elif packet_type == 0xE0:
            # DISCONNECT
            pass  # connection will close naturally

        elif packet_type == 0x60:
            # PUBREL (QoS 2 flow) -> PUBCOMP
            remaining_len, len_bytes = _decode_remaining_length(packet, 1)
            offset = 1 + len_bytes
            if offset + 2 <= len(packet):
                packet_id = packet[offset:offset + 2]
                self.request.sendall(bytes([0x70, 0x02]) + packet_id)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """TCP server with threading support."""
    allow_reuse_address = True


def main():
    parser = argparse.ArgumentParser(description='MQTT test server')
    parser.add_argument('--port', type=int, default=1883, help='MQTT port (default: 1883)')
    parser.add_argument('--mode', choices=['good', 'evil', 'both'], default='good',
                        help='Server response mode (only good supported for this protocol)')
    parser.add_argument('--state-dir', default=None, help='Directory for malformation state files')
    add_tls_args(parser)
    args = parser.parse_args()

    server = ThreadedTCPServer(('0.0.0.0', args.port), MQTTHandler)
    server.malformed = (args.mode != 'good')

    if args.tls:
        server.socket = wrap_socket(server.socket, args.certfile, args.keyfile)

    proto = 'MQTTS' if args.tls else 'MQTT'
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
