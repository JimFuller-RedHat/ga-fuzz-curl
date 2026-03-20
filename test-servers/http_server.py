#!/usr/bin/env python3
"""flask-based HTTP/HTTPS/WS/WSS test server for curl fuzzing.

Supports HTTP/1.1 and HTTP/2 via Hypercorn (ASGI).
Falls back to Werkzeug (HTTP/1.1 only) if Hypercorn not installed.
"""

import argparse
import os
import random
import socket
import socketserver
import sys
import time
from flask import Flask, request, Response

sys.path.insert(0, os.path.dirname(__file__))
from tls_wrapper import add_tls_args, create_tls_context
from malformation_rotator import MalformationRotator

app = Flask(__name__)


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
def catch_all(path):
    """Handle all HTTP requests in good mode."""
    if path == 'ws':
        return handle_websocket()
    return Response('OK\n', status=200)


def handle_websocket():
    """Handle WebSocket connections."""
    try:
        from simple_websocket import Server as WSServer, ConnectionClosed
        ws = WSServer.connected(request.environ)
    except (ImportError, ConnectionError):
        return Response('WebSocket upgrade failed\n', status=400)
    try:
        while True:
            data = ws.receive(timeout=5)
            if data is None:
                break
            ws.send(data)
    except Exception:
        pass
    return Response('', status=200)


def _read_http_request(conn):
    """Read and discard an HTTP request."""
    data = b""
    try:
        conn.settimeout(3)
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
    except Exception:
        pass
    return data


def evil_missing_crlf(conn):
    """Headers with bare \n instead of \r\n."""
    _read_http_request(conn)
    response = b"HTTP/1.1 200 OK\nContent-Length: 5\n\nOK\n\n"
    try:
        conn.sendall(response)
    except Exception:
        pass


def evil_truncated_headers(conn):
    """Send HTTP/1.1 200 OK\r\nContent-Len then close."""
    _read_http_request(conn)
    response = b"HTTP/1.1 200 OK\r\nContent-Len"
    try:
        conn.sendall(response)
    except Exception:
        pass


def evil_duplicate_content_length(conn):
    """Two conflicting Content-Length headers."""
    _read_http_request(conn)
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 5\r\n"
        b"Content-Length: 50000\r\n"
        b"\r\n"
        b"OK\n\n"
    )
    try:
        conn.sendall(response)
    except Exception:
        pass


def evil_oversized_header(conn):
    """Header value of 64KB+."""
    _read_http_request(conn)
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"X-Large: " + b"X" * 65536 + b"\r\n"
        b"\r\n"
    )
    try:
        conn.sendall(response)
    except Exception:
        pass


def evil_nul_in_headers(conn):
    """X-Test: val\x00ue."""
    _read_http_request(conn)
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"X-Test: val\x00ue\r\n"
        b"\r\n"
    )
    try:
        conn.sendall(response)
    except Exception:
        pass


def evil_missing_status_line(conn):
    """Send This is not HTTP at all\r\n."""
    _read_http_request(conn)
    response = b"This is not HTTP at all\r\n"
    try:
        conn.sendall(response)
    except Exception:
        pass


def evil_malformed_status_line(conn):
    """HTTP/9.9 999 FAKE."""
    _read_http_request(conn)
    response = b"HTTP/9.9 999 FAKE\r\n\r\n"
    try:
        conn.sendall(response)
    except Exception:
        pass


def evil_header_no_colon(conn):
    """NotAHeader\r\n without colon."""
    _read_http_request(conn)
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"NotAHeader\r\n"
        b"\r\n"
    )
    try:
        conn.sendall(response)
    except Exception:
        pass


def evil_content_length_short(conn):
    """Claims 10000, sends 5 bytes."""
    _read_http_request(conn)
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 10000\r\n"
        b"\r\n"
        b"OK\n\n"
    )
    try:
        conn.sendall(response)
    except Exception:
        pass


def evil_content_length_long(conn):
    """Claims 5, sends 10000 bytes."""
    _read_http_request(conn)
    body = b"X" * 10000
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 5\r\n"
        b"\r\n" + body
    )
    try:
        conn.sendall(response)
    except Exception:
        pass


def evil_truncated_chunked(conn):
    """Chunk started, EOF mid-chunk."""
    _read_http_request(conn)
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"a\r\n"
        b"12345"
    )
    try:
        conn.sendall(response)
    except Exception:
        pass


def evil_invalid_chunk_size(conn):
    """Non-hex chunk length ZZZZ."""
    _read_http_request(conn)
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"ZZZZ\r\n"
    )
    try:
        conn.sendall(response)
    except Exception:
        pass


def evil_chunked_no_terminator(conn):
    """Chunks sent, no 0\r\n\r\n."""
    _read_http_request(conn)
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"5\r\n"
        b"hello\r\n"
        b"5\r\n"
        b"world\r\n"
    )
    try:
        conn.sendall(response)
    except Exception:
        pass


def evil_gzip_lie(conn):
    """Claims gzip encoding, sends raw text."""
    _read_http_request(conn)
    body = b"This is not gzipped\n"
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Encoding: gzip\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n" + body
    )
    try:
        conn.sendall(response)
    except Exception:
        pass


def evil_slow_drip(conn):
    """1 byte every 500ms, capped at 20 bytes."""
    _read_http_request(conn)
    header = b"HTTP/1.1 200 OK\r\n\r\n"
    try:
        conn.sendall(header)
        for i in range(20):
            conn.sendall(b"X")
            time.sleep(0.5)
    except Exception:
        pass


def evil_immediate_close(conn):
    """Just return without sending."""
    _read_http_request(conn)


def evil_partial_then_close(conn):
    """Send HTTP/1.1 200 then close."""
    _read_http_request(conn)
    response = b"HTTP/1.1 200"
    try:
        conn.sendall(response)
    except Exception:
        pass


HTTP_MALFORMATIONS = [
    (evil_missing_crlf, "missing_crlf"),
    (evil_truncated_headers, "truncated_headers"),
    (evil_duplicate_content_length, "duplicate_content_length"),
    (evil_oversized_header, "oversized_header"),
    (evil_nul_in_headers, "nul_in_headers"),
    (evil_missing_status_line, "missing_status_line"),
    (evil_malformed_status_line, "malformed_status_line"),
    (evil_header_no_colon, "header_no_colon"),
    (evil_content_length_short, "content_length_short"),
    (evil_content_length_long, "content_length_long"),
    (evil_truncated_chunked, "truncated_chunked"),
    (evil_invalid_chunk_size, "invalid_chunk_size"),
    (evil_chunked_no_terminator, "chunked_no_terminator"),
    (evil_gzip_lie, "gzip_lie"),
    (evil_slow_drip, "slow_drip"),
    (evil_immediate_close, "immediate_close"),
    (evil_partial_then_close, "partial_then_close"),
]


def _do_normal_http(conn):
    """Minimal well-formed HTTP response."""
    _read_http_request(conn)
    body = b"Hello from curl-fuzz test server\n"
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n" + body
    )
    try:
        conn.sendall(response)
    except Exception:
        pass


class EvilHTTPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        rotator = self.server.rotator
        is_evil, fn, n = rotator.next_action()

        if is_evil:
            name = "unknown"
            for mfn, mname in HTTP_MALFORMATIONS:
                if mfn is fn:
                    name = mname
                    break
            rotator.log_action("HTTP", n, True, name)
            try:
                fn(self.request)
            except Exception:
                pass
        else:
            rotator.log_action("HTTP", n, False)
            _do_normal_http(self.request)

        try:
            self.request.close()
        except Exception:
            pass


def _run_flask(args):
    """Run Flask server in good mode."""
    tls = args.tls
    if tls and (not args.certfile or not args.keyfile):
        print('Error: --tls requires --certfile and --keyfile', file=sys.stderr)
        sys.exit(1)

    if args.no_h2:
        run_with_werkzeug(args.port, tls, args.certfile, args.keyfile, args.mode)
        return

    try:
        import hypercorn  # noqa: F401
        run_with_hypercorn(args.port, tls, args.certfile, args.keyfile, args.mode)
    except ImportError:
        print('Warning: hypercorn not installed, falling back to werkzeug (no h2)',
              file=sys.stderr)
        run_with_werkzeug(args.port, tls, args.certfile, args.keyfile, args.mode)


def run_with_hypercorn(port, tls, certfile, keyfile, mode):
    """Run with Hypercorn for HTTP/2 support."""
    import asyncio
    import logging
    from hypercorn.config import Config
    from hypercorn.asyncio import serve

    logging.getLogger("hypercorn.error").setLevel(logging.CRITICAL)

    config = Config()
    config.bind = [f'0.0.0.0:{port}']

    if tls:
        config.certfile = certfile
        config.keyfile = keyfile
        proto = 'HTTPS+H2'
    else:
        proto = 'HTTP+H2C'

    print(f'{proto} server running on port {port} (mode={mode}) [hypercorn]', file=sys.stderr)
    asyncio.run(serve(app, config))


def run_with_werkzeug(port, tls, certfile, keyfile, mode):
    """Fallback: run with Flask/Werkzeug (HTTP/1.1 only)."""
    ssl_ctx = None
    if tls:
        ssl_ctx = create_tls_context(certfile, keyfile)

    proto = 'HTTPS' if tls else 'HTTP'
    print(f'{proto} server running on port {port} (mode={mode}) [werkzeug, no h2]', file=sys.stderr)
    app.run(host='0.0.0.0', port=port, threaded=True, ssl_context=ssl_ctx)


def main():
    parser = argparse.ArgumentParser(description='HTTP/HTTPS/WS/WSS test server')
    parser.add_argument('--port', type=int, default=8080, help='Listen port')
    parser.add_argument('--mode', choices=['good', 'evil', 'both'],
                        default='good', help='Server behavior mode')
    parser.add_argument('--no-h2', action='store_true',
                        help='Disable HTTP/2, use Werkzeug instead of Hypercorn')
    parser.add_argument('--state-dir', default=None,
                        help='Directory for malformation state files')
    add_tls_args(parser)

    args = parser.parse_args()

    if args.mode == 'good':
        _run_flask(args)
        return

    # evil or both mode: use raw TCP server
    state_file = None
    if args.state_dir:
        os.makedirs(args.state_dir, exist_ok=True)
        state_file = os.path.join(args.state_dir, "http.state")
    malformation_fns = [fn for fn, _ in HTTP_MALFORMATIONS]
    rotator = MalformationRotator(malformation_fns, mode=args.mode, state_file=state_file)

    socketserver.ThreadingTCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer(('0.0.0.0', args.port), EvilHTTPHandler)
    server.rotator = rotator

    if args.tls:
        if not args.certfile or not args.keyfile:
            print('Error: --tls requires --certfile and --keyfile', file=sys.stderr)
            sys.exit(1)
        import ssl
        ssl_ctx = create_tls_context(args.certfile, args.keyfile)
        server.socket = ssl_ctx.wrap_socket(server.socket, server_side=True)
        proto = 'HTTPS'
    else:
        proto = 'HTTP'

    print(f'{proto} server running on port {args.port} (mode={args.mode}) [evil/socketserver]',
          file=sys.stderr)
    server.serve_forever()


if __name__ == '__main__':
    main()
