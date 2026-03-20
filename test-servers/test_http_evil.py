"""Tests for HTTP evil server malformations."""

import sys
import os
import socket
import subprocess
import time

sys.path.insert(0, os.path.dirname(__file__))

SERVER_SCRIPT = os.path.join(os.path.dirname(__file__), "http_server.py")
TEST_PORT = 18080


def start_server(mode, port=TEST_PORT):
    proc = subprocess.Popen(
        [sys.executable, SERVER_SCRIPT, "--port", str(port), "--mode", mode, "--no-h2"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(3)
    return proc


def raw_http_get(port=TEST_PORT):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(("127.0.0.1", port))
    s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    data = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    finally:
        s.close()
    return data


def test_good_mode_returns_normal():
    proc = start_server("good", port=18080)
    try:
        data = raw_http_get(port=18080)
        assert b"HTTP/1." in data
        assert b"200" in data
    finally:
        proc.terminate()
        proc.wait()


def test_evil_mode_returns_malformed():
    proc = start_server("evil", port=18081)
    try:
        responses = []
        for _ in range(3):
            data = raw_http_get(port=18081)
            responses.append(data)
        normal_count = sum(1 for r in responses if b"HTTP/1.1 200 OK\r\n" in r
                          and b"\r\n\r\n" in r)
        assert normal_count < 3, "Expected at least one malformed response"
    finally:
        proc.terminate()
        proc.wait()


def test_both_mode_alternates():
    proc = start_server("both", port=18082)
    try:
        r0 = raw_http_get(port=18082)
        r1 = raw_http_get(port=18082)
        r2 = raw_http_get(port=18082)
        assert b"HTTP/1." in r0
        assert b"HTTP/1." in r2
    finally:
        proc.terminate()
        proc.wait()
