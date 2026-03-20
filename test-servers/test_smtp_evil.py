"""Tests for SMTP evil server malformations."""

import os
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))

SERVER_SCRIPT = os.path.join(os.path.dirname(__file__), "smtp_server.py")
TEST_PORT = 12525


def start_server(mode, port=TEST_PORT):
    proc = subprocess.Popen(
        [sys.executable, SERVER_SCRIPT, "--port", str(port), "--mode", mode],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(2)
    return proc


def smtp_connect(port=TEST_PORT):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(("127.0.0.1", port))
    return s


def recv_all(s, timeout=3):
    s.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data


def test_good_mode_smtp():
    proc = start_server("good", port=12525)
    try:
        s = smtp_connect(port=12525)
        banner = recv_all(s, timeout=2)
        assert b"220" in banner
        s.close()
    finally:
        proc.terminate()
        proc.wait()


def test_evil_mode_smtp():
    proc = start_server("evil", port=12526)
    try:
        results = []
        for _ in range(3):
            try:
                s = smtp_connect(port=12526)
                data = recv_all(s, timeout=3)
                results.append(data)
                s.close()
            except Exception:
                results.append(b"")
        normal = sum(1 for r in results if r == b"220 SMTP server ready\r\n")
        assert normal < 3
    finally:
        proc.terminate()
        proc.wait()


def test_both_mode_smtp():
    proc = start_server("both", port=12527)
    try:
        s0 = smtp_connect(port=12527)
        d0 = recv_all(s0, timeout=2)
        assert b"220" in d0
        s0.close()
    finally:
        proc.terminate()
        proc.wait()
