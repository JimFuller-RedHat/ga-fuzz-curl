"""Tests for FTP evil server malformations."""

import os
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))

SERVER_SCRIPT = os.path.join(os.path.dirname(__file__), "ftp_server.py")
TEST_PORT = 12121


def start_server(mode, port=TEST_PORT):
    """Start FTP server in specified mode."""
    proc = subprocess.Popen(
        [sys.executable, SERVER_SCRIPT, "--port", str(port), "--mode", mode],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(2)
    return proc


def ftp_connect(port=TEST_PORT):
    """Connect to FTP server."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(("127.0.0.1", port))
    return s


def recv_all(s, timeout=3):
    """Receive all data from socket with timeout."""
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


def test_good_mode_ftp():
    """Test that good mode serves normal FTP responses."""
    proc = start_server("good", port=12121)
    try:
        s = ftp_connect(port=12121)
        banner = recv_all(s, timeout=2)
        assert b"220" in banner
        s.close()
    finally:
        proc.terminate()
        proc.wait()


def test_evil_mode_ftp():
    """Test that evil mode serves malformations."""
    proc = start_server("evil", port=12122)
    try:
        results = []
        for _ in range(3):
            s = ftp_connect(port=12122)
            data = recv_all(s, timeout=2)
            results.append(data)
            s.close()
        # In evil mode, we should not get all normal banners
        normal = sum(1 for r in results if r == b"220 FTP server ready\r\n")
        assert normal < 3
    finally:
        proc.terminate()
        proc.wait()


def test_both_mode_ftp():
    """Test that both mode serves both good and evil responses."""
    proc = start_server("both", port=12123)
    try:
        s0 = ftp_connect(port=12123)
        d0 = recv_all(s0, timeout=2)
        assert b"220" in d0
        s0.close()
    finally:
        proc.terminate()
        proc.wait()
