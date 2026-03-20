#!/usr/bin/env python3
"""Shared TLS certificate generation and socket wrapping for test servers."""

import os
import ssl
import sys


def generate_cert(output_dir):
    """Generate self-signed RSA 2048 cert+key. Returns (certfile, keyfile) paths."""
    os.makedirs(output_dir, exist_ok=True)
    cert_path = os.path.join(output_dir, 'server.crt')
    key_path = os.path.join(output_dir, 'server.key')

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from datetime import datetime, timedelta, timezone
        import ipaddress

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'localhost'),
        ])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName('localhost'),
                    x509.IPAddress(ipaddress.IPv4Address('127.0.0.1')),
                ]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        with open(key_path, 'wb') as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        with open(cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    except ImportError:
        import subprocess
        cmd = [
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
            '-keyout', key_path, '-out', cert_path,
            '-days', '365', '-nodes',
            '-subj', '/CN=localhost',
            '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
        ]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    return cert_path, key_path


def create_tls_context(certfile, keyfile):
    """Create an SSL context for wrapping server sockets."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile, keyfile)
    return context


def wrap_socket(sock, certfile, keyfile):
    """Wrap an existing server socket with TLS."""
    context = create_tls_context(certfile, keyfile)
    return context.wrap_socket(sock, server_side=True)


def add_tls_args(parser):
    """Add standard --tls, --certfile, --keyfile args to an argparse parser."""
    parser.add_argument('--tls', action='store_true', help='Enable TLS')
    parser.add_argument('--certfile', type=str, help='Path to TLS certificate')
    parser.add_argument('--keyfile', type=str, help='Path to TLS private key')
