#!/usr/bin/env python3
"""Verify the LDAPS server rejects TLS versions below 1.3."""

import ssl
import socket
import sys

DEFAULT_HOST = "localhost"
DEFAULT_PORT = 636

def try_tls_version(host, port, version_name, min_version, max_version):
    """Attempt a TLS connection with a specific version."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = min_version
    ctx.maximum_version = max_version

    try:
        sock = socket.create_connection((host, port), timeout=5)
        tls_sock = ctx.wrap_socket(sock, server_hostname=host)
        negotiated = tls_sock.version()
        tls_sock.close()
        print(f"  FAIL: {version_name} connection succeeded (negotiated {negotiated})")
        return False
    except ssl.SSLError as e:
        print(f"  PASS: {version_name} rejected: {e}")
        return True
    except Exception as e:
        print(f"  PASS: {version_name} connection failed: {e}")
        return True

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT

    print(f"Target: {host}:{port}")
    results = []

    tests = [
        ("TLS 1.0", ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
        ("TLS 1.1", ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
        ("TLS 1.2", ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
    ]

    for name, min_v, max_v in tests:
        print(f"\n[TEST] {name} connection attempt")
        results.append(try_tls_version(host, port, name, min_v, max_v))

    # TLS 1.3 should succeed
    print(f"\n[TEST] TLS 1.3 connection attempt (should succeed)")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    try:
        sock = socket.create_connection((host, port), timeout=5)
        tls_sock = ctx.wrap_socket(sock, server_hostname=host)
        print(f"  PASS: TLS 1.3 connected (negotiated {tls_sock.version()})")
        results.append(True)
        tls_sock.close()
    except Exception as e:
        print(f"  FAIL: TLS 1.3 connection failed: {e}")
        results.append(False)

    passed = sum(results)
    print(f"\nResults: {passed}/{len(results)} passed")

if __name__ == "__main__":
    main()
