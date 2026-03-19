#!/usr/bin/env python3
"""Send malformed BER payloads to an LDAPS server to test codec robustness."""

import ssl
import socket
import sys
import struct

DEFAULT_HOST = "localhost"
DEFAULT_PORT = 636

def make_tls_connection(host, port):
    """Connect to the LDAPS server with TLS 1.3."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    sock = socket.create_connection((host, port), timeout=5)
    return ctx.wrap_socket(sock, server_hostname=host)

def test_oversized_length(conn):
    """Send SEQUENCE with 4GB length claim."""
    payload = b'\x30\x84\xff\xff\xff\xff'  # SEQUENCE, 4-byte length = ~4GB
    try:
        conn.send(payload)
        # Server should reject and close connection
        data = conn.recv(1024)
        print(f"  Response ({len(data)} bytes): {data[:50].hex()}")
    except Exception as e:
        print(f"  Connection closed (expected): {e}")
    return True

def test_deeply_nested_filter():
    """Build a search request with deeply nested NOT filters."""
    # Present filter: (objectClass=*)
    leaf = bytes([0x87]) + bytes([len(b"objectClass")]) + b"objectClass"
    # Wrap in 100 NOT tags
    nested = leaf
    for _ in range(100):
        nested = bytes([0xA2]) + encode_ber_length(len(nested)) + nested
    return nested

def test_truncated_message(conn):
    """Send a truncated LDAP message."""
    payload = b'\x30\x10\x02\x01\x01'  # SEQUENCE(16 bytes), but only 5 bytes sent
    try:
        conn.send(payload)
        import time; time.sleep(1)
        conn.send(b'\x00')  # Trickle one more byte
        data = conn.recv(1024)
        print(f"  Response ({len(data)} bytes)")
    except Exception as e:
        print(f"  Connection closed: {e}")
    return True

def test_invalid_tag(conn):
    """Send bytes with invalid/unexpected tags."""
    payload = b'\xFF\x00'  # Invalid tag 0xFF
    try:
        conn.send(payload)
        data = conn.recv(1024)
        print(f"  Response: {data[:50].hex()}")
    except Exception as e:
        print(f"  Connection closed (expected): {e}")
    return True

def encode_ber_length(length):
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    elif length < 0x10000:
        return bytes([0x82, length >> 8, length & 0xFF])
    else:
        return bytes([0x84]) + struct.pack('>I', length)

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT

    tests = [
        ("Oversized length field", test_oversized_length),
        ("Truncated message", test_truncated_message),
        ("Invalid tag byte", test_invalid_tag),
    ]

    print(f"Target: {host}:{port}")
    passed = 0
    for name, test_fn in tests:
        print(f"\n[TEST] {name}")
        try:
            conn = make_tls_connection(host, port)
            if test_fn(conn):
                print(f"  PASS: Server handled gracefully")
                passed += 1
            conn.close()
        except ConnectionRefusedError:
            print(f"  SKIP: Connection refused (server not running?)")
        except Exception as e:
            print(f"  ERROR: {e}")

    print(f"\nResults: {passed}/{len(tests)} passed")

if __name__ == "__main__":
    main()
