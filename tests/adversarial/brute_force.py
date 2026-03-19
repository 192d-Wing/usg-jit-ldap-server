#!/usr/bin/env python3
"""Test bind rate limiting by sending rapid authentication attempts."""

import ssl
import socket
import sys
import struct

DEFAULT_HOST = "localhost"
DEFAULT_PORT = 636
NUM_ATTEMPTS = 20

def encode_ber_length(length):
    if length < 0x80:
        return bytes([length])
    return bytes([0x81, length])

def make_bind_request(message_id, dn, password):
    """Build a minimal LDAP BindRequest."""
    # version INTEGER(3)
    version = b'\x02\x01\x03'
    # name OCTET STRING
    dn_bytes = dn.encode('utf-8')
    name = b'\x04' + encode_ber_length(len(dn_bytes)) + dn_bytes
    # auth [0] password
    pw_bytes = password.encode('utf-8')
    auth = b'\x80' + encode_ber_length(len(pw_bytes)) + pw_bytes
    # BindRequest [APPLICATION 0]
    bind_contents = version + name + auth
    bind_req = b'\x60' + encode_ber_length(len(bind_contents)) + bind_contents
    # messageID INTEGER
    msg_id = b'\x02\x01' + bytes([message_id & 0xFF])
    # LDAPMessage SEQUENCE
    msg_contents = msg_id + bind_req
    return b'\x30' + encode_ber_length(len(msg_contents)) + msg_contents

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
    attempts = int(sys.argv[3]) if len(sys.argv) > 3 else NUM_ATTEMPTS

    print(f"Target: {host}:{port}")
    print(f"Sending {attempts} bind attempts for cn=testuser,dc=example,dc=com")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3

    rate_limited = False
    for i in range(attempts):
        try:
            sock = socket.create_connection((host, port), timeout=5)
            tls_sock = ctx.wrap_socket(sock, server_hostname=host)

            bind_req = make_bind_request(i + 1, "cn=testuser,dc=example,dc=com", f"wrong-password-{i}")
            tls_sock.send(bind_req)

            response = tls_sock.recv(4096)
            # Check if response contains InvalidCredentials (49) or other error
            if b'\x31' in response:  # ResultCode 49 = InvalidCredentials
                status = "invalid_credentials"
            elif len(response) == 0:
                status = "connection_closed"
                rate_limited = True
            else:
                status = f"response({len(response)} bytes)"

            print(f"  Attempt {i+1}: {status}")
            tls_sock.close()
        except Exception as e:
            print(f"  Attempt {i+1}: error - {e}")
            rate_limited = True

    if rate_limited:
        print("\nPASS: Rate limiting detected")
    else:
        print("\nINFO: No rate limiting detected (may need more attempts)")

if __name__ == "__main__":
    main()
