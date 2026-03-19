#!/usr/bin/env python3
"""Test connection flood handling -- server should enforce max_connections."""

import ssl
import socket
import sys
import time
import concurrent.futures

DEFAULT_HOST = "localhost"
DEFAULT_PORT = 636
NUM_CONNECTIONS = 200

def make_connection(host, port, conn_id):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    try:
        sock = socket.create_connection((host, port), timeout=5)
        tls_sock = ctx.wrap_socket(sock, server_hostname=host)
        return (conn_id, True, tls_sock)
    except Exception as e:
        return (conn_id, False, str(e))

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
    count = int(sys.argv[3]) if len(sys.argv) > 3 else NUM_CONNECTIONS

    print(f"Target: {host}:{port}")
    print(f"Attempting {count} simultaneous connections...")

    connections = []
    rejected = 0
    accepted = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(make_connection, host, port, i) for i in range(count)]
        for future in concurrent.futures.as_completed(futures):
            conn_id, success, result = future.result()
            if success:
                accepted += 1
                connections.append(result)
            else:
                rejected += 1

    print(f"\nAccepted: {accepted}")
    print(f"Rejected: {rejected}")

    if rejected > 0:
        print("PASS: Server enforced connection limits")
    else:
        print("WARNING: All connections accepted -- verify max_connections config")

    # Clean up
    for conn in connections:
        try:
            conn.close()
        except:
            pass

if __name__ == "__main__":
    main()
