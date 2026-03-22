# Adversarial Penetration Test Harness

Standalone Python scripts that probe the LDAPS server for protocol-level
weaknesses. Each script connects over TLS and exercises one attack surface.

## Prerequisites

- **Python 3.8+** (standard library only -- no pip packages required)
- **openssl** CLI (optional, for manual TLS inspection)
- A running instance of the LDAP server with TLS enabled (default `localhost:636`)

## Scripts

| Script | What it tests |
|---|---|
| `malformed_ber.py` | Sends malformed BER/ASN.1 payloads: oversized length fields, truncated messages, invalid tag bytes, and more. The server must reject every payload without crashing. |
| `tls_downgrade.py` | Attempts TLS 1.0, 1.1, and 1.2 connections. All must be rejected. Confirms only TLS 1.3 works. |
| `connection_flood.py` | Opens 200 simultaneous TLS connections to verify the server enforces its `max_connections` limit. |
| `brute_force.py` | Fires rapid bind (authentication) attempts to trigger rate limiting. |

## Usage

Run all scripts through the Justfile:

```bash
just pentest                         # localhost:636
just pentest 10.0.0.5 6360           # custom host/port
```

Or run individually:

```bash
python3 tests/adversarial/tls_downgrade.py [host] [port]
python3 tests/adversarial/malformed_ber.py [host] [port]
python3 tests/adversarial/connection_flood.py [host] [port]
python3 tests/adversarial/brute_force.py [host] [port]
```

## Interpreting results

Each script prints **PASS** / **FAIL** / **SKIP** per test case and a summary
line at the end. A well-configured server should pass every case. `SKIP` means
the server was unreachable (not running, firewall, etc.).
