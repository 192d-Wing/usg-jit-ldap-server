# Certificate Rotation

This document describes the procedure for rotating the TLS certificate used by the USG JIT LDAP Server. The server enforces TLS 1.3 only.

---

## Prerequisites

- OpenSSL 1.1.1+ installed on the host.
- Access to the server's configuration file (`config.toml`).
- Permission to restart the LDAP server process.
- The new certificate must be signed by a CA trusted by all connecting brokers.

---

## Procedure

### 1. Generate a New Private Key and CSR

```bash
# Generate a new ECDSA P-256 private key
openssl ecparam -genkey -name prime256v1 -noout -out server-new.key

# Create a certificate signing request
openssl req -new -key server-new.key \
  -out server-new.csr \
  -subj "/C=US/O=USG/CN=ldap.example.gov" \
  -addext "subjectAltName=DNS:ldap.example.gov"
```

Submit `server-new.csr` to your CA and obtain the signed certificate (`server-new.crt`).

### 2. Validate the Certificate Chain

```bash
# Verify the certificate was signed by the expected CA
openssl verify -CAfile /path/to/ca-bundle.crt server-new.crt

# Confirm the certificate and key match
openssl x509 -noout -modulus -in server-new.crt | openssl sha256
openssl ec -noout -modulus -in server-new.key 2>/dev/null | openssl sha256
# (For ECDSA keys, compare the public key instead)
openssl pkey -pubout -in server-new.key | openssl sha256
openssl x509 -pubkey -noout -in server-new.crt | openssl sha256

# Inspect the certificate details
openssl x509 -noout -text -in server-new.crt | head -30
```

Verify that:
- The subject and SAN match the expected hostname.
- The validity period (`Not Before` / `Not After`) is correct.
- The signature algorithm is acceptable (e.g. `ecdsa-with-SHA256`).

### 3. Install the New Certificate

```bash
# Back up existing certificates
cp /etc/ldap-server/certs/server.crt /etc/ldap-server/certs/server.crt.bak
cp /etc/ldap-server/certs/server.key /etc/ldap-server/certs/server.key.bak

# Install new certificate and key with restrictive permissions
install -m 0644 server-new.crt /etc/ldap-server/certs/server.crt
install -m 0600 server-new.key /etc/ldap-server/certs/server.key
```

### 4. Update config.toml (if paths changed)

If the new certificate uses different file paths, update `config.toml`:

```toml
[tls]
cert_path = "/etc/ldap-server/certs/server.crt"
key_path  = "/etc/ldap-server/certs/server.key"
```

### 5. Restart the Service

```bash
# Systemd
sudo systemctl restart ldap-server

# Or, if running in a container
docker restart ldap-server
```

### 6. Verify the TLS Handshake

```bash
# Confirm the server is presenting the new certificate with TLS 1.3
openssl s_client -connect ldap.example.gov:636 \
  -tls1_3 \
  -brief \
  </dev/null 2>&1 | head -20

# Check the certificate serial / fingerprint matches the new cert
openssl s_client -connect ldap.example.gov:636 \
  </dev/null 2>&1 | openssl x509 -noout -serial -fingerprint
```

### 7. Monitor for TLS Errors

After rotation, watch the logs for at least 15 minutes:

```bash
# Systemd journal
journalctl -u ldap-server -f --since "now" | grep -i tls

# Or container logs
docker logs -f ldap-server 2>&1 | grep -i tls
```

Check the audit log for authentication failures that may indicate brokers are rejecting the new certificate:

```bash
grep '"event":"bind_failure"' /var/log/ldap-server/audit.jsonl | tail -20
```

---

## Rollback Procedure

If brokers cannot connect after rotation:

1. Restore the backed-up certificate and key:
   ```bash
   cp /etc/ldap-server/certs/server.crt.bak /etc/ldap-server/certs/server.crt
   cp /etc/ldap-server/certs/server.key.bak /etc/ldap-server/certs/server.key
   ```
2. Restart the service:
   ```bash
   sudo systemctl restart ldap-server
   ```
3. Verify connectivity is restored using the TLS handshake check above.
4. Investigate the root cause before reattempting rotation.

---

## Automation Notes

Consider automating certificate rotation with a tool like `certbot` or your organization's PKI tooling. The server does not currently support hot-reloading certificates; a restart is always required.
