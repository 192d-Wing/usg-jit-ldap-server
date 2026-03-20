# USG JIT LDAP Server -- Deployment Guide

## Prerequisites

- **PostgreSQL 16+** with an empty database for the identity schema
- **TLS certificates** (X.509 server cert + private key, CA bundle for client verification)
- **Rust 1.75+** (for building from source) or **Docker 24+** (for container deployment)
- A dedicated non-root service account (`ldap-server`)

## 1. Database Setup

Create the PostgreSQL database and run migrations:

```bash
# Create user and database
sudo -u postgres createuser --no-superuser --no-createrole --no-createdb ldap_server
sudo -u postgres createdb --owner=ldap_server ldap_identity

# Set a strong password
sudo -u postgres psql -c "ALTER USER ldap_server WITH PASSWORD '<strong-random-password>';"

# Run migrations (from the project root)
export DATABASE_URL="postgres://ldap_server:<password>@localhost/ldap_identity"
sqlx migrate run --source migrations/
```

Verify the schema was created:

```bash
sudo -u postgres psql -d ldap_identity -c "\dt"
```

You should see tables for identities, groups, audit logs, and JIT provisioning state.

## 2. Certificate Provisioning

The server requires TLS certificates for LDAPS (port 636):

```bash
# Create certificate directory
sudo mkdir -p /etc/ldap-server/certs
sudo chmod 0700 /etc/ldap-server/certs

# Copy certificates (from your CA or ACME provider)
sudo cp server.crt /etc/ldap-server/certs/server.crt
sudo cp server.key /etc/ldap-server/certs/server.key
sudo cp ca-bundle.crt /etc/ldap-server/certs/ca-bundle.crt

# Lock down permissions
sudo chmod 0600 /etc/ldap-server/certs/*
sudo chown -R ldap-server:ldap-server /etc/ldap-server/certs/
```

For mutual TLS (mTLS), also provide the client CA certificate that will be used to
verify connecting clients.

## 3. Configuration File

Create `/etc/ldap-server/config.toml` from the example config:

```bash
sudo cp config.example.toml /etc/ldap-server/config.toml
sudo chmod 0600 /etc/ldap-server/config.toml
sudo chown ldap-server:ldap-server /etc/ldap-server/config.toml
```

Edit the configuration to set at minimum:

- `[tls]` -- paths to your server certificate, key, and CA bundle
- `[database]` -- PostgreSQL connection string
- `[ldap]` -- base DN, bind credentials, listen address
- `[admin]` -- health/metrics endpoint bind address (default `127.0.0.1:9090`)

## 4a. Binary Deployment (Direct)

Build and install the binary:

```bash
# Build release binary
cargo build --release

# Install
sudo install -o root -g root -m 0755 target/release/usg-jit-ldap-server /usr/local/bin/

# Install migrations
sudo mkdir -p /etc/ldap-server/migrations
sudo cp -r migrations/* /etc/ldap-server/migrations/
```

## 4b. Docker Deployment

Build and run the container:

```bash
# Build image
docker build -t usg-jit-ldap-server:latest .

# Run with host networking (simplest for LDAPS port 636)
docker run -d \
  --name ldap-server \
  --restart unless-stopped \
  -v /etc/ldap-server/config.toml:/etc/ldap-server/config.toml:ro \
  -v /etc/ldap-server/certs:/etc/ldap-server/certs:ro \
  -p 636:636 \
  -p 127.0.0.1:9090:9090 \
  usg-jit-ldap-server:latest
```

The health check is built into the image and will probe `http://localhost:9090/healthz`
every 30 seconds.

## 5. systemd Service Installation

For bare-metal / VM deployments:

```bash
# Install the unit file
sudo cp deploy/ldap-server.service /etc/systemd/system/
sudo systemctl daemon-reload

# Enable and start
sudo systemctl enable ldap-server
sudo systemctl start ldap-server

# Check status
sudo systemctl status ldap-server
sudo journalctl -u ldap-server -f
```

The unit file includes 20+ security directives (see `deploy/ldap-server.service`).

## 6. Verification

### Health Endpoint

```bash
curl -s http://127.0.0.1:9090/healthz
# Expected: {"status":"ok"}
```

### LDAPS Connectivity

```bash
# Test TLS handshake
openssl s_client -connect localhost:636 -CAfile /etc/ldap-server/certs/ca-bundle.crt

# LDAP search (requires ldap-utils)
ldapsearch -H ldaps://localhost:636 -x -b "dc=example,dc=com" "(objectClass=*)"
```

### Logs

```bash
# systemd journal
journalctl -u ldap-server --since "5 minutes ago"

# Check for startup errors
journalctl -u ldap-server -p err
```

## 7. Monitoring

### Health Check

The admin endpoint at `http://<host>:9090/healthz` returns HTTP 200 when the server is
healthy. Configure your monitoring system (Nagios, Prometheus Blackbox Exporter, etc.)
to poll this endpoint.

**Important:** The admin port (9090) should only be accessible from your monitoring
subnet. See `docs/deployment/hardening.md` for firewall rules.

### Log Aggregation

The server writes structured logs to stdout/stderr. When running under systemd, these
are captured by the journal. Forward them to your central logging system:

- **journald -> Loki**: Use `promtail` with a journald source
- **journald -> Elasticsearch**: Use `filebeat` with the journald input
- **Docker**: Use the `json-file` or `fluentd` logging driver

### Key Metrics to Monitor

- Health endpoint response time and status
- TLS certificate expiry (see `docs/deployment/hardening.md`)
- PostgreSQL connection pool usage (from server logs)
- LDAP bind failure rate (from audit logs in the database)
- Process memory and CPU usage via systemd resource accounting or cAdvisor
