# OS-Level Hardening Checklist

This document covers operating system and infrastructure hardening for a production
deployment of the USG JIT LDAP Server.

## 1. Non-Root User

Create a dedicated service account with no login shell and no home directory:

```bash
sudo groupadd -r ldap-server
sudo useradd -r -g ldap-server -s /sbin/nologin -d /nonexistent ldap-server
```

The systemd unit file enforces this at the service level via `User=ldap-server` and
`Group=ldap-server`.

## 2. File Permissions

| Path | Owner | Mode | Notes |
|------|-------|------|-------|
| `/usr/local/bin/usg-jit-ldap-server` | `root:root` | `0755` | Server binary |
| `/etc/ldap-server/config.toml` | `ldap-server:ldap-server` | `0600` | Contains DB credentials |
| `/etc/ldap-server/certs/server.key` | `ldap-server:ldap-server` | `0600` | TLS private key |
| `/etc/ldap-server/certs/server.crt` | `ldap-server:ldap-server` | `0600` | TLS certificate |
| `/etc/ldap-server/certs/ca-bundle.crt` | `ldap-server:ldap-server` | `0600` | CA trust chain |
| `/var/lib/ldap-server/` | `ldap-server:ldap-server` | `0700` | Runtime data directory |
| `/var/log/ldap-server/` | `ldap-server:ldap-server` | `0750` | Log directory |

Apply permissions:

```bash
sudo chmod 0755 /usr/local/bin/usg-jit-ldap-server
sudo chmod 0600 /etc/ldap-server/config.toml
sudo chmod 0600 /etc/ldap-server/certs/*
sudo chmod 0700 /var/lib/ldap-server
sudo chmod 0750 /var/log/ldap-server
sudo chown -R ldap-server:ldap-server /etc/ldap-server /var/lib/ldap-server /var/log/ldap-server
```

## 3. Firewall Rules

Allow only necessary traffic. Example using `nftables`:

```nft
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # Loopback
        iif lo accept

        # Established connections
        ct state established,related accept

        # LDAPS from authorized networks
        tcp dport 636 ip saddr { 10.0.0.0/8, 172.16.0.0/12 } accept

        # Admin/health endpoint from monitoring subnet only
        tcp dport 9090 ip saddr 10.200.0.0/24 accept

        # SSH from bastion
        tcp dport 22 ip saddr 10.100.0.0/28 accept

        # ICMP (for network diagnostics)
        icmp type echo-request limit rate 5/second accept

        # Log and drop everything else
        log prefix "nft-drop: " counter drop
    }

    chain output {
        type filter hook output priority 0; policy accept;

        # Allow PostgreSQL, DNS, NTP, HTTPS (for CRL/OCSP)
        # Consider restricting to specific destination IPs in high-security environments
    }
}
```

**Key rules:**
- Port 636 (LDAPS): allow inbound only from authorized client networks
- Port 9090 (admin/health): allow only from the monitoring subnet
- No plaintext LDAP (port 389) should ever be exposed

## 4. SELinux / AppArmor Policy

### SELinux (RHEL/CentOS)

Create a custom SELinux policy module:

```bash
# Generate policy from audit log after running the service in permissive mode
sudo semanage permissive -a ldap_server_t

# Run the service, exercise all code paths, then:
sudo audit2allow -a -M ldap-server-policy
sudo semodule -i ldap-server-policy.pp

# Remove permissive mode
sudo semanage permissive -d ldap_server_t
```

At minimum, the policy should allow:
- Binding to TCP ports 636 and 9090
- Reading `/etc/ldap-server/`
- Writing to `/var/lib/ldap-server/` and `/var/log/ldap-server/`
- Connecting to PostgreSQL (TCP port 5432)

### AppArmor (Debian/Ubuntu)

Create `/etc/apparmor.d/usr.local.bin.usg-jit-ldap-server`:

```
#include <tunables/global>

/usr/local/bin/usg-jit-ldap-server {
    #include <abstractions/base>
    #include <abstractions/nameservice>
    #include <abstractions/openssl>

    /usr/local/bin/usg-jit-ldap-server mr,

    /etc/ldap-server/** r,
    /etc/ldap-server/certs/** r,

    /var/lib/ldap-server/** rw,
    /var/log/ldap-server/** rw,

    network inet stream,
    network inet6 stream,
}
```

Load the profile:

```bash
sudo apparmor_parser -r /etc/apparmor.d/usr.local.bin.usg-jit-ldap-server
```

## 5. Kernel Parameter Tuning

Add to `/etc/sysctl.d/99-ldap-server.conf`:

```ini
# Increase connection backlog for high-throughput LDAP
net.core.somaxconn = 4096
net.core.netdev_max_backlog = 4096

# TCP tuning
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5

# Harden against SYN floods
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_orphans = 4096

# Disable IP forwarding (not a router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Restrict dmesg access
kernel.dmesg_restrict = 1
```

Apply:

```bash
sudo sysctl --system
```

## 6. Log Rotation

Create `/etc/logrotate.d/ldap-server`:

```
/var/log/ldap-server/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 ldap-server ldap-server
    sharedscripts
    postrotate
        systemctl kill -s HUP ldap-server.service 2>/dev/null || true
    endscript
}
```

If using journald exclusively (the default systemd configuration), configure journal
size limits in `/etc/systemd/journald.conf`:

```ini
[Journal]
SystemMaxUse=500M
SystemKeepFree=1G
MaxFileSec=1day
```

## 7. Backup Strategy

### What to Back Up

| Component | Method | Frequency | Retention |
|-----------|--------|-----------|-----------|
| PostgreSQL identity schema | `pg_dump --schema=identity` | Every 6 hours | 30 days |
| Configuration files | File-level backup | On change | 90 days |
| TLS certificates | File-level backup | On change | Until expiry + 30 days |

### PostgreSQL Backup

```bash
# Automated backup script (run via cron)
#!/bin/bash
BACKUP_DIR="/var/backups/ldap-server"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p "$BACKUP_DIR"

pg_dump -U ldap_server -d ldap_identity \
    --format=custom \
    --compress=9 \
    -f "$BACKUP_DIR/ldap_identity_$TIMESTAMP.dump"

# Prune backups older than 30 days
find "$BACKUP_DIR" -name "*.dump" -mtime +30 -delete
```

### Restore

```bash
pg_restore -U ldap_server -d ldap_identity --clean --if-exists \
    /var/backups/ldap-server/ldap_identity_<timestamp>.dump
```

## 8. Certificate Lifecycle

### Monitoring Expiry

Add a cron job or monitoring check for certificate expiry:

```bash
#!/bin/bash
# /usr/local/bin/check-ldap-cert-expiry.sh
CERT="/etc/ldap-server/certs/server.crt"
WARN_DAYS=30

expiry=$(openssl x509 -enddate -noout -in "$CERT" | cut -d= -f2)
expiry_epoch=$(date -d "$expiry" +%s)
now_epoch=$(date +%s)
days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

if [ "$days_left" -lt "$WARN_DAYS" ]; then
    echo "WARNING: LDAP server certificate expires in $days_left days" >&2
    exit 1
fi
echo "OK: Certificate valid for $days_left days"
```

### Rotation Procedure

1. Obtain a new certificate from your CA (or via ACME/certbot).
2. Place the new cert and key in a staging directory.
3. Verify the new certificate:
   ```bash
   openssl verify -CAfile /etc/ldap-server/certs/ca-bundle.crt new-server.crt
   openssl x509 -in new-server.crt -noout -text | grep -A2 "Validity"
   ```
4. Replace the files atomically:
   ```bash
   sudo cp new-server.crt /etc/ldap-server/certs/server.crt
   sudo cp new-server.key /etc/ldap-server/certs/server.key
   sudo chmod 0600 /etc/ldap-server/certs/server.{crt,key}
   sudo chown ldap-server:ldap-server /etc/ldap-server/certs/server.{crt,key}
   ```
5. Restart the service:
   ```bash
   sudo systemctl restart ldap-server
   ```
6. Verify the new certificate is being served:
   ```bash
   echo | openssl s_client -connect localhost:636 2>/dev/null | openssl x509 -noout -dates
   ```

### ACME / Certbot Integration

If using Let's Encrypt or another ACME provider:

```bash
# Deploy hook for certbot
sudo certbot certonly \
    --standalone \
    --preferred-challenges tls-alpn-01 \
    -d ldap.example.com \
    --deploy-hook "/usr/local/bin/ldap-cert-deploy.sh"
```

Where `ldap-cert-deploy.sh` copies the renewed certs and restarts the service.
