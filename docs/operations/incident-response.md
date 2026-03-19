# Incident Response Playbooks

This document contains playbooks for responding to security incidents and operational emergencies affecting the USG JIT LDAP Server.

---

## Playbook 1: Compromised JIT Credential

**Trigger:** A JIT-provisioned credential is suspected or confirmed to have been exposed or misused.

### Immediate Actions (within 15 minutes)

1. **Revoke the credential immediately.**
   ```sql
   -- Expire the compromised credential
   UPDATE runtime.jit_credentials
   SET expires_at = NOW(), revoked = true, revoke_reason = 'compromised'
   WHERE bind_dn = 'cn=AFFECTED_USER,ou=jit,dc=example,dc=gov';
   ```

2. **Block the affected BIND DN.** If the server supports an explicit deny list, add the DN. Otherwise, the expiry in step 1 is sufficient.

3. **Verify revocation.** Attempt a BIND with the compromised credential and confirm it fails:
   ```bash
   ldapwhoami -H ldaps://ldap.example.gov:636 \
     -D "cn=AFFECTED_USER,ou=jit,dc=example,dc=gov" \
     -w "COMPROMISED_PASSWORD"
   # Expected: ldap_bind: Invalid credentials (49)
   ```

### Investigation

4. **Pull audit logs for the affected DN.**
   ```bash
   grep '"bind_dn":"cn=AFFECTED_USER' /var/log/ldap-server/audit.jsonl | \
     jq -r '[.timestamp, .event, .source_ip] | @tsv' | sort
   ```

5. **Identify unauthorized usage.** Look for:
   - BIND events from unexpected source IPs.
   - SEARCH operations accessing data outside the credential's expected scope.
   - Unusually high request volume.

6. **Determine the exposure vector.** Was the credential:
   - Logged in plaintext somewhere?
   - Intercepted in transit (check TLS configuration)?
   - Exfiltrated from the broker?

### Recovery

7. **Issue a new credential** for the legitimate user/broker through the normal JIT provisioning flow.
8. **Notify the affected broker operator** of the incident and the new credential.
9. **File an incident report** per your organization's security incident process.

---

## Playbook 2: Rate Limit Storm

**Trigger:** A sudden spike in failed BIND attempts triggers rate limiting across many source IPs, or a single source is generating excessive traffic.

### Immediate Actions

1. **Identify the source(s).**
   ```bash
   # Find top source IPs by failed BIND count in the last hour
   grep '"event":"bind_failure"' /var/log/ldap-server/audit.jsonl | \
     grep "$(date -u +%Y-%m-%dT%H)" | \
     jq -r '.source_ip' | sort | uniq -c | sort -rn | head -20
   ```

2. **Determine if this is an attack or misconfiguration.**
   - A single IP with thousands of failures: likely a brute-force attack or misconfigured client.
   - Many IPs with similar patterns: possible distributed attack or widespread client misconfiguration (e.g. after a credential rotation).

3. **Block offending IPs at the firewall** (if confirmed as malicious):
   ```bash
   # Example: iptables
   sudo iptables -A INPUT -s OFFENDING_IP -p tcp --dport 636 -j DROP

   # Example: firewalld
   sudo firewall-cmd --add-rich-rule='rule family="ipv4" source address="OFFENDING_IP" port port="636" protocol="tcp" drop'
   ```

4. **Review the rate-limiting configuration** in `config.toml`:
   ```toml
   [security]
   max_bind_attempts = 5
   rate_limit_window_secs = 300
   ```
   Tighten these values if the current settings are too permissive.

### Recovery

5. **Monitor for continued activity** after blocking.
6. **Review audit logs** for any successful BINDs from the offending IPs (may indicate credential compromise — see Playbook 1).
7. **Unblock IPs** only after confirming the source is legitimate and the root cause is resolved.

---

## Playbook 3: Audit Queue Overflow

**Trigger:** The audit log system is unable to write events, causing a backlog. Symptoms include disk full errors, audit log write failures, or (if `failure_policy = "halt"` is configured) refused LDAP operations.

### Immediate Actions

1. **Check disk space.**
   ```bash
   df -h /var/log/ldap-server/
   ```

2. **If disk is full — emergency cleanup.**
   ```bash
   # Compress old audit logs
   gzip /var/log/ldap-server/audit.jsonl.1
   gzip /var/log/ldap-server/audit.jsonl.2

   # Or archive and remove logs older than 30 days
   find /var/log/ldap-server/ -name "audit.jsonl.*" -mtime +30 -exec gzip {} \;
   find /var/log/ldap-server/ -name "audit.jsonl.*.gz" -mtime +90 -delete
   ```

3. **Verify logging has resumed.**
   ```bash
   # Tail the audit log and perform a test BIND
   tail -f /var/log/ldap-server/audit.jsonl &
   ldapwhoami -H ldaps://ldap.example.gov:636 -D "cn=test,dc=example,dc=gov" -w test
   ```

4. **If using log forwarding (syslog, SIEM):** check the forwarding pipeline for backpressure or connectivity issues:
   ```bash
   # Check if rsyslog/fluentd/vector is healthy
   systemctl status rsyslog    # or your log forwarder
   ```

### Prevention

5. **Set up log rotation** if not already configured:
   ```
   # /etc/logrotate.d/ldap-server
   /var/log/ldap-server/audit.jsonl {
       daily
       rotate 90
       compress
       delaycompress
       missingok
       notifempty
   }
   ```

6. **Set up disk space monitoring** to alert before the disk fills.

---

## Playbook 4: TLS Certificate Expiry

**Trigger:** The server's TLS certificate has expired or is about to expire. Brokers are unable to establish TLS connections.

### Immediate Actions

1. **Confirm the certificate has expired.**
   ```bash
   openssl s_client -connect ldap.example.gov:636 </dev/null 2>&1 | \
     openssl x509 -noout -dates
   ```

2. **Follow the emergency rotation procedure** in [certificate-rotation.md](certificate-rotation.md).
   - If a valid replacement certificate is already available, skip to step 3 (Install) in that document.
   - If no replacement is available, generate a self-signed certificate as a temporary measure:
     ```bash
     openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
       -keyout /etc/ldap-server/certs/server.key \
       -out /etc/ldap-server/certs/server.crt \
       -days 7 -nodes \
       -subj "/C=US/O=USG/CN=ldap.example.gov"
     ```
     **Warning:** Brokers may reject a self-signed certificate. This is a stopgap only.

3. **Restart the service.**
   ```bash
   sudo systemctl restart ldap-server
   ```

4. **Notify all broker operators** if using a temporary certificate, so they can adjust trust settings if needed.

### Prevention

5. **Set up certificate expiry monitoring:**
   ```bash
   # Check days until expiry (add to cron)
   DAYS=$(openssl s_client -connect ldap.example.gov:636 </dev/null 2>&1 | \
     openssl x509 -noout -checkend $((30*86400)) && echo "OK" || echo "EXPIRING")
   ```
   Alert when the certificate is within 30 days of expiry.

---

## Playbook 5: Unauthorized Broker Detected

**Trigger:** Audit logs show successful or attempted BIND operations from an unrecognized broker identity.

### Immediate Actions

1. **Identify the unauthorized broker.**
   ```bash
   # Find BINDs from unknown DNs
   grep '"event":"bind_success"' /var/log/ldap-server/audit.jsonl | \
     jq -r '[.timestamp, .bind_dn, .source_ip] | @tsv' | \
     grep -v "known-broker-1\|known-broker-2"
   ```

2. **Revoke any JIT credentials issued to the unauthorized broker.**
   ```sql
   UPDATE runtime.jit_credentials
   SET expires_at = NOW(), revoked = true, revoke_reason = 'unauthorized_broker'
   WHERE provisioned_by = 'cn=UNAUTHORIZED_BROKER,ou=brokers,dc=example,dc=gov';
   ```

3. **Disable the broker's BIND identity.**
   ```sql
   -- If broker identities are stored locally
   UPDATE identity.brokers
   SET enabled = false, disabled_reason = 'unauthorized - under investigation'
   WHERE cn = 'UNAUTHORIZED_BROKER';
   ```

4. **Block the source IP** at the firewall if it is not part of the expected network:
   ```bash
   sudo iptables -A INPUT -s UNAUTHORIZED_IP -p tcp --dport 636 -j DROP
   ```

### Investigation

5. **Audit all activity from the unauthorized broker.**
   ```bash
   grep 'UNAUTHORIZED_BROKER' /var/log/ldap-server/audit.jsonl | \
     jq -r '[.timestamp, .event, .source_ip, .details] | @tsv' | sort
   ```

6. **Determine how the broker obtained credentials:**
   - Was a broker provisioning endpoint left open?
   - Was an existing broker's credentials stolen?
   - Was the `broker_dns` configuration overly permissive?

7. **Check for data exfiltration.** Review SEARCH operations performed by the unauthorized broker to determine what data was accessed.

### Recovery

8. **Tighten the `broker_dns` configuration** in `config.toml` to explicitly list only authorized brokers.
9. **Rotate credentials** for any legitimate brokers that may have been affected.
10. **File an incident report** per your organization's security incident process.
