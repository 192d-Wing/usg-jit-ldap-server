# Operational Runbook

This directory contains operational procedures and playbooks for the USG JIT LDAP Server.

## Documents

| Document | Description |
|----------|-------------|
| [certificate-rotation.md](certificate-rotation.md) | Step-by-step TLS certificate rotation procedure |
| [database-failover.md](database-failover.md) | PostgreSQL failover detection, reconnection, and verification |
| [replication-recovery.md](replication-recovery.md) | Recovering from replication failures and WAN outages |
| [incident-response.md](incident-response.md) | Playbooks for security incidents and operational emergencies |
| [monitoring.md](monitoring.md) | Key metrics, alerting thresholds, dashboards, and log queries |

## General Guidance

- Always verify changes in a staging environment before applying to production.
- Follow your organization's change-management process for any configuration changes.
- Keep audit logging enabled at all times; never disable it to "fix" a problem.
- When in doubt, escalate to the team lead before taking destructive action.
