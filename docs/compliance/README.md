# ATO Compliance Documentation

This directory contains the Authority to Operate (ATO) compliance documentation
package for the USG JIT LDAP Server. These documents provide assessor-ready
inputs for the System Security Plan (SSP), risk assessment, and security test
evidence.

## Document Index

| Document | Location | Purpose |
| ---------- | ---------- | --------- |
| System Security Plan Inputs | [system-security-plan-inputs.md](system-security-plan-inputs.md) | SSP-ready control implementation statements |
| NIST Traceability Matrix | [nist-traceability-matrix.md](nist-traceability-matrix.md) | Control-to-code mapping with file:line references |
| Risk Assessment Inputs | [risk-assessment-inputs.md](risk-assessment-inputs.md) | Threat model, residual risks, mitigations |
| Test Evidence | [test-evidence.md](test-evidence.md) | Summary of security testing performed |

## Supporting Documentation

| Document | Location |
| ---------- | ---------- |
| Architecture Overview | [../architecture/README.md](../architecture/README.md) |
| Threat Model | [../architecture/threat-model.md](../architecture/threat-model.md) |
| Trust Boundaries | [../architecture/trust-boundaries.md](../architecture/trust-boundaries.md) |
| Security Invariants | [../architecture/security-invariants.md](../architecture/security-invariants.md) |
| NIST Control Mapping Strategy | [../architecture/nist-control-mapping.md](../architecture/nist-control-mapping.md) |
| Full NIST Mapping | [../security/nist-sp800-53-rev5-mapping.md](../security/nist-sp800-53-rev5-mapping.md) |
| Abuse Cases | [../security/abuse-cases.md](../security/abuse-cases.md) |
| Audit Strategy | [../security/audit-strategy.md](../security/audit-strategy.md) |
| Code Review Checklist | [../security/code-review-checklist.md](../security/code-review-checklist.md) |
| Operational Security | [../security/operational-security.md](../security/operational-security.md) |
| Architecture Decision Records | [../architecture/decisions/](../architecture/decisions/) |

## Operational Runbooks

| Document | Location |
| ---------- | ---------- |
| Operations Overview | [../operations/README.md](../operations/README.md) |
| Audit Forwarding | [../operations/audit-forwarding.md](../operations/audit-forwarding.md) |
| Certificate Rotation | [../operations/certificate-rotation.md](../operations/certificate-rotation.md) |
| Database Failover | [../operations/database-failover.md](../operations/database-failover.md) |
| Incident Response | [../operations/incident-response.md](../operations/incident-response.md) |
| Monitoring | [../operations/monitoring.md](../operations/monitoring.md) |
| Replication Recovery | [../operations/replication-recovery.md](../operations/replication-recovery.md) |

## Deployment Artifacts

| Artifact | Location |
| ---------- | ---------- |
| Dockerfile | [../../Dockerfile](../../Dockerfile) |
| Deployment Guide | [../deployment/](../deployment/) |
| systemd Unit | [../../deploy/](../../deploy/) |
| Example Configuration | [../../config.example.toml](../../config.example.toml) |
| Dependency Policy | [../../deny.toml](../../deny.toml) |

## How to Use This Package

1. **Assessors**: Start with the [System Security Plan Inputs](system-security-plan-inputs.md)
   for control implementation statements organized by NIST SP 800-53 Rev. 5
   control family. Each statement is written for direct inclusion in an SSP.

2. **Control Verification**: Use the [NIST Traceability Matrix](nist-traceability-matrix.md)
   to locate every control implementation in source code with file and line
   references.

3. **Risk Review**: The [Risk Assessment Inputs](risk-assessment-inputs.md)
   summarize the threat model, residual risks, and compensating controls.

4. **Test Evidence**: The [Test Evidence](test-evidence.md) document catalogs
   all security testing: 108+ unit and property tests, 10 integration tests,
   5 fuzz targets, and 4 penetration test scripts.
