# Data Flows

This document traces the complete data flow for each major operation in the
USG JIT LDAP Server system.

## 1. Bind Flow (Client Authentication)

A client authenticates by sending a Simple Bind request with a DN and password.

```
Client              LDAPS Listener    Session Handler    Auth Module        Runtime DB        Audit
  │                      │                  │                │                  │               │
  │── TLS handshake ────►│                  │                │                  │               │
  │◄── TLS established ──│                  │                │                  │               │
  │                      │                  │                │                  │               │
  │── BindRequest ──────►│                  │                │                  │               │
  │   (DN + password)    │── decode PDU ───►│                │                  │               │
  │                      │                  │── check state ─┤                  │               │
  │                      │                  │  (must be      │                  │               │
  │                      │                  │   unauth'd or  │                  │               │
  │                      │                  │   re-binding)  │                  │               │
  │                      │                  │                │                  │               │
  │                      │                  │── rate check ─►│                  │               │
  │                      │                  │                │── check limits ──┤               │
  │                      │                  │                │  (per-DN,        │               │
  │                      │                  │                │   per-IP)        │               │
  │                      │                  │                │                  │               │
  │                      │                  │  [if rate exceeded]               │               │
  │                      │                  │◄─ reject ──────│                  │               │
  │                      │                  │────────────────┼──────────────────┼──► log event  │
  │◄── BindResponse ─────│◄── encode PDU ──│                │                  │    (rejected) │
  │    (unwilling)       │                  │                │                  │               │
  │                      │                  │                │                  │               │
  │                      │                  │  [if rate OK]  │                  │               │
  │                      │                  │── verify ─────►│                  │               │
  │                      │                  │                │── SELECT hash ──►│               │
  │                      │                  │                │  from runtime.   │               │
  │                      │                  │                │  credentials     │               │
  │                      │                  │                │  WHERE dn=?      │               │
  │                      │                  │                │  AND NOT expired  │               │
  │                      │                  │                │◄── hash row ─────│               │
  │                      │                  │                │                  │               │
  │                      │                  │                │── compare hash   │               │
  │                      │                  │                │   (constant time)│               │
  │                      │                  │                │── zeroize pwd ───┤               │
  │                      │                  │                │                  │               │
  │                      │                  │  [if match]    │                  │               │
  │                      │                  │◄─ success ─────│                  │               │
  │                      │                  │── set state ───┤                  │               │
  │                      │                  │   to Bound     │                  │               │
  │                      │                  │────────────────┼── INSERT ───────►│               │
  │                      │                  │                │   bind_event     │               │
  │                      │                  │────────────────┼──────────────────┼──► log event  │
  │◄── BindResponse ─────│◄── encode PDU ──│                │                  │   (success)   │
  │    (success)         │                  │                │                  │               │
  │                      │                  │                │                  │               │
  │                      │                  │  [if no match] │                  │               │
  │                      │                  │◄─ failure ─────│                  │               │
  │                      │                  │── increment ───┤                  │               │
  │                      │                  │   rate counter │                  │               │
  │                      │                  │────────────────┼── INSERT ───────►│               │
  │                      │                  │                │   bind_event     │               │
  │                      │                  │                │   (failed)       │               │
  │                      │                  │────────────────┼──────────────────┼──► log event  │
  │◄── BindResponse ─────│◄── encode PDU ──│                │                  │   (failed)    │
  │    (invalid creds)   │                  │                │                  │               │
```

### Key Properties

- Password material is zeroized in memory immediately after hash comparison.
- The hash comparison uses constant-time equality to prevent timing attacks.
- The same error response is returned for "DN not found" and "wrong password"
  to prevent user enumeration.
- Rate limit check occurs BEFORE hash computation to prevent CPU exhaustion.
- Both successful and failed Bind attempts are recorded in `runtime.bind_events`
  and emitted as audit events.

## 2. Search Flow (Directory Query)

An authenticated client queries the directory for identity data.

```
Client              LDAPS Listener    Session Handler    Identity DB       Audit
  │                      │                  │                │               │
  │── SearchRequest ────►│                  │                │               │
  │   (baseDN, scope,    │── decode PDU ───►│                │               │
  │    filter, attrs)    │                  │── check state ─┤               │
  │                      │                  │  (must be      │               │
  │                      │                  │   Bound)       │               │
  │                      │                  │                │               │
  │                      │                  │  [if not bound]│               │
  │◄── error ────────────│◄── encode PDU ──│                │               │
  │   (operations error) │                  │                │               │
  │                      │                  │                │               │
  │                      │                  │  [if bound]    │               │
  │                      │                  │── validate ────┤               │
  │                      │                  │   filter       │               │
  │                      │                  │   complexity   │               │
  │                      │                  │                │               │
  │                      │                  │── query ──────►│               │
  │                      │                  │   SELECT from  │               │
  │                      │                  │   identity.*   │               │
  │                      │                  │   WHERE filter │               │
  │                      │                  │   LIMIT size   │               │
  │                      │                  │◄── rows ───────│               │
  │                      │                  │                │               │
  │                      │                  │── filter attrs─┤               │
  │                      │                  │   (server-side │               │
  │                      │                  │    attr list)  │               │
  │                      │                  │                │               │
  │◄── SearchResultEntry─│◄── encode PDU ──│                │               │
  │◄── SearchResultEntry─│◄── encode PDU ──│  (one per row) │               │
  │    ...               │                  │                │               │
  │◄── SearchResultDone──│◄── encode PDU ──│────────────────┼──► log event  │
  │    (success)         │                  │                │   (search)    │
```

### Key Properties

- Search operations are read-only against the `identity` schema.
- Password hashes (in `runtime` schema) are never included in Search results.
- Server-side attribute filtering ensures only requested and permitted
  attributes are returned.
- Filter complexity is validated before query execution to prevent expensive
  queries.
- A `sizelimit` caps the number of result entries returned.
- The Search operation, base DN, scope, and result count are audit-logged.

## 3. Password Issuance Flow (JIT Broker)

The JIT Broker issues an ephemeral password for a user at a specific site.

### Via Password Modify Extended Operation

```
JIT Broker          LDAPS Listener    Session Handler    Runtime DB        Audit
  │                      │                  │                │               │
  │── TLS handshake ────►│                  │                │               │
  │── BindRequest ──────►│                  │                │               │
  │   (broker service DN)│── decode PDU ───►│                │               │
  │                      │                  │── verify ──────┤               │
  │                      │                  │   broker cred  │               │
  │◄── BindResponse ─────│◄── success ─────│                │               │
  │    (success)         │                  │                │               │
  │                      │                  │                │               │
  │── ExtendedRequest ──►│                  │                │               │
  │   (PasswdModify)     │── decode PDU ───►│                │               │
  │   userIdentity=DN    │                  │── check role ──┤               │
  │   newPasswd=hash     │                  │  (must be      │               │
  │                      │                  │   password-    │               │
  │                      │                  │   issuer)      │               │
  │                      │                  │                │               │
  │                      │                  │── UPSERT ─────►│               │
  │                      │                  │   runtime.     │               │
  │                      │                  │   credentials  │               │
  │                      │                  │   (dn, hash,   │               │
  │                      │                  │    ttl, issued) │               │
  │                      │                  │◄── OK ─────────│               │
  │                      │                  │                │               │
  │                      │                  │────────────────┼──► log event  │
  │◄── ExtendedResponse──│◄── encode PDU ──│                │   (issuance)  │
  │    (success)         │                  │                │               │
```

### Via Direct Database API

```
JIT Broker                        Runtime DB             Audit
  │                                    │                    │
  │── mTLS connect (broker cert) ─────►│                    │
  │                                    │                    │
  │── INSERT/UPDATE ──────────────────►│                    │
  │   runtime.credentials             │                    │
  │   (dn, hash, ttl, issued_at,      │                    │
  │    broker_id)                      │                    │
  │◄── OK ────────────────────────────│                    │
  │                                    │── trigger ────────►│
  │                                    │   audit event      │
  │                                    │   (DB trigger)     │
```

### Key Properties

- The JIT Broker is the only entity that writes to `runtime.credentials`.
- The LDAP service never generates passwords; it only verifies them.
- Each credential record includes a TTL. The LDAP service checks expiry at
  Bind time.
- The Broker's identity is recorded in the credential row and audit event.
- Password hashes use Argon2id with site-configured cost parameters.

## 4. Replication Flow (Identity Sync)

Identity data flows from the central hub to each site via pull-based
replication.

```
Site Puller                         Central Hub             Site Identity DB
  │                                      │                        │
  │── mTLS connect ─────────────────────►│                        │
  │   (site cert CN = site_id)           │                        │
  │                                      │── validate cert ──┤    │
  │                                      │   check site_id   │    │
  │                                      │                        │
  │── GET /changes?since=N ────────────►│                        │
  │                                      │── query change_log ─┤  │
  │                                      │   WHERE seq > N       │
  │                                      │   AND site_scope      │
  │                                      │   includes site_id    │
  │                                      │                        │
  │◄── ChangeSet ───────────────────────│                        │
  │    (seq N+1..N+M, ops, digest)      │                        │
  │                                      │                        │
  │── verify digest ──┤                  │                        │
  │                    │                  │                        │
  │── BEGIN TRANSACTION ────────────────┼───────────────────────►│
  │                                      │                        │
  │── apply ops in sequence order ──────┼───────────────────────►│
  │   INSERT/UPDATE/DELETE identity.*   │                        │
  │                                      │                        │
  │── UPDATE replication_health ────────┼───────────────────────►│
  │   (last_seq, last_pull_time)        │                        │
  │                                      │                        │
  │── COMMIT ───────────────────────────┼───────────────────────►│
  │                                      │                        │
  │── ACK seq=N+M ─────────────────────►│                        │
  │                                      │── update site ───┤    │
  │                                      │   last_ack_seq   │    │
  │                                      │                        │
  │── disconnect ───────────────────────►│                        │
```

### Key Properties

- Pull-based: the site initiates. The hub never pushes.
- Only `identity` schema data is transferred. The `runtime` schema is never
  included in replication queries.
- Change sets are applied in a single transaction for atomicity.
- Payload integrity is verified via SHA-256 digest before application.
- Sequence numbers are monotonic and gapless within a site's scope.
- The site's `replication_health` table is updated within the same transaction.

## 5. Audit Flow (Event Logging)

All security-relevant operations produce structured audit events.

```
Operation           Audit Module        Runtime DB          External SIEM
  │                      │                  │                     │
  │── emit event ───────►│                  │                     │
  │   (type, dn, ip,    │                  │                     │
  │    timestamp, result)│                  │                     │
  │                      │── INSERT ───────►│                     │
  │                      │   runtime.       │                     │
  │                      │   audit_queue    │                     │
  │                      │                  │                     │
  │                      │── write to ─────►│                     │
  │                      │   structured     │                     │
  │                      │   log (stdout/   │                     │
  │                      │   file)          │                     │
  │                      │                  │                     │
  │                      │                  │  [async forwarder]  │
  │                      │                  │── forward ─────────►│
  │                      │                  │   queued events     │
  │                      │                  │                     │
  │                      │                  │◄── ACK ────────────│
  │                      │                  │                     │
  │                      │                  │── DELETE from ──┤   │
  │                      │                  │   audit_queue   │   │
  │                      │                  │   WHERE acked   │   │
```

### Audit Event Types

| Event Type | Trigger | Key Fields |
|---|---|---|
| `bind.success` | Successful Bind | DN, source IP, timestamp |
| `bind.failure` | Failed Bind | DN (attempted), source IP, failure reason, timestamp |
| `bind.rate_limited` | Bind rejected by rate limiter | DN or IP, limit type, timestamp |
| `search.executed` | Search operation completed | Bound DN, base DN, scope, filter summary, result count, timestamp |
| `password.issued` | JIT Broker issues credential | Target DN, Broker ID, TTL, timestamp |
| `password.expired` | Credential TTL elapsed | Target DN, original TTL, timestamp |
| `session.opened` | TLS connection established | Source IP, TLS version, cipher suite, timestamp |
| `session.closed` | Connection closed | Source IP, duration, operations count, timestamp |
| `replication.pull` | Replication pull completed | Site ID, seq range, rows applied, duration, timestamp |
| `replication.error` | Replication pull failed | Site ID, error type, timestamp |
| `replication.stale` | Site entered stale status | Site ID, lag seconds, lag sequences, timestamp |

### Key Properties

- Audit events are written to both a local database queue and structured log
  output.
- The database queue provides durability; events survive process restarts.
- The structured log provides real-time visibility for log aggregation.
- Events are forwarded to a central SIEM asynchronously. Forwarding failure
  does not block LDAP operations.
- The audit queue is append-only from the LDAP service's perspective.
- Audit events include enough context for security incident investigation
  without including sensitive material (no passwords, no password hashes).
