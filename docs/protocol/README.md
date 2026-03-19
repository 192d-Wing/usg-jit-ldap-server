# LDAPv3 Protocol Design — USG JIT LDAP Server

## Supported Operations

| Operation | Application Tag | Direction | Description |
|---|---|---|---|
| BindRequest | 0 (0x60) | Client → Server | Simple authentication (DN + password) |
| BindResponse | 1 (0x61) | Server → Client | Authentication result |
| UnbindRequest | 2 (0x42) | Client → Server | Graceful disconnect (no response) |
| SearchRequest | 3 (0x63) | Client → Server | Directory search |
| SearchResultEntry | 4 (0x64) | Server → Client | One matching entry |
| SearchResultDone | 5 (0x65) | Server → Client | Search completion status |
| ExtendedRequest | 23 (0x77) | Client → Server | Password Modify (OID 1.3.6.1.4.1.4203.1.11.1) |
| ExtendedResponse | 24 (0x78) | Server → Client | Extended operation result |

## Rejected Operations

All operations not listed above are rejected with `unwillingToPerform` (resultCode 53).
This includes: Add, Delete, Modify, ModifyDN, Compare, SASL Bind, and any unknown operation.

Anonymous binds (empty DN or empty password) are rejected with `invalidCredentials` (resultCode 49).

Abandon requests are silently consumed and ignored (no response per RFC 4511).

## Session State Machine

```
  ┌──────────────┐
  │              │
  │  Connected   │◄── TLS handshake complete
  │              │
  └──────┬───────┘
         │
         │ BindRequest (simple, version 3)
         │
         ▼
  ┌──────────────┐
  │              │
  │    Bound     │◄── BindResponse(success)
  │              │
  └──────┬───────┘
         │
         │ SearchRequest / ExtendedRequest / re-Bind / UnbindRequest
         │
         ▼
  ┌──────────────┐
  │              │
  │   Closed     │◄── UnbindRequest or connection drop
  │              │
  └──────────────┘
```

**State rules:**
- `Connected`: Only BindRequest is accepted. All other operations return `operationsError`.
- `Bound`: SearchRequest, ExtendedRequest, re-Bind, and UnbindRequest are accepted.
- `Closed`: No further processing; connection is torn down.

Re-binding from `Bound` state is allowed per RFC 4511 Section 4.2.1 and resets the session identity.

## Message Flow: Bind

```
Client                          Server
  │                                │
  │  BindRequest(v3, DN, password) │
  │──────────────────────────────►│
  │                                │  Validate version == 3
  │                                │  Reject anonymous (empty DN/pw)
  │                                │  Authenticate against local DB
  │  BindResponse(resultCode)      │
  │◄──────────────────────────────│
  │                                │  If success: session → Bound
```

## Message Flow: Search

```
Client                          Server
  │                                │
  │  SearchRequest(base, scope,    │
  │    filter, attributes)         │
  │──────────────────────────────►│
  │                                │  Verify session is Bound
  │                                │  Execute query against PostgreSQL
  │  SearchResultEntry #1          │
  │◄──────────────────────────────│
  │  SearchResultEntry #2          │
  │◄──────────────────────────────│
  │  ...                           │
  │  SearchResultDone(resultCode)  │
  │◄──────────────────────────────│
```

## Message Flow: Password Modify Extended Operation

```
Client (JIT Broker)             Server
  │                                │
  │  ExtendedRequest(              │
  │    OID=1.3.6.1.4.1.4203.1.11.1│
  │    value=PasswdModifyReqValue) │
  │──────────────────────────────►│
  │                                │  Verify session is Bound
  │                                │  Verify caller is authorized broker
  │                                │  Parse userIdentity, newPasswd
  │                                │  Hash and store in runtime schema
  │  ExtendedResponse(resultCode)  │
  │◄──────────────────────────────│
```

## BER/ASN.1 Codec Strategy

We use **manual BER encoding/decoding** with tag-length-value (TLV) primitives rather than
depending on `rasn`/`rasn-ldap` crate compatibility. This keeps the dependency surface minimal
and the codec fully auditable.

### Wire format

Every LDAPv3 message on the wire is:
```
LDAPMessage ::= SEQUENCE {
    messageID  INTEGER,
    protocolOp CHOICE { ... },
    controls   [0] Controls OPTIONAL
}
```

### Tag classes used

| Class | Bits 7-6 | Usage |
|---|---|---|
| Universal | 00 | SEQUENCE, INTEGER, OCTET STRING, BOOLEAN, ENUMERATED |
| Application | 01 | ProtocolOp tags (BindRequest=0x60, etc.) |
| Context-specific | 10 | Field-level tags within operations |

### Encoding helpers

The codec module provides low-level TLV helpers (`encode_sequence`, `encode_integer`,
`encode_octet_string`, `encode_length`, `decode_tag`, `decode_length`) and higher-level
per-operation encode/decode functions.

### Length encoding

- Short form: lengths 0-127 use a single byte.
- Long form: lengths 128+ use 0x80|N followed by N bytes of big-endian length.

## Result Codes Used

| Code | Value | Usage |
|---|---|---|
| success | 0 | Successful operation |
| operationsError | 1 | Operation requested in wrong state |
| protocolError | 2 | Malformed message or unsupported version |
| invalidCredentials | 49 | Bad DN/password or anonymous bind |
| insufficientAccessRights | 50 | Caller lacks permission |
| busy | 51 | Server overloaded / rate limited |
| unavailable | 52 | Server shutting down |
| unwillingToPerform | 53 | Unsupported operation |
| other | 80 | Catch-all for unexpected errors |

## Error Handling

- Malformed BER → close connection (no partial parse recovery).
- Unknown/unsupported operation tag → `unwillingToPerform` response.
- State violation (e.g., search before bind) → `operationsError` response.
- Internal errors → `other` result code with diagnostic message.
- All errors are logged to the audit subsystem before response.

## Security Considerations

- **SC-8**: All communication is over TLS (LDAPS on port 636 only).
- **SC-23**: Session state is server-authoritative; no client-supplied session tokens.
- **AC-3**: Access enforcement checked at every operation dispatch point.
- **IA-2**: Identification and authentication required before any data access.
- **AU-3**: All protocol operations generate audit events with sufficient detail.
