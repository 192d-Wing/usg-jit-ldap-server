# Multi-Agent Execution Plan

## Agent Roster

| # | Agent | Branch | Worktree | Responsibility |
|---|---|---|---|---|
| 1 | DevOps/Repo | `feat/devops` | `../ldap-devops` | Repo structure, CI scaffolding, contributor docs |
| 2 | Architecture | `feat/architecture` | `../ldap-arch` | System design, trust boundaries, threat model |
| 3 | Data | `feat/data` | `../ldap-data` | PostgreSQL schemas, migrations, repositories |
| 4 | Protocol | `feat/protocol` | `../ldap-protocol` | LDAP codec, session state, operation handlers |
| 5 | Runtime | `feat/runtime` | `../ldap-runtime` | Rust service structure, TLS, config, main loop |
| 6 | Replication | `feat/replication` | `../ldap-replication` | Replication design, puller, health tracking |
| 7 | Security | `feat/security` | `../ldap-security` | Compliance review, NIST mappings, audit strategy |

## Dependency Graph

```
DevOps (foundation)
  └─► Architecture (design decisions)
        ├─► Data (schema depends on architecture)
        ├─► Protocol (operations depend on architecture)
        │     └─► Runtime (runtime wires protocol + data together)
        └─► Replication (replication depends on architecture + data)
              └─► Security (reviews everything, runs last)
```

## Merge Order

Merge into `integration` branch, then into `main`:

1. `feat/devops` — repo skeleton, Cargo.toml, config templates
2. `feat/architecture` — design docs, module stubs
3. `feat/data` — SQL migrations, db module implementation
4. `feat/protocol` — LDAP codec, operation handlers
5. `feat/runtime` — main.rs, TLS, config, service wiring
6. `feat/replication` — replication module implementation
7. `feat/security` — compliance review, NIST comment pass, audit module

## Parallelization Strategy

**Wave 1 (parallel):** DevOps + Architecture
- No code dependencies between them
- DevOps creates skeleton; Architecture creates design docs

**Wave 2 (parallel):** Data + Protocol + Replication design
- All depend on Architecture being done
- Minimal code overlap between them

**Wave 3 (sequential):** Runtime
- Wires together Data + Protocol modules
- Needs their interfaces defined

**Wave 4 (final):** Security
- Reviews and annotates all other work
- Adds NIST control mapping comments
- Final compliance pass

## Git Strategy

### Branch Structure
- `main` — stable, merged, reviewed code
- `integration` — staging branch for ordered merges
- `feat/*` — one per agent workstream

### Worktree Layout
Each agent works in an isolated worktree under `/private/tmp/`:
- Prevents merge conflicts during parallel development
- Each worktree has its own working directory
- Agents commit independently to their branches

### Merge Protocol
1. Each agent commits to its `feat/*` branch in its worktree
2. Create `integration` branch from `main`
3. Merge branches in dependency order (see above)
4. Resolve any conflicts at each merge step
5. Fast-forward `main` to `integration` when clean
