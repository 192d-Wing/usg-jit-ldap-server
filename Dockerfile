# Build stage
FROM rust:slim-bookworm AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY migrations/ migrations/
ENV SQLX_OFFLINE=true
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN groupadd -r ldap-server && useradd -r -g ldap-server -s /sbin/nologin ldap-server
COPY --from=builder /build/target/release/usg-jit-ldap-server /usr/local/bin/
COPY --from=builder /build/migrations/ /etc/ldap-server/migrations/
RUN mkdir -p /etc/ldap-server/certs /var/lib/ldap-server && \
    chown -R ldap-server:ldap-server /etc/ldap-server /var/lib/ldap-server
USER ldap-server
EXPOSE 636 9090
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -sf http://localhost:9090/healthz || exit 1
ENTRYPOINT ["usg-jit-ldap-server"]
CMD ["--config", "/etc/ldap-server/config.toml"]
