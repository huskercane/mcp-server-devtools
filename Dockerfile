# mcp-devtools container image (plan ADR-010 / §3.4, WP A.9).
#
# Multi-stage: a static musl build in the pinned Rust toolchain, copied into
# a distroless *static* runtime — no shell, no package manager, no libc to
# patch, non-root, and (with the mounts below) a read-only root filesystem.
# One image serves every role; `--role` (or `MCP_ROLE`) picks it at runtime.
#
#   docker build -t mcp-devtools .
#   docker run --rm -p 3000:3000 --read-only --tmpfs /tmp \
#     -e MCP_AUTH_MODE=okta -e MCP_OKTA_ISSUER=... -e MCP_OKTA_AUDIENCE=... \
#     -e MCP_PUBLIC_URL=https://mcp.example.com -e MCP_POLICY_FILE=/policy/policy.yaml \
#     -e MCP_AUDIT_JOURNAL_DIR=/journal -v ./policy:/policy:ro -v journal:/journal \
#     mcp-devtools --role gateway
#
# The image binds 0.0.0.0, which the fail-closed startup gate refuses unless
# MCP_AUTH_MODE=okta is fully configured. For a local smoke test in
# community mode, override the bind: `-e MCP_BIND_ADDR=127.0.0.1`.
#
# Writable paths the process needs (mount them; everything else can be
# read-only): /tmp (response artifacts and, via HOME=/tmp, diagnostic logs)
# and MCP_AUDIT_JOURNAL_DIR (a persistent volume — audit RPO is 0 only if
# the journal survives the pod).
#
# Features: the OS keychain is meaningless in a container (`keychain` off);
# WRDS stays on so the image is the same catalog as the binary release, and
# `secrets-vault` so `vault://` references work from the image (C.2b).

# ---- build ---------------------------------------------------------------
# Alpine ships musl; aws-lc-sys (the TLS/JWT crypto, via rustls and
# jsonwebtoken) needs cmake, a C compiler, and perl to build from source.
FROM rust:1.96-alpine AS build
RUN apk add --no-cache build-base cmake perl pkgconfig linux-headers
WORKDIR /src
# Dependency layer first, so a source-only change does not rebuild the world.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY benches ./benches
RUN mkdir -p src/bin && echo 'fn main() {}' > src/main.rs && echo '' > src/lib.rs \
 && cargo build --release --locked --no-default-features --features wrds,secrets-vault \
      --target x86_64-unknown-linux-musl 2>/dev/null || true
COPY src ./src
COPY README.md ./
RUN touch src/main.rs src/lib.rs \
 && cargo build --release --locked --no-default-features --features wrds,secrets-vault \
      --target x86_64-unknown-linux-musl \
 && cp target/x86_64-unknown-linux-musl/release/mcp-devtools /mcp-devtools \
 && /mcp-devtools --version

# ---- runtime -------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /mcp-devtools /mcp-devtools
COPY deploy/policies /policies
ENV TRANSPORT_MODE=http \
    PORT=3000 \
    MCP_BIND_ADDR=0.0.0.0 \
    HOME=/tmp \
    LOG_STDERR=on
USER nonroot:nonroot
EXPOSE 3000
# The binary probes itself: distroless has no curl.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/mcp-devtools", "health"]
ENTRYPOINT ["/mcp-devtools", "serve", "--transport", "http"]
CMD ["--role", "all"]
