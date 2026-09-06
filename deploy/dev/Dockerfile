FROM rust:1.96.0-bookworm@sha256:5e2214abe154fe26e39f64488952e5c991eeed1d6d6da7cc8381ae83927f0cfc
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake pkg-config libssl-dev python3 openssl curl \
    && rm -rf /var/lib/apt/lists/*
RUN rustup component add --toolchain 1.96.0 rustfmt clippy
WORKDIR /workspace
ENV CARGO_TARGET_DIR=/build
CMD ["bash", "deploy/dev/start.sh"]
