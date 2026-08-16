# syntax=docker/dockerfile:1
# ---------- builder ----------
# Pinned to the exact channel in rust-toolchain.toml. rust-toolchain.toml is
# intentionally NOT copied into the image — it would make rustup download a
# second toolchain at build time; matching the base image is both faster and
# reproducible, and it guarantees the Cargo.toml `rust-version` floor is met.
FROM rust:1.97.1-bookworm AS builder

# aws-lc-sys (rustls/aws-lc-rs) needs a C toolchain, cmake, clang (bindgen) and perl
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        clang \
        pkg-config \
        perl \
    && rm -rf /var/lib/apt/lists/*

# Keep peak memory sane on small Railway builders (aws-lc-sys is the heavy one)
ENV CARGO_BUILD_JOBS=2 \
    CARGO_NET_RETRY=5 \
    CARGO_HTTP_TIMEOUT=60

WORKDIR /app

# Phase 1: compile every dependency once with a placeholder crate so
# redeploys only rebuild our code (~2 min instead of ~10 min).
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && printf 'fn main() {}\n' > src/main.rs \
    && : > src/lib.rs \
    && cargo build --release --locked

# Phase 2: real source. contracts/ is required — the executor creation hex is
# include_str!-ed from non-test code. README.md and .env.example are only
# include_str!-ed under #[cfg(test)], and this stage runs `cargo build`, never
# `cargo test`, so they are deliberately not copied: doing so would invalidate
# this layer (and force a full recompile) on every docs-only commit.
COPY src ./src
COPY contracts ./contracts
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --locked

# ---------- runtime ----------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/opensea-mint /usr/local/bin/opensea-mint

# Wallet manifest lives here. Mount a Railway Volume at /data and set
# WALLETS_FILE=/data/wallets.json so keys survive restarts/redeploys.
WORKDIR /data

LABEL org.opencontainers.image.source=https://github.com/Savage27z/drizzy

# Long-polling Telegram bot: no port, no webhook.
CMD ["opensea-mint", "bot"]
