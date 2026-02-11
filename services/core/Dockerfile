FROM rust:1.85-bookworm AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*
RUN apt-get update && apt-get install -y libmnl-dev libnftnl-dev && rm -rf /var/lib/apt/lists/*
ARG CORE_CARGO_FEATURES=""

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY services ./services

RUN if [ -n "$CORE_CARGO_FEATURES" ]; then \
      cargo build --release -p core --locked --features "$CORE_CARGO_FEATURES"; \
    else \
      cargo build --release -p core --locked; \
    fi

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates iptables nftables iproute2 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/core /usr/local/bin/core

ENV APP_ENV=production
EXPOSE 50051
ENTRYPOINT ["/usr/local/bin/core"]
