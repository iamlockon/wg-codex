FROM rust:1.93-bookworm AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY services ./services
COPY clients/windows-desktop/src-tauri/Cargo.toml ./clients/windows-desktop/src-tauri/Cargo.toml
COPY clients/windows-desktop/src-tauri/build.rs ./clients/windows-desktop/src-tauri/build.rs
COPY clients/windows-desktop/src-tauri/src ./clients/windows-desktop/src-tauri/src

RUN cargo build --release -p entry --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/entry /usr/local/bin/entry

ENV APP_ENV=production
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entry"]
