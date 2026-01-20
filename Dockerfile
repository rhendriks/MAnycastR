# ---- Build Stage ----
FROM --platform=linux/amd64 rust:latest AS builder

# Install necessary build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends protobuf-compiler musl-tools gcc

RUN rustup target add x86_64-unknown-linux-musl

RUN USER=root cargo new --bin manycastr
WORKDIR /manycastr

# Copy necessary files
COPY ./Cargo.toml ./Cargo.toml
COPY ./proto ./proto
COPY ./build.rs ./build.rs
COPY ./src ./src

# Build the application
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/manycastr/target \
    export PROTOC_NO_VENDOR=1 && \
    RUSTFLAGS="-C target-cpu=x86-64-v2" \
    cargo build --release --target x86_64-unknown-linux-musl && \
    cp target/x86_64-unknown-linux-musl/release/manycastr /manycastr/manycastr_release

# ---- Final Stage ----
FROM scratch
COPY --from=builder /manycastr/manycastr_release /manycastr
ENTRYPOINT ["/manycastr"]
CMD ["--help"]