# ---- Build Stage ----
FROM --platform=linux/amd64 rust:latest AS builder

# Install necessary build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        protobuf-compiler \
        musl-tools \
        gcc

RUN rustup target add x86_64-unknown-linux-musl

RUN USER=root cargo new --bin manycast
WORKDIR /manycast

# Copy necessary files
COPY ./Cargo.toml ./Cargo.toml
COPY ./proto ./proto
COPY ./build.rs ./build.rs
COPY ./src ./src

# Build the application
RUN cargo build --release --target x86_64-unknown-linux-musl

RUN strip target/x86_64-unknown-linux-musl/release/manycast

# ---- Final Stage ----
FROM scratch
COPY --from=builder /manycast/target/x86_64-unknown-linux-musl/release/manycast /manycast
ENTRYPOINT ["/manycast"]
CMD ["--help"]