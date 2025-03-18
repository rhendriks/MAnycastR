FROM rust:latest AS build

# TODO build musl and run with scratch

# create a new empty shell project
RUN USER=root cargo new --bin manycast
WORKDIR /manycast

# install dependencies
RUN apt-get update && apt-get install -y protobuf-compiler

# Copy over manifests
COPY ./Cargo.toml ./Cargo.toml
COPY ./proto ./proto
COPY ./build.rs ./build.rs
RUN mkdir /out

# cache dependencies
RUN cargo build --release
RUN rm src/*.rs

# copy source tree
COPY ./src ./src

# build for release
RUN rm ./target/release/deps/manycast*
RUN cargo build --release

# final base
FROM debian:bookworm-slim

# copy the build artifact from the build stage
COPY --from=build /manycast/target/release/manycast .

# set the startup command to run binary (takes arguments from docker command)
ENTRYPOINT ["./manycast"]

# Default command used
CMD ["--help"]