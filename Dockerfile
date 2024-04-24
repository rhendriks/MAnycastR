FROM rust:latest as build

# create a new empty shell project
RUN USER=root cargo new --bin manycast
WORKDIR /manycast

# install dependencies
RUN apt-get update && apt-get install -y protobuf-compiler gcc libpcap0.8-dev

# Copy over manifests
COPY ./Cargo.toml ./Cargo.toml
COPY ./proto ./proto
COPY ./build.rs ./build.rs
RUN mkdir /out

# this build step will cache dependencies
RUN cargo build --release
RUN rm src/*.rs

# copy source tree
COPY ./src ./src

# build for release
RUN rm ./target/release/deps/manycast*
RUN cargo build --release

# our final base
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y libpcap0.8-dev

# copy the build artifact from the build stage
COPY --from=build /manycast/target/release/manycast .

# set the startup command to run binary (takes arguments from docker command)
ENTRYPOINT ["./manycast"]
#ENTRYPOINT ["/manycast/target/release/manycast"]

# Default command used
CMD ["--help"]
