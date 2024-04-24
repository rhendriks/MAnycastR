FROM rust:latest as build

# create a new empty shell project
RUN USER=root cargo new --bin manycast
WORKDIR /manycast

# install dependencies
#RUN apt-get update && apt-get install -y protobuf-compiler && apt-get install -y gcc && apt-get install -y libpcap-dev

# Copy over manifests
COPY ./Cargo.toml ./Cargo.toml
COPY ./proto ./proto
COPY ./build.rs ./build.rs
RUN mkdir /out

# this build step will cache your dependencies
RUN cargo build --release
RUN rm src/*.rs

# copy your source tree
COPY ./src ./src

# build for release
RUN rm ./target/release/deps/manycast*
RUN cargo build --release

# our final base
FROM debian:buster-slim

# copy the build artifact from the build stage
COPY --from=build /manycast/target/release/manycast .

# set the startup command to run your binary (takes arguments from docker command)
ENTRYPOINT ["./manycast"]

# Default command used
CMD ["--help"]
