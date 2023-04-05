FROM rust:latest as build

# create a new empty shell project
RUN USER=root cargo new --bin manycast
WORKDIR /manycast

# TODO copy over your manifests
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml

# this build step will cache your dependencies
RUN cargo build --release
RUN rm src/*.rs

# copy your source tree
COPY ./src ./src

# build for release
RUN rm ./target/release/deps/manycast*
RUN cargo build --release

# our final base
FROM rust:latest

# copy the build artifact from the build stage
COPY --from=build /manycast/target/release/manycast .

# set the startup command to run your binary
CMD ["./manycast"]

# TODO steps 4 and 5 of this tutorial?
#https://dev.to/rogertorres/first-steps-with-docker-rust-30oi