use std::process::Command;

// Generates the tonic/grpc code from the .proto file
fn main() {
    // Compile Protocol Buffers definitions
    tonic_prost_build::compile_protos("proto/manycastr.proto")
        .expect("Failed to compile Protobuf definitions");

    // Gets commit string
    let git_hash = std::env::var("GIT_HASH").unwrap_or_else(|_| {
        Command::new("git")
            .args(["rev-parse", "--short=7", "HEAD"])
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .unwrap_or_else(|| "unknown".to_string())
    });
    println!("cargo:rustc-env=GIT_HASH=git-{git_hash}");
    println!("cargo:rustc-rerun-if-changed=.git/HEAD");
}
