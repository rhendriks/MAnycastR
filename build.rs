use std::process::Command;

// Generates the tonic/grpc code from the .proto file
fn main() {
    // Compile Protocol Buffers definitions
    tonic_build::compile_protos("proto/verfploeter.proto")
        .unwrap_or_else(|e| panic!("Failed to compile protos {:?}", e));

    // Gets commit string
    let output = Command::new("git").args(&["rev-parse", "--short=7", "HEAD"]).output().unwrap();
    let git_hash = String::from_utf8(output.stdout).unwrap();
    println!("cargo:rustc-env=GIT_HASH=git-{}", git_hash);
    println!("cargo:rustc-rerun-if-changed=.git/HEAD");

}
