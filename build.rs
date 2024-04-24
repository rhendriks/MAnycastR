// Generates the tonic/grpc code from the .proto file
fn main() {
    // Compile Protocol Buffers definitions
    tonic_build::compile_protos("proto/verfploeter.proto")
        .unwrap_or_else(|e| panic!("Failed to compile protos: {:?}", e));
}
