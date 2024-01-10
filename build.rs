// Generates the tonic/grpc code from the .proto file
fn main() {
    // Compile Protocol Buffers definitions
    tonic_build::compile_protos("proto/verfploeter.proto")
        .unwrap_or_else(|e| panic!("Failed to compile protos: {:?}", e));

    // println!("cargo:rerun-if-env-changed=LIBPCAP_DIR");
    // println!("cargo:rustc-link-search=native={}", "/lib/x86_64-linux-gnu/libpcap.a");
    // println!("cargo:rustc-link-lib=pcap");
//    println!("cargo:rustc-link-search=static=/lib/x86_64-linux-gnu/libpcap.a");
//    println!("cargo:rustc-link-lib=static=pcap");

//    println!("cargo:rustc-link-search=static=/lib/x86_64-linux-gnu/libdbus-1.a");
//    println!("cargo:rustc-link-lib=static=dbus-1");

    //println!("cargo:rustc-link-search=static=/lib/x86_64-linux-gnu/libdbus-1.a");
    //println!("cargo:rustc-link-lib=static=systemd-dev");
    // // Link against libpcap if LIBPCAP_DIR is set
    // if let Ok(libpcap_dir) = std::env::var("LIBPCAP_DIR") { // TODO cannot compile musl with libpcap
    //     println!("cargo:rerun-if-env-changed=LIBPCAP_DIR");
    //     println!("cargo:rustc-link-search=native={}", libpcap_dir);
    //     println!("cargo:rustc-link-lib=pcap");
    // } else {
    //     println!("cargo:warning=LIBPCAP_DIR environment variable not set");
    // }
}
