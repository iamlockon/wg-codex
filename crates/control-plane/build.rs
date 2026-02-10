fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("failed to resolve vendored protoc");
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/vpn_control.proto"], &["proto"])
        .expect("failed to compile protos");
}
