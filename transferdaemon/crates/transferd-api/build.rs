fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use the vendored protoc when none is on PATH, so the build is hermetic
    // on CI runners and fresh machines (the Android cross-compile runs this on
    // the host, so the host protoc is used either way).
    if std::env::var_os("PROTOC").is_none() && std::env::var_os("PROTOC_NO_VENDORED").is_none() {
        if let Ok(p) = protoc_bin_vendored::protoc_bin_path() {
            std::env::set_var("PROTOC", p);
        }
    }
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile(
            &["proto/transferd.proto"],
            &["proto"],
        )?;
    Ok(())
}