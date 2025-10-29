fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(true) // Enable client for integration tests
        .compile_protos(&["proto/infera.proto"], &["proto"])?;
    Ok(())
}
