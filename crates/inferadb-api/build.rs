fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true) // Enable client for integration tests
        .file_descriptor_set_path(out_dir.join("inferadb_descriptor.bin"))
        .compile_protos(&["proto/inferadb.proto"], &["proto"])?;
    Ok(())
}
