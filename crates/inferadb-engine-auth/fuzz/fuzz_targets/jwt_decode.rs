#![no_main]

use libfuzzer_sys::fuzz_target;
use inferadb_engine_auth::jwt::{decode_jwt_header, decode_jwt_claims};

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string (allow invalid UTF-8)
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz JWT header decoding
        let _ = decode_jwt_header(s);

        // Fuzz JWT claims decoding
        let _ = decode_jwt_claims(s);
    }

    // Test with string conversion that replaces invalid UTF-8
    let lossy_string = String::from_utf8_lossy(data);
    let _ = decode_jwt_header(&lossy_string);
    let _ = decode_jwt_claims(&lossy_string);

    // Create variations of malformed JWTs
    if data.len() > 10 {
        // Add extra parts
        let malformed1 = format!("{}.{}.{}.{}",
            String::from_utf8_lossy(&data[0..data.len()/4]),
            String::from_utf8_lossy(&data[data.len()/4..data.len()/2]),
            String::from_utf8_lossy(&data[data.len()/2..3*data.len()/4]),
            String::from_utf8_lossy(&data[3*data.len()/4..])
        );
        let _ = decode_jwt_header(&malformed1);
        let _ = decode_jwt_claims(&malformed1);

        // Remove parts
        let malformed2 = format!("{}.{}",
            String::from_utf8_lossy(&data[0..data.len()/2]),
            String::from_utf8_lossy(&data[data.len()/2..])
        );
        let _ = decode_jwt_header(&malformed2);
        let _ = decode_jwt_claims(&malformed2);
    }
});
