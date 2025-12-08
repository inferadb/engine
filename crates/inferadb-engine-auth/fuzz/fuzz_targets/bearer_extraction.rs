#![no_main]

use libfuzzer_sys::fuzz_target;
use inferadb_engine_auth::middleware::extract_bearer_token;
use axum::http::HeaderMap;

fuzz_target!(|data: &[u8]| {
    // Create header map with fuzzed Authorization header
    let mut headers = HeaderMap::new();

    // Try to insert the data as an Authorization header
    if let Ok(header_value) = std::str::from_utf8(data) {
        if let Ok(value) = header_value.parse() {
            headers.insert("authorization", value);
            let _ = extract_bearer_token(&headers);
        }
    }

    // Also try with "Bearer " prefix variations
    if data.len() > 0 {
        let variations = vec![
            format!("Bearer {}", String::from_utf8_lossy(data)),
            format!("bearer {}", String::from_utf8_lossy(data)),
            format!("BEARER {}", String::from_utf8_lossy(data)),
            format!("Bearer{}", String::from_utf8_lossy(data)),
            format!("Bearer  {}", String::from_utf8_lossy(data)),
            format!(" Bearer {}", String::from_utf8_lossy(data)),
            String::from_utf8_lossy(data).to_string(),
        ];

        for var in variations {
            if let Ok(value) = var.parse() {
                let mut h = HeaderMap::new();
                h.insert("authorization", value);
                let _ = extract_bearer_token(&h);
            }
        }
    }

    // Test with various header names
    if let Ok(header_value) = std::str::from_utf8(data) {
        if let Ok(value) = header_value.parse() {
            let header_names = vec!["authorization", "Authorization", "AUTHORIZATION"];
            for name in header_names {
                let mut h = HeaderMap::new();
                h.insert(name, value.clone());
                let _ = extract_bearer_token(&h);
            }
        }
    }
});
