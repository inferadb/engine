#![no_main]

use libfuzzer_sys::fuzz_target;
use infera_auth::{jwt::{validate_claims, JwtClaims}, validation::validate_algorithm};
use std::time::{SystemTime, UNIX_EPOCH};

fuzz_target!(|data: &[u8]| {
    // Fuzz algorithm validation with random strings
    if let Ok(s) = std::str::from_utf8(data) {
        let accepted = vec!["EdDSA".to_string(), "RS256".to_string()];
        let _ = validate_algorithm(s, &accepted);

        // Also try with random accepted algorithms
        if data.len() > 10 {
            let alg1 = String::from_utf8_lossy(&data[0..data.len()/2]).to_string();
            let alg2 = String::from_utf8_lossy(&data[data.len()/2..]).to_string();
            let random_accepted = vec![alg1, alg2];
            let _ = validate_algorithm(s, &random_accepted);
        }
    }

    // Fuzz claims validation with random timestamp values
    if data.len() >= 24 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create claims with fuzzed timestamps
        let exp = u64::from_le_bytes(data[0..8].try_into().unwrap_or([0u8; 8]));
        let iat = u64::from_le_bytes(data[8..16].try_into().unwrap_or([0u8; 8]));
        let nbf = if data[16] % 2 == 0 {
            Some(u64::from_le_bytes(data[16..24].try_into().unwrap_or([0u8; 8])))
        } else {
            None
        };

        let iss = String::from_utf8_lossy(&data[24..data.len().min(64)]).to_string();
        let sub = String::from_utf8_lossy(&data[0..data.len().min(32)]).to_string();
        let aud = String::from_utf8_lossy(&data[0..data.len().min(32)]).to_string();

        let claims = JwtClaims {
            iss,
            sub,
            aud,
            exp,
            iat,
            nbf,
            jti: None,
            scope: "inferadb.check".to_string(),
            tenant_id: None,
        };

        // This should never panic, only return Ok or Err
        let _ = validate_claims(&claims, Some("inferadb"));
        let _ = validate_claims(&claims, None);
    }
});
