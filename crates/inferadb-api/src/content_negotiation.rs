//! Content negotiation support for multiple response formats (JSON and TOON).
//!
//! This module provides content negotiation via the `Accept` header, allowing clients
//! to request responses in either JSON (default) or TOON (Token Oriented Object Notation)
//! format. TOON provides 30-60% token reduction for LLM-based clients.
//!
//! # Examples
//!
//! ```rust,no_run
//! use axum::{
//!     extract::State,
//!     Extension,
//!     Json,
//! };
//! use inferadb_api::{AppState, ApiError, content_negotiation::{AcceptHeader, ResponseData}};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Deserialize)]
//! struct MyRequest {
//!     name: String,
//! }
//!
//! #[derive(Serialize)]
//! struct MyResponse {
//!     message: String,
//! }
//!
//! async fn my_handler(
//!     State(state): State<AppState>,
//!     AcceptHeader(format): AcceptHeader,
//!     Json(request): Json<MyRequest>,
//! ) -> Result<ResponseData<MyResponse>, ApiError> {
//!     let response = MyResponse {
//!         message: format!("Hello {}", request.name),
//!     };
//!     Ok(ResponseData::new(response, format))
//! }
//! ```

use axum::{
    extract::FromRequestParts,
    http::{StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use tracing::{debug, warn};

/// Response format options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseFormat {
    /// JSON format (application/json)
    Json,
    /// TOON format (text/toon) - Token Oriented Object Notation
    Toon,
}

impl ResponseFormat {
    /// Returns the MIME type for this format
    pub fn mime_type(&self) -> &'static str {
        match self {
            ResponseFormat::Json => "application/json",
            ResponseFormat::Toon => "text/toon",
        }
    }
}

/// Extractor for the Accept header that determines response format preference.
///
/// Parses the `Accept` header and returns the preferred format based on:
/// - Explicit format request (application/json or text/toon)
/// - Quality values (q-values) for prioritization
/// - Defaults to JSON if header is missing or contains wildcard (*/*)
///
/// # Examples
///
/// ```text
/// Accept: application/json          → ResponseFormat::Json
/// Accept: text/toon                 → ResponseFormat::Toon
/// Accept: text/toon, application/json;q=0.5 → ResponseFormat::Toon (higher priority)
/// Accept: */*                       → ResponseFormat::Json (default)
/// (missing Accept header)           → ResponseFormat::Json (default)
/// ```
pub struct AcceptHeader(pub ResponseFormat);

impl<S> FromRequestParts<S> for AcceptHeader
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let accept_header =
            parts.headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()).unwrap_or("*/*");

        debug!("Accept header: {}", accept_header);

        let format = parse_accept_header(accept_header);
        Ok(AcceptHeader(format))
    }
}

/// Parse Accept header with q-value support
fn parse_accept_header(accept: &str) -> ResponseFormat {
    #[derive(Debug)]
    struct MediaType {
        format: ResponseFormat,
        quality: f32,
    }

    let mut media_types: Vec<MediaType> = Vec::new();

    // Parse each media type from the Accept header
    for part in accept.split(',') {
        let part = part.trim();

        // Split media type from parameters (e.g., "text/toon;q=0.9")
        let mut segments = part.split(';');
        let media_type = segments.next().unwrap_or("").trim();

        // Parse quality value (default is 1.0)
        let mut quality = 1.0;
        for param in segments {
            let param = param.trim();
            if let Some(q_value) = param.strip_prefix("q=") {
                if let Ok(q) = q_value.parse::<f32>() {
                    quality = q.clamp(0.0, 1.0);
                }
            }
        }

        // Match media type to format
        let format = match media_type {
            "application/json" => Some(ResponseFormat::Json),
            "text/toon" => Some(ResponseFormat::Toon),
            "*/*" | "text/*" | "application/*" => Some(ResponseFormat::Json), // Default
            _ => None,
        };

        if let Some(fmt) = format {
            media_types.push(MediaType { format: fmt, quality });
        }
    }

    // Sort by quality (highest first)
    media_types
        .sort_by(|a, b| b.quality.partial_cmp(&a.quality).unwrap_or(std::cmp::Ordering::Equal));

    // Return the highest priority format, or default to JSON
    media_types.first().map(|mt| mt.format).unwrap_or(ResponseFormat::Json)
}

/// Generic response wrapper that handles format-aware serialization.
///
/// This type wraps any serializable data and implements `IntoResponse` to
/// serialize it in the requested format (JSON or TOON).
#[derive(Debug)]
pub struct ResponseData<T: Serialize> {
    pub data: T,
    pub format: ResponseFormat,
}

impl<T: Serialize> ResponseData<T> {
    /// Create a new response with the specified data and format
    pub fn new(data: T, format: ResponseFormat) -> Self {
        Self { data, format }
    }
}

impl<T: Serialize> IntoResponse for ResponseData<T> {
    fn into_response(self) -> Response {
        match self.format {
            ResponseFormat::Json => {
                // Serialize as JSON
                match serde_json::to_string(&self.data) {
                    Ok(json) => (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, ResponseFormat::Json.mime_type())],
                        json,
                    )
                        .into_response(),
                    Err(e) => {
                        warn!("Failed to serialize response as JSON: {}", e);
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            [(header::CONTENT_TYPE, "application/json")],
                            r#"{"error":"Internal serialization error"}"#,
                        )
                            .into_response()
                    },
                }
            },
            ResponseFormat::Toon => {
                // Convert to JSON Value first, then encode as TOON
                match serde_json::to_value(&self.data) {
                    Ok(json_value) => {
                        let toon_str = toon::encode(&json_value, None);
                        (
                            StatusCode::OK,
                            [(header::CONTENT_TYPE, ResponseFormat::Toon.mime_type())],
                            toon_str,
                        )
                            .into_response()
                    },
                    Err(e) => {
                        // TOON encoding failed, fall back to JSON
                        warn!(
                            "TOON encoding failed (JSON value conversion error), falling back to JSON: {}",
                            e
                        );

                        // Attempt JSON serialization as fallback
                        match serde_json::to_string(&self.data) {
                            Ok(json) => (
                                StatusCode::OK,
                                [(header::CONTENT_TYPE, ResponseFormat::Json.mime_type())],
                                json,
                            )
                                .into_response(),
                            Err(e2) => {
                                // Both TOON and JSON serialization failed
                                warn!("JSON fallback serialization also failed: {}", e2);
                                (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    [(header::CONTENT_TYPE, "application/json")],
                                    r#"{"error":"Internal serialization error"}"#,
                                )
                                    .into_response()
                            },
                        }
                    },
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use serde::Serialize;

    use super::*;

    #[test]
    fn test_parse_accept_header_json() {
        assert_eq!(parse_accept_header("application/json"), ResponseFormat::Json);
    }

    #[test]
    fn test_parse_accept_header_toon() {
        assert_eq!(parse_accept_header("text/toon"), ResponseFormat::Toon);
    }

    #[test]
    fn test_parse_accept_header_wildcard() {
        assert_eq!(parse_accept_header("*/*"), ResponseFormat::Json);
    }

    #[test]
    fn test_parse_accept_header_empty() {
        assert_eq!(parse_accept_header(""), ResponseFormat::Json);
    }

    #[test]
    fn test_parse_accept_header_priority_json_first() {
        let accept = "application/json, text/toon;q=0.5";
        assert_eq!(parse_accept_header(accept), ResponseFormat::Json);
    }

    #[test]
    fn test_parse_accept_header_priority_toon_first() {
        let accept = "text/toon, application/json;q=0.5";
        assert_eq!(parse_accept_header(accept), ResponseFormat::Toon);
    }

    #[test]
    fn test_parse_accept_header_priority_explicit_q() {
        let accept = "text/toon;q=0.9, application/json;q=0.8";
        assert_eq!(parse_accept_header(accept), ResponseFormat::Toon);
    }

    #[test]
    fn test_parse_accept_header_unknown_defaults_to_json() {
        let accept = "application/xml";
        assert_eq!(parse_accept_header(accept), ResponseFormat::Json);
    }

    #[test]
    fn test_response_format_mime_type() {
        assert_eq!(ResponseFormat::Json.mime_type(), "application/json");
        assert_eq!(ResponseFormat::Toon.mime_type(), "text/toon");
    }

    #[derive(Serialize)]
    struct TestData {
        message: String,
        count: u32,
    }

    #[tokio::test]
    async fn test_response_data_json_serialization() {
        let data = TestData { message: "test".to_string(), count: 42 };
        let response_data = ResponseData::new(data, ResponseFormat::Json);
        let response = response_data.into_response();

        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(content_type, "application/json");
    }

    #[tokio::test]
    async fn test_response_data_toon_serialization() {
        let data = TestData { message: "test".to_string(), count: 42 };
        let response_data = ResponseData::new(data, ResponseFormat::Toon);
        let response = response_data.into_response();

        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(content_type, "text/toon");
    }
}
