# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Multi-format API response support via content negotiation
  - REST APIs now support both JSON (`application/json`) and TOON (`text/toon`) formats
  - Clients can request format via `Accept` header
  - TOON (Token Oriented Object Notation) provides 30-60% token reduction for LLM clients
  - New module: `infera-api::content_negotiation`
  - New types: `ResponseFormat`, `AcceptHeader`, `ResponseData<T>`
  - JSON remains the default format for backward compatibility
- Comprehensive TOON documentation in `api/content-negotiation.md`
  - Format specification and examples
  - Token efficiency benchmarks (34-45% reduction)
  - LLM integration examples (Claude, GPT-4, Gemini)
  - Migration guide for API consumers
- TOON dependency: `toon` crate v0.1.2

### Changed

- All REST API handlers updated to support content negotiation
  - Handler signatures now include `AcceptHeader` extractor
  - Return type changed from `Json<T>` to `ResponseData<T>`
  - Error responses respect client format preferences
- Streaming endpoints (SSE) remain JSON-only
  - TOON requests to streaming endpoints return 406 Not Acceptable

### Removed

- None
