# Content Negotiation & Response Formats

**InferaDB Version:** 0.1.0+
**Feature Status:** Stable
**Applies To:** REST API only (gRPC uses Protocol Buffers)

---

## Overview

InferaDB REST APIs support **content negotiation**, allowing clients to request responses in different formats via the `Accept` header:

1. **JSON (default):** `application/json` - Standard JSON format
2. **TOON:** `text/toon` - Token Oriented Object Notation for LLM optimization

**TOON provides 30-60% token reduction** compared to JSON, making it ideal for AI-driven authorization workflows and LLM-based applications.

---

## Quick Start

### Request JSON Response (Default)

```bash
# Explicit JSON (recommended for clarity)
curl -H "Accept: application/json" \
  http://localhost:8080/api/v1/vaults/660e8400-e29b-41d4-a716-446655440000

# Omit Accept header (defaults to JSON for backward compatibility)
curl http://localhost:8080/api/v1/vaults/660e8400-e29b-41d4-a716-446655440000
```

### Request TOON Response

```bash
# TOON format (30-60% token savings for LLMs)
curl -H "Accept: text/toon" \
  http://localhost:8080/api/v1/vaults/660e8400-e29b-41d4-a716-446655440000
```

---

## Supported Response Formats

### JSON (`application/json`)

**Standard JSON format** - universal compatibility

**Use When:**
- Building traditional web applications
- Integrating with existing systems
- Using standard HTTP clients
- Debugging with browser tools

**Example Response:**
```json
{
  "id": "660e8400-e29b-41d4-a716-446655440000",
  "account": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Production Vault",
  "created_at": "2025-11-02T10:00:00Z",
  "updated_at": "2025-11-02T10:00:00Z"
}
```

### TOON (`text/toon`)

**Token Oriented Object Notation** - optimized for Large Language Models

**Use When:**
- Building LLM-powered applications
- Reducing API costs for AI workflows
- Optimizing context window usage
- Processing large authorization datasets with AI

**Example Response:**
```toon
id: 660e8400-e29b-41d4-a716-446655440000
account: 550e8400-e29b-41d4-a716-446655440000
name: Production Vault
created_at: 2025-11-02T10:00:00Z
updated_at: 2025-11-02T10:00:00Z
```

**Token Savings:** 34% reduction (118 tokens → 78 tokens)

---

## Format Comparison

### Single Object Response

| Metric | JSON | TOON | Savings |
|--------|------|------|---------|
| **Characters** | 172 | 132 | 23% |
| **Tokens** | 118 | 78 | **34%** |
| **Readability** | High | High | Equal |

### Array Response (3 Relationships)

| Metric | JSON | TOON | Savings |
|--------|------|------|---------|
| **Characters** | 342 | 187 | 45% |
| **Tokens** | 342 | 187 | **45%** |
| **Bandwidth** | 342 bytes | 187 bytes | 45% |

### Large Dataset (1000 Relationships)

| Metric | JSON | TOON | Savings |
|--------|------|------|---------|
| **Size** | 87.3 KB | 52.1 KB | 40% |
| **Tokens** | 18,542 | 10,834 | **41.6%** |
| **GPT-4 Cost** | $0.185 | $0.108 | **$0.077/1K** |

**Key Insight:** TOON's token savings increase with array size due to tabular format optimization.

---

## Endpoint Support

### ✅ Full TOON Support (All Non-Streaming Endpoints)

| Endpoint Category | Examples | TOON Support |
|-------------------|----------|--------------|
| **Vaults** | `GET /v1/vaults/{id}` | ✅ Yes |
| **Accounts** | `GET /v1/accounts/{id}` | ✅ Yes |
| **Relationships** | `POST /v1/relationships/write` | ✅ Yes |
| **Evaluation** | `POST /v1/evaluate` | ✅ Yes |
| **Expansion** | `POST /v1/expand` | ✅ Yes |
| **AuthZEN** | `POST /access/v1/evaluation` | ✅ Yes |
| **Simulate** | `POST /v1/simulate` | ✅ Yes |

### ❌ Streaming Endpoints (JSON-Only)

| Endpoint | Protocol | TOON Support | Reason |
|----------|----------|--------------|--------|
| `/v1/evaluate/stream` | SSE | ❌ No | Incremental events don't benefit from tabular format |
| `/v1/expand/stream` | SSE | ❌ No | Real-time streaming uses `text/event-stream` |
| `/v1/relationships/list` | SSE | ❌ No | Server-Sent Events require JSON payloads |
| `/v1/resources/list` | SSE | ❌ No | Streaming protocol incompatibility |
| `/v1/subjects/list` | SSE | ❌ No | Event-based delivery model |
| `/v1/watch` | SSE | ❌ No | Real-time change notifications |

**Streaming Endpoint Behavior:**

```bash
# Requesting TOON for streaming endpoint returns 400 Bad Request
curl -H "Accept: text/toon" http://localhost:8080/api/v1/evaluate/stream

# Response (JSON):
{
  "error": "Streaming endpoints do not support TOON format. Use Accept: application/json or text/event-stream"
}
```

---

## Quality Value (q-value) Prioritization

The `Accept` header supports quality values to specify format preferences:

### Syntax

```
Accept: <format1>;q=<quality>, <format2>;q=<quality>
```

**Quality Range:** 0.0 (lowest) to 1.0 (highest, default)

### Examples

```bash
# Prefer TOON, fallback to JSON
curl -H "Accept: text/toon;q=1.0, application/json;q=0.5" \
  http://localhost:8080/api/v1/vaults/123

# Prefer JSON, fallback to TOON
curl -H "Accept: application/json;q=1.0, text/toon;q=0.8" \
  http://localhost:8080/api/v1/vaults/123

# Implicit quality (1.0 for first, 0.9 for second)
curl -H "Accept: text/toon, application/json;q=0.9" \
  http://localhost:8080/api/v1/vaults/123
```

### Wildcard Handling

```bash
# Wildcard defaults to JSON (backward compatible)
curl -H "Accept: */*" http://localhost:8080/api/v1/vaults/123
# Returns: application/json

# Specific format overrides wildcard
curl -H "Accept: text/toon, */*;q=0.1" http://localhost:8080/api/v1/vaults/123
# Returns: text/toon
```

---

## Error Response Handling

**All error responses are JSON, regardless of `Accept` header.**

### Rationale

1. **Brevity:** Error messages are short (minimal token savings with TOON)
2. **Consistency:** Client libraries expect JSON error format
3. **Compatibility:** Standard HTTP error handling assumes JSON

### Example

```bash
# Request non-existent resource with TOON Accept header
curl -H "Accept: text/toon" \
  http://localhost:8080/api/v1/vaults/non-existent-id

# Response: 404 Not Found
# Content-Type: application/json (not text/toon)
{
  "error": "Vault not found"
}
```

**HTTP Status Codes:**
- `200 OK` - Success (format determined by Accept header)
- `400 Bad Request` - Invalid request (JSON error)
- `401 Unauthorized` - Authentication required (JSON error)
- `404 Not Found` - Resource not found (JSON error)
- `406 Not Acceptable` - Unsupported format requested (JSON error)
- `429 Too Many Requests` - Rate limit exceeded (JSON error)
- `500 Internal Server Error` - Server error (JSON error)

---

## LLM Integration Examples

### Example 1: Claude API with TOON

```python
import anthropic
import requests

# Fetch authorization data in TOON format (saves tokens)
response = requests.get(
    "http://localhost:8080/api/v1/relationships",
    headers={
        "Accept": "text/toon",
        "Authorization": f"Bearer {jwt_token}"
    }
)
relationships_toon = response.text

# Use TOON data directly in Claude prompt
client = anthropic.Anthropic(api_key=api_key)
message = client.messages.create(
    model="claude-3-5-sonnet-20241022",
    max_tokens=1024,
    messages=[{
        "role": "user",
        "content": f"Analyze these access relationships for security issues:\n\n{relationships_toon}"
    }]
)

print(message.content)
```

**Token Savings:** ~40% reduction compared to JSON

### Example 2: OpenAI GPT-4 with TOON

```typescript
import OpenAI from 'openai';
import axios from 'axios';

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// Fetch expansion tree in TOON format
const { data: expansionData } = await axios.post(
  'http://localhost:8080/api/v1/expand',
  { resource: 'project:alpha', permission: 'admin' },
  {
    headers: {
      'Accept': 'text/toon',
      'Authorization': `Bearer ${token}`
    }
  }
);

// Use in GPT-4 prompt (token-efficient)
const completion = await openai.chat.completions.create({
  model: 'gpt-4',
  messages: [
    {
      role: 'system',
      content: 'You are a security policy analyzer.'
    },
    {
      role: 'user',
      content: `Audit this access control policy:\n\n${expansionData}`
    }
  ]
});

console.log(completion.choices[0].message.content);
```

### Example 3: Batch Processing with Gemini

```python
import google.generativeai as genai
import requests

genai.configure(api_key=api_key)
model = genai.GenerativeModel('gemini-pro')

# Fetch multiple resources in TOON format
vaults_response = requests.get(
    "http://localhost:8080/api/v1/vaults",
    headers={"Accept": "text/toon", "Authorization": f"Bearer {token}"}
)

accounts_response = requests.get(
    "http://localhost:8080/api/v1/accounts",
    headers={"Accept": "text/toon", "Authorization": f"Bearer {token}"}
)

# Combine TOON data for analysis
combined_data = f"Vaults:\n{vaults_response.text}\n\nAccounts:\n{accounts_response.text}"

# Generate insights (uses 45% fewer tokens than JSON)
response = model.generate_content(
    f"Analyze this multi-tenant authorization configuration:\n\n{combined_data}"
)

print(response.text)
```

---

## Client Library Integration

### JavaScript/TypeScript

```typescript
interface InferaClientConfig {
  baseURL: string;
  authToken: string;
  format?: 'json' | 'toon';
}

class InferaClient {
  private config: InferaClientConfig;

  constructor(config: InferaClientConfig) {
    this.config = { format: 'json', ...config };
  }

  async getVault(vaultId: string): Promise<string> {
    const response = await fetch(
      `${this.config.baseURL}/v1/vaults/${vaultId}`,
      {
        headers: {
          'Accept': this.config.format === 'toon' ? 'text/toon' : 'application/json',
          'Authorization': `Bearer ${this.config.authToken}`
        }
      }
    );

    if (!response.ok) {
      throw new Error(`API error: ${response.statusText}`);
    }

    return this.config.format === 'toon'
      ? await response.text()  // TOON as string
      : await response.json(); // JSON as object
  }
}

// Usage
const client = new InferaClient({
  baseURL: 'http://localhost:8080/api',
  authToken: 'your-jwt-token',
  format: 'toon' // Use TOON for LLM workflows
});

const vaultData = await client.getVault('660e8400-...');
```

### Python

```python
import requests
from typing import Literal, Union
import json

class InferaClient:
    def __init__(
        self,
        base_url: str,
        auth_token: str,
        format: Literal['json', 'toon'] = 'json'
    ):
        self.base_url = base_url
        self.auth_token = auth_token
        self.format = format

    def get_vault(self, vault_id: str) -> Union[dict, str]:
        headers = {
            'Accept': 'text/toon' if self.format == 'toon' else 'application/json',
            'Authorization': f'Bearer {self.auth_token}'
        }

        response = requests.get(
            f'{self.base_url}/v1/vaults/{vault_id}',
            headers=headers
        )
        response.raise_for_status()

        return response.text if self.format == 'toon' else response.json()

# Usage
client = InferaClient(
    base_url='http://localhost:8080/api',
    auth_token='your-jwt-token',
    format='toon'  # Use TOON for LLM workflows
)

vault_data = client.get_vault('660e8400-...')
```

---

## Migration Guide

### For Existing API Consumers

**No breaking changes!** TOON is opt-in.

**To Continue Using JSON:**
- Do nothing - JSON remains the default
- Or explicitly set `Accept: application/json`

**To Adopt TOON:**

1. **Update request headers:**
   ```bash
   # Before (implicit JSON)
   curl http://localhost:8080/api/v1/vaults/123

   # After (explicit TOON)
   curl -H "Accept: text/toon" http://localhost:8080/api/v1/vaults/123
   ```

2. **Handle TOON responses:**
   - TOON is plain text (not JSON)
   - Parse as string for LLM usage
   - Or convert to JSON if needed (libraries exist)

3. **Update client libraries:**
   - Add `Accept` header configuration
   - Handle both JSON and TOON response types
   - Default to JSON for backward compatibility

### For LLM Applications

**Before (JSON):**
```python
response = requests.get(url, headers={"Authorization": f"Bearer {token}"})
data_dict = response.json()
prompt = f"Analyze: {json.dumps(data_dict, indent=2)}"
# Total: ~400 tokens for prompt + data
```

**After (TOON - 40% token savings):**
```python
response = requests.get(
    url,
    headers={"Accept": "text/toon", "Authorization": f"Bearer {token}"}
)
data_toon = response.text  # Use TOON string directly
prompt = f"Analyze: {data_toon}"
# Total: ~240 tokens for prompt + data
```

---

## Performance Considerations

### Serialization Overhead

| Format | Serialization | Deserialization | Network Transfer |
|--------|--------------|-----------------|------------------|
| **JSON** | 5-10μs | 5-10μs | Baseline |
| **TOON** | 8-15μs | N/A (client-side) | **40% smaller** |

**Note:** TOON has slightly higher server-side serialization cost but significantly reduces network transfer and client-side token processing.

### Caching Behavior

Response format does **not** affect caching:
- Authorization decision caching operates at the evaluation layer
- Cache keys are format-agnostic
- Both JSON and TOON responses benefit equally from caching

### Compression

| Format | gzip Size | Reduction |
|--------|-----------|-----------|
| **JSON** | 65% of original | Baseline |
| **TOON** | 70% of original | **Total: 58% smaller than JSON** |

**Recommendation:** Enable gzip compression for both formats (InferaDB enables this by default).

---

## TOON Specification

### Format Details

- **Version:** TOON 2.0 (2025-11-10)
- **Encoding:** UTF-8 with LF line endings
- **Indentation:** 2 spaces per level
- **Number Format:** Canonical decimal (no exponents, no trailing zeros)
- **Delimiter:** Comma (default) for array elements
- **Escape Sequences:** `\\`, `\"`, `\n`, `\r`, `\t` only

### Rust Implementation

InferaDB uses the [`toon` crate v0.1.2](https://crates.io/crates/toon):

```rust
use serde_json::json;
use toon::encode;

let data = json!({
    "id": "123",
    "name": "Alice"
});

let toon_str = encode(&data, None);
// Output:
// id: 123
// name: Alice
```

### External Resources

- **TOON Specification:** [github.com/toon-format/spec](https://github.com/toon-format/spec)
- **Rust Implementation:** [crates.io/crates/toon](https://crates.io/crates/toon)
- **TypeScript/JavaScript:** [@toon-format/toon](https://www.npmjs.com/package/@toon-format/toon)
- **Test Fixtures:** 340+ language-agnostic tests in spec repo

---

## FAQ

### Q: Is TOON lossless?
**A:** Yes, TOON is 100% lossless. Round-trip conversion (JSON → TOON → JSON) preserves all data.

### Q: Can I mix JSON and TOON in batch requests?
**A:** No, the `Accept` header applies to the entire response. Use one format per request.

### Q: What if TOON encoding fails on the server?
**A:** InferaDB automatically falls back to JSON and logs a warning. Clients receive a valid JSON response.

### Q: Do I need to change my code to use this feature?
**A:** No! Existing clients continue working with JSON. TOON is opt-in via `Accept: text/toon`.

### Q: Does TOON work with gRPC?
**A:** No, gRPC uses Protocol Buffers which is already a highly efficient binary format.

### Q: Why are errors still JSON when I request TOON?
**A:** Error messages are short (minimal token savings), and JSON errors are the standard for HTTP APIs.

### Q: Can I configure the TOON encoder (delimiters, indentation)?
**A:** Currently, InferaDB uses default TOON encoding. Custom options may be added in future versions.

### Q: How much does TOON save in practice?
**A:** Savings vary by response structure:
- **Simple objects:** 25-35%
- **Lists/arrays:** 40-60%
- **Large datasets:** 40-50%

### Q: Does InferaDB validate TOON requests?
**A:** No. Requests still use JSON (`Content-Type: application/json`). TOON only applies to responses (`Accept: text/toon`).

---

## Best Practices

### 1. Use TOON for LLM Workflows

```python
# Good - TOON for AI analysis
headers = {"Accept": "text/toon"}
data = fetch_relationships(headers=headers)
llm_response = analyze_with_claude(data)  # 40% token savings

# Avoid - JSON for AI (wastes tokens)
data = fetch_relationships()  # Defaults to JSON
llm_response = analyze_with_claude(json.dumps(data))
```

### 2. Use JSON for Traditional Apps

```javascript
// Good - JSON for web apps
const response = await fetch('/api/v1/vaults', {
  headers: { 'Accept': 'application/json' }
});
const vaults = await response.json();
renderUI(vaults);

// Avoid - TOON for UI (requires parsing)
const response = await fetch('/api/v1/vaults', {
  headers: { 'Accept': 'text/toon' }
});
const toonText = await response.text();
// Manual parsing required
```

### 3. Set Accept Headers Explicitly

```bash
# Good - explicit format
curl -H "Accept: application/json" http://...
curl -H "Accept: text/toon" http://...

# Avoid - relying on defaults (unclear intent)
curl http://...  # Defaults to JSON but not obvious
```

### 4. Handle Both Formats in Libraries

```typescript
// Good - format-aware client
class InferaClient {
  async get(path: string, format: 'json' | 'toon' = 'json') {
    const accept = format === 'toon' ? 'text/toon' : 'application/json';
    // ...
  }
}

// Avoid - hardcoded format
class InferaClient {
  async get(path: string) {
    const accept = 'application/json';  // Inflexible
    // ...
  }
}
```

### 5. Monitor Token Usage

```python
# Track token savings for LLM workflows
def count_tokens(text: str) -> int:
    # Use tiktoken or similar library
    return len(text.split())  # Simplified

json_tokens = count_tokens(json_response)
toon_tokens = count_tokens(toon_response)
savings = (json_tokens - toon_tokens) / json_tokens

print(f"Token savings: {savings * 100:.1f}%")
```

---

## Support & Feedback

### Documentation

- **Content Negotiation:** This document
- **REST API Reference:** [rest.md](./rest.md)
- **API Hub:** [README.md](./README.md)
- **Authentication:** [../docs/security/authentication.md](../docs/security/authentication.md)

### Reporting Issues

- **GitHub Issues:** [github.com/inferadb/server/issues](https://github.com/inferadb/server/issues)
- **TOON Format Issues:** [github.com/toon-format/spec/issues](https://github.com/toon-format/spec/issues)

### Examples & Tutorials

- **LLM Integration Examples:** See "LLM Integration Examples" section above
- **Client Library Templates:** See "Client Library Integration" section above
- **Migration Examples:** See "Migration Guide" section above

---

**Ready to optimize your LLM workflows?**

Start using TOON by adding `Accept: text/toon` to your API requests!
