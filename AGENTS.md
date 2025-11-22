# **AGENTS.md**

This file provides directives for code-generation agents (such as Codex, Claude Code, GPT-based tools, etc.) contributing to this repository. Follow these rules strictly to ensure generated code adheres to our standards for performance, maintainability, and reliability.

---

## **Core Principles**

- **No legacy or backward-compatibility code.**
    Do not introduce workarounds for previous behavior or deprecated APIs. Implement clean, modern solutions.

- **Prioritize correctness and quality over preservation.**
    Breaking changes are acceptable when they improve design clarity, correctness, or performance.

- **Always use modern idiomatic Rust.**
    Favor safety, clarity, and performance. Follow current Rust best practices and community conventions (e.g., Clippy suggestions, Rust 2024 idioms).

---

## **Code Quality and Style**

- Code must compile without warnings.
- Run and satisfy all `cargo fmt`, `cargo clippy`, and `cargo check` validations.
- Prefer expressive, self-documenting code over terse or cryptic implementations.
- Avoid unsafe code unless strictly necessary; if used, document the justification and safety invariants clearly.
- Prefer immutable data and pure functions where possible.
- Follow consistent error handling: use `Result` and `thiserror` or `anyhow` consistently.
- Use pattern matching, enums, and traits to express domain concepts cleanly.
- Avoid unnecessary heap allocations, clones, or reference counting unless required by ownership semantics.

---

## **Testing and Validation**

- All tests **must** pass.
- If a test fails because of a legitimate bug, fix the underlying code rather than altering the test.
- Add or update tests to ensure adequate coverage of new functionality.
- Run `cargo test --all` and confirm no regressions.
- Prefer integration tests for public interfaces and unit tests for core logic.
- Use property-based testing (e.g., `proptest`) when it improves coverage or robustness.
- Never remove existing tests unless explicitly instructed.

---

## **Documentation and Comments**

- Every public function, struct, and module must include Rustdoc comments (`///`) with a clear description, parameter notes, and examples if appropriate.
- Keep comments concise and factual—avoid explaining language mechanics.
- Update module-level and crate-level documentation when modifying behavior or APIs.
- When implementing complex algorithms, include brief rationale or references to external resources.

---

## **Dependencies and Build**

- Prefer stable, well-maintained crates. Avoid unmaintained, unlicensed, or pre-1.0 crates unless justified.
- Keep the dependency tree minimal; remove unused or redundant crates when encountered.
- Do not pin crate versions unless required for compatibility or reproducibility.
- Always ensure the build succeeds with `cargo build --release`.
- Do not invoke external tools or commands beyond the standard Rust toolchain.

---

## **Git and Repository Safety**

- **Never invoke any `git` command or perform any filesystem operations beyond code generation.**
- Do not modify repository metadata, configuration files, or commit history.
- Focus only on producing source code and related documentation.

---

## **Performance and Optimization**

- Optimize for clarity first, then performance.
- Use profiling tools or benchmarking crates (like `criterion`) to guide optimization.
- Avoid premature optimization or unsafe micro-optimizations.
- Leverage zero-cost abstractions and efficient data structures.
- Use `#[inline]` only when justified and measured.

---

## **AI Agent Conduct**

- Be deterministic: generate consistent, reproducible output.
- Do not hallucinate APIs or types; verify all symbols exist within the codebase or standard library.
- If context is ambiguous, prefer explicit, conservative implementations rather than assumptions.
- Do not fabricate documentation, dependencies, or tests.
- If you encounter incomplete or unclear requirements, annotate the generated code with a `TODO:` comment rather than guessing.
- Always perform a self-review: reason through logic, confirm function signatures, and ensure no unused imports, dead code, or warnings remain.

---

### **Summary Checklist**

Before submitting generated code:

1. `cargo fmt` passes (no formatting issues).
2. `cargo clippy -- -D warnings` passes.
3. `cargo test --all` passes.
4. No unsafe or unreviewed blocks.
5. Code is idiomatic, minimal, and well-documented.
6. No `git` commands invoked.
7. Adequate test coverage confirmed.
8. No unnecessary dependencies introduced.
