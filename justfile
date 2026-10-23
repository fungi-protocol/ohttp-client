# Single source of truth: `rust-version` in Cargo.toml.
MSRV := `grep -m1 '^rust-version' Cargo.toml | cut -d'"' -f2`

# Run the full validation suite: fmt check, clippy, tests, wasm, js e2e, msrv, audit.
check: fmt-check lint test check-wasm test-js msrv audit

# Format all code.
fmt:
    cargo fmt --all

# Check formatting without writing changes.
fmt-check:
    cargo fmt --all -- --check

# Lint with clippy, treating warnings as errors, across all features.
lint:
    cargo clippy --all-targets --all-features -- -D warnings

clippy: lint

# Run tests across all features.
test:
    cargo test --all-features

# Verify the crate (including wasm-bindgen exports) builds for browsers.
check-wasm:
    cargo check --target wasm32-unknown-unknown --features wasm

# Build the web wasm package into js/pkg/.
build-wasm:
    wasm-pack build --target web --out-dir js/pkg --out-name ohttp_client -- --features wasm

# Build wasm and run the JS e2e against the Rust test harness.
test-js: build-wasm
    node js/e2e.test.js

# Verify the crate still builds on its declared MSRV.
# `--locked` is load-bearing: a lockfile update that raises the floor must fail
# here, not silently.
# `MSRV_CARGO` (set by the nix dev shell) points straight at an MSRV cargo;
# cargo still runs `rustc` from PATH, so pin RUSTC beside it or it builds with
# whatever rustc PATH has (stable locally, a rustup proxy on CI).
# Without `MSRV_CARGO` we fall back to rustup's toolchain selection.
msrv:
    @if [ -n "${MSRV_CARGO:-}" ]; then \
        RUSTC="$(dirname "$MSRV_CARGO")/rustc" "$MSRV_CARGO" check --locked --all-features --all-targets; \
    else \
        rustup toolchain list | grep -q '^{{MSRV}}' || (echo "missing toolchain: rustup toolchain install {{MSRV}}" && exit 1); \
        cargo +{{MSRV}} check --locked --all-features --all-targets; \
    fi

# Audit dependencies for known security advisories.
audit:
    cargo audit
