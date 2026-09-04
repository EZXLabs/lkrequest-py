default:
    @just --list

python := if os_family() == "windows" { ".venv/Scripts/python.exe" } else { ".venv/bin/python" }

# Build and install the extension module for development
dev:
    maturin develop

# Build release wheel
build:
    maturin build --release

build-linux:
    maturin build --release --strip --zig --target x86_64-unknown-linux-gnu --compatibility manylinux_2_28

# Run all checks (format, lint, type-check, test)
check: fmt-check lint test

# Run cargo check (fast compilation check)
cargo-check:
    cargo check

# Run tests
test:
    {{python}} -m pytest tests/ -v

# Format all code
fmt:
    cargo fmt
    ruff format python/ tests/

# Check formatting without modifying files
fmt-check:
    cargo fmt --check
    ruff format --check python/ tests/

# Run linters
lint:
    cargo clippy -- -D warnings
    ruff check python/ tests/

# Run benchmark suite
bench:
    maturin develop --release
    {{python}} benchmarks/bench_latency.py
    {{python}} benchmarks/bench_throughput.py
    {{python}} benchmarks/bench_memory.py

# Verify TLS fingerprints against example.com
verify-fingerprint:
    maturin develop --release
    {{python}} benchmarks/verify_fingerprint.py

# Clean build artifacts
clean:
    cargo clean
    rm -rf dist/ build/ *.egg-info .pytest_cache __pycache__
