# Contributing to lkrequest

Thanks for your interest in contributing! This package is a [PyO3](https://pyo3.rs)
binding over the `lkrequest` Rust workspace, built with
[maturin](https://www.maturin.rs).

## Development setup

```bash
git clone https://github.com/ez-opensource/lkrequest-py
cd lkrequest-py
python3 -m venv .venv                 # Linux/macOS
# py -m venv .venv                    # Windows
# Windows:        .venv\Scripts\Activate.ps1
# Linux / macOS:  source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install maturin
python -m pip install -e ".[test,lint]"
```

Alternatively, use uv to create and manage the environment:

```bash
uv sync --extra test --extra lint
```

Optional build features:

```bash
maturin develop --features telemetry  # enable metrics_snapshot() counters
maturin develop --features quic-h3     # enable QUIC / HTTP3
```

## Running the test suite

```bash
python -m pip install -e ".[test]"   # pytest + local server dependencies
just test

# With uv:
just test
# Or:
uv run pytest tests/ -v

# Skip the network/server tests and run only unit-level checks:
python -m pytest tests/ -v -k "not httpbin and not echo"
```

## Before opening a pull request

The CI lint gate is strict — please run these locally and make sure they pass:

```bash
cargo fmt --all          # format (CI runs `cargo fmt --check`)
cargo clippy -- -D warnings
python -m pytest tests/ -v
```

A few project conventions:

- **Type stubs are the source of truth for the public API.** Any new public
  class, method, or module function in Rust must also be declared in
  `python/lkrequest/_lkrequest.pyi`. `tests/test_stub_parity.py` enforces this.
- **Avoid `unwrap()` / `expect()`** in non-test code (clippy is configured to
  warn). Propagate errors with `?` and the project's error types, or add an
  `#[allow(...)]` with a justifying comment where a panic is genuinely
  unreachable (e.g. a `LazyLock` initializer).
- Keep new code formatted to match the surrounding style; `cargo fmt` handles
  this for Rust.

## License

By contributing, you agree that your contributions will be licensed under the
[Apache License 2.0](LICENSE), consistent with the rest of the project.
