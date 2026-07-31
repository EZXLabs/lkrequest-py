# lkrequest Benchmark Suite

Performance benchmarks comparing lkrequest against httpx, aiohttp, and requests.

## Setup

```bash
pip install -r benchmarks/requirements.txt
pip install lkrequest httpx aiohttp requests
```

## Benchmarks

### Single-Request Latency

Measures per-request latency with connection reuse (warm connections):

```bash
python benchmarks/bench_latency.py
```

### Concurrent Throughput

Measures requests per second under concurrent load:

```bash
python benchmarks/bench_throughput.py
```

### Memory Usage

Measures memory allocation for sequential requests:

```bash
python benchmarks/bench_memory.py
```

### TLS Fingerprint Verification

Validates that browser presets produce accurate TLS/H2 fingerprints:

```bash
python benchmarks/verify_fingerprint.py
```

## Configuration

All benchmarks use `https://httpbin.org/get` as the default target.
Set `TARGET_URL` at the top of each script to use a different endpoint.
