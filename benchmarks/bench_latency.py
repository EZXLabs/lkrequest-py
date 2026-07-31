"""Single-request latency benchmark: lkrequest vs httpx vs requests."""

import time
import statistics

TARGET_URL = "https://httpbin.org/get"
WARMUP_ROUNDS = 3
BENCH_ROUNDS = 20


def bench_lkrequest_blocking():
    import lkrequest.blocking as lk

    client = lk.Client.chrome_144()
    session = client.session()

    for _ in range(WARMUP_ROUNDS):
        session.get(TARGET_URL)

    times = []
    for _ in range(BENCH_ROUNDS):
        start = time.perf_counter()
        resp = session.get(TARGET_URL)
        elapsed = time.perf_counter() - start
        assert resp.status_code == 200
        times.append(elapsed * 1000)

    return times


def bench_httpx():
    import httpx

    with httpx.Client(http2=True) as client:
        for _ in range(WARMUP_ROUNDS):
            client.get(TARGET_URL)

        times = []
        for _ in range(BENCH_ROUNDS):
            start = time.perf_counter()
            resp = client.get(TARGET_URL)
            elapsed = time.perf_counter() - start
            assert resp.status_code == 200
            times.append(elapsed * 1000)

    return times


def bench_requests():
    import requests as req

    session = req.Session()

    for _ in range(WARMUP_ROUNDS):
        session.get(TARGET_URL)

    times = []
    for _ in range(BENCH_ROUNDS):
        start = time.perf_counter()
        resp = session.get(TARGET_URL)
        elapsed = time.perf_counter() - start
        assert resp.status_code == 200
        times.append(elapsed * 1000)

    return times


def print_stats(name: str, times: list[float]):
    avg = statistics.mean(times)
    med = statistics.median(times)
    p95 = sorted(times)[int(len(times) * 0.95)]
    mn = min(times)
    mx = max(times)
    print(f"  {name:15s}  avg={avg:7.1f}ms  med={med:7.1f}ms  "
          f"p95={p95:7.1f}ms  min={mn:7.1f}ms  max={mx:7.1f}ms")


if __name__ == "__main__":
    print(f"Latency benchmark ({BENCH_ROUNDS} rounds, {WARMUP_ROUNDS} warmup)")
    print(f"Target: {TARGET_URL}\n")

    results = {}

    print("Running lkrequest...")
    results["lkrequest"] = bench_lkrequest_blocking()

    print("Running httpx...")
    results["httpx"] = bench_httpx()

    print("Running requests...")
    results["requests"] = bench_requests()

    print("\n--- Results ---")
    for name, times in results.items():
        print_stats(name, times)
