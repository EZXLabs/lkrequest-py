"""Memory usage benchmark: lkrequest vs httpx vs requests."""

import tracemalloc
import gc


TARGET_URL = "https://postman-echo.com/get"
NUM_REQUESTS = 50


def measure_memory(name: str, fn):
    gc.collect()
    tracemalloc.start()

    fn()

    snapshot = tracemalloc.take_snapshot()
    tracemalloc.stop()
    gc.collect()

    total = sum(stat.size for stat in snapshot.statistics("filename"))
    peak = tracemalloc.get_traced_memory()[1] if tracemalloc.is_tracing() else 0

    stats = snapshot.statistics("lineno")
    top_allocs = stats[:5]

    print(f"\n  {name}:")
    print(f"    Total allocated: {total / 1024:.1f} KB")
    print(f"    Top allocations:")
    for stat in top_allocs:
        print(f"      {stat}")


def bench_lkrequest():
    import lkrequest.blocking as lk

    client = lk.Client.chrome_144()
    session = client.session()

    responses = []
    for _ in range(NUM_REQUESTS):
        resp = session.get(TARGET_URL)
        responses.append(resp.text())
    return responses


def bench_httpx():
    import httpx

    # See bench_latency.py: all clients must go direct for a fair comparison.
    with httpx.Client(http2=True, trust_env=False) as client:
        responses = []
        for _ in range(NUM_REQUESTS):
            resp = client.get(TARGET_URL)
            responses.append(resp.text)
        return responses


def bench_requests():
    import requests as req

    session = req.Session()
    session.trust_env = False  # go direct, as lkrequest does
    responses = []
    for _ in range(NUM_REQUESTS):
        resp = session.get(TARGET_URL)
        responses.append(resp.text)
    return responses


if __name__ == "__main__":
    print(f"Memory benchmark ({NUM_REQUESTS} requests)")
    print(f"Target: {TARGET_URL}")

    measure_memory("lkrequest", bench_lkrequest)
    measure_memory("httpx", bench_httpx)
    measure_memory("requests", bench_requests)
