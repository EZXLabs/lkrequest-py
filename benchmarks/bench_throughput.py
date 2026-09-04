"""Concurrent throughput benchmark: lkrequest vs httpx vs aiohttp."""

import asyncio
import time

TARGET_URL = "https://postman-echo.com/get"
CONCURRENCY = 50
TOTAL_REQUESTS = 200


async def bench_lkrequest_async():
    import lkrequest

    client = lkrequest.Client.chrome_144()
    session = client.session()

    sem = asyncio.Semaphore(CONCURRENCY)
    success = 0
    errors = 0

    async def make_request():
        nonlocal success, errors
        async with sem:
            try:
                resp = await session.get(TARGET_URL)
                if resp.status_code == 200:
                    success += 1
                else:
                    errors += 1
            except Exception:
                errors += 1

    start = time.perf_counter()
    tasks = [asyncio.create_task(make_request()) for _ in range(TOTAL_REQUESTS)]
    await asyncio.gather(*tasks)
    elapsed = time.perf_counter() - start

    return elapsed, success, errors


async def bench_httpx_async():
    import httpx

    # See bench_latency.py: all clients must go direct for a fair comparison.
    # aiohttp already ignores the proxy environment unless trust_env=True.
    async with httpx.AsyncClient(http2=True, trust_env=False) as client:
        sem = asyncio.Semaphore(CONCURRENCY)
        success = 0
        errors = 0

        async def make_request():
            nonlocal success, errors
            async with sem:
                try:
                    resp = await client.get(TARGET_URL)
                    if resp.status_code == 200:
                        success += 1
                    else:
                        errors += 1
                except Exception:
                    errors += 1

        start = time.perf_counter()
        tasks = [asyncio.create_task(make_request()) for _ in range(TOTAL_REQUESTS)]
        await asyncio.gather(*tasks)
        elapsed = time.perf_counter() - start

    return elapsed, success, errors


async def bench_aiohttp_async():
    import aiohttp

    async with aiohttp.ClientSession() as session:
        sem = asyncio.Semaphore(CONCURRENCY)
        success = 0
        errors = 0

        async def make_request():
            nonlocal success, errors
            async with sem:
                try:
                    async with session.get(TARGET_URL) as resp:
                        if resp.status == 200:
                            await resp.read()
                            success += 1
                        else:
                            errors += 1
                except Exception:
                    errors += 1

        start = time.perf_counter()
        tasks = [asyncio.create_task(make_request()) for _ in range(TOTAL_REQUESTS)]
        await asyncio.gather(*tasks)
        elapsed = time.perf_counter() - start

    return elapsed, success, errors


def print_result(name: str, elapsed: float, success: int, errors: int):
    rps = TOTAL_REQUESTS / elapsed
    print(f"  {name:15s}  {elapsed:6.2f}s  {rps:7.1f} req/s  "
          f"ok={success}  err={errors}")


async def main():
    print(f"Throughput benchmark ({TOTAL_REQUESTS} requests, "
          f"concurrency={CONCURRENCY})")
    print(f"Target: {TARGET_URL}\n")

    results = {}

    print("Running lkrequest...")
    results["lkrequest"] = await bench_lkrequest_async()

    print("Running httpx...")
    results["httpx"] = await bench_httpx_async()

    print("Running aiohttp...")
    results["aiohttp"] = await bench_aiohttp_async()

    print("\n--- Results ---")
    for name, (elapsed, success, errors) in results.items():
        print_result(name, elapsed, success, errors)


if __name__ == "__main__":
    asyncio.run(main())
