"""Where the proxies of a pool come from, and the options both pools take.

Besides a list, `ProxyPool` and `SessionPool` take a function, called for every
proxy they hand out, as a gateway that picks the exit by a session id in the
username needs. What the function raises comes out of the `acquire()` that
called it. There is a blocking `ProxyPool` as well, and `SessionPool` takes the
`bad_proxy_config=` and `health_check=` that `ProxyPool` already did.

The proxies are local servers that refuse every CONNECT, which is enough to see
which proxy, and which credentials, a request went out through.
"""

from __future__ import annotations

import asyncio
import base64
import threading
import time

import pytest

import lkrequest
import lkrequest.blocking
from lkrequest.blocking import Client as BlockingClient

REFUSED = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
TARGET = "https://target.example/"
# Spliced into proxy URLs rather than written in them: the public mirror's
# cleaner rewrites any `scheme://user:pass@host` it finds.
USERINFO = "alice:secret@"


def basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


class Gateway:
    """A proxy function that gives every proxy a new session id."""

    def __init__(self, port: int) -> None:
        self.port = port
        self.calls = 0

    def __call__(self) -> str:
        self.calls += 1
        return self.url(self.calls)

    def url(self, session_id: int) -> str:
        return f"http://user-{session_id}:pw@127.0.0.1:{self.port}"


def broken() -> str:
    raise RuntimeError("no exit available")


def start(call):
    """Run a blocking `call` on a daemon thread, so a test can tell whether it
    returns; `outcome` gets its `value` or its `error`."""
    outcome: dict = {}

    def run() -> None:
        try:
            outcome["value"] = call()
        except BaseException as err:  # noqa: BLE001 - handed to the test
            outcome["error"] = err

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, outcome


def wait_until(condition, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition() and time.monotonic() < deadline:
        time.sleep(0.02)


# ---------------------------------------------------------------------------
# A function as the source of proxies
# ---------------------------------------------------------------------------


async def test_a_function_makes_a_new_proxy_for_every_lease(raw_http):
    proxy = raw_http(lambda request: REFUSED)
    pool = lkrequest.ProxyPool(Gateway(proxy.port))
    for _ in range(2):
        async with await asyncio.wait_for(pool.acquire(), 5) as lease:
            session = lkrequest.Client.chrome_131().session(proxy=lease.proxy)
            with pytest.raises(lkrequest.ProxyError):
                await session.get(TARGET, timeout=5.0)
    assert [r.values("proxy-authorization") for r in proxy.requests] == [
        [basic("user-1", "pw")],
        [basic("user-2", "pw")],
    ]


async def test_the_function_may_return_a_proxy_config():
    config = lkrequest.ProxyConfig("socks5://127.0.0.1:1").with_user_pass("u", "p")
    lease = await asyncio.wait_for(lkrequest.ProxyPool(lambda: config).acquire(), 5)
    assert lease.proxy.identity() == config.identity()


async def test_what_the_function_raises_comes_out_of_acquire():
    pool = lkrequest.ProxyPool(broken)
    with pytest.raises(RuntimeError, match="no exit available"):
        await asyncio.wait_for(pool.acquire(), 5)


@pytest.mark.parametrize(
    ("returned", "error"),
    [("not a proxy URL", ValueError), (None, TypeError), (42, TypeError)],
)
async def test_a_function_that_returns_no_proxy_fails_acquire(returned, error):
    # Upstream would only log it and ask again, and acquire() would wait for good.
    pool = lkrequest.ProxyPool(lambda: returned)
    with pytest.raises(error):
        await asyncio.wait_for(pool.acquire(), 5)


def test_an_async_function_is_refused():
    async def make() -> str:
        return "http://127.0.0.1:8080"

    with pytest.raises(TypeError, match="async"):
        lkrequest.ProxyPool(make)


async def test_max_proxies_caps_a_function_pool_too():
    gateway = Gateway(1)
    pool = lkrequest.ProxyPool(gateway, max_proxies=1)
    first = await asyncio.wait_for(pool.acquire(), 5)
    second = asyncio.ensure_future(pool.acquire())
    await asyncio.sleep(0.2)
    assert not second.done(), "a second lease was handed out past max_proxies"
    # The function is only asked once there is a share to go with the proxy.
    assert gateway.calls == 1
    first.release()
    await asyncio.wait_for(second, 5)
    assert gateway.calls == 2


def test_proxy_buffer_needs_a_function():
    with pytest.raises(ValueError, match="proxy_buffer"):
        lkrequest.ProxyPool(["http://127.0.0.1:8080"], proxy_buffer=2)
    with pytest.raises(ValueError, match="proxy_buffer"):
        lkrequest.SessionPool(lkrequest.Client(), [], proxy_buffer=2)


async def test_proxy_buffer_makes_proxies_ahead_of_time():
    gateway = Gateway(1)
    pool = lkrequest.ProxyPool(gateway, proxy_buffer=3)
    deadline = time.monotonic() + 5
    while gateway.calls < 3 and time.monotonic() < deadline:
        await asyncio.sleep(0.02)
    assert gateway.calls == 3, "the buffer was not filled before any acquire()"
    lease = await asyncio.wait_for(pool.acquire(), 5)
    assert lease.proxy.identity() == lkrequest.ProxyConfig(gateway.url(1)).identity()


def test_a_failing_function_does_not_spin_the_buffer():
    calls = []

    def failing() -> str:
        calls.append(time.monotonic())
        raise RuntimeError("down")

    pool = lkrequest.ProxyPool(failing, proxy_buffer=2)
    wait_until(lambda: calls)
    time.sleep(0.5)
    # Upstream's buffer thread calls again at once, over and over.
    assert 1 <= len(calls) <= 2
    del pool


# ---------------------------------------------------------------------------
# The blocking ProxyPool
# ---------------------------------------------------------------------------


def test_the_blocking_pool_leases_a_proxy_with_its_credentials(raw_http):
    proxy = raw_http(lambda request: REFUSED)
    pool = lkrequest.blocking.ProxyPool(
        [f"http://{USERINFO}127.0.0.1:{proxy.port}"], max_proxies=1
    )
    assert pool.max_concurrent == 1
    with pool.acquire() as lease:
        session = BlockingClient.chrome_131().session(proxy=lease.proxy)
        with pytest.raises(lkrequest.ProxyError):
            session.get(TARGET, timeout=5.0)
    assert lease.released
    [connect] = proxy.requests
    assert connect.values("proxy-authorization") == [basic("alice", "secret")]


def test_the_blocking_pool_waits_for_a_share():
    pool = lkrequest.blocking.ProxyPool(["http://127.0.0.1:8080"], max_proxies=1)
    first = pool.acquire()
    thread, outcome = start(pool.acquire)
    thread.join(0.3)
    assert thread.is_alive(), "a second lease was handed out past max_proxies"
    first.release()
    thread.join(5)
    assert not thread.is_alive()
    assert not outcome["value"].released


def test_the_blocking_pool_acquires_fresh():
    pool = lkrequest.blocking.ProxyPool(
        ["http://127.0.0.1:8080", "http://127.0.0.1:8081"],
        max_proxies=1,
        bad_proxy_config=lkrequest.BadProxyConfig(
            failure_threshold=1, cooldown_duration=60.0
        ),
    )
    first = pool.acquire()
    # With max_proxies=1 this only returns because `first` is released first.
    thread, outcome = start(lambda: pool.acquire_fresh(first))
    thread.join(5)
    assert not thread.is_alive()
    assert first.released
    assert outcome["value"].proxy.identity() != first.proxy.identity()


def test_the_blocking_pool_raises_what_the_function_raises():
    pool = lkrequest.blocking.ProxyPool(broken)
    thread, outcome = start(pool.acquire)
    thread.join(5)
    assert not thread.is_alive(), "acquire() kept waiting on a failing function"
    assert isinstance(outcome["error"], RuntimeError)


def test_the_blocking_pool_takes_a_function():
    gateway = Gateway(1)
    pool = lkrequest.blocking.ProxyPool(gateway)
    lease = pool.acquire()
    assert lease.proxy.identity() == lkrequest.ProxyConfig(gateway.url(1)).identity()


# ---------------------------------------------------------------------------
# SessionPool
# ---------------------------------------------------------------------------


async def test_a_session_pool_takes_a_function(raw_http):
    proxy = raw_http(lambda request: REFUSED)
    pool = lkrequest.SessionPool(lkrequest.Client.chrome_131(), Gateway(proxy.port))
    async with await asyncio.wait_for(pool.acquire(), 5) as session:
        with pytest.raises(lkrequest.ProxyError):
            await session.get(TARGET, timeout=5.0)
    [connect] = proxy.requests
    assert connect.values("proxy-authorization") == [basic("user-1", "pw")]


async def test_a_session_pool_raises_what_the_function_raises():
    pool = lkrequest.SessionPool(lkrequest.Client.chrome_131(), broken)
    with pytest.raises(RuntimeError, match="no exit available"):
        await asyncio.wait_for(pool.acquire(), 5)


def test_a_blocking_session_pool_takes_a_function(raw_http):
    proxy = raw_http(lambda request: REFUSED)
    pool = lkrequest.BlockingSessionPool(
        BlockingClient.chrome_131(), Gateway(proxy.port)
    )
    with pool.acquire() as session:
        with pytest.raises(lkrequest.ProxyError):
            session.get(TARGET, timeout=5.0)
    [connect] = proxy.requests
    assert connect.values("proxy-authorization") == [basic("user-1", "pw")]


def test_a_blocking_session_pool_raises_what_the_function_raises():
    pool = lkrequest.BlockingSessionPool(BlockingClient.chrome_131(), broken)
    thread, outcome = start(pool.acquire)
    thread.join(5)
    assert not thread.is_alive(), "acquire() kept waiting on a failing function"
    assert isinstance(outcome["error"], RuntimeError)


@pytest.mark.parametrize(
    ("pool_cls", "client_cls"),
    [
        (lkrequest.SessionPool, lkrequest.Client),
        (lkrequest.BlockingSessionPool, BlockingClient),
    ],
)
def test_a_session_pool_checks_the_health_of_its_proxies(
    raw_http, pool_cls, client_cls
):
    proxy = raw_http(lambda request: REFUSED)
    health = lkrequest.HealthCheckConfig(target_host="health.example", target_port=443)
    # The first check runs as soon as the pool is built.
    pool = pool_cls(
        client_cls.chrome_131(), [f"http://127.0.0.1:{proxy.port}"], health_check=health
    )
    wait_until(lambda: proxy.requests)
    [connect] = proxy.requests
    assert (connect.method, connect.target) == ("CONNECT", "health.example:443")
    del pool


async def test_a_session_pool_cools_a_bad_proxy_down():
    pool = lkrequest.SessionPool(
        lkrequest.Client.chrome_131(),
        ["socks5://127.0.0.1:1"],
        # The default needs three failures before a cooldown.
        bad_proxy_config=lkrequest.BadProxyConfig(
            failure_threshold=1, cooldown_duration=60.0
        ),
    )
    guard = await asyncio.wait_for(pool.acquire(), 5)
    await pool.mark_bad(guard)
    async with guard:
        pass
    acquiring = asyncio.ensure_future(pool.acquire())
    await asyncio.sleep(0.3)
    assert not acquiring.done(), "the only proxy should be cooling down"
    acquiring.cancel()


def test_a_blocking_session_pool_cools_a_bad_proxy_down():
    pool = lkrequest.BlockingSessionPool(
        BlockingClient.chrome_131(),
        ["socks5://127.0.0.1:1"],
        bad_proxy_config=lkrequest.BadProxyConfig(
            failure_threshold=1, cooldown_duration=1.0
        ),
    )
    guard = pool.acquire()
    pool.mark_bad(guard)
    with guard:
        pass
    thread, _ = start(pool.acquire)
    thread.join(0.3)
    assert thread.is_alive(), "the only proxy should be cooling down"
    # ... and it is handed out again once the cooldown is over.
    thread.join(5)
    assert not thread.is_alive()
