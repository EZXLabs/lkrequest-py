"""Lifecycle of a Session: reclaiming one whose hooks refer back to its owner,
`close()`, and the context managers.

The collector tests build the reference cycle that used to keep a session (and
its connections) alive forever, then check that a weak reference to something
only the cycle holds goes dead. Those that look at connections use a server of
their own, so they do not depend on timing in the shared test server.
"""

from __future__ import annotations

import asyncio
import gc
import inspect
import socket
import threading
import time
import weakref

import pytest

import lkrequest
from lkrequest.blocking import Client as BlockingClient

CLIENT_CLASSES = [lkrequest.Client, BlockingClient]


class Token:
    """Stands in for whatever owns a session. A weak reference to it says
    whether the owner, and everything the owner holds, was reclaimed."""


def reclaimed(ref: weakref.ref) -> bool:
    gc.collect()
    return ref() is None


# ---------------------------------------------------------------------------
# Hooks no longer keep their session alive
# ---------------------------------------------------------------------------

HOOK_REGISTRATIONS = [
    "on_request",
    "on_response",
    "kwarg_on_request",
    "kwarg_on_response",
]


@pytest.mark.parametrize("client_cls", CLIENT_CLASSES)
@pytest.mark.parametrize("registration", HOOK_REGISTRATIONS)
def test_a_hook_that_is_a_method_of_the_owner_does_not_keep_it_alive(
    client_cls, registration
):
    class Owner:
        def __init__(self) -> None:
            self.token = Token()
            client = client_cls(verify=False)
            if registration == "on_request":
                self.session = client.session()
                self.session.on_request(self.hook)
            elif registration == "on_response":
                self.session = client.session()
                self.session.on_response(self.hook)
            elif registration == "kwarg_on_request":
                self.session = client.session(on_request=self.hook)
            else:
                self.session = client.session(on_response=self.hook)

        def hook(self, *args) -> None:
            pass

    # owner -> session -> hook list -> bound method -> owner
    #
    # A statement of its own: inside the `assert`, pytest's rewriting would keep
    # the `Owner()` it evaluated alive until the assertion is over.
    ref = weakref.ref(Owner().token)
    assert reclaimed(ref)


@pytest.mark.parametrize("client_cls", CLIENT_CLASSES)
def test_a_hook_closing_over_its_session_does_not_keep_it_alive(client_cls):
    def build() -> weakref.ref:
        token = Token()
        session = client_cls(verify=False).session()

        def hook(*args):
            return session, token

        session.on_response(hook)
        return weakref.ref(token)

    assert reclaimed(build())


@pytest.mark.parametrize("client_cls", CLIENT_CLASSES)
def test_sessions_take_part_in_garbage_collection(client_cls):
    # The reason the cycles above can be broken: the type reports its references.
    assert gc.is_tracked(client_cls(verify=False).session())


# ---------------------------------------------------------------------------
# Hooks still do their job
# ---------------------------------------------------------------------------


def test_hooks_fire_in_registration_order(server_url):
    calls = []
    session = BlockingClient(verify=False).session()
    session.on_response(lambda status, url, elapsed: calls.append("first"))
    session.on_response(lambda status, url, elapsed: calls.append("second"))
    session.get(f"{server_url}/get")
    assert calls == ["first", "second"]


def test_a_hook_registered_after_a_request_sees_the_next_one(server_url):
    calls = []
    session = BlockingClient(verify=False).session()
    session.get(f"{server_url}/get")
    session.on_request(lambda method, url, headers: calls.append(method))
    session.get(f"{server_url}/get")
    assert calls == ["GET"]


def test_a_hook_that_raises_does_not_fail_the_request(server_url):
    def broken(*args):
        raise ValueError("boom")

    session = BlockingClient(verify=False).session(
        on_request=broken, on_response=broken
    )
    assert session.get(f"{server_url}/get").status_code == 200


async def test_hooks_run_for_a_request_whose_session_was_dropped(server_url):
    seen = []
    # The session is a temporary: once `.get()` has returned its awaitable,
    # nothing but the request in flight refers to it.
    response = await (
        lkrequest.Client(verify=False)
        .session(on_response=lambda status, url, elapsed: seen.append(status))
        .get(f"{server_url}/get")
    )
    assert (response.status_code, seen) == (200, [200])


# ---------------------------------------------------------------------------
# close()
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("client_cls", CLIENT_CLASSES)
def test_close_marks_the_session_closed_and_is_idempotent(client_cls):
    session = client_cls(verify=False).session()
    assert session.closed is False
    session.close()
    session.close()
    assert session.closed is True


def _blocking_operations():
    return {
        "get": lambda s, url: s.get(url),
        "post": lambda s, url: s.post(url, json={}),
        "request": lambda s, url: s.request("GET", url),
        "send_streaming": lambda s, url: s.send_streaming("GET", url),
        "preconnect": lambda s, url: s.preconnect(url),
        "preconnect_many": lambda s, url: s.preconnect_many([url]),
        "prefetch": lambda s, url: s.prefetch([url]),
        "ws_connect": lambda s, url: s.ws_connect(url.replace("https", "wss")),
        "on_request": lambda s, url: s.on_request(print),
        "on_response": lambda s, url: s.on_response(print),
    }


@pytest.mark.parametrize("operation", list(_blocking_operations()))
def test_a_closed_blocking_session_refuses_work(operation, server_url):
    session = BlockingClient(verify=False).session()
    session.close()
    with pytest.raises(RuntimeError, match="closed"):
        _blocking_operations()[operation](session, f"{server_url}/get")


@pytest.mark.parametrize("operation", list(_blocking_operations()))
async def test_a_closed_async_session_refuses_work(operation, server_url):
    session = lkrequest.Client(verify=False).session()
    session.close()
    with pytest.raises(RuntimeError, match="closed"):
        result = _blocking_operations()[operation](session, f"{server_url}/get")
        if inspect.isawaitable(result):
            await result


@pytest.mark.parametrize("client_cls", CLIENT_CLASSES)
def test_a_closed_session_still_lets_you_read_its_cookies(client_cls):
    session = client_cls(verify=False).session()
    session.close()
    assert session.get_all_cookies() == []


def test_close_releases_the_pooled_connections(server_url):
    session = BlockingClient(verify=False).session()
    session.get(f"{server_url}/get")
    assert session.pool_stats().h2_connections == 1
    session.close()
    stats = session.pool_stats()
    assert (stats.h2_connections, stats.h1_connections) == (0, 0)
    # The connection's slot is handed back once the aborted task has wound down.
    wait_until(lambda: session.pool_stats().total == 0)


def test_closing_one_session_leaves_the_others_alone(server_url):
    client = BlockingClient(verify=False)
    first, second = client.session(), client.session()
    first.close()
    assert second.get(f"{server_url}/get").status_code == 200
    assert client.session().get(f"{server_url}/get").status_code == 200


@pytest.mark.parametrize("client_cls", CLIENT_CLASSES)
def test_close_drops_the_hooks_at_once(client_cls):
    token = Token()
    ref = weakref.ref(token)
    session = client_cls(verify=False).session()
    session.on_response(lambda *args, held=token: held)
    del token
    assert ref() is not None  # the hook holds it
    session.close()
    assert ref() is None  # and close() let go, with no help from the collector


@pytest.mark.parametrize("client_cls", CLIENT_CLASSES)
def test_close_releases_the_callbacks_of_session_middleware(client_cls):
    token = Token()
    ref = weakref.ref(token)
    middleware = lkrequest.Middleware(
        "held", on_request=lambda request, held=token: request
    )
    session = client_cls(verify=False).session(middleware=[middleware])
    del token, middleware
    assert ref() is not None  # the session still owns the callback
    session.close()
    assert ref() is None


# ---------------------------------------------------------------------------
# Context managers
# ---------------------------------------------------------------------------


def test_with_closes_the_session_on_exit():
    with BlockingClient(verify=False).session() as session:
        assert session.closed is False
        entered = session
    assert session.closed is True
    assert entered is session


def test_with_closes_the_session_when_the_block_raises():
    holder = []
    with pytest.raises(KeyError):
        with BlockingClient(verify=False).session() as session:
            holder.append(session)
            raise KeyError("from the block")
    assert holder[0].closed is True


def test_with_refuses_a_closed_session():
    session = BlockingClient(verify=False).session()
    session.close()
    with pytest.raises(RuntimeError, match="closed"):
        with session:
            pass


async def test_async_with_closes_the_session_on_exit(server_url):
    async with lkrequest.Client(verify=False).session() as session:
        assert session.closed is False
        assert (await session.get(f"{server_url}/get")).status_code == 200
    assert session.closed is True


async def test_async_with_closes_the_session_when_the_block_raises():
    holder = []
    with pytest.raises(KeyError):
        async with lkrequest.Client(verify=False).session() as session:
            holder.append(session)
            raise KeyError("from the block")
    assert holder[0].closed is True


async def test_async_with_refuses_a_closed_session():
    session = lkrequest.Client(verify=False).session()
    session.close()
    with pytest.raises(RuntimeError, match="closed"):
        async with session:
            pass


# ---------------------------------------------------------------------------
# Requests in flight when the session is closed
# ---------------------------------------------------------------------------


@pytest.fixture
def silent_server():
    """Accepts connections and never answers. Yields (base url, accepted sockets)."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0.1)
    accepted: list[socket.socket] = []
    stop = threading.Event()

    def accept() -> None:
        while not stop.is_set():
            try:
                accepted.append(listener.accept()[0])
            except OSError:
                continue

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{listener.getsockname()[1]}", accepted
    stop.set()
    thread.join()
    for connection in accepted:
        connection.close()
    listener.close()


def wait_until(condition, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "timed out"
        time.sleep(0.01)


def peer_closed(connection: socket.socket, timeout: float = 5.0) -> bool:
    """Whether the client end of an accepted connection has gone away."""
    connection.settimeout(timeout)
    try:
        while connection.recv(65536):
            pass  # the request it had already sent
    except (socket.timeout, OSError):
        return False
    return True


def test_closing_abandons_a_blocking_request_in_flight(silent_server):
    base, accepted = silent_server
    session = BlockingClient(verify=False).session()
    outcome: dict[str, BaseException] = {}

    def request() -> None:
        try:
            session.get(f"{base}/")
        except BaseException as error:  # noqa: BLE001 - recorded for the assertions
            outcome["error"] = error

    worker = threading.Thread(target=request)
    worker.start()
    wait_until(lambda: accepted)  # the request is on the wire
    session.close()
    worker.join(5)

    assert not worker.is_alive(), "close() left the request hanging"
    assert isinstance(outcome["error"], RuntimeError)
    assert "closed" in str(outcome["error"])
    assert peer_closed(accepted[0]), "the connection was not closed"


async def test_closing_abandons_an_async_request_in_flight(silent_server):
    base, accepted = silent_server
    session = lkrequest.Client(verify=False).session()
    request = asyncio.ensure_future(session.get(f"{base}/"))
    while not accepted:
        await asyncio.sleep(0.01)
    session.close()

    with pytest.raises(RuntimeError, match="closed"):
        await asyncio.wait_for(request, 5)
    assert await asyncio.to_thread(peer_closed, accepted[0]), (
        "the connection was not closed"
    )
