"""`get()` … `options()` straight from a client.

Each call sends its request from a session of its own, so it takes what the
session's method of the same name takes, and keeps no cookie or connection
from one call to the next.
"""

from __future__ import annotations

import pytest

import lkrequest
from lkrequest.blocking import Client as BlockingClient

METHODS = ["get", "post", "put", "delete", "head", "patch", "options"]


def blocking() -> BlockingClient:
    return BlockingClient(
        tls_profile="chrome_152", h2_profile="chrome_152", verify=False
    )


def asynchronous() -> lkrequest.Client:
    return lkrequest.Client(
        tls_profile="chrome_152", h2_profile="chrome_152", verify=False
    )


@pytest.mark.parametrize("method", METHODS)
def test_each_method_sends_its_own(server_url, method):
    response = getattr(blocking(), method)(f"{server_url}/anything")
    assert response.status_code == 200
    if method not in ("head", "options"):
        assert response.json()["method"] == method.upper()


@pytest.mark.parametrize("method", METHODS)
async def test_each_async_method_sends_its_own(server_url, method):
    response = await getattr(asynchronous(), method)(f"{server_url}/anything")
    assert response.status_code == 200
    if method not in ("head", "options"):
        assert response.json()["method"] == method.upper()


def test_the_arguments_are_the_sessions(server_url):
    response = blocking().post(
        f"{server_url}/anything",
        params={"page": "2"},
        headers={"X-Probe": "yes"},
        json={"id": 1},
        timeout=5.0,
    )
    seen = response.json()
    assert seen["args"] == {"page": "2"}
    assert seen["headers"]["X-Probe"] == "yes"
    assert seen["json"] == {"id": 1}
    with pytest.raises(TypeError):
        blocking().get(f"{server_url}/get", jsn={"id": 1})
    with pytest.raises(ValueError, match="Duration must be"):
        blocking().get(f"{server_url}/get", timeout=-1.0)


def test_no_cookie_is_kept_from_one_call_to_the_next(server_url):
    client = blocking()
    # Set on the redirect, which the same call follows in its own session.
    first = client.get(f"{server_url}/cookies/set?flavour=oat")
    assert first.json()["cookies"] == {"flavour": "oat"}
    assert client.get(f"{server_url}/cookies").json()["cookies"] == {}
    # A session keeps it.
    session = client.session()
    session.get(f"{server_url}/cookies/set?flavour=oat")
    assert session.get(f"{server_url}/cookies").json()["cookies"] == {"flavour": "oat"}


async def test_an_async_call_outlives_the_session_made_for_it(server_url):
    pending = asynchronous().get(f"{server_url}/delay/0.2")
    # Nothing but the awaitable refers to the session any more.
    assert (await pending).status_code == 200
