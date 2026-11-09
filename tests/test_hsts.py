"""HSTS policies: whether an `http://` URL is upgraded to `https://` before
connecting.

An `Hsts` object holds one policy, shared by every session it is given to, so
what a dynamic one learns from a `Strict-Transport-Security` header applies to
all of them, as in one browser profile. A policy can also be written in Python.

HSTS is never applied to an IP literal, so the local server is addressed as
`localhost`, which its certificate covers. Spoken to in plain HTTP, its TLS port
fails the request, which is how a test sees that no upgrade happened.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import pytest

import lkrequest
from lkrequest import Hsts
from lkrequest.blocking import Client as BlockingClient

OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"


@pytest.fixture
def localhost(server_url) -> str:
    """The local server's TLS port, by name."""
    return f"localhost:{urlsplit(server_url).port}"


def client() -> BlockingClient:
    return BlockingClient(
        tls_profile="chrome_152", h2_profile="chrome_152", verify=False
    )


def learn(session, localhost: str) -> None:
    """Have `session` receive a Strict-Transport-Security header over HTTPS."""
    session.get(
        f"https://{localhost}/response-headers",
        params={"Strict-Transport-Security": "max-age=3600"},
    )


def test_what_a_dynamic_policy_learns_applies_to_every_session_given_it(localhost):
    hsts = Hsts.dynamic()
    learn(client().session(hsts=hsts), localhost)
    later = client().session(hsts=hsts)
    assert later.get(f"http://{localhost}/get").url.startswith("https://")
    assert hsts.should_upgrade("localhost")
    assert hsts.should_upgrade("example.com") is False


def test_another_dynamic_policy_has_learned_nothing(localhost):
    learn(client().session(hsts=Hsts.dynamic()), localhost)
    other = Hsts.dynamic()
    assert other.should_upgrade("localhost") is False
    with pytest.raises(lkrequest.RequestError):
        client().session(hsts=other).get(f"http://{localhost}/get", timeout=5.0)


def test_the_presets_answer_as_a_session_would_ask_them():
    assert Hsts.none().should_upgrade("example.com") is False
    fixed = Hsts.static_(["example.com"])
    assert fixed.should_upgrade("api.example.com")
    assert fixed.should_upgrade("example.org") is False
    assert Hsts.static_([], preloaded_tlds=True).should_upgrade("web.dev")
    assert Hsts.dynamic(seed=["example.com"]).should_upgrade("example.com")


def test_a_custom_policy_decides_which_hosts_are_upgraded(localhost):
    asked = []

    def should_upgrade(host: str) -> bool:
        asked.append(host)
        return host == "localhost"

    session = client().session(hsts=Hsts.custom(should_upgrade))
    assert session.get(f"http://{localhost}/get").url.startswith("https://")
    assert asked == ["localhost"]


async def test_an_async_session_asks_a_custom_policy_too(localhost):
    hsts = Hsts.custom(lambda host: True)
    session = lkrequest.Client(
        tls_profile="chrome_152", h2_profile="chrome_152", verify=False
    ).session(hsts=hsts)
    response = await session.get(f"http://{localhost}/get")
    assert response.url.startswith("https://")


def test_a_custom_policy_is_told_of_each_header(localhost):
    recorded = []
    hsts = Hsts.custom(
        lambda host: False, lambda host, header: recorded.append((host, header))
    )
    learn(client().session(hsts=hsts), localhost)
    assert recorded == [("localhost", "max-age=3600")]


def broken(*args) -> bool:
    raise RuntimeError("policy store unavailable")


def test_a_custom_policy_that_raises_upgrades_nothing(raw_http):
    server = raw_http(lambda request: OK)
    session = client().session(hsts=Hsts.custom(broken, broken))
    response = session.get(f"http://127.0.0.1:{server.port}/")
    assert response.url.startswith("http://") and response.text() == "OK"
    assert Hsts.custom(broken).should_upgrade("example.com") is False


def test_the_answer_is_taken_for_its_truth():
    assert Hsts.custom(lambda host: "yes").should_upgrade("example.com")
    assert Hsts.custom(lambda host: None).should_upgrade("example.com") is False


def test_a_custom_policy_must_be_plain_functions():
    async def should_upgrade(host):
        return True

    with pytest.raises(TypeError, match="should_upgrade must be a plain function"):
        Hsts.custom(should_upgrade)
    with pytest.raises(TypeError, match="record_sts must be callable"):
        Hsts.custom(lambda host: True, "not a function")
