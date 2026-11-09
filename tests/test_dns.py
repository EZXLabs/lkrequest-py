"""Where a client looks names up: `dns=` naming a DNS server of its own, or
Python code that does the looking up.

The names are under `.test`, which no public resolver answers, so a request
that reaches the local server proves the name was looked up where `dns=` said.
"""

from __future__ import annotations

import socket
import struct
import threading
import time
from urllib.parse import urlsplit

import pytest

import lkrequest
from lkrequest.blocking import Client as BlockingClient

OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
A = 1


class DnsServer:
    """A DNS server over UDP: A queries for `records` get their address, every
    other query an empty answer. `queries` lists the `(name, type)` asked."""

    def __init__(self, records: dict[str, str]) -> None:
        self.records = records
        self.queries: list[tuple[str, int]] = []
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 0))
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def address(self) -> str:
        return "127.0.0.1:%d" % self._sock.getsockname()[1]

    def close(self) -> None:
        self._sock.close()

    def _serve(self) -> None:
        while True:
            try:
                packet, peer = self._sock.recvfrom(4096)
            except OSError:
                return  # closed
            self._sock.sendto(self._answer(packet), peer)

    def _answer(self, packet: bytes) -> bytes:
        (query_id,) = struct.unpack(">H", packet[:2])
        labels, pos = [], 12
        while packet[pos]:
            length = packet[pos]
            labels.append(packet[pos + 1 : pos + 1 + length].decode().lower())
            pos += 1 + length
        qtype, _ = struct.unpack(">HH", packet[pos + 1 : pos + 5])
        name = ".".join(labels)
        self.queries.append((name, qtype))
        question = packet[12 : pos + 5]
        answers = b""
        if qtype == A and name in self.records:
            # A pointer to the name in the question, then type A, class IN.
            answers = (
                b"\xc0\x0c"
                + struct.pack(">HHIH", A, 1, 60, 4)
                + socket.inet_aton(self.records[name])
            )
        # A response, recursion desired and available, no error.
        header = struct.pack(">HHHHHH", query_id, 0x8180, 1, int(bool(answers)), 0, 0)
        return header + question + answers


@pytest.fixture
def dns_server():
    server = DnsServer({"service.test": "127.0.0.1"})
    yield server
    server.close()


def test_dns_names_the_server_to_ask(raw_http, dns_server):
    target = raw_http(lambda request: OK)
    session = BlockingClient(dns=dns_server.address).session()
    response = session.get(f"http://service.test:{target.port}/", timeout=5.0)
    assert response.status_code == 200
    assert ("service.test", A) in dns_server.queries


async def test_the_async_client_asks_it_too(raw_http, dns_server):
    target = raw_http(lambda request: OK)
    session = lkrequest.Client(dns=dns_server.address).session()
    response = await session.get(f"http://service.test:{target.port}/", timeout=5.0)
    assert response.status_code == 200


def test_a_name_the_server_does_not_know_fails(dns_server):
    session = BlockingClient(dns=dns_server.address).session()
    with pytest.raises(lkrequest.RequestError):
        session.get("http://unknown.test/", timeout=5.0)
    assert ("unknown.test", A) in dns_server.queries


@pytest.mark.parametrize("server", ["1.1.1.1", "1.1.1.1:53", "[2606:4700::1111]:53"])
def test_a_server_is_an_address_with_an_optional_port(server):
    # Port 53 unless given; an IPv6 address with a port goes in brackets.
    assert "Client" in repr(BlockingClient(dns=server))
    assert "Client" in repr(lkrequest.Client(dns=server))


@pytest.mark.parametrize("server", ["1.1.1.1:0", "dns.example:53", "nonsense"])
def test_anything_else_is_refused(server):
    with pytest.raises(ValueError, match="ip:port"):
        BlockingClient(dns=server)


# ---------------------------------------------------------------------------
# Python code as the resolver
# ---------------------------------------------------------------------------


def test_a_function_resolves_the_names(raw_http):
    target = raw_http(lambda request: OK)
    asked = []

    def resolve(host, port):
        asked.append((host, port))
        return ["127.0.0.1"]

    session = BlockingClient(dns=resolve).session()
    assert session.get(f"http://service.test:{target.port}/").status_code == 200
    assert asked == [("service.test", target.port)]


def test_an_address_may_carry_a_port_of_its_own(raw_http):
    target = raw_http(lambda request: OK)
    session = BlockingClient(
        dns=lambda host, port: [f"127.0.0.1:{target.port}"]
    ).session()
    assert session.get("http://service.test:1/").status_code == 200


async def test_the_async_client_calls_it_too(raw_http):
    target = raw_http(lambda request: OK)
    session = lkrequest.Client(dns=lambda host, port: ["127.0.0.1"]).session()
    response = await session.get(f"http://service.test:{target.port}/")
    assert response.status_code == 200


def test_a_copy_with_a_randomized_fingerprint_keeps_it(raw_http):
    target = raw_http(lambda request: OK)
    client = BlockingClient(dns=lambda host, port: ["127.0.0.1"])
    session = client.randomize_fingerprint().session()
    assert session.get(f"http://service.test:{target.port}/").status_code == 200


def test_what_the_resolver_raises_is_the_cause():
    def resolve(host, port):
        raise KeyError(host)

    session = BlockingClient(dns=resolve).session()
    with pytest.raises(lkrequest.LkConnectionError, match="KeyError") as info:
        session.get("http://service.test:1/")
    # Its traceback, and so the line of the resolver that failed, comes along.
    assert isinstance(info.value.__cause__, KeyError)


@pytest.mark.parametrize("answer", ["nonsense", "127.0.0.1:0", 42])
def test_an_answer_that_is_not_an_address_fails(answer):
    session = BlockingClient(dns=lambda host, port: [answer]).session()
    with pytest.raises(lkrequest.LkConnectionError):
        session.get("http://service.test:1/")


def test_ip_family_applies_to_its_answers():
    session = BlockingClient(dns=lambda host, port: ["::1"], ip_family="ipv4").session()
    with pytest.raises(lkrequest.RequestError, match="ip_family"):
        session.get("http://service.test:1/")


def test_dns_timeout_bounds_it():
    def slow(host, port):
        time.sleep(2)
        return ["127.0.0.1"]

    session = BlockingClient(dns=slow, dns_timeout=0.2).session()
    started = time.monotonic()
    with pytest.raises(lkrequest.LkTimeoutError) as info:
        session.get("http://service.test:1/")
    assert time.monotonic() - started < 1.5
    assert info.value.phase == "dns_resolution"


@pytest.mark.skipif(
    not hasattr(lkrequest, "QuicProfile"), reason="built without the quic-h3 feature"
)
@pytest.mark.parametrize(
    ("record", "version"), [(None, "H2"), ({"alpn": ["h3", "h2"]}, "H3")]
)
def test_lookup_https_tells_the_client_about_http3(h3_server_url, record, version):
    asked = []

    class Resolver:
        def resolve(self, host, port):
            return ["127.0.0.1"]

        def lookup_https(self, host):
            asked.append(host)
            return record

    client = BlockingClient(
        tls_profile="chrome_146",
        h2_profile="chrome_146",
        quic_profile="chrome_146",
        verify=False,
        dns=Resolver(),
    )
    session = client.session(protocol_policy=lkrequest.ProtocolPolicy.chrome_standard())
    port = urlsplit(h3_server_url).port
    # The first request of a session: nothing but the record can advertise h3.
    response = session.get(f"https://service.test:{port}/get", timeout=5.0)
    assert response.version is getattr(lkrequest.HttpVersion, version)
    assert asked == ["service.test"]


@pytest.mark.parametrize(
    "dns",
    [42, type("NoResolve", (), {})(), type("NotCallable", (), {"resolve": 1})()],
)
def test_anything_else_is_a_type_error(dns):
    with pytest.raises(TypeError):
        BlockingClient(dns=dns)


def test_an_async_resolver_is_refused():
    async def resolve(host, port):
        return ["127.0.0.1"]

    with pytest.raises(TypeError, match="async"):
        lkrequest.Client(dns=resolve)
