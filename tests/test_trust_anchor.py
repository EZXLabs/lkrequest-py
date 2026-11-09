"""Trust Anchor Identifiers: the IDs a ClientHello advertises in extension
0xca34, the `trust_anchor_*` client options, `trust_anchor_identity()` and the
`diagnostics["trust_anchor"]` snapshot.

Recovery needs a server that answers with trust anchor IDs of its own, which
Python's `ssl` cannot send; upstream's tests cover that part.
"""

from __future__ import annotations

import json
import re
import socket
import ssl
import threading

import pytest

import lkrequest
from lkrequest import TlsProfile
from lkrequest.blocking import Client as BlockingClient

EXTENSION = 0xCA34
CUSTOM_ID = "81fd5901"


def profile_ids(name: str) -> list[str]:
    """The trust anchor IDs a TLS profile lists, in the listed order."""
    profile = json.loads(getattr(TlsProfile, name)().to_json())
    [source] = [
        extension["source"]
        for extension in profile["extensions"]
        if (extension.get("source") or {}).get("type") == "trust_anchor_ids"
    ]
    return source["ids"]


def extensions(hello: bytes) -> list[tuple[int, bytes]]:
    """A ClientHello record's extensions, as (type, data) in wire order."""
    body = hello[5 + 4 :]  # record and handshake headers
    pos = 2 + 32  # legacy_version, random
    pos += 1 + body[pos]  # session ID
    pos += 2 + int.from_bytes(body[pos : pos + 2], "big")  # cipher suites
    pos += 1 + body[pos]  # compression methods
    end = pos + 2 + int.from_bytes(body[pos : pos + 2], "big")
    pos += 2
    found = []
    while pos < end:
        kind = int.from_bytes(body[pos : pos + 2], "big")
        length = int.from_bytes(body[pos + 2 : pos + 4], "big")
        found.append((kind, body[pos + 4 : pos + 4 + length]))
        pos += 4 + length
    return found


def wire_ids(hello: bytes) -> list[str] | None:
    """The IDs in a ClientHello record's trust_anchors extension, in wire order."""
    for kind, data in extensions(hello):
        if kind == EXTENSION:
            ids, i = [], 2
            while i < len(data):
                ids.append(data[i + 1 : i + 1 + data[i]].hex())
                i += 1 + data[i]
            return ids
    return None


def extension_order(hello: bytes) -> tuple[int, ...]:
    """The extension types of a ClientHello record in wire order, GREASE left out."""
    return tuple(kind for kind, _ in extensions(hello) if kind & 0x0F0F != 0x0A0A)


class HelloCatcher:
    """Keeps the ClientHello record of each connection, then hangs up."""

    def __init__(self) -> None:
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.url = f"https://127.0.0.1:{self._listener.getsockname()[1]}/"
        self.hellos: list[bytes] = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return
            with conn:
                data = b""
                while len(data) < 5 or len(data) < 5 + int.from_bytes(data[3:5], "big"):
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                self.hellos.append(data)

    def close(self) -> None:
        self._listener.close()


@pytest.fixture
def catcher():
    server = HelloCatcher()
    yield server
    server.close()


def sent_ids(client: BlockingClient, catcher: HelloCatcher, requests: int) -> list:
    """The trust anchor IDs of the ClientHellos sent by `requests` requests,
    each of which fails when the catcher hangs up."""
    for _ in range(requests):
        with pytest.raises(lkrequest.RequestError):
            client.session().get(catcher.url, timeout=5.0)
    return [wire_ids(hello) for hello in catcher.hellos]


def der_of(pem: bytes) -> bytes:
    return ssl.PEM_cert_to_DER_cert(pem.decode())


@pytest.mark.parametrize("preset", ["chrome_155", "chrome_156", "chrome_157"])
def test_chrome_155_to_157_send_their_ids_in_one_fixed_sorted_order(catcher, preset):
    # Chromium sorts them before encoding them. The extensions around them are
    # still permuted on every handshake, independently of the IDs.
    listed = profile_ids(preset)
    assert len(listed) == 28 and listed == sorted(listed)
    client = BlockingClient(tls_profile=preset, h2_profile=preset, verify=False)
    sent = sent_ids(client, catcher, 4)
    assert len(sent) >= 4
    assert sent == [listed] * len(sent)
    assert len({extension_order(hello) for hello in catcher.hellos}) > 1


def test_chrome_154_shuffles_them_on_every_handshake(catcher):
    client = BlockingClient(
        tls_profile="chrome_154", h2_profile="chrome_154", verify=False
    )
    sent = sent_ids(client, catcher, 4)
    assert all(sorted(ids) == sorted(profile_ids("chrome_154")) for ids in sent)
    # 28 IDs have 28! orders: four handshakes in a single one would be a bug.
    assert len({tuple(ids) for ids in sent}) > 1


def test_trusted_advertisement_sends_the_ids_of_trusted_roots(catcher, server_ca):
    der = der_of(server_ca)
    client = BlockingClient(
        tls_profile="chrome_157",
        h2_profile="chrome_157",
        ca_cert_der=der,
        trust_anchor_advertisement="trusted",
        trust_anchor_bindings={CUSTOM_ID: lkrequest.trust_anchor_identity(der)},
    )
    [sent] = sent_ids(client, catcher, 1)
    assert sent == sorted(set(sent))
    assert CUSTOM_ID in sent
    # The others are bundled IDs of the roots in the store. Chrome 157 lists
    # them too, besides the IDs of intermediates, which have no root here.
    assert set(sent) - {CUSTOM_ID} < set(profile_ids("chrome_157"))


def test_a_failed_handshake_reports_what_it_requested(catcher):
    client = BlockingClient(
        tls_profile="chrome_157", h2_profile="chrome_157", verify=False
    )
    with pytest.raises(lkrequest.RequestError) as caught:
        client.session().get(catcher.url, timeout=5.0)
    info = caught.value.diagnostics["trust_anchor"]
    assert info["requested_ids"] == profile_ids("chrome_157")
    assert info["available_ids"] == []
    assert info["authenticated"] is False


def test_a_verified_connection_names_its_anchor(server_url, server_ca):
    session = BlockingClient(
        tls_profile="chrome_157", h2_profile="chrome_157", ca_cert_pem=server_ca
    ).session()
    first = session.get(f"{server_url}/get")
    assert first.diagnostics["trust_anchor"] == {
        "requested_ids": profile_ids("chrome_157"),
        "available_ids": [],
        "matched_request": False,
        "verified_anchor": lkrequest.trust_anchor_identity(der_of(server_ca)),
        "authenticated": True,
        "ech_rejected": False,
        "recovered": False,
        "failure": None,
        "recovery_eligible": False,
        "previous_attempt": None,
    }
    # A request on the pooled connection negotiated nothing.
    assert session.get(f"{server_url}/get").diagnostics["trust_anchor"] is None


async def test_the_async_client_reports_it_too(server_url, server_ca):
    session = lkrequest.Client(
        tls_profile="chrome_157", h2_profile="chrome_157", ca_cert_pem=server_ca
    ).session()
    response = await session.get(f"{server_url}/get")
    assert response.diagnostics["trust_anchor"]["authenticated"] is True


def test_recovery_with_the_bundled_ids_needs_no_other_setting():
    BlockingClient(tls_profile="chrome_157", trust_anchor_recovery="once")
    BlockingClient(trust_anchor_advertisement="trusted", trust_anchor_recovery="once")


@pytest.mark.parametrize("client_cls", [lkrequest.Client, BlockingClient])
@pytest.mark.parametrize(
    "options, message",
    [
        ({"trust_anchor_advertisement": "all"}, "'profile' or 'trusted'"),
        ({"trust_anchor_recovery": "twice"}, "'disabled' or 'once'"),
        (
            {"trust_anchor_recovery": "once", "verify": False},
            "requires certificate verification",
        ),
        (
            {"trust_anchor_recovery": "once", "proxy_fallback_direct": True},
            "proxy-to-direct fallback",
        ),
        (
            {"tls_profile": "firefox_147", "trust_anchor_recovery": "once"},
            "trust_anchors extension slot",
        ),
        ({"trust_anchor_bindings": {"zz": "00" * 32}}, 'invalid trust anchor ID "zz"'),
        ({"trust_anchor_bindings": {CUSTOM_ID: "00" * 32}}, "untrusted root"),
    ],
    ids=[
        "advertisement",
        "recovery",
        "recovery-without-verify",
        "recovery-with-direct-fallback",
        "profile-without-the-extension",
        "malformed-id",
        "root-not-in-the-store",
    ],
)
def test_invalid_settings_are_refused(client_cls, options, message):
    with pytest.raises(ValueError, match=re.escape(message)):
        client_cls(**options)


def test_identity_is_stable_hex_and_refuses_non_certificates(server_ca):
    identity = lkrequest.trust_anchor_identity(der_of(server_ca))
    assert re.fullmatch("[0-9a-f]{64}", identity)
    assert lkrequest.trust_anchor_identity(der_of(server_ca)) == identity
    with pytest.raises(ValueError, match="not a usable DER root certificate"):
        lkrequest.trust_anchor_identity(b"not a certificate")
