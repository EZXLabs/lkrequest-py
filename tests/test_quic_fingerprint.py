"""`quic_fingerprint`: the ClientHello sent inside QUIC, a `TlsProfile` or a
name. A preset's name stands for the one that preset sends over QUIC, as
`Client.<name>()` sends it, so `"chrome_158"` is Chrome 158's QUIC
ClientHello rather than the one it sends over TCP.

The wire tests read the ClientHello off the local HTTP/3 server, which runs on
aioquic in this process.
"""

from __future__ import annotations

import aioquic.tls
import pytest

import lkrequest
from lkrequest import TlsProfile, list_presets
from lkrequest.blocking import Client as BlockingClient

QUIC_TLS_PRESETS = sorted(name for name in dir(TlsProfile) if name.endswith("_quic"))
PRESET_NAMES = [preset["name"] for preset in list_presets()]


def offer(cipher_suites, signature_algorithms) -> tuple[tuple[int, ...], ...]:
    """A ClientHello's cipher suites and signature schemes, GREASE left out."""

    def keep(values) -> tuple[int, ...]:
        return tuple(v for v in values if v & 0x0F0F != 0x0A0A)

    return keep(cipher_suites), keep(signature_algorithms)


@pytest.fixture
def client_hellos(monkeypatch) -> list:
    """What the ClientHellos the local HTTP/3 server parses offer."""
    seen = []
    pull = aioquic.tls.pull_client_hello

    def record(buf):
        hello = pull(buf)
        seen.append(offer(hello.cipher_suites, hello.signature_algorithms))
        return hello

    monkeypatch.setattr(aioquic.tls, "pull_client_hello", record)
    return seen


@pytest.mark.skipif(
    not hasattr(lkrequest, "QuicProfile"),
    reason="built without the quic-h3 feature (maturin develop --features quic-h3)",
)
@pytest.mark.parametrize(
    "name, sent",
    [
        ("chrome_158", TlsProfile.chrome_158_quic),
        ("chrome_158_quic", TlsProfile.chrome_158_quic),
        # What Client.chrome_147() sends over QUIC.
        ("chrome_147", TlsProfile.chrome_146_quic),
        # Presets without a QUIC ClientHello of their own send their TLS one.
        ("chrome_131", TlsProfile.chrome_131),
        ("firefox_156", TlsProfile.firefox_156),
    ],
)
def test_a_name_sends_what_its_preset_sends_over_quic(
    h3_server_url, client_hellos, name, sent
):
    client = BlockingClient(
        quic_profile="chrome_158", quic_fingerprint=name, verify=False
    )
    response = client.session(http3_only=True).get(f"{h3_server_url}/get", timeout=5.0)
    assert response.version == lkrequest.HttpVersion.H3
    profile = sent()
    assert client_hellos
    assert set(client_hellos) == {
        offer(profile.cipher_suites, profile.signature_algorithms)
    }


@pytest.mark.parametrize("name", PRESET_NAMES + QUIC_TLS_PRESETS)
def test_every_preset_and_quic_tls_preset_is_a_name(name):
    BlockingClient(quic_fingerprint=name)


def test_an_unknown_name_lists_the_names():
    with pytest.raises(ValueError) as caught:
        BlockingClient(quic_fingerprint="chrome_999")
    message = str(caught.value)
    assert message.startswith("Unknown QUIC TLS profile: 'chrome_999'. Available: ")
    assert (
        message.split("Available: ")[1].split(", ") == PRESET_NAMES + QUIC_TLS_PRESETS
    )


@pytest.mark.parametrize("client_cls", [lkrequest.Client, BlockingClient])
def test_both_clients_take_the_same_names(client_cls):
    client_cls(quic_fingerprint="chrome_158_quic")
    client_cls(quic_fingerprint=TlsProfile.chrome_158())
    with pytest.raises(ValueError, match="Unknown QUIC TLS profile"):
        client_cls(quic_fingerprint="chrome_158_tcp")
    with pytest.raises(TypeError, match="quic_fingerprint must be"):
        client_cls(quic_fingerprint=158)
