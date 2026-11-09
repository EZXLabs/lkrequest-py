"""The parts of a hand-built `TlsProfile` beyond its lists: the ClientHello
style of the TLS stack it copies, the ECH extension it sends, and the
extensions an inner ClientHello compresses under real ECH.

`TlsProfile.from_json()` could always say all of them; these tests check that
the constructor says the same, by comparing with `to_dict()`.
"""

from __future__ import annotations

import base64

import pytest

from lkrequest import EchMode, TlsProfile


def chrome_like(**kwargs) -> dict:
    """A profile of Chrome 155's lists, and `kwargs`, as a dict."""
    chrome = TlsProfile.chrome_155().to_dict()
    profile = TlsProfile(
        "custom",
        cipher_suites=chrome["cipher_suites"],
        supported_groups=chrome["supported_groups"],
        **kwargs,
    )
    return profile.to_dict()


def test_left_out_they_send_nothing_extra():
    profile = chrome_like()
    assert profile["tls_client_hello_style"] == "generic"
    assert profile["ech"] is None
    assert profile["ech_outer_extensions"] is None


@pytest.mark.parametrize(
    "style",
    ["generic", "chromium_boringssl", "firefox_nss", "safari_cfnetwork", "java_jsse"],
)
def test_the_hello_style_reads_back(style):
    assert chrome_like(tls_client_hello_style=style)["tls_client_hello_style"] == style


def test_an_unknown_hello_style_is_refused():
    with pytest.raises(ValueError, match="chromium_boringssl"):
        TlsProfile("custom", tls_client_hello_style="boringssl")


def test_chromes_ech_can_be_said_by_hand():
    chrome = TlsProfile.chrome_155().to_dict()
    grease = EchMode.grease(payload_length_min=128, payload_length_max=224)
    profile = chrome_like(
        tls_client_hello_style="chromium_boringssl",
        ech=grease,
        ech_outer_extensions=chrome["ech_outer_extensions"],
    )
    assert profile["ech"] == chrome["ech"]
    assert profile["ech_outer_extensions"] == chrome["ech_outer_extensions"]


def test_grease_defaults_to_chromes_suite():
    assert chrome_like(ech=EchMode.grease())["ech"] == {
        "type": "grease",
        "kdf_id": 1,
        "aead_id": 1,
        "enc_length": 32,
        "payload_length_min": None,
        "payload_length_max": None,
    }


def test_a_grease_payload_range_must_be_one():
    with pytest.raises(ValueError, match="must not exceed payload_length_max"):
        EchMode.grease(payload_length_min=240, payload_length_max=128)


def test_real_ech_carries_the_config_list():
    config_list = b"\x00\x45\xfe\x0d\x00\x41"
    ech = chrome_like(ech=EchMode.real(config_list))["ech"]
    assert ech == {
        "type": "real",
        "ech_config_list": base64.b64encode(config_list).decode(),
    }
    assert chrome_like(ech=EchMode.disabled())["ech"] == {"type": "disabled"}


def test_the_repr_reads_like_the_call():
    assert repr(EchMode.grease(payload_length_min=128)) == (
        "EchMode.grease(kdf_id=1, aead_id=1, enc_length=32, "
        "payload_length_min=128, payload_length_max=None)"
    )
    assert repr(EchMode.disabled()) == "EchMode.disabled()"
