"""Complete profile bundles: a browser preset written out as lkrequest's v2
preset JSON by `export_preset_json()`, and a client built from one with
`Client.from_preset_json()` / `Client.from_preset_file()`.
"""

from __future__ import annotations

import json

import pytest

import lkrequest
from lkrequest import TcpFingerprint, export_preset_json, list_presets
from lkrequest.blocking import Client as BlockingClient

PRESET_NAMES = [preset["name"] for preset in list_presets()]


def settings(client) -> tuple:
    """What a bundle carries, as the client reads it back."""
    policy = client.protocol_policy
    return (
        client.tls_profile.to_dict(),
        client.h2_profile.to_dict(),
        client.header_order,
        client.h3_header_order,
        client.cookie_order,
        (policy.intent, policy.acquisition, policy.upgrade, policy.fallback),
    )


@pytest.mark.parametrize("name", PRESET_NAMES)
def test_every_preset_comes_back_from_its_bundle(name):
    bundle = export_preset_json(name)
    assert json.loads(bundle)["name"] == name
    client = BlockingClient.from_preset_json(bundle)
    assert settings(client) == settings(getattr(BlockingClient, name)())
    # A bundle has no TCP fingerprint.
    assert client.tcp_fingerprint is None


@pytest.mark.parametrize("client_cls", [lkrequest.Client, BlockingClient])
def test_bytes_a_file_and_a_tcp_fingerprint(client_cls, tmp_path):
    bundle = export_preset_json("chrome_158")
    path = tmp_path / "chrome_158.json"
    path.write_text(bundle, encoding="utf-8")
    expected = settings(client_cls.chrome_158())
    for client in (
        client_cls.from_preset_json(bundle.encode(), tcp_fingerprint="chrome"),
        client_cls.from_preset_file(path, tcp_fingerprint=TcpFingerprint.chrome()),
        client_cls.from_preset_file(str(path), tcp_fingerprint="chrome"),
    ):
        assert settings(client) == expected
        assert client.tcp_fingerprint.to_dict() == TcpFingerprint.chrome().to_dict()


OK = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
ORDERED = ("accept", "user-agent", "sec-ch-ua")


def wire_order(raw_http, client) -> list[str]:
    """The order three headers went out in."""
    server = raw_http(lambda request: OK)
    headers = {"Accept": "*/*", "User-Agent": "test", "Sec-Ch-Ua": "x"}
    client.session().get(f"{server.url}/", headers=headers)
    [request] = server.requests
    return [name for name in map(str.lower, request.raw_names) if name in ORDERED]


def test_the_header_order_in_the_bundle_goes_on_the_wire(raw_http):
    bundle = json.loads(export_preset_json("chrome_158"))
    as_exported = wire_order(
        raw_http, BlockingClient.from_preset_json(json.dumps(bundle))
    )
    assert sorted(as_exported) == sorted(ORDERED)
    bundle["header_order"] = list(reversed(bundle["header_order"]))
    edited = BlockingClient.from_preset_json(json.dumps(bundle))
    assert edited.header_order == bundle["header_order"]
    assert wire_order(raw_http, edited) == list(reversed(as_exported))


def test_the_protocol_policy_in_the_bundle_is_used_and_checked():
    bundle = json.loads(export_preset_json("chrome_158"))
    bundle["runtime"]["protocol"] = {
        "intent": "reuse_existing_protocol",
        "acquisition": {"type": "reuse_existing_first"},
        "upgrade": "off",
        "fallback": "allow_fallback",
    }
    client = BlockingClient.from_preset_json(json.dumps(bundle))
    assert client.protocol_policy.intent == lkrequest.HttpIntent.ReuseExistingProtocol
    # H2-only cannot fall back to HTTP/3, so a bundle saying both is refused.
    bundle["runtime"]["protocol"]["intent"] = "h2_only"
    with pytest.raises(ValueError, match="InvalidProfile at /runtime/protocol"):
        BlockingClient.from_preset_json(json.dumps(bundle))


@pytest.mark.parametrize(
    "bundle, message",
    [
        ("{nope", "InvalidJson at /"),
        ('{"format": "lkrequest-profile-bundle", "schema_version": 9}', "at /"),
    ],
)
def test_a_bundle_upstream_refuses_raises_value_error(bundle, message):
    with pytest.raises(ValueError, match=f"Invalid preset bundle: .*{message}"):
        BlockingClient.from_preset_json(bundle)


def test_an_unknown_field_is_named_by_its_json_pointer():
    bundle = json.loads(export_preset_json("chrome_158"))
    bundle["runtime"]["surprise"] = 1
    with pytest.raises(ValueError, match="UnknownField at /runtime/surprise"):
        BlockingClient.from_preset_json(json.dumps(bundle))


def test_a_missing_file_raises_value_error(tmp_path):
    with pytest.raises(ValueError, match="Failed to load preset bundle from"):
        BlockingClient.from_preset_file(tmp_path / "missing.json")


def test_an_unknown_preset_cannot_be_exported():
    with pytest.raises(ValueError, match="Unknown preset: 'chrome_999'"):
        export_preset_json("chrome_999")
