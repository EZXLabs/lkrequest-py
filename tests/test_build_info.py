"""`features()` and `list_presets()`: what this build of the module offers.

The preset list is a table of its own in the Rust code, so these tests also
check that it names every preset the clients take, and nothing else.
"""

from __future__ import annotations

import pytest

import lkrequest
from lkrequest.blocking import Client as BlockingClient

FEATURES = {"quic-h3", "masque", "doh", "telemetry", "synthetic-fp"}
# A class each feature registers, which is how its presence used to be told.
REGISTERS = {
    "quic-h3": "QuicProfile",
    "masque": "MasqueConfig",
    "synthetic-fp": "Layers",
}


def test_every_feature_is_named():
    features = lkrequest.features()
    assert set(features) == FEATURES
    assert all(isinstance(enabled, bool) for enabled in features.values())


@pytest.mark.parametrize(("feature", "name"), REGISTERS.items())
def test_a_feature_is_there_when_its_class_is(feature, name):
    assert lkrequest.features()[feature] == hasattr(lkrequest, name)


def test_presets_come_in_a_stable_order():
    presets = lkrequest.list_presets()
    assert presets == lkrequest.list_presets()
    assert presets[0] == {
        "name": "chrome_131",
        "browser": "chrome",
        "http3": lkrequest.features()["quic-h3"],
    }
    assert {p["browser"] for p in presets} == {"chrome", "firefox", "safari"}
    assert all(p["name"].startswith(p["browser"] + "_") for p in presets)


def test_the_list_is_every_preset_the_clients_take():
    listed = [p["name"] for p in lkrequest.list_presets()]
    constructors = [
        name
        for name in dir(lkrequest.Client)
        if name.startswith(("chrome_", "firefox_", "safari_"))
    ]
    assert sorted(listed) == sorted(constructors)
    for name in listed:
        assert hasattr(BlockingClient, name)
        BlockingClient(tls_profile=name, h2_profile=name)


@pytest.mark.skipif(
    not hasattr(lkrequest, "QuicProfile"), reason="built without the quic-h3 feature"
)
def test_safari_has_no_http3():
    http3 = {p["name"]: p["http3"] for p in lkrequest.list_presets()}
    assert http3["chrome_155"] is True
    assert http3["safari_26"] is False
