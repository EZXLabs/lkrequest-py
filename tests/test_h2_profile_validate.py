"""`H2Profile.validate()`: the rules of HTTP/2 a usable fingerprint keeps.

Nothing checks them otherwise, so a profile that breaks one, made by hand or
read from JSON, is sent as it is: useful for seeing how a server copes, not for
looking like a browser.
"""

from __future__ import annotations

import pytest

import lkrequest
from lkrequest import H2Profile, H2Setting
from lkrequest.blocking import Client as BlockingClient

ORDER = ["method", "authority", "scheme", "path"]
PRESETS = [
    name
    for name in dir(H2Profile)
    if name.startswith(("chrome_", "firefox_", "safari_"))
]


def profile(settings=(), window_update=15663105, order=ORDER) -> H2Profile:
    return H2Profile([H2Setting(*s) for s in settings], window_update, list(order))


@pytest.mark.parametrize("name", PRESETS)
def test_every_preset_keeps_the_rules(name):
    getattr(H2Profile, name)().validate()


def test_a_profile_made_by_hand_keeps_them_too():
    profile([("header_table_size", 65536), ("enable_push", 0)]).validate()


@pytest.mark.parametrize(
    ("built", "message"),
    [
        (
            profile(order=["method", "authority", "path"]),
            "pseudo_header_order must be the four pseudo-headers, once each",
        ),
        (
            profile(order=["method", "method", "scheme", "path"]),
            "pseudo_header_order must be the four pseudo-headers",
        ),
        (
            profile([("initial_window_size", 1), ("initial_window_size", 2)]),
            "duplicate SETTINGS id 0x0004",
        ),
        (profile([("enable_push", 2)]), "ENABLE_PUSH 2 not 0/1"),
        (
            profile([("initial_window_size", 2**31)]),
            r"INITIAL_WINDOW_SIZE 2147483648 > 2\^31-1",
        ),
        (profile([("max_frame_size", 1000)]), "MAX_FRAME_SIZE 1000 out of range"),
        (
            profile(window_update=2**31 - 65535),
            "WINDOW_UPDATE increment 2147418113 too large",
        ),
    ],
    ids=[
        "pseudo-header-missing",
        "pseudo-header-twice",
        "setting-twice",
        "enable-push",
        "initial-window",
        "max-frame-size",
        "window-update",
    ],
)
def test_a_profile_that_breaks_one_is_refused(built, message):
    with pytest.raises(ValueError, match=f"invalid H2Profile: {message}"):
        built.validate()


def test_nothing_else_checks():
    broken = H2Profile.from_json(
        H2Profile.chrome_152()
        .to_json()
        .replace('"window_update": 15663105', '"window_update": 2147483647')
    )
    assert broken.to_dict()["window_update"] == 2**31 - 1
    with pytest.raises(ValueError, match="WINDOW_UPDATE"):
        broken.validate()
    # A client takes it as it is.
    BlockingClient(h2_profile=broken)
    lkrequest.Client(h2_profile=broken)
