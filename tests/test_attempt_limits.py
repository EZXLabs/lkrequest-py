"""Attempt limits and attempt summaries: how many HTTP submissions and
connection starts one request may make, at client, session and request scope,
and what a request did, read back from its response or its exception.
"""

from __future__ import annotations

import pickle

import pytest

import lkrequest
from lkrequest import AttemptLimits, FixedInterval
from lkrequest.blocking import Client as BlockingClient

UNAVAILABLE = (
    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n"
    b"Connection: close\r\n\r\n"
)
NO_LIMITS = {
    "extra_http_attempts": None,
    "extra_http_scope": None,
    "connect_attempts": None,
    "connect_scope": None,
}


def client(**kwargs) -> BlockingClient:
    return BlockingClient(verify=False, **kwargs)


def test_limits_are_a_value():
    limits = AttemptLimits(extra_http_attempts=2, connect_attempts=0)
    assert (limits.extra_http_attempts, limits.connect_attempts) == (2, 0)
    assert limits == AttemptLimits(connect_attempts=0, extra_http_attempts=2)
    assert repr(limits) == "AttemptLimits(extra_http_attempts=2, connect_attempts=0)"
    assert AttemptLimits() == AttemptLimits(
        extra_http_attempts=None, connect_attempts=None
    )
    with pytest.raises(OverflowError):
        AttemptLimits(extra_http_attempts=-1)
    with pytest.raises(TypeError):
        AttemptLimits(2)


def test_a_response_says_what_its_request_did(server_url):
    response = client().session().get(f"{server_url}/get")
    assert response.attempt_summary == {
        "started": True,
        "effective_limits": NO_LIMITS,
        "http_submissions": 1,
        "extra_http_submissions": 0,
        "redirects": 0,
        "recoveries": 0,
        "connect_initiations": 1,
        "probe_suppressed_by_connect_limit": False,
        "outcome": "succeeded",
        "final": True,
        "denial_reason": None,
    }


async def test_an_async_response_says_so_too(server_url):
    session = lkrequest.Client(verify=False).session()
    response = await session.get(f"{server_url}/redirect/2")
    summary = response.attempt_summary
    # Redirects are submissions of their own, but not extra ones, and the
    # pooled connection carries them.
    assert (summary["http_submissions"], summary["redirects"]) == (3, 2)
    assert (summary["extra_http_submissions"], summary["connect_initiations"]) == (
        0,
        1,
    )


def test_a_streamed_response_is_summarised_when_handed_over(server_url):
    stream = client().session().send_streaming("GET", f"{server_url}/get")
    assert (stream.attempt_summary["outcome"], stream.attempt_summary["final"]) == (
        "succeeded",
        True,
    )
    stream.bytes()


@pytest.mark.parametrize(
    "limits, submissions, denial",
    [
        (None, 4, None),
        (AttemptLimits(extra_http_attempts=1), 2, "extra_http_limit"),
        (AttemptLimits(extra_http_attempts=0), 1, "extra_http_limit"),
    ],
)
def test_extra_http_attempts_caps_the_retries(raw_http, limits, submissions, denial):
    server = raw_http(lambda request: UNAVAILABLE)
    session = client().session(retry=FixedInterval(max_retries=3, interval=0.01))
    response = session.get(f"{server.url}/", attempt_limits=limits)
    assert response.status_code == 503
    assert len(server.requests) == submissions
    summary = response.attempt_summary
    assert summary["http_submissions"] == submissions
    assert summary["extra_http_submissions"] == summary["recoveries"] == submissions - 1
    assert summary["denial_reason"] == denial


def test_connect_attempts_of_zero_starts_no_connection(server_url):
    capped = client(attempt_limits=AttemptLimits(connect_attempts=0))
    with pytest.raises(
        lkrequest.ResourceLimitError, match="connection attempt"
    ) as caught:
        capped.session().get(f"{server_url}/get")
    summary = caught.value.attempt_summary
    assert (summary["connect_initiations"], summary["denial_reason"]) == (
        0,
        "connect_limit",
    )
    assert summary["outcome"] == "failed"


def test_connect_attempts_of_zero_still_reuses_a_pooled_connection(server_url):
    session = client().session()
    session.get(f"{server_url}/get")
    response = session.get(
        f"{server_url}/get", attempt_limits=AttemptLimits(connect_attempts=0)
    )
    assert response.status_code == 200
    assert response.attempt_summary["connect_initiations"] == 0


def test_a_scope_can_only_tighten_the_one_above():
    capped = client(attempt_limits=AttemptLimits(extra_http_attempts=2))
    assert capped.attempt_limits == AttemptLimits(extra_http_attempts=2)
    assert capped.effective_attempt_limits == {
        **NO_LIMITS,
        "extra_http_attempts": 2,
        "extra_http_scope": "client",
    }
    # Refused where it is given, rather than when a request is sent.
    with pytest.raises(ValueError, match="exceeds inherited limit 2"):
        capped.session(attempt_limits=AttemptLimits(extra_http_attempts=5))
    session = capped.session(attempt_limits=AttemptLimits(extra_http_attempts=1))
    assert session.attempt_limits == AttemptLimits(extra_http_attempts=1)
    assert session.effective_attempt_limits["extra_http_scope"] == "session"
    # A session given none inherits the client's.
    assert capped.session().effective_attempt_limits["extra_http_scope"] == "client"


def test_a_request_above_its_session_is_refused_before_it_is_sent(raw_http):
    server = raw_http(lambda request: UNAVAILABLE)
    session = client().session(attempt_limits=AttemptLimits(extra_http_attempts=1))
    with pytest.raises(ValueError, match="exceeds inherited limit 1"):
        session.get(server.url, attempt_limits=AttemptLimits(extra_http_attempts=3))
    assert server.connections == 0
    response = session.get(
        server.url, attempt_limits=AttemptLimits(extra_http_attempts=0)
    )
    assert response.attempt_summary["effective_limits"]["extra_http_scope"] == "request"


def test_a_status_error_carries_the_summary_through_pickling(raw_http):
    server = raw_http(lambda request: UNAVAILABLE)
    response = client().session().get(server.url)
    with pytest.raises(lkrequest.HttpStatusError) as caught:
        response.error_for_status()
    assert caught.value.attempt_summary == response.attempt_summary
    restored = pickle.loads(pickle.dumps(caught.value))
    assert restored.attempt_summary == response.attempt_summary


def test_an_exception_built_by_hand_has_no_summary():
    assert lkrequest.RequestError("by hand").attempt_summary is None
