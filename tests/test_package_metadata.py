"""Tests for installed package metadata."""

from importlib.metadata import version as distribution_version

import lkrequest


def test_runtime_version_matches_distribution_metadata():
    assert lkrequest.__version__ == distribution_version("lkrequest")
