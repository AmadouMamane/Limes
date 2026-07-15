"""Shared test fixtures."""

from __future__ import annotations

import pytest

from limes.verdict import Evidence, Witness

FIXED_OBSERVED_AT = "2026-07-15T00:00:00Z"


@pytest.fixture
def sample_evidence() -> Evidence:
    """A minimal, valid Evidence for constructing verdicts in tests."""
    return Evidence(
        witnesses=(Witness(detector_id="injection", detector_version="0.1.0"),),
        policy_hash="policy-sha",
        content_sha="content-sha",
        matched_spans=(),
        observed_at=FIXED_OBSERVED_AT,
    )
