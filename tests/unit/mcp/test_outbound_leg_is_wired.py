from __future__ import annotations

import pytest

from limes.detector import Detector
from limes.detectors import ADMITTED

bridge = pytest.importorskip("limes.transports.mcp.bridge")


def test_the_proxy_installs_every_admitted_egress_detector():
    # The defect this pins: `serve` defaulted its outbound leg to (), so the
    # shipped proxy ran with NOTHING on the leg the README describes it guarding.
    # It was found by an end-to-end test of a poisoned tools/list, not by any
    # unit test, because every unit test passed its own detectors in.
    installed = {detector.id for detector in bridge.outbound_detectors()}
    admitted = {cls.id for cls in ADMITTED if str(cls.id).endswith("-egress")}
    assert installed == admitted
    assert installed, "an empty outbound leg is the bug, not a configuration"


def test_the_derivation_cannot_quietly_select_nothing():
    # A derived set is only safe while somebody checks what it derives. If the
    # naming convention it reads ever changes, this goes red instead of the proxy
    # going silently unguarded.
    assert len(bridge.outbound_detectors()) >= 3


def test_every_installed_detector_satisfies_the_protocol():
    for detector in bridge.outbound_detectors():
        assert isinstance(detector, Detector)


def test_an_explicit_empty_sequence_is_still_expressible():
    # `()` must keep meaning "deliberately unguarded": the transparency tests use
    # it to prove exact pass-through, and a default that swallowed that
    # distinction would make those tests unable to say what they say.
    import inspect

    signature = inspect.signature(bridge.serve)
    assert signature.parameters["outbound"].default is None
