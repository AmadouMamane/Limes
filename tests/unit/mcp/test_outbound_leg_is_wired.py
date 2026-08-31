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


# --- the HTTP transport, same sentinel (the same defect shipped twice) -------


@pytest.mark.mutation  # seen red with the sentinel resolving to () instead
def test_the_http_factory_wires_the_outbound_leg_by_default():
    # The stdio fix above never reached the HTTP transport: build_asgi_app,
    # serve_http and run_http all defaulted outbound=(), so `limes proxy-http`
    # filtered injection inbound and let PII and secrets leave unscanned —
    # while every HTTP end-to-end proof passed its own detectors in. This
    # interrogates the relay the shipped default actually builds, not a
    # signature: the leg must come out wired.
    http = pytest.importorskip("limes.transports.mcp.http")
    from limes.transports.mcp.sink import NullSink

    config = http.HttpProxyConfig(upstream_url="http://127.0.0.1:1/mcp")
    make_relay = http._relay_factory(
        config, sink=NullSink(), clock=bridge.utc_now_iso, outbound=None
    )
    assert make_relay().outbound_is_wired, (
        "outbound=None must install the admitted egress detectors"
    )


def test_every_http_entry_point_defaults_its_outbound_leg_to_the_sentinel():
    # All three public layers funnel into _relay_factory; each must pass the
    # sentinel through rather than re-introducing `()` as its own default.
    import inspect

    http = pytest.importorskip("limes.transports.mcp.http")
    for entry in (http.build_asgi_app, http.serve_http, http.run_http):
        assert inspect.signature(entry).parameters["outbound"].default is None, entry.__name__
