"""Detector discovery via entry points (ADR 0004).

Detectors are discovered from the ``limes.detectors`` entry-point group. The
*canonical* admitted set, however, is the code tuple
:data:`limes.detectors.ADMITTED` — a test asserts the entry points and that
tuple name the same detectors, so neither can drift from the other, and there is
no silent fallback that would let a mis-declared plugin pass unnoticed.
"""

from __future__ import annotations

from importlib.metadata import entry_points

from limes.detector import Detector

__all__ = ["discover"]


def discover() -> dict[str, type[Detector]]:
    """Return the detector classes registered under the ``limes.detectors`` group.

    Returns:
        A mapping of entry-point name to the loaded detector class.
    """
    found: dict[str, type[Detector]] = {}
    for entry in entry_points(group="limes.detectors"):
        found[entry.name] = entry.load()
    return found
