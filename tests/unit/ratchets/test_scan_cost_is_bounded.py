"""A scan is bounded in time, not only in size (ADR 0023).

``max_content_chars`` bounds what a detector will read. It did not bound what
reading it cost: three rules were quadratic in adversarial input, and every one
of them blew up *inside* the declared budget —

* ``pii:email`` had no left boundary, so every character of a run of letters
  started a fresh scan for an ``@`` that was not there: **43 s** on 200 000
  letters, on the proxy's event loop, from one tool result;
* ``injection:hidden-tag`` scanned to the end of the content from every opening
  tag that had no closing tag: **18 to 23 s** on 200 000 characters of open tags;
* ``injection:tag-breakout`` (inbound) re-scanned the rest of the line from every
  closing tag: **11 s** on one 200 000-character line of ``</field>``.

Seen red on all three before the rules were bounded. The bound below is loose on
purpose — a CI runner is slower than the machine that measured 0.4 s at worst
after the fix — and still an order of magnitude under the smallest failure.
"""

from __future__ import annotations

import time

import pytest

from limes.detector import Context, Direction
from limes.detectors.injection import InjectionDetector
from limes.detectors.injection_egress import InjectionEgressDetector
from limes.detectors.pii_egress import PiiEgressDetector
from limes.detectors.secrets_egress import SecretsEgressDetector

pytestmark = pytest.mark.mutation

#: The declared egress budget, and the inbound one since ADR 0023: the largest
#: content a detector agrees to read, so the cost at this size is the cost it
#: exposes to a hostile peer.
N = 200_000

#: Seconds a single (detector, input) pair may take at ``N`` characters.
BOUND_SECONDS = 5.0

_CONTEXT = Context(policy_hash="scan-cost", actor=None)


def _repeated(unit: str) -> str:
    return (unit * (N // len(unit) + 1))[:N]


#: Each input is the worst case some rule family was measured against, named by
#: the shape that made it expensive. The three that were red are first.
ADVERSARIAL: dict[str, str] = {
    "letters_no_at": "a" * N,
    "important_open_tags": _repeated("<IMPORTANT>"),
    "field_tags_one_line": _repeated("</field>"),
    "hidden_open_tags": _repeated("<HIDDEN>x"),
    "sk_prefixes": _repeated("sk-"),
    "jwt_long_segments": _repeated("a" * 1000 + "."),
    "email_local_parts": _repeated("john.doe%x+y-"),
    "pem_begin_lines": _repeated("-----BEGIN PRIVATE KEY-----\n"),
    "dialogue_turns": _repeated("\nUser: hello "),
    "ignore_words": _repeated("ignore the instructions "),
    "bracket_run": "[" * N,
    "brace_run": "{" * N,
    "system_colon": _repeated("SYSTEM: "),
    "aws_secret_carriers": _repeated("aws_secret_access_key = "),
}

DETECTORS = {
    "injection": (InjectionDetector, Direction.INBOUND),
    "pii-egress": (PiiEgressDetector, Direction.OUTBOUND),
    "secrets-egress": (SecretsEgressDetector, Direction.OUTBOUND),
    "injection-egress": (InjectionEgressDetector, Direction.OUTBOUND),
}


@pytest.mark.parametrize("shape", sorted(ADVERSARIAL))
@pytest.mark.parametrize("detector_id", sorted(DETECTORS))
def test_a_full_budget_of_adversarial_content_scans_in_bounded_time(detector_id, shape):
    factory, direction = DETECTORS[detector_id]
    detector = factory()
    started = time.perf_counter()
    detector.inspect(direction, ADVERSARIAL[shape], _CONTEXT)
    elapsed = time.perf_counter() - started
    assert elapsed < BOUND_SECONDS, (
        f"{detector_id} took {elapsed:.1f}s on {N} characters of {shape!r}: a rule is "
        "re-scanning the content from every position, and a hostile peer can freeze the "
        "guard inside its own declared budget (ADR 0023)"
    )


def test_the_budget_is_the_size_this_ratchet_measures_at():
    # The bound is only a bound at the size a detector actually agrees to read.
    # If a budget grows, this file must grow with it or it measures a smaller
    # exposure than the one that ships.
    from limes.detectors.egress_policy import load_egress_policy
    from limes.policy import load_injection_policy

    egress = load_egress_policy()
    for detector_id in egress.detectors():
        assert egress.budget_for(detector_id) <= N
    assert load_injection_policy().max_content_chars <= N
