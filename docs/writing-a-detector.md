# Writing a detector

A new capability in limes is a **detector**, never a change to the core (ADR
0004). This guide shows the contract, the two ways to build one (rules-as-data, or
code), and the bar a detector must clear to be *admitted* into the shipped set.

You do not have to clear that bar to use your own detector privately — you hand
any object that satisfies the protocol to a `Guard`, and the verdict algebra, the
ledger and the egress dispositions come for free. The admission bar governs what
**limes itself** ships.

---

## 1. The contract

A detector declares `id` and `version` and implements one method
(`limes.detector.Detector`):

```python
from limes.detector import Context, Direction, Finding, DetectorBlind
from limes.spans import redact

class HexColorDetector:
    """Toy detector: flags hex colour codes on the outbound leg."""
    id = "hex-color"
    version = "0.1.0"

    def inspect(self, direction: Direction, content: str, ctx: Context) -> list[Finding]:
        if direction is not Direction.OUTBOUND:      # this detector only guards egress
            return []
        findings: list[Finding] = []
        import re
        for m in re.finditer(r"#[0-9a-fA-F]{6}\b", content):
            findings.append(
                Finding(
                    detector_id=self.id,
                    label="style:hex-color",           # kind:name — 'style' is the egress kind
                    spans=(redact(content, m.start(), m.end(), "style:hex-color"),),
                )
            )
        return findings
```

Three rules the contract enforces, and why each matters:

- **A detector returns findings; it never decides the verdict.** The core
  (`limes.guard.decide`) turns findings into `Deny`, no findings into `Allow`, and
  a blind detector into `CannotSay`. Keeping that decision in one pure place is
  what makes a `Deny` re-derive identically across transports.
- **A span is the *validated* value, exactly** — `redact(content, start, end,
  label)` records the offsets and a hash of the matched text, never the raw bytes.
  The transport masks by those offsets and the eval grades by them, so a span you
  report but did not verify would mislead both.
- **If you cannot look, raise `DetectorBlind`.** Dependency absent, content
  unreadable, budget exceeded — the core turns it into `CannotSay`, and the egress
  leg blocks. Returning `[]` when you did not actually inspect is the one lie the
  system forbids: it reads as "clean".

Wire it into a guard like any shipped detector:

```python
from limes.transports.in_process import Guard
guard = Guard([HexColorDetector()], policy_hash="my-policy-sha")
```

---

## 2. Prefer rules-as-data

Most detectors do not need Python at all. The egress detectors are a **shared
scanner** driven by a YAML file (`src/limes/detectors/egress.yaml`): each rule is
a *shape* (a regex) plus a *check* (a named validator). Adding a category is
adding a rule, not code:

```yaml
- label: pii:pan          # kind:name — 'pii' is what the transport policies by
  validator: luhn         # a name from the closed VALIDATORS registry
  retry_trim: false
  pattern: '(?<![A-Za-z0-9+])\d(?:[ \xa0-]?\d){12,18}(?![A-Za-z0-9]|[.,]\d)'
```

- **`validator`** is a name from a *closed* registry
  (`limes.detectors.egress_policy.VALIDATORS`: `none`, `luhn`, `iban_mod97`,
  `jwt_header`, …). An unknown name is a **load error**, never a rule that matches
  a shape and vouches for nothing. `validator: none` says out loud that the shape
  *is* the whole claim (an e-mail has no checksum).
- **The arithmetic a regex cannot express** — Luhn, MOD 97-10, the NIR key, the
  JWT header decode — lives in `src/limes/detectors/checksums.py` and is *named*
  from the YAML, so an auditor reads which shapes are scanned and which check gates
  each without reading Python.
- **`retry_trim`** lets a candidate that failed its check be retried after
  dropping its trailing group (prose runs an IBAN into the next word). It can only
  ever *shorten* a candidate, never relax the validator.

Rules-as-data is why the egress detectors' whole difference is "a plugin, a policy
file and a corpus" — the core never moved to add them.

---

## 3. Discovery and the admitted set

Detectors are discovered two ways, and a test keeps them in sync:

- an **entry point** in `pyproject.toml` under `[project.entry-points."limes.detectors"]`;
- the canonical code tuple `limes.detectors.ADMITTED`.

`tests/unit/test_admission_rule.py` asserts the entry points and `ADMITTED` name
the **same** detectors, so metadata and code cannot drift.

---

## 4. The admission bar (to ship in limes)

To land a detector in the shipped `ADMITTED` set, ADR 0003 requires — and the
enforcer checks, per detector — all of:

1. a **positive corpus** (values it must locate), synthetic by construction;
2. a **benign corpus** of lookalikes (values it must *not* fire on) — this is what
   measures precision;
3. a **null control it measurably beats** (see [Measuring detection](measuring-detection.md));
4. a **dated, published matrix** under `eval/matrices/`.

A detector added to `ADMITTED` without these does not pass silently — it turns the
admission enforcer red, naming itself. And the frontier ratchet
(`tests/unit/test_frontier.py`) requires a new detector's files to land in the
**detector perimeter**, never touching the frozen core — so a "detector" that
edited `guard.py` or `verdict.py` would be caught too.

If a capability cannot be measured this way (e.g. a category with no checksum and
no way to separate it from ordinary prose), it is **not admitted** — an unmeasured
category is a claim, not a capability. That refusal is itself documented rather
than hidden.

---

## See also

- [`docs/decisions/0004-core-detectors-transports.md`](decisions/0004-core-detectors-transports.md) — the three places a capability may land.
- [`docs/decisions/0003-no-detector-without-eval-and-null-control.md`](decisions/0003-no-detector-without-eval-and-null-control.md)
- [Measuring detection](measuring-detection.md) — how the two numbers are produced and read.
