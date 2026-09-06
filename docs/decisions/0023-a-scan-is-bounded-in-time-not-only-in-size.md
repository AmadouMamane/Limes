# 23. A scan is bounded in time, not only in size

Date: 2026-09-06

## Status

Accepted. Amends ADR 0004's frontier for three files by the mechanism ADR 0011
established — `src/limes/detectors/policy.yaml` (re-pinned), `src/limes/policy.py`
and `src/limes/detectors/injection.py` (pinned for the first time) — and adds a
ratchet that measures what those files cost.

## Context

`max_content_chars` exists so that "an unbounded regex sweep over an unbounded
tool result" — the README's own words — cannot be a denial-of-service surface.
It bounds the **size** a detector agrees to read. It said nothing about the
**time** reading that size takes, and three rules were quadratic in adversarial
input, every one of them at or under the declared 200 000 characters:

| rule | input | measured |
|---|---|---|
| `pii:email` | 200 000 letters with no `@` | **43 s** |
| `injection:hidden-tag` | 200 000 characters of `<IMPORTANT>` with no closing tag | **18–23 s** |
| `injection:tag-breakout` (inbound) | one 200 000-character line of `</field>` | **11 s** |

The cause was the same each time: a shape with no left boundary, or an unbounded
quantifier, starts a fresh scan of the remaining content at every candidate
position. The e-mail rule is the worst because its character class includes `.`,
`-` and `+`, so a run of letters, a dotted path, or a string of `sk-` prefixes is
one run — and a run of `n` characters costs `n²/2` steps.

The transports run detectors synchronously on their event loop. One hostile tool
result, or one fetched page that happens to be long and unbroken, freezes the
stdio proxy for the duration; under the HTTP proxy every session shares that
loop. Nothing leaks and nothing is forwarded — it is closed — but a guard that
can be stopped by its own budget is not the guard the budget was declared for.

Two smaller facts belong beside it. The inbound leg declared no budget at all:
`injection` read whatever arrived, so the same class of input, a few times
larger, reached the same rules with no size floor under them. And a policy file
whose pattern did not compile, or which was not YAML, left the loaders as
`re.error` or `yaml.YAMLError` — neither a `ValueError` — so `limes check` printed
a traceback and exited **1**, the code that means *deny*, where its contract says
a mis-invocation exits 2.

## Decision

**1. Every rule's cost is linear in the content, and a ratchet measures it.**
`tests/unit/ratchets/test_scan_cost_is_bounded.py` runs all four detectors over a
named set of adversarial inputs at the declared budget and refuses any pair that
takes longer than five seconds — an order of magnitude under the smallest
failure, and loose enough for a CI runner. It was seen red on all three rules
before any of them was bounded.

**2. The three rules are bounded by shape, and the bound is stated in the file.**

- `pii:email` gains a left boundary, `(?<![A-Za-z0-9._%+-])`. It is a cost gate,
  not a precision gate: an address that starts inside a run of local-part
  characters was already part of that longer local part, so every address the
  old shape located, the new one locates. 43 s → 0.00 s on the same input; the
  matrices are unchanged to the digit.
- `injection:hidden-tag` bounds its body to 2 000 characters. A block longer than
  that is not spanned by this rule; what it carries is still read by every other
  rule in the file. 18–23 s → 0.03 s.
- `injection:tag-breakout` looks 600 characters ahead instead of to the end of
  the line. This is the one ported rule that is no longer byte-verbatim from
  Tessera, and the file's header says so; the baseline's recall (22/33) is
  pinned by a test, so the port stays a measured thing. 11 s → 0.05 s.

**3. The inbound leg declares a budget too.** `policy.yaml` gains
`max_content_chars: 200000` — the same figure the egress detectors declare, so
both legs refuse at one size — and `injection` raises `DetectorBlind` beyond it,
which the core renders as `CannotSay` and every transport turns into a block. It
is data in the policy file, hashed into every piece of evidence, for the reason
`egress.yaml` gives: "I did not look at this" must be auditable.

The key is **optional** in an injection policy, unlike in `egress.yaml`, because
injection policies written before it existed are in use; an absent key gets the
packaged default and the file's hash still covers the absence. A present key
must be a positive integer, or the policy does not load.

**4. A policy that cannot load raises `ValueError`, whatever failed.** The four
loaders (`policy.py`, `egress_policy.py`, `redaction.read_egress_policy`,
`config.read_on_cannot_say`) wrap a pattern that does not compile and a file
that is not YAML into the `ValueError` their docstrings always promised. The CLI
maps that to exit 2; the proxies refuse to start with the reason on stderr.

## Consequences

- `pii-egress`, `secrets-egress`, `injection-egress` and `injection` each scan a
  full budget of any of the fourteen named adversarial shapes in under 0.4 s on
  the machine that measured the failures, and the ratchet holds them under 5 s
  anywhere.
- `src/limes/detectors/policy.yaml` leaves its ADR 0019 pin and is re-pinned to
  its post-ADR bytes; `src/limes/policy.py` and `src/limes/detectors/injection.py`
  leave byte-identity to v0.1 and are pinned beside it. The ratchet's strength
  is intact: any further drift is red.
- The Tessera-regex baseline reads the bounded `tag-breakout` rule. Its measured
  recall did not move (22/33), and the test that pins it is the witness that the
  port is still the port.
- `limes check --policy` on a broken policy exits 2 and says which rule or
  which line, instead of printing a traceback and exiting 1.
- A denial-of-service through the guard now costs an attacker more than a long
  string. What it does not buy: a bound on a *pathological policy* an operator
  writes themselves — `--policy` is trusted input, and a rule with a nested
  unbounded quantifier will still cost what it costs.
