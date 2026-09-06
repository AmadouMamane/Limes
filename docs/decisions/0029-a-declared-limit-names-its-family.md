# 29. A declared limit names its family

Date: 2026-09-06

## Status

Accepted. Amends ADR 0002's algebra a second time: `CannotSay` gains `kinds`.
Amends ADR 0026's ruling: `on_cannot_say` becomes a policy by family rather than
a switch. Amends ADR 0004's frontier for `src/limes/verdict.py`,
`src/limes/detector.py`, `src/limes/guard.py`, `src/limes/detectors/injection.py`
and the two contract tests that construct a `CannotSay`
(`tests/unit/test_verdict.py`, `tests/unit/test_record_chain.py`), each re-pinned
in `tests/unit/test_frontier.py`. Reaffirms ADR 0026's refusal of a fourth
verdict: a family is a property of the third state, not a state of its own.

## Context

0.14.0 made the guard say what it cannot read (ADR 0028), and the honest answer
turned out to be blocked by default for four kinds of ordinary deployment:

- an agent that navigates by **screenshot** — the tool returns an image, the
  guard reads text, the whole result is refused, its text included;
- a tool that returns **encoded files** — the official GitHub server returns a
  file's contents as base64, a PDF reader does the same; the most common case in
  practice;
- a deployment in **another language** — a result mostly in Chinese, Arabic,
  Russian or Japanese is declared unreadable by both word-reading detectors,
  which before ADR 0028 called it "clean" and now, more honestly, call it
  unread;
- marginally, a fetched page whose words carry **invisible characters**.

The remedy was `on_cannot_say: allow`, and it was coarse. It accepted, in one
word, every declared limit at once: the image *and* the base64 *and* the other
script *and* the budget *and* the leg nobody reads. An operator whose tools
return screenshots wanted to accept exactly one of those, and the setting could
not say which. ADR 0026 had separated the *causes* — a declared limit, a fault,
a refusal — so that accepting the guard's limits did not mean accepting a
crashed guard. The same argument applies one level down: accepting one limit
the guard declared does not mean accepting them all.

A second defect sat in the script measure itself, and it is repaired beside this
record as ADR 0028 Amendment 1: the measure "most letters are outside the Latin
script" ran whatever `locales` the policy declared, so an operator who wrote
their own rules in Chinese and declared `locales: [zh]` saw every result in
Chinese declared unreadable. The measure's premise — that the rules read Latin
script — was contradicted by the operator's own declaration, and the code did
not read it.

## Decision

**A declared limit names its family.** `BlindKind` is a closed `StrEnum` of
nine values, each the *what* of a limit the guard declared:

| family | what could not be read |
|---|---|
| `budget` | content over the size the detector declared it scans |
| `encoding` | content that does not encode to UTF-8 |
| `opaque` | content mostly made of base64 / hex / serialised-blob runs |
| `invisible` | a format character wedged inside a word or a number |
| `script` | text mostly in a script the word-reading rules were not written for |
| `locale` | a caller-declared language the policy does not list |
| `binary` | an image, audio or blob block the payload walk derived no text from |
| `unwitnessed` | a leg no detector reads, or a kind of message the relay forwards unread |
| `unspecified` | a `DetectorBlind` that named no family |

The vocabulary is closed for the reason `VALIDATORS` is closed (ADR 0004): a
policy naming a family that does not exist would be a setting that governs
nothing, and it is refused at load rather than ignored.

**The verdict carries them.** `CannotSay(blind_spot, cause, kinds)`, where
`kinds` is a `frozenset[BlindKind]` with no default. A `DECLARED` blind spot
must carry at least one — a limit with no family is `UNSPECIFIED`, said out loud
— and the type refuses an empty set or a string somebody typed. A `REFUSED`
blind spot carries none: nothing about the content was declared. A `FAULT` may
carry the families declared beside it, for the journal; no policy reads them off
a fault. `fingerprint()` seals `kinds` (sorted) into the canonical JSON, so two
blind spots that differ only in family are different records; `render()` and a
new `blind_label()` show `declared: binary, script`.

**The detector names it.** `DetectorBlind(message, kind=BlindKind.BUDGET)`.
`kind` defaults to `UNSPECIFIED`; a name outside the vocabulary raises
`ValueError` out of the detector, which the core renders as a `FAULT` — a
detector naming a family that does not exist is a bug, not a limit. Every
shipped raise site names its family: the two budget checks (`budget`), the
UTF-8 check (`encoding`), and the readability screen (`opaque`, `invisible`,
`script`, `locale`).

**The core aggregates them.** `decide()` collects the family of every
`DetectorBlind`, adds `UNWITNESSED` when nobody read the leg, and takes the
caller's blind spots as `(family, sentence)` pairs — the payload walk hands over
its binary blocks under `binary`. The relay's declarations of what it forwards
unread carry `unwitnessed`.

**The setting becomes a policy.** `CannotSayPolicy(default, by_kind)` mirrors
the egress policy of ADR 0006. The policy file accepts the scalar it always did
— `on_cannot_say: allow` means every declared family — and a mapping:

```yaml
on_cannot_say:
  default: deny
  by_kind:
    binary: allow      # tool results carrying screenshots cross
    opaque: allow      # …and base64 file contents
```

The loader refuses an unknown family, an unknown key and an unknown disposition,
each by name. `--on-cannot-say deny|allow` keeps its shape and moves the
*default*, leaving the file's per-family lines alone, exactly as
`--on-egress-finding` does: a flag that quietly rewrote a family the file named
would be a trap in either direction.

**The ruling opens all of a verdict's families or none.** `rule()` forwards a
`CannotSay` only when its cause is `DECLARED` **and** the policy allows every
family it carries. A result that is an image beside a base64 dump carries
`binary` and `opaque`, and crosses under a policy that opened both — not under
one that opened `binary` alone. The reason line of a blocked declared verdict
names the families that closed it (`closed by on_cannot_say for: opaque`), the
refusal an agent reads gives the exact setting that would open the verdict
(`on_cannot_say: {by_kind: {binary: allow, opaque: allow}}`), and `_meta.limes`
gains a `kinds` list beside `cause`. A fault and a refusal block under every
policy, as ADR 0026 decided.

**The in-process guard and the CLI change no disposition.** `check_egress`
still blocks every `CannotSay`; `limes check` still exits `3`; both now name the
families in their reason line and their text output, and `--json` carries
`kinds` because it is the fingerprint.

## Consequences

- An operator whose tools return screenshots writes `by_kind: {binary: allow}`
  and nothing else moves: a base64 dump, Cyrillic prose, an over-budget result
  and a leg nobody reads stay blocked, each named in the refusal with the line
  that would open it. The README's day-one warning now points at that line.
- The all-of-them rule is the conservative one, and it is stated: a verdict
  whose families are partly open is blocked, and the refusal says which family
  closed it. The alternative — forward when *any* family is open — would let an
  operator who accepted images accept, unknowingly, the base64 riding beside
  them. A ratchet holds the rule at *all*, and was seen red under *any*.
- Every recorded `CannotSay` digest changes at 0.15.0, for the second release
  running; ledgers are per session and no chain spans a version. Doing this and
  ADR 0028 Amendment 1 in one release is deliberate: neither is publishable on
  its own without a deployment meeting one more digest change later.
- `CannotSay(blind_spot, cause)` with two arguments no longer constructs; in
  this repository, three relay methods, the core and a handful of tests. The
  package is not on PyPI. `case CannotSay(blind_spot, cause):` keeps matching.
- The relay's declared-unread records now say `unwitnessed`, so an auditor
  counting "what the guard never read" filters on `"kinds":["unwitnessed"]`
  rather than on prose.
- `BlindKind`, like `BlindCause`, is imported from `limes.verdict` and not
  re-exported from `limes` (ADR 0014's rule for the prose-only module).
- The ratchet `tests/unit/ratchets/test_a_declared_limit_names_its_family.py`
  (37 tests) was seen red under seven named mutations before this record was
  written: the core dropping a family to `unspecified`; the policy opening on
  *any* family; the policy ignoring the cause; the fingerprint omitting the
  families; the payload walk labelling an image `unspecified`; the loader
  accepting an unknown family; and the script measure firing under a policy
  that declares a non-Latin language.
